package encoding_test

import (
	"bytes"
	"context"
	"crypto/md5"
	"fmt"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vmess"
	vmessaead "github.com/xtls/xray-core/proxy/vmess/aead"
	. "github.com/xtls/xray-core/proxy/vmess/encoding"
)

const syntheticUUID = "00112233-4455-6677-8899-aabbccddeeff"

func compatUser(t *testing.T, id string, raw bool) *protocol.MemoryUser {
	t.Helper()
	acc, err := (&vmess.Account{Id: id, RawUuidAuth: raw}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	return &protocol.MemoryUser{Email: "u@example.com", Account: acc}
}

func encodeHeader(t *testing.T, user *protocol.MemoryUser) []byte {
	t.Helper()
	req := &protocol.RequestHeader{
		Version:  1,
		User:     user,
		Command:  protocol.RequestCommandTCP,
		Address:  net.DomainAddress("www.example.com"),
		Port:     net.Port(443),
		Security: protocol.SecurityType_AES128_GCM,
		Option:   protocol.RequestOptionChunkStream,
	}
	b := buf.New()
	defer b.Release()
	common.Must(NewClientSession(context.Background(), 0).EncodeRequestHeader(req, b))
	return append([]byte(nil), b.Bytes()...)
}

func uuidBytes(t *testing.T, s string) [16]byte {
	t.Helper()
	u, err := uuid.ParseString(s)
	if err != nil {
		t.Fatal(err)
	}
	var out [16]byte
	copy(out[:], u.Bytes())
	return out
}

func md5CmdKey(t *testing.T, s string) [16]byte {
	t.Helper()
	acc := compatUser(t, s, false).Account.(*vmess.MemoryAccount)
	var k [16]byte
	copy(k[:], acc.ID.CmdKey())
	return k
}

// openRaw opens a packet the way a peer that knows the raw-UUID mode would:
// AuthID is the first 16 bytes, the key is the raw UUID.
func openWith(key [16]byte, packet []byte) ([]byte, error) {
	var authID [16]byte
	copy(authID[:], packet[:16])
	plain, _, _, err := vmessaead.OpenVMessAEADHeader(key, authID, bytes.NewReader(packet[16:]))
	return plain, err
}

func TestRawUUIDAuthPacketThroughRealEncoder(t *testing.T) {
	raw := uuidBytes(t, syntheticUUID)
	user := compatUser(t, syntheticUUID, true)

	p1 := encodeHeader(t, user)
	if !bytes.Equal(p1[:16], raw[:]) {
		t.Fatalf("raw mode: bytes[0:16] = %x, want UUID %x", p1[:16], raw)
	}
	plain, err := openWith(raw, p1)
	if err != nil {
		t.Fatalf("raw mode: open with raw UUID key failed: %v", err)
	}
	if plain[0] != 1 {
		t.Fatalf("raw mode: plaintext version = %d, want 1", plain[0])
	}
	if _, err := openWith(md5CmdKey(t, syntheticUUID), p1); err == nil {
		t.Fatal("raw mode: the MD5-derived command key must not open the packet")
	}

	// Fresh connection nonce and session material on every request.
	p2 := encodeHeader(t, user)
	if bytes.Equal(p1[34:42], p2[34:42]) {
		t.Fatal("raw mode: connection nonce repeated")
	}
	plain2, err := openWith(raw, p2)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(plain[1:33], plain2[1:33]) {
		t.Fatal("raw mode: request body IV/key repeated")
	}
}

func TestRawUUIDAuthRejectedByStockServer(t *testing.T) {
	user := compatUser(t, syntheticUUID, true)
	packet := encodeHeader(t, user)

	// A stock inbound with the same UUID as a standard user cannot match the
	// raw AuthID.
	stdUser := compatUser(t, syntheticUUID, false)
	v := vmess.NewTimedUserValidator()
	common.Must(v.Add(stdUser))
	defer common.Close(v)
	h := NewSessionHistory()
	defer common.Close(h)
	b := buf.New()
	b.Write(packet)
	if _, err := NewServerSession(v, h).DecodeRequestHeader(b, false); err == nil {
		t.Fatal("stock server accepted a raw-UUID packet")
	}
}

func TestStandardModeUnchanged(t *testing.T) {
	user := compatUser(t, syntheticUUID, false)
	acc := user.Account.(*vmess.MemoryAccount)
	if acc.RawUUIDAuth {
		t.Fatal("standard account has RawUUIDAuth set")
	}
	// The command key is still MD5(UUID || magic).
	raw := uuidBytes(t, syntheticUUID)
	want := md5.Sum(append(raw[:], []byte("c48619fe-8f02-49e0-b9e9-edf763e17e21")...))
	if !bytes.Equal(acc.ID.CmdKey(), want[:]) {
		t.Fatalf("standard command key changed: %x want %x", acc.ID.CmdKey(), want)
	}

	packet := encodeHeader(t, user)
	if bytes.Equal(packet[:16], raw[:]) {
		t.Fatal("standard mode sent the raw UUID as AuthID")
	}
	// The AuthID decodes with the stock decoder (timestamp + CRC).
	holder := vmessaead.NewAuthIDDecoderHolder()
	holder.AddUser(md5CmdKey(t, syntheticUUID), "ok")
	var authID [16]byte
	copy(authID[:], packet[:16])
	if ticket, err := holder.Match(authID); err != nil || ticket != "ok" {
		t.Fatalf("standard AuthID not matched by stock decoder: %v", err)
	}
	if _, err := openWith(raw, packet); err == nil {
		t.Fatal("standard packet opened with the raw UUID key")
	}

	// And the full stock server path decodes it.
	v := vmess.NewTimedUserValidator()
	common.Must(v.Add(user))
	defer common.Close(v)
	h := NewSessionHistory()
	defer common.Close(h)
	b := buf.New()
	b.Write(packet)
	got, err := NewServerSession(v, h).DecodeRequestHeader(b, false)
	if err != nil {
		t.Fatalf("stock server failed to decode a standard packet: %v", err)
	}
	if got.Address.Domain() != "www.example.com" || got.Port != 443 {
		t.Fatalf("decoded wrong target %v:%v", got.Address, got.Port)
	}
}

func TestMixedModesConcurrently(t *testing.T) {
	raw := uuidBytes(t, syntheticUUID)
	stdKey := md5CmdKey(t, syntheticUUID)
	// Same UUID in both modes, to expose any cache keyed on the UUID alone.
	rawUser := compatUser(t, syntheticUUID, true)
	stdUser := compatUser(t, syntheticUUID, false)

	var wg sync.WaitGroup
	errs := make(chan string, 400)
	for i := 0; i < 200; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			p := encodeHeader(t, rawUser)
			if !bytes.Equal(p[:16], raw[:]) {
				errs <- "raw packet without raw AuthID"
				return
			}
			if _, err := openWith(raw, p); err != nil {
				errs <- "raw packet not opened by raw key"
			}
		}()
		go func() {
			defer wg.Done()
			p := encodeHeader(t, stdUser)
			if bytes.Equal(p[:16], raw[:]) {
				errs <- "standard packet with raw AuthID"
				return
			}
			if _, err := openWith(stdKey, p); err != nil {
				errs <- "standard packet not opened by MD5 key"
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
}

func TestRawUUIDAuthMixedInboundReplay(t *testing.T) {
	v := vmess.NewTimedUserValidator()
	h := NewSessionHistory()
	defer h.Close()
	users := []*protocol.MemoryUser{compatUser(t, syntheticUUID, false), compatUser(t, syntheticUUID, true)}
	for i, u := range users {
		u.Email = fmt.Sprintf("user%d", i)
		if e := v.Add(u); e != nil {
			t.Fatal(e)
		}
	}
	for n := 0; n < 4; n++ {
		for _, u := range users {
			packet := encodeHeader(t, u)
			got, e := NewServerSession(v, h).DecodeRequestHeader(bytes.NewReader(packet), false)
			if e != nil || got.User != u {
				t.Fatalf("mode=%v: %v", u.Account.(*vmess.MemoryAccount).RawUUIDAuth, e)
			}
			if _, e := NewServerSession(v, h).DecodeRequestHeader(bytes.NewReader(packet), false); e == nil {
				t.Fatal("replay accepted")
			}
		}
	}
}

func TestRawUUIDAuthInboundWrongModeAndCorruption(t *testing.T) {
	for _, raw := range []bool{false, true} {
		v := vmess.NewTimedUserValidator()
		h := NewSessionHistory()
		defer h.Close()
		u := compatUser(t, syntheticUUID, raw)
		if e := v.Add(u); e != nil {
			t.Fatal(e)
		}
		wrong := encodeHeader(t, compatUser(t, syntheticUUID, !raw))
		if _, e := NewServerSession(v, h).DecodeRequestHeader(bytes.NewReader(wrong), false); e == nil {
			t.Fatalf("raw=%v accepted opposite mode", raw)
		}
		unknown := encodeHeader(t, compatUser(t, "ffeeddcc-bbaa-9988-7766-554433221100", raw))
		if _, e := NewServerSession(v, h).DecodeRequestHeader(bytes.NewReader(unknown), false); e == nil {
			t.Fatal("unknown UUID accepted")
		}
		for _, offset := range []int{0, 15, 16, 33, 34, 41, 42} {
			packet := encodeHeader(t, u)
			packet[offset] ^= 1
			if _, e := NewServerSession(v, h).DecodeRequestHeader(bytes.NewReader(packet), false); e == nil {
				t.Fatalf("corruption accepted at %d", offset)
			}
		}
		packet := encodeHeader(t, u)
		for _, n := range []int{0, 1, 15, 16, 17, 33, 34, 41, len(packet) - 1} {
			if _, e := NewServerSession(v, h).DecodeRequestHeader(bytes.NewReader(packet[:n]), false); e == nil {
				t.Fatalf("truncation accepted at %d", n)
			}
		}
	}
}
