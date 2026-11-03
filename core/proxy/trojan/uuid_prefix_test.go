package trojan_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	. "github.com/xtls/xray-core/proxy/trojan"
	"google.golang.org/protobuf/proto"
)

const syntheticPassword = "00112233-4455-6677-8899-aabbccddeeff"

func mem(t *testing.T, password string, prefix bool) *MemoryAccount {
	t.Helper()
	a, err := (&Account{Password: password, UuidHashPrefix: prefix}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	return a.(*MemoryAccount)
}

func stdKey(password string) []byte {
	d := sha256.Sum224([]byte(password))
	k := make([]byte, 56)
	hex.Encode(k, d[:])
	return k
}

// The spec's synthetic vector.
func TestUUIDHashPrefixVector(t *testing.T) {
	std := mem(t, syntheticPassword, false)
	if string(std.Key) != "38c8230d6895bda978c7041d05ae9f2f4cf58de362ed11c8dc19a989" {
		t.Fatalf("standard key = %s", std.Key)
	}
	custom := mem(t, syntheticPassword, true)
	want := "00112233445566778899aabbccddeeff37386337303431643035616539663266346366353864653336326564313163386463313961393839"
	if got := hex.EncodeToString(custom.Key); got != want {
		t.Fatalf("custom key = %s\nwant         %s", got, want)
	}
	if len(custom.Key) != 56 {
		t.Fatalf("custom key length %d", len(custom.Key))
	}
}

// Alternate spellings: the binary UUID is the same, but the hash suffix is
// taken from the original text, so each spelling has its own key suffix.
func TestUUIDHashPrefixSpellings(t *testing.T) {
	raw, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	for _, p := range []string{
		"00112233-4455-6677-8899-aabbccddeeff",
		"00112233-4455-6677-8899-AABBCCDDEEFF",
		"00112233445566778899aabbccddeeff",
		"{00112233-4455-6677-8899-aabbccddeeff}",
		"urn:uuid:00112233-4455-6677-8899-aabbccddeeff",
	} {
		k := mem(t, p, true).Key
		if len(k) != 56 || !bytes.Equal(k[:16], raw) {
			t.Fatalf("%q: prefix %x", p, k[:16])
		}
		if !bytes.Equal(k[16:], stdKey(p)[16:]) {
			t.Fatalf("%q: suffix is not the original text's hash", p)
		}
	}
}

func TestUUIDHashPrefixNonUUIDPassword(t *testing.T) {
	for _, p := range []string{"password", "", "00112233-4455-6677-8899-aabbccddeef", "not-a-uuid-at-all-but-36-chars-long!", "zz112233-4455-6677-8899-aabbccddeeff"} {
		if k := mem(t, p, true).Key; !bytes.Equal(k, stdKey(p)) {
			t.Fatalf("%q: non-UUID password must keep the ordinary key", p)
		}
	}
}

func TestStandardTrojanKeyUnchanged(t *testing.T) {
	// Flag off: never a UUID prefix, even for a UUID password.
	k := mem(t, syntheticPassword, false).Key
	if !bytes.Equal(k, stdKey(syntheticPassword)) {
		t.Fatal("standard key changed")
	}
	wire, _ := proto.Marshal(mem(t, "pw", false).ToProto())
	old, _ := proto.Marshal(&Account{Password: "pw"})
	if !bytes.Equal(wire, old) {
		t.Fatal("standard account protobuf bytes changed")
	}
}

func TestUUIDHashPrefixRoundTripAndEquals(t *testing.T) {
	for _, prefix := range []bool{false, true} {
		a := mem(t, "{00112233-4455-6677-8899-AABBCCDDEEFF}", prefix)
		pb := a.ToProto().(*Account)
		if pb.Password != "{00112233-4455-6677-8899-AABBCCDDEEFF}" || pb.UuidHashPrefix != prefix {
			t.Fatalf("ToProto lost data: %+v", pb)
		}
		b := mem(t, pb.Password, pb.UuidHashPrefix)
		if !bytes.Equal(a.Key, b.Key) || !a.Equals(b) {
			t.Fatal("round trip changed the account")
		}
	}
	if mem(t, syntheticPassword, true).Equals(mem(t, syntheticPassword, false)) {
		t.Fatal("same password in different modes must not be equal")
	}
	if mem(t, syntheticPassword, true).Equals(mem(t, "00112233445566778899aabbccddeeff", true)) {
		t.Fatal("different password spellings must not be equal")
	}
}

func TestUUIDHashPrefixOnTheWire(t *testing.T) {
	for _, prefix := range []bool{false, true} {
		acc := mem(t, syntheticPassword, prefix)
		b := buf.New()
		dest := net.Destination{Network: net.Network_TCP, Address: net.DomainAddress("example.com"), Port: 443}
		w := &ConnWriter{Writer: b, Target: dest, Account: acc}
		data := buf.New()
		data.Write([]byte("x"))
		common.Must(w.WriteMultiBuffer(buf.MultiBuffer{data}))
		out := b.Bytes()
		if !bytes.Equal(out[:56], acc.Key) || out[56] != '\r' || out[57] != '\n' {
			t.Fatalf("prefix=%v: header is not key(56) + CRLF: %x", prefix, out[:58])
		}
		b.Release()
	}
}

func TestValidatorMixedUUIDHashPrefix(t *testing.T) {
	v := new(Validator)
	standard := &protocol.MemoryUser{Email: "stock@example.test", Account: mem(t, syntheticPassword, false)}
	custom := &protocol.MemoryUser{Email: "custom@example.test", Account: mem(t, syntheticPassword, true)}
	for _, user := range []*protocol.MemoryUser{standard, custom} {
		if err := v.Add(user); err != nil {
			t.Fatal(err)
		}
		key := hex.EncodeToString(user.Account.(*MemoryAccount).Key)
		if got := v.Get(key); got != user {
			t.Fatal("account key matched wrong identity")
		}
	}
	if v.GetCount() != 2 {
		t.Fatal("mixed modes not retained")
	}
	wrong := bytes.Clone(custom.Account.(*MemoryAccount).Key)
	wrong[17] ^= 1
	if v.Get(hex.EncodeToString(wrong)) != nil {
		t.Fatal("wrong authentication key accepted")
	}
	if err := v.Del(custom.Email); err != nil {
		t.Fatal(err)
	}
	if v.Get(hex.EncodeToString(custom.Account.(*MemoryAccount).Key)) != nil {
		t.Fatal("removed custom key still accepted")
	}
	if v.Get(hex.EncodeToString(standard.Account.(*MemoryAccount).Key)) != standard {
		t.Fatal("custom removal changed standard account")
	}
}

func TestValidatorUUIDHashPrefixCollisionIsAtomic(t *testing.T) {
	for _, customFirst := range []bool{false, true} {
		v := new(Validator)
		first := &protocol.MemoryUser{Email: "first@example.test", Account: mem(t, "ordinary-password", customFirst)}
		second := &protocol.MemoryUser{Email: "second@example.test", Account: mem(t, "ordinary-password", !customFirst)}
		if err := v.Add(first); err != nil {
			t.Fatal(err)
		}
		if err := v.Add(second); err == nil {
			t.Fatal("ambiguous standard/custom key allowed")
		}
		if v.GetByEmail(second.Email) != nil || v.GetCount() != 1 {
			t.Fatal("failed add partly registered account")
		}
		if v.Get(hex.EncodeToString(first.Account.(*MemoryAccount).Key)) != first {
			t.Fatal("failed add replaced identity")
		}
	}
	v := new(Validator)
	if err := v.Add(nil); err == nil {
		t.Fatal("nil user accepted")
	}
	if err := v.Add(&protocol.MemoryUser{Email: "bad@example.test"}); err == nil {
		t.Fatal("missing account accepted")
	}
	var a *MemoryAccount
	if err := v.Add(&protocol.MemoryUser{Email: "nil@example.test", Account: a}); err == nil {
		t.Fatal("typed nil account accepted")
	}
	if v.GetCount() != 0 {
		t.Fatal("malformed account partially registered")
	}
}

func TestValidatorUUIDHashPrefixHotUpdates(t *testing.T) {
	v := new(Validator)
	standard := &protocol.MemoryUser{Email: "stable@example.test", Account: mem(t, syntheticPassword, false)}
	if err := v.Add(standard); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errors := make(chan error, 16)
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			password := fmt.Sprintf("00112233-4455-6677-8899-aabbccdd%04x", worker)
			custom := &protocol.MemoryUser{Email: fmt.Sprintf("custom-%d@example.test", worker), Account: mem(t, password, true)}
			for i := 0; i < 50; i++ {
				if err := v.Add(custom); err != nil {
					errors <- err
					return
				}
				if v.GetByEmail(custom.Email) != custom || v.Get(hex.EncodeToString(custom.Account.(*MemoryAccount).Key)) != custom {
					errors <- fmt.Errorf("added account missing")
					return
				}
				if err := v.Del(custom.Email); err != nil {
					errors <- err
					return
				}
				if v.GetByEmail(custom.Email) != nil || v.Get(hex.EncodeToString(custom.Account.(*MemoryAccount).Key)) != nil {
					errors <- fmt.Errorf("removed account retained")
					return
				}
				if v.Get(hex.EncodeToString(standard.Account.(*MemoryAccount).Key)) != standard {
					errors <- fmt.Errorf("standard identity changed")
					return
				}
			}
		}(worker)
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	if v.GetCount() != 1 {
		t.Fatal("custom hot updates leaked users")
	}
}

func TestUUIDHashPrefixConcurrentMixed(t *testing.T) {
	want := map[bool][]byte{false: mem(t, syntheticPassword, false).Key, true: mem(t, syntheticPassword, true).Key}
	var wg sync.WaitGroup
	fail := make(chan bool, 200)
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(prefix bool) {
			defer wg.Done()
			a, _ := (&Account{Password: syntheticPassword, UuidHashPrefix: prefix}).AsAccount()
			if !bytes.Equal(a.(*MemoryAccount).Key, want[prefix]) {
				fail <- prefix
			}
		}(i%2 == 0)
	}
	wg.Wait()
	close(fail)
	for p := range fail {
		t.Fatalf("mode %v produced the wrong key under concurrency", p)
	}
}
