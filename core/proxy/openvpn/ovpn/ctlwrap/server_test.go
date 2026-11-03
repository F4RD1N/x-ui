package ctlwrap

import (
	"bytes"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/wire"
)

func TestNativeTLSCryptV2Server(t *testing.T) {
	needOpenVPN(t)
	oracle := makeOracleKeys(t)
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "OpenVPN tls-crypt-v2 server key", Bytes: oracle.v2Server})
	key, err := ParseTLSCryptV2ServerKey(pemKey)
	if err != nil {
		t.Fatal(err)
	}
	decoded, meta, err := UnwrapTLSCryptV2ClientKey(key, oracle.v2WKc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded[:], oracle.v2Kc[:]) || len(meta) == 0 {
		t.Fatal("stock key mismatch")
	}
	c, err := NewTLSCryptV2Client(oracle.v2Kc, oracle.v2WKc)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewTLSCryptV2Server(key)
	if err != nil {
		t.Fatal(err)
	}
	var sid wire.SessionID
	rand.Read(sid[:])
	p := &wire.ControlPacket{Opcode: wire.ControlHardResetClientV3, SessionID: sid}
	b, _ := c.Wrap(p)
	got, err := s.Unwrap(b)
	if err != nil || got.Opcode != p.Opcode {
		t.Fatalf("unwrap: %v", err)
	}
	if _, err = s.Unwrap(b); !errors.Is(err, ErrReplay) {
		t.Fatal("replay accepted")
	}
	p.Opcode = wire.ControlV1
	p.PacketID = 1
	p.Payload = []byte("continuation")
	b, _ = c.Wrap(p)
	got, err = s.Unwrap(b)
	if err != nil || !bytes.Equal(got.Payload, p.Payload) {
		t.Fatalf("continuation: %v", err)
	}
	back, _ := s.Wrap(&wire.ControlPacket{Opcode: wire.ControlHardResetServerV2, SessionID: sid})
	if _, err = c.Unwrap(back); err != nil {
		t.Fatal(err)
	}
	for _, index := range []int{0, 32, len(oracle.v2WKc) - 1} {
		bad := bytes.Clone(oracle.v2WKc)
		bad[index] ^= 1
		if _, _, err = UnwrapTLSCryptV2ClientKey(key, bad); err == nil {
			t.Fatal("tampered wrapped key admitted")
		}
	}
	wrong := *key
	wrong[64] ^= 1
	if _, _, err = UnwrapTLSCryptV2ClientKey(&wrong, oracle.v2WKc); err == nil {
		t.Fatal("wrong key admitted")
	}
	if _, err = ParseTLSCryptV2ServerKey(pem.EncodeToMemory(&pem.Block{Type: "OpenVPN tls-crypt-v2 client key", Bytes: oracle.v2Server})); err == nil {
		t.Fatal("client key used as server key")
	}
}
func FuzzNativeTLSCryptV2Server(f *testing.F) {
	f.Add([]byte{0x50, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add(make([]byte, 300))
	f.Fuzz(func(t *testing.T, b []byte) {
		var key TLSCryptV2ServerKey
		w, _ := NewTLSCryptV2Server(&key)
		w.Unwrap(b)
		UnwrapTLSCryptV2ClientKey(&key, b)
	})
}

func TestNativeTLSCryptV2Issuance(t *testing.T) {
	key, err := GenerateTLSCryptV2ServerKey()
	if err != nil {
		t.Fatal(err)
	}
	round, err := ParseTLSCryptV2ServerKey(key.MarshalPEM())
	if err != nil || *round != *key {
		t.Fatal("server PEM roundtrip")
	}
	for _, metadata := range [][]byte{nil, {}, []byte("fixture-user"), bytes.Repeat([]byte{'x'}, 733)} {
		text, err := IssueTLSCryptV2ClientKey(key, metadata)
		if err != nil {
			t.Fatal(err)
		}
		kc, wkc, err := ParseTLSCryptV2ClientKey(text)
		if err != nil {
			t.Fatal(err)
		}
		plain, meta, err := UnwrapTLSCryptV2ClientKey(key, wkc)
		if err != nil || !bytes.Equal(kc[:], plain[:]) {
			t.Fatalf("issued key unwrap: %v", err)
		}
		if metadata == nil {
			if len(meta) != 9 || meta[0] != 1 {
				t.Fatal("timestamp metadata")
			}
		} else if len(meta) != len(metadata)+1 || meta[0] != 0 || !bytes.Equal(meta[1:], metadata) {
			t.Fatal("user metadata")
		}
		second, err := IssueTLSCryptV2ClientKey(key, metadata)
		if err != nil {
			t.Fatal(err)
		}
		other, _, err := ParseTLSCryptV2ClientKey(second)
		if err != nil || bytes.Equal(kc[:], other[:]) {
			t.Fatal("client keys reused")
		}
	}
	if _, err = IssueTLSCryptV2ClientKey(key, make([]byte, 734)); err == nil {
		t.Fatal("oversized metadata issued")
	}
	if _, err = IssueTLSCryptV2ClientKey(nil, nil); err == nil {
		t.Fatal("nil key accepted")
	}
}

func TestNativeIssuedKeyStockServerOracle(t *testing.T) {
	needOpenVPN(t)
	key, err := GenerateTLSCryptV2ServerKey()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "native-v2-server.key")
	if err = os.WriteFile(path, key.MarshalPEM(), 0600); err != nil {
		t.Fatal(err)
	}
	server := startServer(t, dir, "--tls-crypt-v2", path, "--mode", "server", "--dev-type", "tun", "--topology", "subnet", "--ifconfig", "10.213.99.1", "255.255.255.0", "--ifconfig-noexec")
	for _, metadata := range [][]byte{nil, []byte("native-issued-fixture")} {
		text, err := IssueTLSCryptV2ClientKey(key, metadata)
		if err != nil {
			t.Fatal(err)
		}
		kc, wkc, err := ParseTLSCryptV2ClientKey(text)
		if err != nil {
			t.Fatal(err)
		}
		wrapper, err := NewTLSCryptV2Client(kc, wkc)
		if err != nil {
			t.Fatal(err)
		}
		c := newOracleClient(t, server, wrapper)
		c.send(&wire.ControlPacket{Opcode: wire.ControlHardResetClientV3})
		p := c.recv(2 * time.Second)
		if p == nil || p.Opcode != wire.ControlHardResetServerV2 {
			t.Fatal("stock server rejected native-issued client key")
		}
	}
}
