package aead

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"testing"
)

// The old entry point always takes the standard path: a fresh, decodable
// AuthID, never the key itself.
func TestSealVMessAEADHeaderStaysStandard(t *testing.T) {
	var key [16]byte
	copy(key[:], []byte("0123456789abcdef"))
	holder := NewAuthIDDecoderHolder()
	holder.AddUser(key, "u")
	for i := 0; i < 4; i++ {
		out := SealVMessAEADHeader(key, []byte("header"))
		var authID [16]byte
		copy(authID[:], out[:16])
		if authID == key {
			t.Fatal("standard sealing used the key as AuthID")
		}
		if _, err := holder.Match(authID); err != nil {
			t.Fatalf("standard AuthID not decodable: %v", err)
		}
		plain, _, _, err := OpenVMessAEADHeader(key, authID, bytes.NewReader(out[16:]))
		if err != nil || string(plain) != "header" {
			t.Fatalf("open failed: %v", err)
		}
	}
}

func TestSealVMessAEADHeaderWithRawUUIDAuth(t *testing.T) {
	var key [16]byte
	copy(key[:], []byte("0123456789abcdef"))
	out := SealVMessAEADHeaderWithRawUUIDAuth(key, []byte("header"), true)
	var authID [16]byte
	copy(authID[:], out[:16])
	if authID != key {
		t.Fatal("raw mode AuthID is not the key")
	}
	plain, _, _, err := OpenVMessAEADHeader(key, authID, bytes.NewReader(out[16:]))
	if err != nil || string(plain) != "header" {
		t.Fatalf("open failed: %v", err)
	}
	if len(out) != 16+18+8+len("header")+16 {
		t.Fatalf("layout changed: %d bytes", len(out))
	}
}

// Generated independently with the older client implementation. Keep the
// plaintext and nonce fixed so this catches accidental KDF/layout changes.
func TestRawUUIDAuthCompatibilityVector(t *testing.T) {
	packet, err := hex.DecodeString("00112233445566778899aabbccddeeff345867c3457831894587bef54c34890f4b290001020304050607c39d6ae490bf294aab37112411ae4c69d0e8bdc81855")
	if err != nil {
		t.Fatal(err)
	}
	var key [16]byte
	copy(key[:], packet[:16])
	plain, _, _, err := OpenVMessAEADHeader(key, key, bytes.NewReader(packet[16:]))
	if err != nil || string(plain) != "header" {
		t.Fatalf("vector: %q %v", plain, err)
	}
	standardKey := md5.Sum(append(append([]byte{}, key[:]...), []byte("c48619fe-8f02-49e0-b9e9-edf763e17e21")...))
	if _, _, _, err := OpenVMessAEADHeader(standardKey, key, bytes.NewReader(packet[16:])); err == nil {
		t.Fatal("standard command key accepted raw vector")
	}
	for _, offset := range []int{16, 33, 34, 41, 42, 63} {
		corrupt := append([]byte{}, packet...)
		corrupt[offset] ^= 1
		if _, _, _, err := OpenVMessAEADHeader(key, key, bytes.NewReader(corrupt[16:])); err == nil {
			t.Fatalf("corruption at %d accepted", offset)
		}
	}
}
