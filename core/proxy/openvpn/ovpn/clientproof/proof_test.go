package clientproof

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestKnownAnswerAndBinding(t *testing.T) {
	secret, exporter := make([]byte, 32), make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
		exporter[i] = byte(i + 32)
	}
	k, err := New("test-key", secret)
	if err != nil {
		t.Fatal(err)
	}
	// Independently calculated using Python's standard hmac/hashlib libraries.
	const expected = "1:test-key:6SXwOXV4LgsK5ZaRfrUam38W7_MurLgANCqjymKAsVg"
	proof, err := k.Generate(exporter)
	if err != nil || proof != expected {
		t.Fatalf("known answer mismatch: %v", err)
	}
	if err := Verify(proof, exporter, secret); err != nil {
		t.Fatal(err)
	}
	otherExporter := bytes.Clone(exporter)
	otherExporter[0] ^= 1
	if Verify(proof, otherExporter, secret) == nil {
		t.Fatal("cross-session replay accepted")
	}
	otherSecret := bytes.Clone(secret)
	otherSecret[0] ^= 1
	if Verify(proof, exporter, otherSecret) == nil {
		t.Fatal("wrong key accepted")
	}
	otherID := strings.Replace(proof, ":test-key:", ":other-key:", 1)
	if Verify(otherID, exporter, secret) == nil {
		t.Fatal("key ID substitution accepted")
	}
	clear(secret)
	again, err := k.Generate(exporter)
	if err != nil || again != expected {
		t.Fatal("constructor retained caller's secret buffer")
	}
}

func TestStrictParsingAndInputs(t *testing.T) {
	secret := bytes.Repeat([]byte{0xA5}, 32)
	key, _ := New("id", secret)
	proof, _ := key.Generate(secret)
	id, tag, err := Parse(proof)
	if err != nil || id != "id" || len(tag) != 32 {
		t.Fatal("valid proof rejected")
	}
	malformed := []string{"", "1", "1:id", "2:id:" + base64.RawURLEncoding.EncodeToString(secret), proof + "=", proof + ":extra", strings.Replace(proof, ":id:", "::", 1), strings.Replace(proof, ":id:", ":a/b:", 1), strings.Replace(proof, ":id:", ":"+strings.Repeat("a", 65)+":", 1), "1:id:" + strings.Repeat("A", 42) + "B", "1:id:" + strings.Repeat("!", 43), "1:id:" + strings.Repeat("A", 43) + "\n"}
	for i, p := range malformed {
		if _, _, err := Parse(p); err == nil {
			t.Errorf("malformed case %d accepted", i)
		}
	}
	for _, id := range []string{"", strings.Repeat("x", 65), "a.b", "a b", "a:b", "ü", "a\nUV_OTHER=bad"} {
		if _, err := New(id, secret); err == nil {
			t.Errorf("bad ID accepted")
		}
	}
	for _, n := range []int{0, 1, 31, 33, 64} {
		if _, err := New("id", make([]byte, n)); err == nil {
			t.Errorf("key length %d accepted", n)
		}
		if _, err := key.Generate(make([]byte, n)); err == nil {
			t.Errorf("exporter length %d accepted", n)
		}
		if Verify(proof, make([]byte, n), secret) == nil || Verify(proof, secret, make([]byte, n)) == nil {
			t.Errorf("Verify length %d accepted", n)
		}
	}
	if _, err := new(Key).Generate(secret); err == nil {
		t.Fatal("uninitialized key accepted")
	}
	var nilKey *Key
	if _, err := nilKey.Generate(secret); err == nil {
		t.Fatal("nil key accepted")
	}
}

func TestFormattingRedactsKeysAndMetadata(t *testing.T) {
	secret := bytes.Repeat([]byte{0xA5}, 32)
	key, _ := New("public-id", secret)
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
		output := fmt.Sprintf(verb, key) + fmt.Sprintf(verb, *key)
		if !strings.Contains(output, "<redacted>") || strings.Contains(output, "165") || strings.Contains(output, "a5a5a5") {
			t.Errorf("secret in format %s", verb)
		}
	}
	if key.String() != key.GoString() {
		t.Fatal("formatters differ")
	}
	proof, _ := key.Generate(secret)
	normal := "IV_VER=2.6.12\nIV_PLAT=android\n"
	if RedactPeerInfo(normal) != normal {
		t.Fatal("ordinary metadata changed")
	}
	redacted := RedactPeerInfo(normal + PeerInfoKey + "=" + proof + "\n")
	if strings.Contains(redacted, proof) || !strings.Contains(redacted, PeerInfoKey+"=<redacted>") {
		t.Fatal("proof exposed in metadata")
	}
}

func FuzzParse(f *testing.F) {
	key, _ := New("fuzz", bytes.Repeat([]byte{42}, 32))
	valid, _ := key.Generate(bytes.Repeat([]byte{18}, 32))
	for _, s := range []string{valid, "", "1:x:" + strings.Repeat("A", 43), valid + "="} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, proof string) {
		id, tag, err := Parse(proof)
		if err != nil {
			return
		}
		if ValidateKeyID(id) != nil || len(tag) != 32 || "1:"+id+":"+base64.RawURLEncoding.EncodeToString(tag) != proof {
			t.Fatal("parser accepted noncanonical proof")
		}
	})
}
