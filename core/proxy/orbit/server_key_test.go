package orbit

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/xtls/xray-core/proxy/orbit/internal/connectionkey"
)

func TestServerRealityConnectionKeyGeneration(t *testing.T) {
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())
	a, err := GenerateRealityConnectionKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateRealityConnectionKey(pub)
	if err != nil || a == b {
		t.Fatal("accounts were not freshly generated", err)
	}
	ca, pin, err := connectionkey.Decode(a)
	if err != nil {
		t.Fatal(err)
	}
	cb, other, err := connectionkey.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if ca.UID == cb.UID || ca.Token == cb.Token || ca.DeviceID == cb.DeviceID || pin != sha256.Sum256(private.PublicKey().Bytes()) || other != pin {
		t.Fatal("incorrect account entropy or public-key pin field")
	}
	for _, bad := range []string{"", pub + "=", pub[:20], base64.RawURLEncoding.EncodeToString(make([]byte, 32))} {
		if _, err = GenerateRealityConnectionKey(bad); err == nil {
			t.Fatal("invalid REALITY public key accepted")
		}
	}
}
