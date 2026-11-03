package connectionkey

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestGenerateRoundTripAndExistingAuthentication(t *testing.T) {
	pin := sha256.Sum256([]byte("owned server public key"))
	key, credentials, err := Generate(pin)
	if err != nil {
		t.Fatal(err)
	}
	decoded, actualPin, err := Decode(key)
	if err != nil || decoded != credentials || actualPin != pin {
		t.Fatal("key did not round-trip")
	}
	other, otherCredentials, err := Generate(pin)
	if err != nil || other == key || otherCredentials == credentials {
		t.Fatal("generated keys are not independent")
	}
	if len(credentials.UID) != 32 || len(credentials.Token) != 32 || len(credentials.DeviceID) != 40 {
		t.Fatal("credentials exceed protocol field capacities")
	}
	// The account store lives in the server; the client only derives the
	// fields. The interoperability vector below pins the derivation itself.
}

func TestDerivationKnownVectorAndDomainSeparation(t *testing.T) {
	// Independent HMAC-SHA256 values from Python's standard hmac module, for
	// seed bytes 0..31 and the documented versioned field labels.
	var seed, pin [32]byte
	for i := range seed {
		seed[i], pin[i] = byte(i), byte(255-i)
	}
	key, got, err := generate(pin, bytes.NewReader(seed[:]))
	if err != nil {
		t.Fatal(err)
	}
	want := Credentials{
		UID: "399c008006bde2055b9f253b2f429be2", Token: "49f5028e7cf9d53cf5c458138d967b65", DeviceID: "7c5c98830fcb5c6a3b9099779c0ab07590eb00dc",
	}
	if got != want {
		t.Fatal("derived credentials changed from the interoperability vector")
	}
	decoded, gotPin, err := Decode(key)
	if err != nil || decoded != want || gotPin != pin {
		t.Fatal("fixed vector decode")
	}
	pin[0] ^= 1
	_, sameIdentity, err := generate(pin, bytes.NewReader(seed[:]))
	if err != nil || sameIdentity != got {
		t.Fatal("changing a server pin unexpectedly rotates the account")
	}
	if got.UID == got.Token || strings.HasPrefix(got.DeviceID, got.Token) || strings.HasPrefix(got.DeviceID, got.UID) {
		t.Fatal("credential fields are not domain-separated")
	}
}

func TestRejectInvalidKeysWithoutLeakingInput(t *testing.T) {
	var payload [64]byte
	for i := range payload {
		payload[i] = byte(i + 1)
	}
	valid := prefix + base64.RawURLEncoding.EncodeToString(payload[:])
	zeroSeed, zeroPin := payload, payload
	clear(zeroSeed[:32])
	clear(zeroPin[32:])
	// The last base64 symbol contains only two data bits. Changing its unused
	// bits must be rejected even if a permissive decoder returns the same bytes.
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, valid[len(valid)-1])
	noncanonical := valid[:len(valid)-1] + string(alphabet[last+1])
	for name, key := range map[string]string{
		"empty": "", "wrong-version": "vck2_" + valid[len(prefix):],
		"padding": valid + "==", "short": valid[:len(valid)-1],
		"oversized": strings.Repeat("x", 1<<20), "space": " " + valid,
		"embedded-newline": valid[:10] + "\n" + valid[11:],
		"bad-alphabet":     valid[:10] + "/" + valid[11:], "noncanonical": noncanonical,
		"zero-seed": prefix + base64.RawURLEncoding.EncodeToString(zeroSeed[:]),
		"zero-pin":  prefix + base64.RawURLEncoding.EncodeToString(zeroPin[:]),
	} {
		t.Run(name, func(t *testing.T) {
			credentials, pin, err := Decode(key)
			if !errors.Is(err, ErrInvalid) || credentials != (Credentials{}) || pin != ([32]byte{}) {
				t.Fatal("invalid key accepted or partial secrets returned")
			}
			if len(key) > 10 && strings.Contains(err.Error(), key) {
				t.Fatal("error leaked private input")
			}
		})
	}
}

func TestGenerationRejectsMissingPinAndEntropy(t *testing.T) {
	pin := sha256.Sum256([]byte("test pin"))
	for _, tc := range []struct {
		pin     [32]byte
		entropy []byte
	}{{[32]byte{}, bytes.Repeat([]byte{1}, 32)}, {pin, nil}, {pin, make([]byte, 32)}} {
		key, c, err := generate(tc.pin, bytes.NewReader(tc.entropy))
		if err == nil || key != "" || c != (Credentials{}) {
			t.Fatal("invalid key generation accepted")
		}
	}
}

func FuzzDecode(f *testing.F) {
	var payload [64]byte
	for i := range payload {
		payload[i] = byte(i + 1)
	}
	f.Add(prefix + base64.RawURLEncoding.EncodeToString(payload[:]))
	f.Add("vck1_invalid")
	f.Fuzz(func(t *testing.T, raw string) {
		c, p, err := Decode(raw)
		if err != nil {
			if c != (Credentials{}) || p != ([32]byte{}) {
				t.Fatal("failure exposed partial credentials")
			}
			return
		}
		if len(raw) != encodedSize || len(c.UID) != 32 || len(c.Token) != 32 || len(c.DeviceID) != 40 || p == ([32]byte{}) {
			t.Fatal("accepted invalid key")
		}
	})
}
