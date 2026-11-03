// Package connectionkey encodes one private connection credential and the
// server's public-key pin. It is a bearer connection key, not an asymmetric
// client private key. It preserves the existing wire credential fields.
package connectionkey

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strings"
)

const prefix = "vck1_"
const payloadSize = 64
const encodedSize = len(prefix) + 86 // Unpadded base64url of 64 bytes.

var ErrInvalid = errors.New("invalid private connection key")

// Credentials are the existing account fields derived from a connection key.
// They are bearer secrets and must never be logged.
type Credentials struct {
	UID      string
	Token    string
	DeviceID string
}

// Generate returns a fresh secret connection key and its existing-protocol
// credentials. The pin is SHA-256 of the server leaf's DER SubjectPublicKeyInfo.
func Generate(pin [32]byte) (string, Credentials, error) {
	return generate(pin, rand.Reader)
}

func generate(pin [32]byte, entropy io.Reader) (string, Credentials, error) {
	if pin == [32]byte{} {
		return "", Credentials{}, ErrInvalid
	}
	var payload [payloadSize]byte
	if _, err := io.ReadFull(entropy, payload[:32]); err != nil {
		return "", Credentials{}, errors.New("connection key entropy unavailable")
	}
	var seed [32]byte
	copy(seed[:], payload[:32])
	if seed == [32]byte{} {
		return "", Credentials{}, errors.New("connection key entropy invalid")
	}
	copy(payload[32:], pin[:])
	return prefix + base64.RawURLEncoding.EncodeToString(payload[:]), derive(seed), nil
}

// Decode accepts only the fixed-length canonical version-1 encoding. Returned
// credentials and input key are private and must not be logged.
func Decode(key string) (Credentials, [32]byte, error) {
	var seed, pin [32]byte
	if len(key) != encodedSize || !strings.HasPrefix(key, prefix) {
		return Credentials{}, pin, ErrInvalid
	}
	raw := key[len(prefix):]
	b, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || len(b) != payloadSize || base64.RawURLEncoding.EncodeToString(b) != raw {
		return Credentials{}, pin, ErrInvalid
	}
	copy(seed[:], b[:32])
	copy(pin[:], b[32:])
	if seed == [32]byte{} || pin == [32]byte{} {
		return Credentials{}, [32]byte{}, ErrInvalid
	}
	return derive(seed), pin, nil
}

func derive(seed [32]byte) Credentials {
	field := func(name string, n int) string {
		h := hmac.New(sha256.New, seed[:])
		h.Write([]byte("vpncore/connection-key/v1/" + name))
		return hex.EncodeToString(h.Sum(nil)[:n])
	}
	return Credentials{UID: field("uid", 16), Token: field("token", 16), DeviceID: field("device", 20)}
}
