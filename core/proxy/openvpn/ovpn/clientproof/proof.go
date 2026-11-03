// Package clientproof implements optional session-bound authentication metadata.
// It leaves the OpenVPN wire format and ordinary authentication unchanged.
package clientproof

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const (
	ExporterLabel  = "EXPORTER-OpenVPN-Client-Proof-v1"
	ExporterLength = 32
	PeerInfoKey    = "UV_CORE_PROOF"
	SecretLength   = 32
	MaxKeyIDLength = 64
)

const domain = "openvpn-client-proof-v1\x00"

// Key holds a private copy of a key. It is immutable and safe for concurrent use.
type Key struct {
	id     string
	secret [SecretLength]byte
}

// ValidateKeyID accepts only short, unambiguous ASCII identifiers.
func ValidateKeyID(id string) error {
	if len(id) == 0 || len(id) > MaxKeyIDLength {
		return errors.New("client proof: keyId must contain 1 to 64 ASCII letters, digits, underscores or hyphens")
	}
	for _, b := range []byte(id) {
		if !(b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '_' || b == '-') {
			return errors.New("client proof: invalid keyId")
		}
	}
	return nil
}

// New validates and copies the secret; it never retains the caller's buffer.
func New(keyID string, secret []byte) (*Key, error) {
	if err := ValidateKeyID(keyID); err != nil {
		return nil, err
	}
	if len(secret) != SecretLength {
		return nil, errors.New("client proof: key must be 32 bytes")
	}
	k := &Key{id: keyID}
	copy(k.secret[:], secret)
	return k, nil
}

// Generate returns the value of the standard peer-info variable, without KEY=.
func (k *Key) Generate(exporter []byte) (string, error) {
	if k == nil || ValidateKeyID(k.id) != nil {
		return "", errors.New("client proof: no valid key")
	}
	if len(exporter) != ExporterLength {
		return "", errors.New("client proof: exporter must be 32 bytes")
	}
	tag := mac(k.id, exporter, k.secret[:])
	defer clear(tag)
	return "1:" + k.id + ":" + base64.RawURLEncoding.EncodeToString(tag), nil
}

func mac(id string, exporter, secret []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(domain))
	var n [2]byte
	binary.BigEndian.PutUint16(n[:], uint16(len(id)))
	h.Write(n[:])
	h.Write([]byte(id))
	h.Write(exporter)
	return h.Sum(nil)
}

// Parse accepts exactly version 1 with a canonical unpadded URL-base64 tag.
func Parse(proof string) (keyID string, tag []byte, err error) {
	if len(proof) > 2+MaxKeyIDLength+1+43 {
		return "", nil, errors.New("client proof: invalid proof")
	}
	parts := strings.Split(proof, ":")
	if len(parts) != 3 || parts[0] != "1" || ValidateKeyID(parts[1]) != nil || len(parts[2]) != 43 {
		return "", nil, errors.New("client proof: invalid proof")
	}
	tag, err = base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(tag) != sha256.Size || base64.RawURLEncoding.EncodeToString(tag) != parts[2] {
		clear(tag)
		return "", nil, errors.New("client proof: invalid proof")
	}
	return parts[1], tag, nil
}

// Verify authenticates the key identifier and this TLS session's exporter.
// Callers select the secret using Parse, and must separately enforce the
// allowed certificate/account identity for that key identifier.
func Verify(proof string, exporter, secret []byte) error {
	if len(exporter) != ExporterLength || len(secret) != SecretLength {
		return errors.New("client proof: invalid key or exporter length")
	}
	id, tag, err := Parse(proof)
	if err != nil {
		return err
	}
	defer clear(tag)
	expected := mac(id, exporter, secret)
	defer clear(expected)
	if !hmac.Equal(tag, expected) {
		return errors.New("client proof: authentication failed")
	}
	return nil
}

// Format keeps secrets out of all fmt verbs, including %#v and %x.
func (k Key) Format(f fmt.State, _ rune) {
	fmt.Fprintf(f, "clientproof.Key{KeyID:%q, Secret:<redacted>}", k.id)
}

func (k Key) String() string   { return fmt.Sprintf("%v", k) }
func (k Key) GoString() string { return k.String() }

// RedactPeerInfo removes proof material from diagnostic formatting while
// preserving ordinary peer-info lines. It does not change on-wire messages.
func RedactPeerInfo(info string) string {
	lines := strings.Split(info, "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, PeerInfoKey+"=") {
			lines[i] = PeerInfoKey + "=<redacted>"
		}
	}
	return strings.Join(lines, "\n")
}
