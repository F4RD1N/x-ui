package orbit

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/orbit/internal/connectionkey"
	"google.golang.org/protobuf/proto"
)

// MemoryAccount is immutable after validation. The key must never be logged.
type MemoryAccount struct {
	key     string
	uid     string
	device  string
	token   [32]byte
	pin     [32]byte
	expires int64
}

func (a *Account) AsAccount() (protocol.Account, error) {
	if a == nil || a.ExpiresAt < 0 {
		return nil, errors.New("orbit: invalid account expiry")
	}
	c, pin, err := connectionkey.Decode(a.Key)
	if err != nil {
		return nil, errors.New("orbit: invalid account key")
	}
	return &MemoryAccount{key: a.Key, uid: c.UID, device: c.DeviceID, token: sha256.Sum256([]byte(c.Token)), pin: pin, expires: a.ExpiresAt}, nil
}
func (a *MemoryAccount) Equals(other protocol.Account) bool {
	b, ok := other.(*MemoryAccount)
	return ok && a != nil && b != nil && subtle.ConstantTimeCompare([]byte(a.key), []byte(b.key)) == 1 && a.expires == b.expires
}
func (a *MemoryAccount) ToProto() proto.Message { return &Account{Key: a.key, ExpiresAt: a.expires} }

// GenerateConnectionKey creates a random account bound to the leaf certificate
// SPKI. It requires only a public certificate, never the server private key.
func GenerateConnectionKey(certificatePEM string) (string, error) {
	if len(certificatePEM) > 1<<20 {
		return "", errors.New("orbit: certificate exceeds limit")
	}
	block, _ := pem.Decode([]byte(certificatePEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return "", errors.New("orbit: certificate PEM required")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || cert.IsCA || len(cert.UnhandledCriticalExtensions) != 0 {
		return "", errors.New("orbit: invalid certificate")
	}
	key, _, err := connectionkey.Generate(sha256.Sum256(cert.RawSubjectPublicKeyInfo))
	return key, err
}

// GenerateRealityConnectionKey generates a fresh native account for a REALITY
// listener. The v1 key still needs a nonzero pin-shaped field, so it contains the
// SHA-256 of the public X25519 key. REALITY authenticates this carrier itself;
// the pinned-TLS field is not used or substituted for REALITY authentication.
func GenerateRealityConnectionKey(publicKey string) (string, error) {
	keyBytes, err := base64.RawURLEncoding.Strict().DecodeString(publicKey)
	if err != nil || len(keyBytes) != 32 {
		return "", errors.New("orbit: invalid REALITY public key")
	}
	var nonzero byte
	for _, b := range keyBytes {
		nonzero |= b
	}
	if nonzero == 0 {
		return "", errors.New("orbit: invalid REALITY public key")
	}
	key, _, err := connectionkey.Generate(sha256.Sum256(keyBytes))
	return key, err
}
