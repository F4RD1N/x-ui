package pki

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// PublicKeyPin parses SHA-256 of a DER SubjectPublicKeyInfo. An all-zero value
// is never an issued pin and is rejected instead of behaving as an empty pin.
func PublicKeyPin(pinHex string) ([32]byte, error) {
	var pin [32]byte
	if len(pinHex) != 64 {
		return pin, errors.New("server public-key pin must contain 64 hexadecimal characters")
	}
	b, err := hex.DecodeString(pinHex)
	if err != nil {
		return pin, errors.New("server public-key pin must contain 64 hexadecimal characters")
	}
	copy(pin[:], b)
	if pin == [32]byte{} {
		return pin, errors.New("server public-key pin must not be zero")
	}
	return pin, nil
}

// CertificatePinPEM extracts the actual leaf public key from a bounded PEM
// certificate file. It does not return any private material.
func CertificatePinPEM(data []byte) (string, error) {
	if len(data) == 0 || len(data) > 1<<20 {
		return "", errors.New("certificate PEM must be nonempty and at most 1 MiB")
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
		return "", errors.New("certificate PEM must start with a certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || cert.IsCA || len(cert.RawSubjectPublicKeyInfo) == 0 {
		return "", errors.New("certificate PEM must contain a valid server leaf")
	}
	pin := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(pin[:]), nil
}

// Errors of the pinned check, wrapped in a tls.CertificateVerificationError.
// ErrPinMismatch is the one that says the private connection key's pin does
// not name this server; ErrPinnedCertificate is every other rejection of the
// pinned leaf (validity period, leaf kind, key usage, name).
var (
	ErrPinMismatch       = errors.New("TLS server public-key pin mismatch")
	ErrPinnedCertificate = errors.New("pinned TLS server certificate rejected")
)

// ClientTLS authenticates only an explicitly pinned leaf public key. It never
// consults system roots or private CA files and rejects a missing pin.
func ClientTLS(serverName, pinHex string) (*tls.Config, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName}
	pin, err := PublicKeyPin(pinHex)
	if err != nil {
		return nil, err
	}
	// Standard chain building is replaced with an explicit exact-key check.
	// VerifyConnection also runs on resumed connections; verification is never
	// disabled merely because the peer presents a self-signed certificate.
	tc.InsecureSkipVerify = true
	tc.VerifyConnection = func(state tls.ConnectionState) error {
		if err := verifyPinned(state, pin, serverName, time.Now()); err != nil {
			return &tls.CertificateVerificationError{UnverifiedCertificates: state.PeerCertificates, Err: err}
		}
		return nil
	}
	return tc, nil
}

func verifyPinned(state tls.ConnectionState, pin [32]byte, serverName string, now time.Time) error {
	if len(state.PeerCertificates) == 0 || state.PeerCertificates[0] == nil {
		return fmt.Errorf("%w: TLS peer did not provide a server certificate", ErrPinnedCertificate)
	}
	leaf := state.PeerCertificates[0]
	actual := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	if len(leaf.RawSubjectPublicKeyInfo) == 0 || subtle.ConstantTimeCompare(actual[:], pin[:]) != 1 {
		return ErrPinMismatch
	}
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return fmt.Errorf("%w: TLS server certificate is outside its validity period", ErrPinnedCertificate)
	}
	if leaf.IsCA || len(leaf.UnhandledCriticalExtensions) != 0 {
		return fmt.Errorf("%w: TLS server certificate is not a supported leaf", ErrPinnedCertificate)
	}
	// An absent EKU means all uses under X.509. A present EKU must explicitly
	// permit server authentication (or any use), including unknown-only EKUs.
	if len(leaf.ExtKeyUsage) != 0 || len(leaf.UnknownExtKeyUsage) != 0 {
		allowed := false
		for _, usage := range leaf.ExtKeyUsage {
			if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
				allowed = true
			}
		}
		if !allowed {
			return fmt.Errorf("%w: TLS server certificate does not permit server authentication", ErrPinnedCertificate)
		}
	}
	if serverName == "" {
		serverName = state.ServerName
	}
	if serverName != "" {
		if err := leaf.VerifyHostname(serverName); err != nil {
			return fmt.Errorf("%w: TLS server certificate does not match the configured server", ErrPinnedCertificate)
		}
	}
	return nil
}
