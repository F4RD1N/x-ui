package pki

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

// TestPinFailuresAreToldApart: only a key that is not the pinned one is
// ErrPinMismatch; every other rejection of the pinned leaf is
// ErrPinnedCertificate, so the outbound does not blame the private key for
// an expired or misnamed certificate.
func TestPinFailuresAreToldApart(t *testing.T) {
	cert, data := pinCertificate(t, nil, nil)
	server, _ := pinnedHTTPServer(t, cert)
	other := sha256.Sum256([]byte("another server key"))
	trust, err := ClientTLS("127.0.0.1", hex.EncodeToString(other[:]))
	if err != nil {
		t.Fatal(err)
	}
	if err = getWithTrust(server.URL, trust); !errors.Is(err, ErrPinMismatch) || errors.Is(err, ErrPinnedCertificate) {
		t.Fatal("a wrong pin:", err)
	}
	pin, err := CertificatePinPEM(data)
	if err != nil {
		t.Fatal(err)
	}
	for name, modify := range map[string]func(*x509.Certificate){
		"expired":    func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) },
		"wrong-name": func(c *x509.Certificate) { c.IPAddresses = nil },
	} {
		cert, data := pinCertificate(t, nil, modify)
		if pin, err = CertificatePinPEM(data); err != nil {
			t.Fatal(err)
		}
		trust, err := ClientTLS("127.0.0.1", pin)
		if err != nil {
			t.Fatal(err)
		}
		server, _ := pinnedHTTPServer(t, cert)
		if err = getWithTrust(server.URL, trust); !errors.Is(err, ErrPinnedCertificate) || errors.Is(err, ErrPinMismatch) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
