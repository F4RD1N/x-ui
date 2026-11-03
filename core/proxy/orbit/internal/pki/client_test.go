package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func pinCertificate(t *testing.T, key *ecdsa.PrivateKey, modify func(*x509.Certificate)) (tls.Certificate, []byte) {
	t.Helper()
	if key == nil {
		var err error
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "owned test server"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"vpn.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if modify != nil {
		modify(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func pinnedHTTPServer(t *testing.T, cert tls.Certificate) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var requests atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		io.WriteString(w, "owned TLS response")
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, &requests
}

func getWithTrust(endpoint string, trust *tls.Config) error {
	transport := &http.Transport{TLSClientConfig: trust, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	response, err := client.Get(endpoint)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	if string(body) != "owned TLS response" {
		return errors.New("unexpected TLS response")
	}
	return nil
}

func TestPinnedTLSHandshakeAndCertificateRenewal(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	original, certPEM := pinCertificate(t, key, nil)
	pin, err := CertificatePinPEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := ClientTLS("127.0.0.1", pin)
	if err != nil {
		t.Fatal(err)
	}
	if trust.RootCAs != nil || trust.VerifyConnection == nil || trust.MinVersion != tls.VersionTLS13 {
		t.Fatal("pin mode loaded roots or omitted its verifier")
	}
	server, _ := pinnedHTTPServer(t, original)
	if err = getWithTrust(server.URL, trust); err != nil {
		t.Fatal("correct pin without CA failed", err)
	}
	// A new serial and validity period signed by the same server key changes
	// certificate bytes while preserving the explicit key identity.
	renewed, renewedPEM := pinCertificate(t, key, func(c *x509.Certificate) { c.NotAfter = time.Now().Add(24 * time.Hour) })
	renewedPin, err := CertificatePinPEM(renewedPEM)
	if err != nil || renewedPin != pin || string(certPEM) == string(renewedPEM) {
		t.Fatal("renewal fixture did not retain only the public key")
	}
	renewedServer, _ := pinnedHTTPServer(t, renewed)
	if err = getWithTrust(renewedServer.URL, trust); err != nil {
		t.Fatal("same-key certificate renewal rejected", err)
	}
	changed, _ := pinCertificate(t, nil, nil)
	changedServer, requests := pinnedHTTPServer(t, changed)
	err = getWithTrust(changedServer.URL, trust)
	var verification *tls.CertificateVerificationError
	if !errors.As(err, &verification) || requests.Load() != 0 {
		t.Fatal("different key was not rejected before the HTTP request")
	}
}

func TestPinnedTLSRejectsInvalidLeafDuringHandshake(t *testing.T) {
	for name, modify := range map[string]func(*x509.Certificate){
		"expired":       func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) },
		"not-yet-valid": func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Minute) },
		"wrong-host":    func(c *x509.Certificate) { c.IPAddresses = []net.IP{net.ParseIP("192.0.2.1")} },
		"client-only":   func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} },
		"unknown-only-usage": func(c *x509.Certificate) {
			c.ExtKeyUsage = nil
			c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 2, 3, 4}}
		},
		"unknown-critical-extension": func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			cert, data := pinCertificate(t, nil, modify)
			pin, err := CertificatePinPEM(data)
			if err != nil {
				t.Fatal(err)
			}
			trust, err := ClientTLS("127.0.0.1", pin)
			if err != nil {
				t.Fatal(err)
			}
			server, requests := pinnedHTTPServer(t, cert)
			var verification *tls.CertificateVerificationError
			if err = getWithTrust(server.URL, trust); !errors.As(err, &verification) || requests.Load() != 0 {
				t.Fatal("invalid certificate reached the application", err)
			}
		})
	}
}

func TestPinnedVerifierMissingCertResumeAndAllowedUsage(t *testing.T) {
	cert, pemBytes := pinCertificate(t, nil, nil)
	pinHex, err := CertificatePinPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := PublicKeyPin(pinHex)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := ClientTLS("", pinHex)
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []tls.ConnectionState{{}, {PeerCertificates: []*x509.Certificate{nil}}} {
		if err = trust.VerifyConnection(state); err == nil {
			t.Fatal("absent certificate accepted")
		}
	}
	for _, usage := range [][]x509.ExtKeyUsage{nil, {x509.ExtKeyUsageAny}, {x509.ExtKeyUsageServerAuth}} {
		leaf := *cert.Leaf
		leaf.ExtKeyUsage = usage
		state := tls.ConnectionState{DidResume: true, ServerName: "vpn.test", PeerCertificates: []*x509.Certificate{&leaf}}
		if err := trust.VerifyConnection(state); err != nil {
			t.Fatal("valid resumed peer rejected", err)
		}
		badPin := pin
		badPin[0] ^= 1
		if err := verifyPinned(state, badPin, "vpn.test", time.Now()); err == nil {
			t.Fatal("resumed wrong-pin peer accepted")
		}
		leaf.IsCA = true
		if err := trust.VerifyConnection(state); err == nil {
			t.Fatal("CA certificate accepted as pinned server leaf")
		}
	}
}

func TestUnpinnedTLSIsNeverConstructed(t *testing.T) {
	for _, host := range []string{"", "127.0.0.1", "vpn.test"} {
		if _, err := ClientTLS(host, ""); err == nil {
			t.Fatal("missing pin enabled system or unverified trust")
		}
	}
}

func TestMalformedPinAndCertificate(t *testing.T) {
	pin := sha256.Sum256([]byte("owned fixture"))
	valid := hex.EncodeToString(pin[:])
	if p, err := PublicKeyPin(strings.ToUpper(valid)); err != nil || p != pin {
		t.Fatal("valid hexadecimal pin rejected")
	}
	for _, bad := range []string{"", "bad", strings.Repeat("0", 64), strings.Repeat("z", 64), valid + "\n"} {
		if _, err := PublicKeyPin(bad); err == nil {
			t.Fatal("invalid pin accepted")
		}
	}
	for _, bad := range []string{"", "bad", strings.Repeat("0", 64)} {
		if _, err := ClientTLS("vpn.test", bad); err == nil {
			t.Fatal("invalid or absent pin accepted")
		}
	}
	_, caPEM := pinCertificate(t, nil, func(c *x509.Certificate) { c.IsCA = true; c.BasicConstraintsValid = true })
	for _, data := range [][]byte{nil, []byte("not PEM"), []byte(strings.Repeat("x", (1<<20)+1)),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid DER")}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a leaf")}), caPEM} {
		if _, err := CertificatePinPEM(data); err == nil {
			t.Fatal("invalid certificate input accepted")
		}
	}
}
