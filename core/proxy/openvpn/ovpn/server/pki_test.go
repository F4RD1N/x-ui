package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/ctlwrap"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
)

type testPKI struct {
	caPEM         []byte
	clientCertPEM []byte
	clientKeyPEM  []byte
	serverCertPEM []byte
	serverKeyPEM  []byte
	serverCert    tls.Certificate
	pool          *x509.CertPool
}

var (
	pkiOnce sync.Once
	pkiVal  *testPKI
	pkiErr  error
)

func getPKI(t testing.TB) *testPKI {
	t.Helper()
	pkiOnce.Do(func() { pkiVal, pkiErr = makePKI() })
	if pkiErr != nil {
		t.Fatalf("making the test PKI: %v", pkiErr)
	}
	return pkiVal
}

func makePKI() (*testPKI, error) {
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	leaf := func(serial int64, cn string, eku x509.ExtKeyUsage) (certPEM, keyPEM []byte, err error) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    now.Add(-time.Hour),
			NotAfter:     now.Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{eku},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &k.PublicKey, caKey)
		if err != nil {
			return nil, nil, err
		}
		kder, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), nil
	}
	p := &testPKI{caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})}
	srvCert, srvKey, err := leaf(2, "server", x509.ExtKeyUsageServerAuth)
	if err != nil {
		return nil, err
	}
	if p.clientCertPEM, p.clientKeyPEM, err = leaf(3, "client", x509.ExtKeyUsageClientAuth); err != nil {
		return nil, err
	}
	p.serverCertPEM, p.serverKeyPEM = srvCert, srvKey
	if p.serverCert, err = tls.X509KeyPair(srvCert, srvKey); err != nil {
		return nil, err
	}
	p.pool = x509.NewCertPool()
	p.pool.AddCert(ca)
	return p, nil
}

func newStaticKey(t testing.TB) *ctlwrap.StaticKey {
	t.Helper()
	var k ctlwrap.StaticKey
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	return &k
}

func staticKeyText(k *ctlwrap.StaticKey) string {
	var b strings.Builder
	b.WriteString("#\n# 2048 bit OpenVPN static key\n#\n-----BEGIN OpenVPN Static key V1-----\n")
	for i := 0; i < len(k); i += 16 {
		b.WriteString(hex.EncodeToString(k[i : i+16]))
		b.WriteByte('\n')
	}
	b.WriteString("-----END OpenVPN Static key V1-----\n")
	return b.String()
}
