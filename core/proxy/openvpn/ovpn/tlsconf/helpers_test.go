package tlsconf

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/options"
)

// testNow is the reference time of the generated PKI; certificates are
// valid from testNow-1h to testNow+24h unless a test says otherwise.
var testNow = time.Now().Truncate(time.Second)

type testCert struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func (c *testCert) der() []byte { return c.cert.Raw }

func (c *testCert) pem() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})
}

func (c *testCert) fingerprint() [32]byte { return sha256.Sum256(c.cert.Raw) }

type certSpec struct {
	cn         string
	subject    *pkix.Name
	rawSubject []byte
	ca         bool
	maxPathLen int // for CAs; -1 unset
	eku        []x509.ExtKeyUsage
	ku         x509.KeyUsage
	extra      []pkix.Extension
	notBefore  time.Time
	notAfter   time.Time
	key        crypto.Signer
}

var (
	serialMu sync.Mutex
	serial   int64 = 1000
)

func nextSerial() *big.Int {
	serialMu.Lock()
	defer serialMu.Unlock()
	serial++
	return big.NewInt(serial)
}

func newECKey(t testing.TB) crypto.Signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

var (
	rsaOnce sync.Once
	rsaKey  *rsa.PrivateKey
)

// sharedRSAKey is one 2048-bit RSA key reused by every test that needs RSA
// (RSA key exchange, PKCS#1 files), since generating them is slow.
func sharedRSAKey(t testing.TB) *rsa.PrivateKey {
	t.Helper()
	rsaOnce.Do(func() {
		var err error
		if rsaKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
	})
	return rsaKey
}

// issue creates a certificate from spec signed by parent (self-signed when
// parent is nil).
func issue(t testing.TB, parent *testCert, s certSpec) *testCert {
	t.Helper()
	if s.key == nil {
		s.key = newECKey(t)
	}
	if s.notBefore.IsZero() {
		s.notBefore = testNow.Add(-time.Hour)
	}
	if s.notAfter.IsZero() {
		s.notAfter = testNow.Add(24 * time.Hour)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          nextSerial(),
		NotBefore:             s.notBefore,
		NotAfter:              s.notAfter,
		ExtKeyUsage:           s.eku,
		KeyUsage:              s.ku,
		ExtraExtensions:       s.extra,
		BasicConstraintsValid: true,
		IsCA:                  s.ca,
		RawSubject:            s.rawSubject,
	}
	switch {
	case s.subject != nil:
		tmpl.Subject = *s.subject
	case s.rawSubject == nil:
		tmpl.Subject = pkix.Name{CommonName: s.cn}
	}
	if s.ca {
		if tmpl.KeyUsage == 0 {
			tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		}
		tmpl.MaxPathLen = s.maxPathLen
		tmpl.MaxPathLenZero = s.maxPathLen == 0
	}
	signer, parentCert := s.key, tmpl
	if parent != nil {
		signer, parentCert = parent.key, parent.cert
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, s.key.Public(), signer)
	if err != nil {
		t.Fatalf("create %q: %v", s.cn, err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCert{cert: c, key: s.key}
}

func newCA(t testing.TB, cn string) *testCert {
	return issue(t, nil, certSpec{cn: cn, ca: true, maxPathLen: -1})
}

// serverSpec is a typical easy-rsa server certificate.
func serverSpec(cn string) certSpec {
	return certSpec{
		cn:  cn,
		eku: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ku:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
}

func tlsCert(leaf *testCert, chain ...*testCert) tls.Certificate {
	c := tls.Certificate{Certificate: [][]byte{leaf.der()}, PrivateKey: leaf.key, Leaf: leaf.cert}
	for _, x := range chain {
		c.Certificate = append(c.Certificate, x.der())
	}
	return c
}

// serverConfig returns a crypto/tls server presenting leaf and chain.
func serverConfig(leaf *testCert, chain ...*testCert) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert(leaf, chain...)},
		MinVersion:   tls.VersionTLS10,
	}
}

type handshakeResult struct {
	state     tls.ConnectionState
	clientErr error
	serverErr error
	sni       string
}

// handshake runs a TLS handshake between client and server over loopback
// TCP and reports both sides' outcome.
func handshake(t *testing.T, client, server *tls.Config) handshakeResult {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	server = server.Clone()
	var res handshakeResult
	sniC := make(chan string, 1)
	server.GetConfigForClient = func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		sniC <- h.ServerName
		return nil, nil
	}
	srvDone := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			srvDone <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(20 * time.Second))
		s := tls.Server(c, server)
		err = s.Handshake()
		if err == nil {
			// One byte of application data tells the client that we
			// accepted it (a TLS 1.3 server judges the client's
			// certificate after the client's handshake is over).
			_, err = s.Write([]byte{1})
		}
		srvDone <- err
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	cli := tls.Client(conn, client)
	res.clientErr = cli.Handshake()
	if res.clientErr == nil {
		res.state = cli.ConnectionState()
		buf := make([]byte, 1)
		if _, err := cli.Read(buf); err != nil {
			res.clientErr = err
		}
	}
	conn.Close()
	res.serverErr = <-srvDone
	select {
	case res.sni = <-sniC:
	default:
	}
	return res
}

func readFixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func loadFixtureCert(t testing.TB, name string) *x509.Certificate {
	t.Helper()
	certs, err := parsePEMCertificates(readFixture(t, name))
	if err != nil || len(certs) != 1 {
		t.Fatalf("%s: %v (%d certs)", name, err, len(certs))
	}
	return certs[0]
}

func loadFixtureKey(t testing.TB, name string) crypto.Signer {
	t.Helper()
	k, err := parsePrivateKeyPEM(readFixture(t, name), "")
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return k
}

func caOptions(ca ...*testCert) *options.Options {
	o := &options.Options{}
	for _, c := range ca {
		o.CA = append(o.CA, c.pem()...)
	}
	return o
}

func mustBuild(t *testing.T, o *options.Options) *tls.Config {
	t.Helper()
	cfg, err := Build(o)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return cfg
}
