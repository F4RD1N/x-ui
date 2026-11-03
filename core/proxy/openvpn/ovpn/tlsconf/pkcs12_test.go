package tlsconf

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"hash"
	"strings"
	"testing"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/options"
)

// p12Fixtures describes testdata/client-*.p12 (see testdata/gen.sh).
var p12Fixtures = []struct {
	file      string
	cn        string
	others    int  // certificates besides the client's
	ec        bool // ECDSA key (else RSA)
	ownReader bool // parsePKCS12 reads it without x/crypto
}{
	{"client-legacy.p12", "p12-client-rsa", 0, false, false},
	{"client-legacy-chain.p12", "p12-client-int", 2, false, false},
	{"client-modern.p12", "p12-client-rsa", 0, false, true},
	{"client-modern-chain.p12", "p12-client-int", 2, false, true},
	{"client-modern-ec.p12", "p12-client-ec", 0, true, true},
	{"client-nopbe.p12", "p12-client-rsa", 0, false, true},
	{"client-mixed.p12", "p12-client-rsa", 0, false, true},
	{"client-nomac.p12", "p12-client-rsa", 0, false, true},
}

func TestDecodePKCS12(t *testing.T) {
	for _, f := range p12Fixtures {
		t.Run(f.file, func(t *testing.T) {
			data := readFixture(t, f.file)
			key, leaf, others, err := decodePKCS12(data, "")
			if err != nil {
				t.Fatal(err)
			}
			if leaf.Subject.CommonName != f.cn || len(others) != f.others {
				t.Errorf("leaf %q with %d others", leaf.Subject.CommonName, len(others))
			}
			switch key.(type) {
			case *ecdsa.PrivateKey:
				if !f.ec {
					t.Error("ECDSA key")
				}
			case *rsa.PrivateKey:
				if f.ec {
					t.Error("RSA key")
				}
			default:
				t.Errorf("key type %T", key)
			}
			if !samePublicKey(key.Public(), leaf.PublicKey) {
				t.Error("key and certificate do not match")
			}
			keys, certs, err := parsePKCS12(data, "")
			if f.ownReader {
				if err != nil || len(keys) != 1 || len(certs) != 1+f.others {
					t.Errorf("parsePKCS12: %d keys, %d certs, %v", len(keys), len(certs), err)
				}
			} else if !errors.Is(err, errP12Unsupported) {
				t.Errorf("parsePKCS12 on an RC2 file: %v", err)
			}
		})
	}
	for _, file := range []string{"client-password.p12", "client-password-legacy.p12"} {
		if _, _, _, err := decodePKCS12(readFixture(t, file), ""); err == nil || !strings.Contains(err.Error(), "password") {
			t.Errorf("%s: %v", file, err)
		}
		if _, _, err := parsePKCS12(readFixture(t, file), ""); !errors.Is(err, errP12Password) {
			t.Errorf("%s: parsePKCS12: %v", file, err)
		}
	}
}

func TestParsePKCS12Corrupt(t *testing.T) {
	modern := readFixture(t, "client-modern.p12")
	flip := func(b []byte, i int) []byte {
		c := append([]byte(nil), b...)
		c[i] ^= 0x01
		return c
	}
	// The MAC covers everything but itself, which sits at the end.
	if _, _, err := parsePKCS12(flip(modern, len(modern)-20), ""); !errors.Is(err, errP12Password) {
		t.Errorf("flipped MAC salt/digest: %v", err)
	}
	if _, _, err := parsePKCS12(flip(modern, len(modern)/2), ""); err == nil {
		t.Error("flipped content accepted")
	}
	for _, n := range []int{0, 1, 10, len(modern) / 2, len(modern) - 1} {
		if _, _, err := parsePKCS12(modern[:n], ""); err == nil {
			t.Errorf("truncated to %d accepted", n)
		}
	}
	nomac := readFixture(t, "client-nomac.p12")
	if _, _, _, err := decodePKCS12(flip(nomac, len(nomac)/2), ""); err == nil {
		t.Error("corrupt ciphertext without MAC accepted")
	}
	old := maxP12Iterations
	maxP12Iterations = 1000
	defer func() { maxP12Iterations = old }()
	if _, _, err := parsePKCS12(modern, ""); err == nil || !strings.Contains(err.Error(), "iteration count") {
		t.Errorf("iteration cap: %v", err)
	}
	// The legacy files reach x/crypto only after their counts were checked.
	if _, _, _, err := decodePKCS12(readFixture(t, "client-legacy.p12"), ""); err == nil || !strings.Contains(err.Error(), "iteration count") {
		t.Errorf("iteration cap, legacy: %v", err)
	}
}

func TestHandshakePKCS12(t *testing.T) {
	p12CA := &testCert{cert: loadFixtureCert(t, "p12-ca.pem"), key: loadFixtureKey(t, "p12-ca.key")}
	server := issue(t, p12CA, serverSpec("p12-server"))
	for _, f := range p12Fixtures {
		t.Run(f.file, func(t *testing.T) {
			o := &options.Options{PKCS12: readFixture(t, f.file)}
			if f.others == 0 {
				if _, err := Build(o); !errors.Is(err, ErrNoTrust) {
					t.Fatalf("no CA anywhere: %v", err)
				}
				o.CA = readFixture(t, "p12-ca.pem")
			}
			// With a chain, the bundled CAs are the trust anchors.
			cfg := mustBuild(t, o)
			if n := len(cfg.Certificates[0].Certificate); n != 1+f.others {
				t.Errorf("chain of %d certificates", n)
			}
			for _, v := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
				srv := serverConfig(server)
				srv.MaxVersion = v
				srv.ClientAuth = tls.RequireAndVerifyClientCert
				srv.ClientCAs = x509.NewCertPool()
				srv.ClientCAs.AddCert(p12CA.cert)
				r := handshake(t, cfg, srv)
				if r.clientErr != nil || r.serverErr != nil {
					t.Fatalf("%s: client: %v; server: %v", tls.VersionName(v), r.clientErr, r.serverErr)
				}
			}
		})
	}
}

func TestP12KDFLengths(t *testing.T) {
	// Output longer than one hash (3DES keys from SHA-1) must extend the
	// first block, not repeat it.
	k := p12KDF(sha1New, []byte{0, 0}, []byte("salt"), 3, 1, 48)
	if len(k) != 48 || string(k[:20]) == string(k[20:40]) {
		t.Errorf("p12KDF: %x", k)
	}
	if string(p12KDF(sha1New, []byte{0, 0}, []byte("salt"), 3, 1, 20)) != string(k[:20]) {
		t.Error("prefix differs")
	}
	if string(p12KDF(sha1New, []byte{0, 0}, []byte("salt"), 3, 2, 20)) == string(k[:20]) {
		t.Error("purpose id ignored")
	}
	if len(p12KDF(sha1New, nil, nil, 1, 3, 20)) != 20 {
		t.Error("empty password and salt")
	}
}

func FuzzParsePKCS12(f *testing.F) {
	for _, p := range p12Fixtures {
		f.Add(readFixture(f, p.file))
	}
	f.Add(readFixture(f, "client-password.p12"))
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x03})
	// Keep each input cheap: the fixtures use 2048 iterations.
	old := maxP12Iterations
	maxP12Iterations = 2048
	f.Cleanup(func() { maxP12Iterations = old })
	f.Fuzz(func(t *testing.T, data []byte) {
		keys, certs, err := parsePKCS12(data, "")
		if err != nil && !errors.Is(err, errP12Unsupported) && (len(keys) > 0 || len(certs) > 0) {
			t.Fatal("results returned with a hard error")
		}
		decodePKCS12(data, "")
	})
}

func sha1New() hash.Hash { return sha1.New() }
