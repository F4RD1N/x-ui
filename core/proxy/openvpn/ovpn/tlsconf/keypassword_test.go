package tlsconf

import (
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/options"
)

// pwKeys are the encrypted forms of the key of testdata/pw-client.pem (see
// testdata/gen.sh) and their passwords.
var pwKeys = []struct{ file, password string }{
	{"pw-legacy-aes256.key", "secret"},
	{"pw-legacy-des3.key", "secret"},
	{"pw-pkcs8-aes256.key", "secret"},
	{"pw-pkcs8-des3.key", "secret"},
	{"pw-pkcs8-pbe3des.key", "secret"},
	{"pw-pkcs8-pbes1.key", "secret"},
	{"pw-pkcs8-utf8.key", "pässwörd"},
}

func checkNoSecret(t *testing.T, err error, password string) {
	t.Helper()
	if err != nil && strings.Contains(err.Error(), password) {
		t.Errorf("error %q shows the password", err)
	}
}

func TestKeyPassword(t *testing.T) {
	cert, ca := readFixture(t, "pw-client.pem"), readFixture(t, "p12-ca.pem")
	leaf := loadFixtureCert(t, "pw-client.pem")
	for _, k := range pwKeys {
		t.Run(k.file, func(t *testing.T) {
			o := &options.Options{CA: ca, Cert: cert, Key: readFixture(t, k.file), KeyPassword: k.password}
			cfg, err := Build(o)
			if err != nil {
				t.Fatalf("right password: %v", err)
			}
			if c := cfg.Certificates[0]; !samePublicKey(c.PrivateKey.(crypto.Signer).Public(), leaf.PublicKey) {
				t.Error("decrypted key does not match the certificate")
			}
			o.KeyPassword = "wrong-" + k.password
			_, err = Build(o)
			if !errors.Is(err, ErrClientKey) || !strings.Contains(err.Error(), "wrong key password") {
				t.Errorf("wrong password: %v", err)
			}
			checkNoSecret(t, err, o.KeyPassword)
			o.KeyPassword = ""
			if _, err := Build(o); !errors.Is(err, ErrClientKey) || !strings.Contains(err.Error(), "encrypted") || !strings.Contains(err.Error(), "keyPassword") {
				t.Errorf("no password: %v", err)
			}
		})
	}
	// A traditional AES-128 RSA key (enc-pkcs1.key has no certificate).
	k, err := parsePrivateKeyPEM(readFixture(t, "enc-pkcs1.key"), "secret")
	if _, ok := k.(*rsa.PrivateKey); err != nil || !ok {
		t.Errorf("enc-pkcs1.key: %T, %v", k, err)
	}
	if _, err := parsePrivateKeyPEM(readFixture(t, "enc-pkcs1.key"), "nope"); !errors.Is(err, errKeyPassword) {
		t.Errorf("enc-pkcs1.key, wrong password: %v", err)
	}
	// A password for a key that is not encrypted is not used.
	plain := ecSEC1PEM(t, issue(t, newCA(t, "CA"), certSpec{cn: "c"}))
	if _, err := parsePrivateKeyPEM(plain, "unused"); err != nil {
		t.Errorf("plain key with a password: %v", err)
	}
}

func TestPKCS12Password(t *testing.T) {
	ca := readFixture(t, "p12-ca.pem")
	for _, f := range []struct{ file, password string }{
		{"client-password.p12", "secret"},
		{"client-password-legacy.p12", "secret"},
		{"pw-utf8.p12", "pässwörd"},
		{"pw-utf8-legacy.p12", "pässwörd"},
	} {
		t.Run(f.file, func(t *testing.T) {
			o := &options.Options{CA: ca, PKCS12: readFixture(t, f.file), KeyPassword: f.password}
			if _, err := Build(o); err != nil {
				t.Fatalf("right password: %v", err)
			}
			o.KeyPassword = "wrong"
			_, err := Build(o)
			if !errors.Is(err, ErrClientKey) || !strings.Contains(err.Error(), "wrong password") {
				t.Errorf("wrong password: %v", err)
			}
			o.KeyPassword = ""
			if _, err := Build(o); !errors.Is(err, ErrClientKey) || !strings.Contains(err.Error(), "needs a password") {
				t.Errorf("no password: %v", err)
			}
		})
	}
	// A file without a password still loads when one is given.
	o := &options.Options{CA: ca, PKCS12: readFixture(t, "client-modern.p12"), KeyPassword: "unused"}
	if _, err := Build(o); err != nil {
		t.Errorf("unprotected file with a password: %v", err)
	}
	o.PKCS12 = readFixture(t, "client-legacy.p12")
	if _, err := Build(o); err != nil {
		t.Errorf("unprotected legacy file with a password: %v", err)
	}
}

// TestAskpassEndToEnd reads the passphrase the way OpenVPN does, from an
// askpass file, through options.ParseWithBaseDir, and handshakes with the
// decrypted key.
func TestAskpassEndToEnd(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pass.txt"), []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatal(err)
	}
	p12CA := &testCert{cert: loadFixtureCert(t, "p12-ca.pem"), key: loadFixtureKey(t, "p12-ca.key")}
	server := issue(t, p12CA, serverSpec("server"))
	for _, key := range []string{"pw-legacy-aes256.key", "pw-pkcs8-aes256.key"} {
		text := "client\nremote r\naskpass pass.txt\nca " + filepath.Join(abs, "p12-ca.pem") +
			"\ncert " + filepath.Join(abs, "pw-client.pem") + "\nkey " + filepath.Join(abs, key) + "\n"
		o, err := options.ParseWithBaseDir(text, dir)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := Build(o)
		if err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		srv := serverConfig(server)
		srv.ClientAuth = tls.RequireAndVerifyClientCert
		srv.ClientCAs = x509.NewCertPool()
		srv.ClientCAs.AddCert(p12CA.cert)
		if r := handshake(t, cfg, srv); r.clientErr != nil || r.serverErr != nil {
			t.Errorf("%s: client: %v; server: %v", key, r.clientErr, r.serverErr)
		}
	}
}

func TestKDFPasswords(t *testing.T) {
	got := kdfPasswords("aé")
	want := [][]byte{{0, 'a', 0, 0xe9, 0, 0}, {0, 'a', 0, 0xc3, 0, 0xa9, 0, 0}}
	if len(got) != len(want) || string(got[0]) != string(want[0]) || string(got[1]) != string(want[1]) {
		t.Errorf("kdfPasswords = %x, want %x", got, want)
	}
	if got := kdfPasswords("ab"); len(got) != 1 || string(got[0]) != "\x00a\x00b\x00\x00" {
		t.Errorf("kdfPasswords(ab) = %x", got)
	}
	if got := kdfPasswords("\U0001F600"); len(got) < 1 || string(got[0]) != "\xd8\x3d\xde\x00\x00\x00" {
		t.Errorf("kdfPasswords(emoji) = %x", got)
	}
}

// FuzzEncryptedKey feeds arbitrary bytes to the encrypted-key reader with a
// password, as a broken profile can.
func FuzzEncryptedKey(f *testing.F) {
	for _, k := range pwKeys {
		f.Add(readFixture(f, k.file))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		parsePrivateKeyPEM(data, "secret")
		decryptPKCS8(data, "secret")
	})
}
