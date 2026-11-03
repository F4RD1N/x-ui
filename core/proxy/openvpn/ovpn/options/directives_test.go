package options

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func mustParse(t *testing.T, text string) *Options {
	t.Helper()
	o, err := Parse(text)
	if err != nil {
		t.Fatalf("Parse(%q): %v", text, err)
	}
	return o
}

// TestAuthUserPassFileWithoutBaseDir: a credentials file that cannot be
// read (no BaseDir) leaves the credentials to the caller instead of
// failing the whole profile.
func TestAuthUserPassFileWithoutBaseDir(t *testing.T) {
	for _, file := range []string{"/etc/openvpn/credentials.txt", "mullvad_userpass.txt"} {
		o := mustParse(t, "remote r\nauth-user-pass "+file+"\n")
		if !o.AuthUserPass || o.Username != "" || o.Password != "" {
			t.Errorf("%s: AuthUserPass=%v user=%q", file, o.AuthUserPass, o.Username)
		}
		if o.AuthUserPassFile != file {
			t.Errorf("%s: AuthUserPassFile = %q", file, o.AuthUserPassFile)
		}
		if !slices.Contains(o.Ignored, "auth-user-pass") {
			t.Errorf("%s: Ignored = %q", file, o.Ignored)
		}
	}
	// A block still wins over the file name, and [inline] still needs it.
	o := mustParse(t, "remote r\nauth-user-pass creds.txt\n"+block("auth-user-pass", "alice\nsecret\n"))
	if o.Username != "alice" || o.Password != "secret" || o.AuthUserPassFile != "" {
		t.Errorf("with a block: %q %q %q", o.Username, o.Password, o.AuthUserPassFile)
	}
	if _, err := Parse("remote r\nauth-user-pass [inline]\n"); err == nil {
		t.Error("auth-user-pass [inline] without a block succeeded")
	}
	// With a BaseDir the file is read; a missing one is an error.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "creds.txt"), []byte("bob\npw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	o, err := ParseWithBaseDir("auth-user-pass creds.txt\n", dir)
	if err != nil || o.Username != "bob" || o.Password != "pw" || o.AuthUserPassFile != "" {
		t.Errorf("ParseWithBaseDir: %v", err)
	}
	if _, err := ParseWithBaseDir("auth-user-pass missing.txt\n", dir); err == nil {
		t.Error("missing credentials file under BaseDir accepted")
	}
}

// TestPingExit: ping-exit sets the same receive timeout as ping-restart;
// the last of the two in the file wins, as in OpenVPN.
func TestPingExit(t *testing.T) {
	for _, tc := range []struct {
		text string
		want time.Duration
	}{
		{"ping 5\nping-exit 60\nping-timer-rem\n", 60 * time.Second},
		{"ping-restart 30\nping-exit 60\n", 60 * time.Second},
		{"ping-exit 60\nping-restart 30\n", 30 * time.Second},
		{"keepalive 10 120\nping-exit 40\n", 40 * time.Second},
	} {
		o := mustParse(t, tc.text)
		if o.PingRestart != tc.want {
			t.Errorf("%q: PingRestart = %v, want %v", tc.text, o.PingRestart, tc.want)
		}
		if slices.Contains(o.Ignored, "ping-exit") {
			t.Errorf("%q: ping-exit listed as ignored", tc.text)
		}
	}
	if _, err := Parse("ping-exit x\n"); err == nil {
		t.Error("ping-exit x accepted")
	}
}

// TestSetenvOpt: "setenv opt X ..." applies X when the parser knows it.
func TestSetenvOpt(t *testing.T) {
	o := mustParse(t, "remote r\nsetenv opt verify-x509-name vpn-server name\n")
	if o.VerifyX509Name != "vpn-server" || o.VerifyX509Type != "name" {
		t.Errorf("verify-x509-name = %q %q", o.VerifyX509Name, o.VerifyX509Type)
	}
	o = mustParse(t, "remote r\nsetenv opt tls-version-min 1.2\nsetenv opt block-outside-dns\n")
	if o.TLSVersionMin != "1.2" {
		t.Errorf("TLSVersionMin = %q", o.TLSVersionMin)
	}
	if !slices.Contains(o.Ignored, "block-outside-dns") || slices.Contains(o.Ignored, "setenv") {
		t.Errorf("Ignored = %q", o.Ignored)
	}
	o = mustParse(t, "remote r\nsetenv FOO bar\nsetenv OPT verify-x509-name x\n")
	if !slices.Contains(o.Ignored, "setenv") || o.VerifyX509Name != "" {
		t.Errorf("plain setenv: Ignored = %q, VerifyX509Name = %q", o.Ignored, o.VerifyX509Name)
	}
	if _, err := Parse("remote r\nsetenv opt fragment 1300\n"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("setenv opt fragment: %v", err)
	}
	o = mustParse(t, "setenv opt remote wrapped.example 443 tcp\n")
	if len(o.Remotes) != 1 || o.Remotes[0] != (Remote{"wrapped.example", 443, "tcp"}) {
		t.Errorf("Remotes = %+v", o.Remotes)
	}
}

// TestZeroTimeouts: OpenVPN accepts 0 for connect-timeout and
// server-poll-timeout; hand-window 0 can never connect and stays an error.
func TestZeroTimeouts(t *testing.T) {
	for _, text := range []string{"connect-timeout 0\n", "server-poll-timeout 0\n", "connect-timeout 10\nserver-poll-timeout 0\n"} {
		o := mustParse(t, text)
		if o.ConnectTimeout != 30*time.Second {
			t.Errorf("%q: ConnectTimeout = %v, want the 30s default", text, o.ConnectTimeout)
		}
	}
	if _, err := Parse("hand-window 0\n"); err == nil || !strings.Contains(err.Error(), "must be positive") {
		t.Errorf("hand-window 0: %v", err)
	}
}

// TestRenegSecDefault: like OpenVPN clients, renegotiate every hour unless
// the configuration says otherwise.
func TestRenegSecDefault(t *testing.T) {
	if o := mustParse(t, "remote r\n"); o.RenegSec != time.Hour {
		t.Errorf("default RenegSec = %v, want 1h", o.RenegSec)
	}
	if o := mustParse(t, "remote r\nreneg-sec 0\n"); o.RenegSec != 0 {
		t.Errorf("reneg-sec 0: RenegSec = %v", o.RenegSec)
	}
	if o := mustParse(t, "remote r\nreneg-sec 120\n"); o.RenegSec != 2*time.Minute {
		t.Errorf("reneg-sec 120: RenegSec = %v", o.RenegSec)
	}
}

// TestStaticChallenge: the challenge is recorded so that callers can refuse
// the profile or explain an AUTH_FAILED.
func TestStaticChallenge(t *testing.T) {
	o := mustParse(t, "remote r\nauth-user-pass\nstatic-challenge \"Enter Authenticator Code\" 1\n")
	if o.StaticChallenge != "Enter Authenticator Code" || !o.StaticChallengeEcho {
		t.Errorf("StaticChallenge = %q, echo %v", o.StaticChallenge, o.StaticChallengeEcho)
	}
	o = mustParse(t, "remote r\nstatic-challenge 'PIN' 0 scrv1\n")
	if o.StaticChallenge != "PIN" || o.StaticChallengeEcho {
		t.Errorf("StaticChallenge = %q, echo %v", o.StaticChallenge, o.StaticChallengeEcho)
	}
	if _, err := Parse("static-challenge\n"); err == nil {
		t.Error("static-challenge without text accepted")
	}
}

// TestServerVerificationDirectives: directives that narrow which server
// certificates are trusted are kept for tlsconf, never ignored.
func TestServerVerificationDirectives(t *testing.T) {
	crl := "-----BEGIN X509 CRL-----\nMIIB\n-----END X509 CRL-----\n"
	h1 := "BF:56:13:E3:35:79:66:5F:C2:4F:96:A0:16:26:5E:61:36:97:30:0A"
	h256 := "fa:cf:cc:6d:cc:93:03:bb:4d:5d:66:58:9e:0f:25:30:31:b2:df:2f:0c:f1:0b:2c:09:62:bc:41:ef:ff:79:f1"

	o := mustParse(t, "remote r\n"+block("crl-verify", crl))
	if string(o.CRLVerify) != crl {
		t.Errorf("CRLVerify = %q", o.CRLVerify)
	}
	o = mustParse(t, "remote r\ncrl-verify crl.pem\n"+block("crl-verify", crl))
	if string(o.CRLVerify) != crl {
		t.Errorf("crl-verify file with a block: CRLVerify = %q", o.CRLVerify)
	}

	o = mustParse(t, "remote r\nremote-cert-eku \"TLS Web Server Authentication\"\n")
	if o.RemoteCertEKU != "TLS Web Server Authentication" {
		t.Errorf("RemoteCertEKU = %q", o.RemoteCertEKU)
	}

	for _, tc := range []struct {
		text string
		set  bool
		want []uint16
	}{
		{"remote-cert-ku\n", true, nil},
		{"remote-cert-ku a0\n", true, []uint16{0xa0}},
		{"remote-cert-ku 80 A0 0x88\n", true, []uint16{0x80, 0xa0, 0x88}},
		{"remote-cert-ku 20 0 80\n", true, []uint16{0x20}},
		{"remote-cert-ku 0 80\n", false, nil}, // OpenVPN: no check at all
	} {
		o := mustParse(t, tc.text)
		if o.RemoteCertKUSet != tc.set || !slices.Equal(o.RemoteCertKU, tc.want) {
			t.Errorf("%q: RemoteCertKU = %x (set %v), want %x (set %v)", tc.text, o.RemoteCertKU, o.RemoteCertKUSet, tc.want, tc.set)
		}
	}

	o = mustParse(t, "verify-hash "+h1+"\n")
	if o.VerifyHashAlgo != "SHA1" || len(o.VerifyHash) != 1 || len(o.VerifyHash[0]) != 20 || o.VerifyHash[0][0] != 0xbf {
		t.Errorf("verify-hash SHA1: %s %x", o.VerifyHashAlgo, o.VerifyHash)
	}
	o = mustParse(t, "verify-hash "+h256+" SHA256\n")
	if o.VerifyHashAlgo != "SHA256" || len(o.VerifyHash) != 1 || len(o.VerifyHash[0]) != 32 {
		t.Errorf("verify-hash SHA256: %s %x", o.VerifyHashAlgo, o.VerifyHash)
	}
	o = mustParse(t, block("verify-hash", "# level-1 certificates\n"+h256+"\n\n"+strings.ToUpper(h256)+"\n"))
	if o.VerifyHashAlgo != "SHA256" || len(o.VerifyHash) != 2 {
		t.Errorf("<verify-hash>: %s %x", o.VerifyHashAlgo, o.VerifyHash)
	}

	for _, n := range []string{"crl-verify", "remote-cert-eku", "remote-cert-ku", "verify-hash"} {
		if slices.Contains(o.Ignored, n) {
			t.Errorf("%s listed as ignored", n)
		}
	}

	for _, tc := range []struct {
		name, text  string
		unsupported bool
		contains    string
	}{
		{"tls-verify", "tls-verify /bin/false\n", true, "tls-verify"},
		{"crl-verify dir", "crl-verify /etc/openvpn/crl dir\n", true, "crl-verify dir"},
		{"crl-verify file without base dir", "crl-verify crl.pem\n", false, "base directory"},
		{"remote-cert-eku without argument", "remote-cert-eku\n", false, "missing argument"},
		{"remote-cert-ku not hex", "remote-cert-ku xyz\n", false, "remote-cert-ku"},
		{"remote-cert-ku too big", "remote-cert-ku 10000\n", false, "remote-cert-ku"},
		{"verify-hash SHA256 digest without algo", "verify-hash " + h256 + "\n", false, "verify-hash"},
		{"verify-hash SHA1 digest as SHA256", "verify-hash " + h1 + " SHA256\n", false, "verify-hash"},
		{"verify-hash without colons", "verify-hash " + strings.ReplaceAll(h1, ":", "") + "\n", false, "verify-hash"},
		{"verify-hash unknown algo", "verify-hash " + h1 + " MD5\n", false, "verify-hash"},
		{"verify-hash block with SHA1", block("verify-hash", h1+"\n"), false, "verify-hash"},
		{"verify-hash empty block", block("verify-hash", "\n"), false, "verify-hash"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.text)
			if err == nil {
				t.Fatal("Parse succeeded")
			}
			if errors.Is(err, ErrUnsupported) != tc.unsupported || !strings.Contains(err.Error(), tc.contains) {
				t.Errorf("err = %v, want unsupported=%v containing %q", err, tc.unsupported, tc.contains)
			}
		})
	}
}

// TestCRLVerifyWithBaseDir reads the CRL file under BaseDir.
func TestCRLVerifyWithBaseDir(t *testing.T) {
	dir := t.TempDir()
	crl := "-----BEGIN X509 CRL-----\nMIIB\n-----END X509 CRL-----\n"
	if err := os.WriteFile(filepath.Join(dir, "crl.pem"), []byte(crl), 0o600); err != nil {
		t.Fatal(err)
	}
	o, err := ParseWithBaseDir("crl-verify crl.pem\n", dir)
	if err != nil || string(o.CRLVerify) != crl {
		t.Fatalf("ParseWithBaseDir: %v", err)
	}
}

// TestAskpass: the key passphrase file is read under BaseDir; without one
// it is the caller's to give (Options.KeyPassword).
func TestAskpass(t *testing.T) {
	o := mustParse(t, "remote r\naskpass pass.txt\n")
	if o.KeyPassword != "" || !slices.Contains(o.Ignored, "askpass") {
		t.Errorf("askpass without BaseDir: KeyPassword set or not ignored (%q)", o.Ignored)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pass.txt"), []byte("s3cret pass\r\nsecond line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	o, err := ParseWithBaseDir("askpass pass.txt\n", dir)
	if err != nil || o.KeyPassword != "s3cret pass" {
		t.Errorf("ParseWithBaseDir: %v", err)
	}
	if o != nil && slices.Contains(o.Ignored, "askpass") {
		t.Errorf("askpass read but listed as ignored")
	}
	o, err = ParseWithBaseDir("askpass\n", dir)
	if err != nil || o.KeyPassword != "" {
		t.Errorf("askpass without a file: %v", err)
	}
	_, err = ParseWithBaseDir("askpass missing.txt\n", dir)
	if err == nil {
		t.Error("missing askpass file accepted")
	}
}
