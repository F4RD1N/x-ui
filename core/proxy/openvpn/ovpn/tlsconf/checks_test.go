package tlsconf

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/options"
)

// makeCRL returns a DER CRL issued by issuer that revokes the given
// certificates and is valid from thisUpdate to nextUpdate.
func makeCRL(t testing.TB, issuer *testCert, thisUpdate, nextUpdate time.Time, revoked ...*testCert) []byte {
	t.Helper()
	tmpl := &x509.RevocationList{Number: nextSerial(), ThisUpdate: thisUpdate, NextUpdate: nextUpdate}
	for _, c := range revoked {
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries,
			x509.RevocationListEntry{SerialNumber: c.cert.SerialNumber, RevocationTime: thisUpdate})
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, issuer.cert, issuer.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func crlPEM(ders ...[]byte) string {
	var s string
	for _, d := range ders {
		s += string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: d}))
	}
	return s
}

func colonSum(b []byte) string { return strings.ToUpper(colonHex(b)) }

func sha1Of(c *testCert) string {
	s := sha1.Sum(c.cert.Raw)
	return colonSum(s[:])
}

func sha256Of(c *testCert) string {
	s := sha256.Sum256(c.cert.Raw)
	return colonSum(s[:])
}

// TestServerVerificationDirectives runs .ovpn text through options.Parse
// and the verifier, as the client does. The expectations are what OpenVPN
// 2.6.19 did with the same shapes of certificates and CRLs.
func TestServerVerificationDirectives(t *testing.T) {
	ca := newCA(t, "Root")
	other := newCA(t, "Other")
	inter := issue(t, ca, certSpec{cn: "Inter", ca: true, maxPathLen: -1})
	good := issue(t, ca, serverSpec("good"))
	revoked := issue(t, ca, serverSpec("revoked"))
	noEKU := issue(t, ca, certSpec{cn: "other-client"}) // neither EKU nor KU
	kuDsig := issue(t, ca, certSpec{cn: "ku-dsig", eku: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, ku: x509.KeyUsageDigitalSignature})
	ekuDER, _ := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 1}, {1, 3, 6, 1, 4, 1, 99999, 1}})
	custom := issue(t, ca, certSpec{cn: "custom", ku: x509.KeyUsageDigitalSignature, extra: []pkix.Extension{{Id: oidExtKeyUsage, Value: ekuDER}}})
	viaInter := issue(t, inter, serverSpec("via-inter"))

	now, day := testNow, 24*time.Hour
	rootRevoking := makeCRL(t, ca, now.Add(-time.Hour), now.Add(day), revoked, noEKU)
	rootEmpty := makeCRL(t, ca, now.Add(-time.Hour), now.Add(day))
	rootExpired := makeCRL(t, ca, now.Add(-2*day), now.Add(-day))
	rootFuture := makeCRL(t, ca, now.Add(day), now.Add(2*day))
	rootBadSig := append([]byte(nil), rootEmpty...)
	rootBadSig[len(rootBadSig)-1] ^= 1
	rootRevokingInter := makeCRL(t, ca, now.Add(-time.Hour), now.Add(day), inter)
	interEmpty := makeCRL(t, inter, now.Add(-time.Hour), now.Add(day))
	interRevoking := makeCRL(t, inter, now.Add(-time.Hour), now.Add(day), viaInter)
	otherEmpty := makeCRL(t, other, now.Add(-time.Hour), now.Add(day))

	crlBlock := func(ders ...[]byte) string { return "<crl-verify>\n" + crlPEM(ders...) + "</crl-verify>\n" }
	tests := []struct {
		name  string
		extra string
		chain []*testCert
		fail  string // "" when the server must be accepted
	}{
		{"crl: revoked leaf", crlBlock(rootRevoking), []*testCert{revoked}, "certificate revoked"},
		{"crl: revoked impostor without EKU", crlBlock(rootRevoking), []*testCert{noEKU}, "certificate revoked"},
		{"crl: leaf not listed", crlBlock(rootRevoking), []*testCert{good}, ""},
		{"crl: expired", crlBlock(rootExpired), []*testCert{good}, "expired"},
		{"crl: not yet valid", crlBlock(rootFuture), []*testCert{good}, "not yet valid"},
		{"crl: bad signature", crlBlock(rootBadSig), []*testCert{good}, "signature"},
		{"crl: a fresh CRL beside an expired one", crlBlock(rootExpired, rootEmpty), []*testCert{good}, ""},
		{"crl: none from the issuer", crlBlock(otherEmpty), []*testCert{good}, ""},
		{"crl: intermediate, root CRL only", crlBlock(rootEmpty), []*testCert{viaInter, inter}, ""},
		{"crl: intermediate, its CRL only", crlBlock(interEmpty), []*testCert{viaInter, inter}, ""},
		{"crl: intermediate, both CRLs", crlBlock(rootEmpty, interEmpty), []*testCert{viaInter, inter}, ""},
		{"crl: leaf revoked by the intermediate", crlBlock(rootEmpty, interRevoking), []*testCert{viaInter, inter}, "certificate revoked"},
		{"crl: intermediate revoked by the root", crlBlock(rootRevokingInter, interEmpty), []*testCert{viaInter, inter}, "certificate revoked"},

		{"eku: long name", "remote-cert-eku \"TLS Web Server Authentication\"\n", []*testCert{good}, ""},
		{"eku: OID", "remote-cert-eku 1.3.6.1.5.5.7.3.1\n", []*testCert{good}, ""},
		{"eku: short name", "remote-cert-eku serverAuth\n", []*testCert{good}, "remote-cert-eku"},
		{"eku: other case", "remote-cert-eku \"tls web server authentication\"\n", []*testCert{good}, "remote-cert-eku"},
		{"eku: client", "remote-cert-eku \"TLS Web Client Authentication\"\n", []*testCert{good}, "remote-cert-eku"},
		{"eku: impostor without EKU", "remote-cert-eku \"TLS Web Server Authentication\"\n", []*testCert{noEKU}, "no extended key usage"},
		{"eku: unknown OID", "remote-cert-eku 1.3.6.1.4.1.99999.1\n", []*testCert{custom}, ""},

		{"ku: present", "remote-cert-ku\n", []*testCert{good}, ""},
		{"ku: impostor without KU", "remote-cert-ku\n", []*testCert{noEKU}, "no key usage"},
		{"ku: a0", "remote-cert-ku a0\n", []*testCert{good}, ""},
		{"ku: a0 on digitalSignature only", "remote-cert-ku a0\n", []*testCert{kuDsig}, "remote-cert-ku"},
		{"ku: impostor, a0", "remote-cert-ku a0\n", []*testCert{noEKU}, "remote-cert-ku"},
		{"ku: 80 or a0", "remote-cert-ku a0 80\n", []*testCert{kuDsig}, ""},
		{"ku: the list ends at 0", "remote-cert-ku 20 0 80\n", []*testCert{kuDsig}, "remote-cert-ku"},
		{"ku: a first 0 turns it off", "remote-cert-ku 0 80\n", []*testCert{noEKU}, ""},

		{"hash: SHA1 of the CA", "verify-hash " + sha1Of(ca) + "\n", []*testCert{good}, ""},
		{"hash: lower case", "verify-hash " + strings.ToLower(sha1Of(ca)) + "\n", []*testCert{good}, ""},
		{"hash: SHA256 of the CA", "verify-hash " + sha256Of(ca) + " SHA256\n", []*testCert{good}, ""},
		{"hash: wrong", "verify-hash " + sha1Of(other) + "\n", []*testCert{noEKU}, "verify-hash"},
		{"hash: the leaf's is not level 1", "verify-hash " + sha1Of(good) + "\n", []*testCert{good}, "verify-hash"},
		{"hash: block", "<verify-hash>\n" + sha256Of(other) + "\n" + sha256Of(ca) + "\n</verify-hash>\n", []*testCert{good}, ""},
		{"hash: intermediate is level 1", "verify-hash " + sha1Of(inter) + "\n", []*testCert{viaInter, inter}, ""},
		{"hash: root is level 2 here", "verify-hash " + sha1Of(ca) + "\n", []*testCert{viaInter, inter}, "verify-hash"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o, err := options.Parse("client\nremote r\n<ca>\n" + string(ca.pem()) + "</ca>\n" + tc.extra)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			var chain []*x509.Certificate
			for _, c := range tc.chain {
				chain = append(chain, c.cert)
			}
			err = verifyWith(t, o, chain...)
			switch {
			case tc.fail == "" && err != nil:
				t.Errorf("rejected: %v", err)
			case tc.fail != "" && err == nil:
				t.Errorf("accepted %q (fail open)", tc.chain[0].cert.Subject.CommonName)
			case tc.fail != "" && (!errors.Is(err, ErrVerify) || !strings.Contains(err.Error(), tc.fail)):
				t.Errorf("err = %v, want ErrVerify mentioning %q", err, tc.fail)
			}
		})
	}
}

// TestServerChecksWithFingerprint: without a CA the chain the server sent
// is what crl-verify and verify-hash look at.
func TestServerChecksWithFingerprint(t *testing.T) {
	ca := newCA(t, "Root")
	leaf := issue(t, ca, serverSpec("pinned"))
	pinned := &options.Options{PeerFingerprints: [][32]byte{leaf.fingerprint()}}
	revoking := makeCRL(t, ca, testNow.Add(-time.Hour), testNow.Add(time.Hour), leaf)
	s := sha1.Sum(ca.cert.Raw)
	ok := withOpt(pinned, func(o *options.Options) { o.VerifyHash, o.VerifyHashAlgo = [][]byte{s[:]}, "SHA1" })
	if err := verifyWith(t, ok, leaf.cert, ca.cert); err != nil {
		t.Errorf("verify-hash with the CA sent: %v", err)
	}
	if err := verifyWith(t, ok, leaf.cert); !errors.Is(err, ErrVerify) || !strings.Contains(err.Error(), "level-1") {
		t.Errorf("verify-hash with no level-1 certificate: %v", err)
	}
	crl := withOpt(pinned, func(o *options.Options) { o.CRLVerify = []byte(crlPEM(revoking)) })
	if err := verifyWith(t, crl, leaf.cert, ca.cert); !errors.Is(err, ErrVerify) || !strings.Contains(err.Error(), "revoked") {
		t.Errorf("crl-verify with the CA sent: %v", err)
	}
	// The issuer was not sent: its CRL cannot be checked, so the server
	// is refused rather than let through.
	if err := verifyWith(t, crl, leaf.cert); !errors.Is(err, ErrVerify) {
		t.Errorf("crl-verify without the issuer: %v", err)
	}
}

func TestCRLBuildErrors(t *testing.T) {
	ca := newCA(t, "Root")
	der := makeCRL(t, ca, testNow.Add(-time.Hour), testNow.Add(time.Hour))
	for name, data := range map[string][]byte{
		"DER":         der,
		"not a CRL":   ca.pem(),
		"garbage PEM": pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: []byte{0x30, 0x03, 1, 2, 3}}),
	} {
		o := caOptions(ca)
		o.CRLVerify = data
		if _, err := Build(o); !errors.Is(err, ErrCRL) {
			t.Errorf("%s: %v", name, err)
		}
	}
	o := caOptions(ca)
	o.VerifyHash, o.VerifyHashAlgo = [][]byte{make([]byte, 20)}, "SHA256"
	if _, err := Build(o); err == nil || !strings.Contains(err.Error(), "verify-hash") {
		t.Errorf("SHA1-sized digest as SHA256: %v", err)
	}
	o.VerifyHashAlgo = "MD5"
	if _, err := Build(o); err == nil {
		t.Error("MD5 verify-hash accepted")
	}
}

// TestHandshakeCRL: a revoked server certificate fails the TLS handshake.
func TestHandshakeCRL(t *testing.T) {
	ca := newCA(t, "Root")
	good := issue(t, ca, serverSpec("good"))
	revoked := issue(t, ca, serverSpec("revoked"))
	o := caOptions(ca)
	o.CRLVerify = []byte(crlPEM(makeCRL(t, ca, testNow.Add(-time.Hour), testNow.Add(time.Hour), revoked)))
	cfg := mustBuild(t, o)
	if r := handshake(t, cfg, serverConfig(good)); r.clientErr != nil {
		t.Errorf("good server: %v", r.clientErr)
	}
	if r := handshake(t, cfg, serverConfig(revoked)); !errors.Is(r.clientErr, ErrVerify) || !strings.Contains(r.clientErr.Error(), "revoked") {
		t.Errorf("revoked server: %v", r.clientErr)
	}
}

func TestOpenSSLKeyUsage(t *testing.T) {
	for _, tc := range []struct {
		ku   x509.KeyUsage
		want uint16
	}{
		{x509.KeyUsageDigitalSignature, 0x80},
		{x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, 0xa0},
		{x509.KeyUsageKeyAgreement, 0x08},
		{x509.KeyUsageEncipherOnly, 0x01},
		{x509.KeyUsageDecipherOnly, 0}, // the ninth bit is not read, as in OpenVPN
	} {
		if got := opensslKeyUsage(tc.ku); got != tc.want {
			t.Errorf("%b: %02x, want %02x", tc.ku, got, tc.want)
		}
	}
}
