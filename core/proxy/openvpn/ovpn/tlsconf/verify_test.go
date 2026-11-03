package tlsconf

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/options"
)

var (
	nsServerExt = pkix.Extension{Id: oidNetscapeCertType, Value: []byte{0x03, 0x02, 0x06, 0x40}} // SSL server
	nsClientExt = pkix.Extension{Id: oidNetscapeCertType, Value: []byte{0x03, 0x02, 0x07, 0x80}} // SSL client
	nsBothExt   = pkix.Extension{Id: oidNetscapeCertType, Value: []byte{0x03, 0x02, 0x06, 0xc0}}
	nsBadExt    = pkix.Extension{Id: oidNetscapeCertType, Value: []byte{0x04, 0x01, 0x40}} // OCTET STRING
)

// leafKinds are the certificate shapes probed against OpenVPN 2.6.19; the
// expectations in the tests below are what the real binary did.
func leafKinds() map[string]certSpec {
	dsig := x509.KeyUsageDigitalSignature
	serverEKU := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	return map[string]certSpec{
		"easy-rsa server": serverSpec("s"),
		"client":          {cn: "c", eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, ku: dsig},
		"no ku":           {cn: "s", eku: serverEKU},
		"ku keyAgreement": {cn: "s", eku: serverEKU, ku: x509.KeyUsageKeyAgreement},
		"ku certSign":     {cn: "s", eku: serverEKU, ku: x509.KeyUsageCertSign},
		"no eku":          {cn: "s", ku: dsig},
		"no eku no ku":    {cn: "s"},
		"eku any":         {cn: "s", eku: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, ku: dsig},
		"eku sgc":         {cn: "s", eku: []x509.ExtKeyUsage{x509.ExtKeyUsageNetscapeServerGatedCrypto}, ku: dsig},
		"ns server":       {cn: "s", ku: dsig, extra: []pkix.Extension{nsServerExt}},
		"ns client":       {cn: "s", eku: serverEKU, ku: dsig, extra: []pkix.Extension{nsClientExt}},
		"ns both":         {cn: "s", ku: dsig, extra: []pkix.Extension{nsBothExt}},
		"ns malformed":    {cn: "s", eku: serverEKU, ku: dsig, extra: []pkix.Extension{nsBadExt}},
	}
}

func TestVerifyPurpose(t *testing.T) {
	ca := newCA(t, "CA")
	kinds := leafKinds()
	// name: {with CA and no option, remote-cert-tls server, ns-cert-type server}
	// (the last two are checked with a pinned fingerprint and no CA, so the
	// default purpose check does not hide them).
	want := map[string][3]bool{
		"easy-rsa server": {true, true, true},
		"client":          {false, false, false},
		"no ku":           {true, false, true},
		"ku keyAgreement": {true, true, true},
		"ku certSign":     {false, false, false},
		"no eku":          {true, false, true},
		"no eku no ku":    {true, false, true},
		"eku any":         {false, false, false},
		"eku sgc":         {true, false, true},
		"ns server":       {true, false, true},
		"ns client":       {false, true, false},
		"ns both":         {true, false, true},
		"ns malformed":    {false, true, false},
	}
	for name, spec := range kinds {
		w, ok := want[name]
		if !ok {
			t.Fatalf("no expectation for %q", name)
		}
		leaf := issue(t, ca, spec)
		pinned := &options.Options{PeerFingerprints: [][32]byte{leaf.fingerprint()}}
		cases := []struct {
			label string
			o     *options.Options
			ok    bool
			check string
		}{
			{"ca", caOptions(ca), w[0], "not a TLS server certificate"},
			{"remote-cert-tls", withOpt(pinned, func(o *options.Options) { o.RemoteCertTLS = "server" }), w[1], "remote-cert-tls server"},
			{"ns-cert-type", withOpt(pinned, func(o *options.Options) { o.NsCertType = "server" }), w[2], "ns-cert-type server"},
		}
		for _, c := range cases {
			err := verifyWith(t, c.o, leaf.cert)
			if c.ok && err != nil {
				t.Errorf("%s/%s: %v", name, c.label, err)
			}
			if !c.ok && (!errors.Is(err, ErrVerify) || !strings.Contains(err.Error(), c.check)) {
				t.Errorf("%s/%s: err = %v, want ErrVerify from %q", name, c.label, err, c.check)
			}
		}
	}
}

func withOpt(o *options.Options, f func(*options.Options)) *options.Options {
	c := *o
	f(&c)
	return &c
}

// verifyWith runs the checks Build would install for o on a chain.
func verifyWith(t *testing.T, o *options.Options, chain ...*x509.Certificate) error {
	t.Helper()
	return verifyAt(t, o, testNow, chain...)
}

func verifyAt(t *testing.T, o *options.Options, now time.Time, chain ...*x509.Certificate) error {
	t.Helper()
	v, err := newVerifier(o)
	if err != nil {
		t.Fatal(err)
	}
	if len(o.CA) > 0 {
		anchors, err := parseCAs(o.CA)
		if err != nil {
			t.Fatal(err)
		}
		v.setAnchors(anchors)
	}
	return v.verify(chain, now)
}

func TestVerifyFingerprints(t *testing.T) {
	ca := newCA(t, "CA")
	other := newCA(t, "Other")
	leaf := issue(t, ca, serverSpec("server"))
	selfSignedExpired := issue(t, nil, certSpec{cn: "old", notBefore: testNow.Add(-72 * time.Hour), notAfter: testNow.Add(-48 * time.Hour)})
	fp := leaf.fingerprint()
	tests := []struct {
		name    string
		o       *options.Options
		cert    *x509.Certificate
		wantErr string
	}{
		{"pin only", &options.Options{PeerFingerprints: [][32]byte{{9}, fp}}, leaf.cert, ""},
		{"pin only, mismatch", &options.Options{PeerFingerprints: [][32]byte{{9}}}, leaf.cert, "peer-fingerprint"},
		{"pin only, expired self-signed", &options.Options{PeerFingerprints: [][32]byte{selfSignedExpired.fingerprint()}}, selfSignedExpired.cert, ""},
		{"pin and ca", withOpt(caOptions(ca), func(o *options.Options) { o.PeerFingerprints = [][32]byte{fp} }), leaf.cert, ""},
		{"pin and ca, pin mismatch", withOpt(caOptions(ca), func(o *options.Options) { o.PeerFingerprints = [][32]byte{{9}} }), leaf.cert, "peer-fingerprint"},
		{"pin and wrong ca", withOpt(caOptions(other), func(o *options.Options) { o.PeerFingerprints = [][32]byte{fp} }), leaf.cert, "chain to --ca"},
		{"pin, name check still applies", &options.Options{PeerFingerprints: [][32]byte{fp}, VerifyX509Name: "other", VerifyX509Type: "name"}, leaf.cert, "verify-x509-name"},
	}
	for _, tt := range tests {
		err := verifyWith(t, tt.o, tt.cert)
		if tt.wantErr == "" {
			if err != nil {
				t.Errorf("%s: %v", tt.name, err)
			}
			continue
		}
		if !errors.Is(err, ErrVerify) || !strings.Contains(err.Error(), tt.wantErr) {
			t.Errorf("%s: err = %v, want ErrVerify mentioning %q", tt.name, err, tt.wantErr)
		}
	}
	// The mismatch message shows the certificate's fingerprint, as OpenVPN
	// does, so that users can pin it.
	err := verifyWith(t, &options.Options{PeerFingerprints: [][32]byte{{9}}}, leaf.cert)
	if !strings.Contains(err.Error(), colonHex(fp[:])) {
		t.Errorf("mismatch error %q lacks the fingerprint", err)
	}
	if err := (&verifier{}).verify(nil, testNow); !errors.Is(err, ErrVerify) {
		t.Errorf("no certificates: %v", err)
	}
	if err := (&verifier{}).verify([]*x509.Certificate{leaf.cert}, testNow); !errors.Is(err, ErrVerify) {
		t.Errorf("no trust: %v", err)
	}
}

func TestVerifyX509Name(t *testing.T) {
	ca := newCA(t, "CA")
	mk := func(raw []byte) *x509.Certificate {
		s := serverSpec("")
		s.rawSubject = raw
		return issue(t, ca, s).cert
	}
	plain := mk(oracleSubjects["plain"].raw)
	twoCN := mk(oracleSubjects["twocn"].raw)
	ctrl := mk(oracleSubjects["ctrl"].raw)
	noCN := mk(oracleSubjects["nocn"].raw)
	tests := []struct {
		cert       *x509.Certificate
		typ, name  string
		ok         bool
		errContain string
	}{
		{plain, "", "C=US, ST=California, L=San Francisco, O=Org, OU=Unit, CN=server, emailAddress=a@b.c", true, ""},
		{plain, "subject", "C=US, ST=California, L=San Francisco, O=Org, OU=Unit, CN=server, emailAddress=a@b.c", true, ""},
		{plain, "subject", "C=US, ST=California, L=San Francisco, O=Org, OU=Unit, CN=server", false, "subject"},
		{plain, "subject", "server", false, "subject"},
		{plain, "name", "server", true, ""},
		{plain, "name", "Server", false, "CN"},
		{plain, "name", "serv", false, "CN"},
		{plain, "name-prefix", "serv", true, ""},
		{plain, "name-prefix", "server", true, ""},
		{plain, "name-prefix", "servers", false, "start with"},
		{twoCN, "name", "second", true, ""},
		{twoCN, "name", "first", false, "CN"},
		{twoCN, "name-prefix", "sec", true, ""},
		{twoCN, "subject", "CN=first, CN=second", true, ""},
		{ctrl, "name", "a_b_c_d", true, ""},
		{ctrl, "subject", `CN=a\01b\7Fc\09d`, true, ""},
		{noCN, "name", "Org", false, "no CN"},
		{noCN, "name-prefix", "O", false, "no CN"},
		{noCN, "subject", "O=Org", true, ""},
	}
	for _, tt := range tests {
		o := withOpt(caOptions(ca), func(o *options.Options) { o.VerifyX509Name, o.VerifyX509Type = tt.name, tt.typ })
		err := verifyWith(t, o, tt.cert)
		if tt.ok {
			if err != nil {
				t.Errorf("%s %q: %v", tt.typ, tt.name, err)
			}
			continue
		}
		if !errors.Is(err, ErrVerify) || !strings.Contains(err.Error(), "verify-x509-name") || !strings.Contains(err.Error(), tt.errContain) {
			t.Errorf("%s %q: err = %v", tt.typ, tt.name, err)
		}
	}
}

func TestVerifySHA1Fallback(t *testing.T) {
	root := loadFixtureCert(t, "sha1-root.pem")
	inter := loadFixtureCert(t, "sha1-int.pem")
	leaf := loadFixtureCert(t, "sha1-server.pem")
	ecLeaf := loadFixtureCert(t, "sha1ec-server.pem")
	rootOpt := &options.Options{CA: readFixture(t, "sha1-root.pem")}
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

	// Go alone refuses the chain, so these really exercise the fallback.
	pool := x509.NewCertPool()
	pool.AddCert(root)
	ip := x509.NewCertPool()
	ip.AddCert(inter)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: ip, CurrentTime: now}); err == nil {
		t.Fatal("crypto/x509 accepted a SHA-1 chain; the fallback is untested")
	}

	tampered := func(c *x509.Certificate) *x509.Certificate {
		d := *c
		d.Signature = append([]byte(nil), c.Signature...)
		d.Signature[len(d.Signature)/2] ^= 1
		return &d
	}
	tests := []struct {
		name    string
		o       *options.Options
		chain   []*x509.Certificate
		now     time.Time
		wantErr string
	}{
		{"rsa chain", rootOpt, []*x509.Certificate{leaf, inter}, now, ""},
		{"rsa chain, root sent too", rootOpt, []*x509.Certificate{leaf, inter, root}, now, ""},
		{"rsa chain, intermediate as anchor", &options.Options{CA: readFixture(t, "sha1-int.pem")}, []*x509.Certificate{leaf}, now, ""},
		{"ecdsa", &options.Options{CA: readFixture(t, "sha1ec-root.pem")}, []*x509.Certificate{ecLeaf}, now, ""},
		{"intermediate missing", rootOpt, []*x509.Certificate{leaf}, now, "no issuer"},
		{"tampered leaf", rootOpt, []*x509.Certificate{tampered(leaf), inter}, now, "verification"},
		{"tampered intermediate", rootOpt, []*x509.Certificate{leaf, tampered(inter)}, now, "verification"},
		{"tampered ecdsa", &options.Options{CA: readFixture(t, "sha1ec-root.pem")}, []*x509.Certificate{tampered(ecLeaf)}, now, "ECDSA-SHA1"},
		{"wrong anchor", &options.Options{CA: readFixture(t, "sha1ec-root.pem")}, []*x509.Certificate{leaf, inter}, now, "no issuer"},
		{"expired", rootOpt, []*x509.Certificate{leaf, inter}, time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC), "expired"},
		{"leaf as issuer", rootOpt, []*x509.Certificate{leaf, leaf, inter}, now, ""},
	}
	for _, tt := range tests {
		err := verifyAt(t, tt.o, tt.now, tt.chain...)
		if tt.wantErr == "" {
			if err != nil {
				t.Errorf("%s: %v", tt.name, err)
			}
			continue
		}
		if !errors.Is(err, ErrVerify) || !strings.Contains(err.Error(), tt.wantErr) {
			t.Errorf("%s: err = %v, want ErrVerify mentioning %q", tt.name, err, tt.wantErr)
		}
	}

	// Without any SHA-1 signature the fallback does not run.
	ca := newCA(t, "CA")
	other := newCA(t, "Other")
	l := issue(t, other, serverSpec("x"))
	err := verifyWith(t, caOptions(ca), l.cert)
	if err == nil || strings.Contains(err.Error(), "SHA-1") {
		t.Errorf("non-SHA-1 failure: %v", err)
	}
}

func TestSHA1BuilderLimits(t *testing.T) {
	leaf := loadFixtureCert(t, "sha1-server.pem")
	root := loadFixtureCert(t, "sha1-root.pem")
	// Many intermediates named like the real one but signed by strangers.
	var inter []*x509.Certificate
	for i := 0; i < 40; i++ {
		s := certSpec{ca: true, maxPathLen: -1, rawSubject: leaf.RawIssuer}
		inter = append(inter, issue(t, newCA(t, "stranger"), s).cert)
	}
	o := &options.Options{CA: readFixture(t, "sha1-root.pem")}
	start := time.Now()
	err := verifyAt(t, o, testNow, append([]*x509.Certificate{leaf}, inter...)...)
	if !errors.Is(err, ErrVerify) {
		t.Fatalf("err = %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v", d)
	}
	b := &sha1Builder{anchors: []*x509.Certificate{root}, inter: inter, now: testNow, budget: 3}
	if err := b.build([]*x509.Certificate{leaf}); err == nil || b.budget != 0 {
		t.Errorf("budget not enforced: err=%v budget=%d", err, b.budget)
	}
}

func TestCheckChainProperties(t *testing.T) {
	root := issue(t, nil, certSpec{cn: "root", ca: true, maxPathLen: 0})
	inter := issue(t, root, certSpec{cn: "inter", ca: true, maxPathLen: -1})
	leaf := issue(t, inter, serverSpec("leaf"))
	if err := checkChainProperties([]*x509.Certificate{leaf.cert, inter.cert, root.cert}, testNow); err == nil ||
		!strings.Contains(err.Error(), "intermediates") {
		t.Errorf("path length: %v", err)
	}
	ok := issue(t, nil, certSpec{cn: "root2", ca: true, maxPathLen: 1})
	inter2 := issue(t, ok, certSpec{cn: "inter2", ca: true, maxPathLen: -1})
	leaf2 := issue(t, inter2, serverSpec("leaf2"))
	if err := checkChainProperties([]*x509.Certificate{leaf2.cert, inter2.cert, ok.cert}, testNow); err != nil {
		t.Errorf("valid chain: %v", err)
	}
	clientOnly := issue(t, ok, certSpec{cn: "client-ca", ca: true, maxPathLen: -1, eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	leaf3 := issue(t, clientOnly, serverSpec("leaf3"))
	if err := checkChainProperties([]*x509.Certificate{leaf3.cert, clientOnly.cert, ok.cert}, testNow); err == nil {
		t.Error("intermediate restricted to clientAuth accepted")
	}
	nc := *inter2.cert
	nc.PermittedDNSDomains = []string{"example.com"}
	if err := checkChainProperties([]*x509.Certificate{leaf2.cert, &nc, ok.cert}, testNow); err == nil ||
		!strings.Contains(err.Error(), "name constraints") {
		t.Errorf("name constraints: %v", err)
	}
	crit := *leaf2.cert
	crit.UnhandledCriticalExtensions = []asn1.ObjectIdentifier{{1, 2, 3}}
	if err := checkChainProperties([]*x509.Certificate{&crit, inter2.cert, ok.cert}, testNow); err == nil {
		t.Error("unhandled critical extension accepted")
	}
	if err := checkSHA1Signature(leaf2.cert, ok.cert); err == nil {
		t.Error("ECDSA-SHA256 signature checked as SHA-1")
	}
}

func TestNetscapeCertType(t *testing.T) {
	tests := []struct {
		der  []byte
		want byte
		ok   bool
	}{
		{[]byte{0x03, 0x02, 0x06, 0x40}, 0x40, true},
		{[]byte{0x03, 0x02, 0x00, 0xff}, 0xff, true},
		{[]byte{0x03, 0x02, 0x07, 0x41}, 0x41, true}, // non-DER padding, as OpenSSL accepts
		{[]byte{0x03, 0x03, 0x07, 0x40, 0x80}, 0x40, true},
		{[]byte{0x03, 0x01, 0x00}, 0, true},
		{[]byte{0x03, 0x00}, 0, false},
		{[]byte{0x03, 0x02, 0x08, 0x40}, 0, false},
		{[]byte{0x04, 0x01, 0x40}, 0, false},
		{[]byte{0x03, 0x02, 0x06, 0x40, 0x00}, 0, false},
		{nil, 0, false},
	}
	for _, tt := range tests {
		got, err := netscapeCertType(tt.der)
		if (err == nil) != tt.ok || got != tt.want {
			t.Errorf("%x: %#x, %v", tt.der, got, err)
		}
	}
}

func TestParseCAs(t *testing.T) {
	ca := newCA(t, "A")
	cb := newCA(t, "B")
	trustedBody := append(append([]byte(nil), cb.der()...), 0x30, 0x00) // cert + empty aux
	bundle := append([]byte("junk before\n"), ca.pem()...)
	bundle = append(bundle, []byte("-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n")...)
	bundle = append(bundle, pemBlock("TRUSTED CERTIFICATE", trustedBody)...)
	certs, err := parseCAs(bundle)
	if err != nil || len(certs) != 2 || !certs[0].Equal(ca.cert) || !certs[1].Equal(cb.cert) {
		t.Fatalf("parseCAs = %d certs, %v", len(certs), err)
	}
	if _, err := parseCAs(pemBlock("TRUSTED CERTIFICATE", []byte{1, 2})); !errors.Is(err, ErrCA) {
		t.Errorf("malformed trusted certificate: %v", err)
	}
}

// FuzzVerify runs every check on arbitrary certificates crypto/x509 parses,
// as a server can send them.
func FuzzVerify(f *testing.F) {
	for _, name := range []string{"sha1-server.pem", "sha1-int.pem", "sha1ec-server.pem", "p12-int.pem"} {
		f.Add(loadFixtureCert(f, name).Raw, uint8(0))
	}
	ca := newCA(f, "CA")
	for _, spec := range leafKinds() {
		f.Add(issue(f, ca, spec).der(), uint8(1))
		f.Add(issue(f, ca, spec).der(), uint8(128|64))
	}
	anchors := []*x509.Certificate{ca.cert, loadFixtureCert(f, "sha1-root.pem")}
	crls, err := parseCRLs([]byte(crlPEM(makeCRL(f, ca, testNow.Add(-time.Hour), testNow.Add(time.Hour)))))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, der []byte, mode uint8) {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return
		}
		v := &verifier{remoteCertTLS: mode&1 != 0, nsCertType: mode&2 != 0, name: "x"}
		v.nameType = [...]string{"", "subject", "name", "name-prefix"}[mode>>2&3]
		if mode&16 != 0 {
			v.fingerprints = [][32]byte{{1}}
		}
		if mode&32 == 0 || len(v.fingerprints) == 0 {
			v.setAnchors(anchors)
		}
		if mode&128 != 0 {
			v.eku, v.kuSet, v.ku = "TLS Web Server Authentication", true, []uint16{0xa0}
			v.hashAlgo, v.hashes = "SHA1", [][]byte{make([]byte, 20)}
			v.crls = crls
		}
		chain := []*x509.Certificate{c}
		if mode&64 != 0 {
			chain = append(chain, c, anchors[1])
		}
		if err := v.verify(chain, testNow); err != nil && !errors.Is(err, ErrVerify) {
			t.Fatalf("error not wrapping ErrVerify: %v", err)
		}
	})
}
