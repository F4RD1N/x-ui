package tlsconf

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/options"
)

func TestBuildConfigShape(t *testing.T) {
	ca := newCA(t, "CA")
	cfg := mustBuild(t, caOptions(ca))
	if !cfg.InsecureSkipVerify || cfg.VerifyConnection == nil {
		t.Fatal("the config must verify the server itself")
	}
	if cfg.ServerName != "" {
		t.Errorf("ServerName = %q, want none (no SNI)", cfg.ServerName)
	}
	if cfg.MinVersion != tls.VersionTLS10 || cfg.MaxVersion != 0 {
		t.Errorf("versions = %x..%x, want TLS 1.0..unlimited", cfg.MinVersion, cfg.MaxVersion)
	}
	if len(cfg.Certificates) != 0 || cfg.GetClientCertificate != nil {
		t.Error("client certificate configured without --cert/--pkcs12")
	}
	for _, id := range []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_AES_256_CBC_SHA, tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	} {
		if !slices.Contains(cfg.CipherSuites, id) {
			t.Errorf("cipher suite %s not offered", tls.CipherSuiteName(id))
		}
	}
	for _, id := range cfg.CipherSuites {
		if strings.Contains(tls.CipherSuiteName(id), "RC4") {
			t.Errorf("RC4 suite %s offered", tls.CipherSuiteName(id))
		}
	}
}

func TestTLSVersions(t *testing.T) {
	tests := []struct {
		min, max   string
		wantMin    uint16
		wantMax    uint16
		wantErrSub string
	}{
		{"", "", tls.VersionTLS10, 0, ""},
		{"1.0", "", tls.VersionTLS10, 0, ""},
		{"1.1", "1.2", tls.VersionTLS11, tls.VersionTLS12, ""},
		{"1.2", "", tls.VersionTLS12, 0, ""},
		{"1.2 or-highest", "1.3", tls.VersionTLS12, tls.VersionTLS13, ""},
		{"1.3", "", tls.VersionTLS13, 0, ""},
		{"", "1.2", tls.VersionTLS10, tls.VersionTLS12, ""},
		{"1.3", "1.2", 0, 0, "below"},
		{"1.4", "", 0, 0, "unknown tls-version-min"},
		{"", "2", 0, 0, "unknown tls-version-max"},
		{"1.2 sometimes", "", 0, 0, "bad tls-version-min"},
		{"", "1.2 or-highest", 0, 0, "bad tls-version-max"},
	}
	for _, tt := range tests {
		minV, maxV, err := tlsVersions(tt.min, tt.max)
		if tt.wantErrSub != "" {
			if err == nil || !strings.Contains(err.Error(), tt.wantErrSub) {
				t.Errorf("(%q, %q): err = %v, want %q", tt.min, tt.max, err, tt.wantErrSub)
			}
			continue
		}
		if err != nil || minV != tt.wantMin || maxV != tt.wantMax {
			t.Errorf("(%q, %q) = %x, %x, %v; want %x, %x", tt.min, tt.max, minV, maxV, err, tt.wantMin, tt.wantMax)
		}
	}
}

func TestBuildErrors(t *testing.T) {
	ca := newCA(t, "CA")
	leaf := issue(t, ca, certSpec{cn: "client", eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	keyDER, _ := x509.MarshalPKCS8PrivateKey(leaf.key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	otherDER, _ := x509.MarshalPKCS8PrivateKey(newECKey(t))
	otherPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: otherDER})

	withCA := func(f func(o *options.Options)) *options.Options {
		o := caOptions(ca)
		f(o)
		return o
	}
	tests := []struct {
		name    string
		o       *options.Options
		wantIs  error
		wantSub string
	}{
		{"nil", nil, nil, "nil options"},
		{"no trust", &options.Options{}, ErrNoTrust, ""},
		{"garbage ca", &options.Options{CA: []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")}, ErrCA, ""},
		{"ca without certs", &options.Options{CA: []byte("not pem at all")}, ErrCA, ""},
		{"remote-cert-tls client", withCA(func(o *options.Options) { o.RemoteCertTLS = "client" }), nil, "remote-cert-tls"},
		{"ns-cert-type client", withCA(func(o *options.Options) { o.NsCertType = "client" }), nil, "ns-cert-type"},
		{"bad x509 type", withCA(func(o *options.Options) { o.VerifyX509Name = "x"; o.VerifyX509Type = "ou" }), nil, "verify-x509-name type"},
		{"bad version", withCA(func(o *options.Options) { o.TLSVersionMin = "0.9" }), nil, "tls-version-min"},
		{"cert without key", withCA(func(o *options.Options) { o.Cert = leaf.pem() }), ErrClientKey, "--cert without --key"},
		{"key without cert", withCA(func(o *options.Options) { o.Key = keyPEM }), ErrClientKey, "--key without --cert"},
		{"mismatched key", withCA(func(o *options.Options) { o.Cert, o.Key = leaf.pem(), otherPEM }), ErrClientKey, "does not belong"},
		{"encrypted pkcs8", withCA(func(o *options.Options) { o.Cert, o.Key = leaf.pem(), readFixture(t, "enc-pkcs8.key") }), ErrClientKey, "encrypted"},
		{"encrypted pkcs1", withCA(func(o *options.Options) { o.Cert, o.Key = leaf.pem(), readFixture(t, "enc-pkcs1.key") }), ErrClientKey, "encrypted"},
		{"key not pem", withCA(func(o *options.Options) { o.Cert, o.Key = leaf.pem(), []byte("junk") }), ErrClientKey, "no private key"},
		{"cert not pem", withCA(func(o *options.Options) { o.Cert, o.Key = []byte("junk"), keyPEM }), ErrClientKey, "no certificate"},
		{"pkcs12 and cert", withCA(func(o *options.Options) {
			o.Cert, o.Key, o.PKCS12 = leaf.pem(), keyPEM, readFixture(t, "client-modern.p12")
		}), ErrClientKey, "cannot be combined"},
		{"extra-certs alone", withCA(func(o *options.Options) { o.ExtraCerts = ca.pem() }), ErrClientKey, "without a client certificate"},
		{"bad extra-certs", withCA(func(o *options.Options) {
			o.Cert, o.Key, o.ExtraCerts = leaf.pem(), keyPEM, []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
		}), ErrClientKey, "--extra-certs"},
		{"pkcs12 garbage", withCA(func(o *options.Options) { o.PKCS12 = []byte{0x30, 0x03, 0x02, 0x01, 0x03} }), ErrClientKey, "--pkcs12"},
		{"pkcs12 password", withCA(func(o *options.Options) { o.PKCS12 = readFixture(t, "client-password.p12") }), ErrClientKey, "password"},
		{"pkcs12 legacy password", withCA(func(o *options.Options) { o.PKCS12 = readFixture(t, "client-password-legacy.p12") }), ErrClientKey, "password"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Build(tt.o)
			if err == nil {
				t.Fatalf("Build succeeded: %+v", cfg)
			}
			if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
				t.Errorf("err = %v, want %v", err, tt.wantIs)
			}
			if tt.wantSub != "" && !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("err = %v, want it to mention %q", err, tt.wantSub)
			}
		})
	}
}

func TestHandshakeVersions(t *testing.T) {
	ca := newCA(t, "CA")
	rsaSpec := serverSpec("rsa-server")
	rsaSpec.key = sharedRSAKey(t)
	rsaLeaf := issue(t, ca, rsaSpec)
	ecLeaf := issue(t, ca, serverSpec("ec-server"))
	client := mustBuild(t, caOptions(ca))
	for _, leaf := range []*testCert{rsaLeaf, ecLeaf} {
		for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13} {
			t.Run(leaf.cert.Subject.CommonName+"/"+tls.VersionName(v), func(t *testing.T) {
				srv := serverConfig(leaf)
				srv.MinVersion, srv.MaxVersion = v, v
				r := handshake(t, client, srv)
				if r.clientErr != nil || r.serverErr != nil {
					t.Fatalf("client: %v; server: %v", r.clientErr, r.serverErr)
				}
				if r.state.Version != v {
					t.Errorf("negotiated %s", tls.VersionName(r.state.Version))
				}
				if r.sni != "" {
					t.Errorf("client sent SNI %q", r.sni)
				}
			})
		}
	}
}

func TestHandshakeCipherSuites(t *testing.T) {
	ca := newCA(t, "CA")
	spec := serverSpec("rsa-server")
	spec.key = sharedRSAKey(t)
	leaf := issue(t, ca, spec)
	client := mustBuild(t, caOptions(ca))
	tests := []struct {
		suite   uint16
		version uint16
		ok      bool
	}{
		{tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.VersionTLS10, true},
		{tls.TLS_RSA_WITH_AES_256_CBC_SHA, tls.VersionTLS12, true},
		{tls.TLS_RSA_WITH_AES_128_GCM_SHA256, tls.VersionTLS12, true},
		{tls.TLS_RSA_WITH_AES_256_GCM_SHA384, tls.VersionTLS12, true},
		{tls.TLS_RSA_WITH_AES_128_CBC_SHA256, tls.VersionTLS12, true},
		{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, tls.VersionTLS12, true},
		{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, tls.VersionTLS12, true},
		{tls.TLS_RSA_WITH_RC4_128_SHA, tls.VersionTLS12, false},
	}
	for _, tt := range tests {
		t.Run(tls.CipherSuiteName(tt.suite), func(t *testing.T) {
			srv := serverConfig(leaf)
			srv.CipherSuites = []uint16{tt.suite}
			srv.MinVersion, srv.MaxVersion = tt.version, tt.version
			r := handshake(t, client, srv)
			if !tt.ok {
				if r.clientErr == nil {
					t.Fatal("handshake succeeded with a suite that must not be offered")
				}
				return
			}
			if r.clientErr != nil || r.serverErr != nil {
				t.Fatalf("client: %v; server: %v", r.clientErr, r.serverErr)
			}
			if r.state.CipherSuite != tt.suite {
				t.Errorf("negotiated %s", tls.CipherSuiteName(r.state.CipherSuite))
			}
		})
	}
}

func TestHandshakeVersionLimits(t *testing.T) {
	ca := newCA(t, "CA")
	leaf := issue(t, ca, serverSpec("server"))
	tests := []struct {
		name       string
		min, max   string
		srvMin     uint16
		srvMax     uint16
		want       uint16 // 0: must fail
		wantClient bool   // failure is the client's (no shared version)
	}{
		{"min 1.2 vs 1.0 server", "1.2", "", tls.VersionTLS10, tls.VersionTLS10, 0, true},
		{"min 1.2 vs modern server", "1.2", "", tls.VersionTLS10, tls.VersionTLS13, tls.VersionTLS13, false},
		{"max 1.2 vs modern server", "", "1.2", tls.VersionTLS10, tls.VersionTLS13, tls.VersionTLS12, false},
		{"max 1.2 vs 1.3-only server", "", "1.2", tls.VersionTLS13, tls.VersionTLS13, 0, true},
		{"max 1.0", "", "1.0", tls.VersionTLS10, tls.VersionTLS13, tls.VersionTLS10, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := caOptions(ca)
			o.TLSVersionMin, o.TLSVersionMax = tt.min, tt.max
			srv := serverConfig(leaf)
			srv.MinVersion, srv.MaxVersion = tt.srvMin, tt.srvMax
			r := handshake(t, mustBuild(t, o), srv)
			if tt.want == 0 {
				if r.clientErr == nil {
					t.Fatalf("handshake succeeded with %s", tls.VersionName(r.state.Version))
				}
				return
			}
			if r.clientErr != nil || r.serverErr != nil {
				t.Fatalf("client: %v; server: %v", r.clientErr, r.serverErr)
			}
			if r.state.Version != tt.want {
				t.Errorf("negotiated %s, want %s", tls.VersionName(r.state.Version), tls.VersionName(tt.want))
			}
		})
	}
}

func TestHandshakeServerChecks(t *testing.T) {
	root := newCA(t, "Root")
	inter := issue(t, root, certSpec{cn: "Intermediate", ca: true, maxPathLen: -1})
	other := newCA(t, "Other")
	leaf := issue(t, inter, serverSpec("server"))
	direct := issue(t, root, serverSpec("direct"))
	clientCert := issue(t, root, certSpec{cn: "a-client", eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ku: x509.KeyUsageDigitalSignature})
	expired := issue(t, root, func() certSpec {
		s := serverSpec("expired")
		s.notBefore, s.notAfter = testNow.Add(-48*time.Hour), testNow.Add(-24*time.Hour)
		return s
	}())

	tests := []struct {
		name    string
		o       *options.Options
		srv     *tls.Config
		time    time.Time
		wantErr string // "" = success
	}{
		{"intermediate sent", caOptions(root), serverConfig(leaf, inter), time.Time{}, ""},
		{"intermediate missing", caOptions(root), serverConfig(leaf), time.Time{}, "chain to --ca"},
		{"intermediate as ca", caOptions(inter), serverConfig(leaf), time.Time{}, ""},
		{"ca bundle", caOptions(other, root), serverConfig(leaf, inter), time.Time{}, ""},
		{"wrong ca", caOptions(other), serverConfig(leaf, inter), time.Time{}, "chain to --ca"},
		{"expired", caOptions(root), serverConfig(expired), time.Time{}, "chain to --ca"},
		{"expired at injected time", caOptions(root), serverConfig(direct), testNow.Add(48 * time.Hour), "chain to --ca"},
		{"not yet valid at injected time", caOptions(root), serverConfig(direct), testNow.Add(-48 * time.Hour), "chain to --ca"},
		{"valid at injected time", caOptions(root), serverConfig(direct), testNow.Add(time.Hour), ""},
		{"client cert posing as server", caOptions(root), serverConfig(clientCert), time.Time{}, "not a TLS server certificate"},
		{"pinned client cert, no ca", &options.Options{PeerFingerprints: [][32]byte{clientCert.fingerprint()}},
			serverConfig(clientCert), time.Time{}, ""},
		{"pinned expired cert, no ca", &options.Options{PeerFingerprints: [][32]byte{expired.fingerprint()}},
			serverConfig(expired), time.Time{}, ""},
		{"wrong pin, no ca", &options.Options{PeerFingerprints: [][32]byte{direct.fingerprint()}},
			serverConfig(leaf, inter), time.Time{}, "peer-fingerprint"},
		{"pin and ca", func() *options.Options {
			o := caOptions(root)
			o.PeerFingerprints = [][32]byte{{1}, leaf.fingerprint()}
			return o
		}(), serverConfig(leaf, inter), time.Time{}, ""},
		{"pin matches, ca does not", func() *options.Options {
			o := caOptions(other)
			o.PeerFingerprints = [][32]byte{leaf.fingerprint()}
			return o
		}(), serverConfig(leaf, inter), time.Time{}, "chain to --ca"},
		{"remote-cert-tls", func() *options.Options {
			o := caOptions(root)
			o.RemoteCertTLS = "server"
			o.VerifyX509Name, o.VerifyX509Type = "CN=server", "subject"
			return o
		}(), serverConfig(leaf, inter), time.Time{}, ""},
		{"verify-x509-name mismatch", func() *options.Options {
			o := caOptions(root)
			o.VerifyX509Name, o.VerifyX509Type = "serv", "name"
			return o
		}(), serverConfig(leaf, inter), time.Time{}, "verify-x509-name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := mustBuild(t, tt.o)
			if !tt.time.IsZero() {
				cfg.Time = func() time.Time { return tt.time }
			}
			for _, v := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
				srv := tt.srv.Clone()
				srv.MaxVersion = v
				r := handshake(t, cfg, srv)
				if tt.wantErr == "" {
					if r.clientErr != nil || r.serverErr != nil {
						t.Fatalf("%s: client: %v; server: %v", tls.VersionName(v), r.clientErr, r.serverErr)
					}
					continue
				}
				if !errors.Is(r.clientErr, ErrVerify) || !strings.Contains(r.clientErr.Error(), tt.wantErr) {
					t.Fatalf("%s: client err = %v, want ErrVerify mentioning %q", tls.VersionName(v), r.clientErr, tt.wantErr)
				}
				if r.serverErr == nil {
					t.Errorf("%s: server did not see the rejection", tls.VersionName(v))
				}
			}
		})
	}
}

func TestHandshakeSHA1Chains(t *testing.T) {
	rsaLeaf := tls.Certificate{
		Certificate: [][]byte{loadFixtureCert(t, "sha1-server.pem").Raw, loadFixtureCert(t, "sha1-int.pem").Raw},
		PrivateKey:  loadFixtureKey(t, "sha1-server.key"),
	}
	ecLeaf := tls.Certificate{
		Certificate: [][]byte{loadFixtureCert(t, "sha1ec-server.pem").Raw},
		PrivateKey:  loadFixtureKey(t, "sha1ec-server.key"),
	}
	tests := []struct {
		name    string
		ca      string
		leaf    tls.Certificate
		mod     func(o *options.Options)
		time    time.Time
		wantErr string
	}{
		{"rsa via intermediate", "sha1-root.pem", rsaLeaf, nil, time.Time{}, ""},
		{"rsa, intermediate as ca", "sha1-int.pem", rsaLeaf, nil, time.Time{}, ""},
		{"rsa with checks", "sha1-root.pem", rsaLeaf, func(o *options.Options) {
			o.RemoteCertTLS = "server"
			o.VerifyX509Name, o.VerifyX509Type = "C=US, O=Test, CN=sha1-server", "subject"
		}, time.Time{}, ""},
		{"ecdsa", "sha1ec-root.pem", ecLeaf, nil, time.Time{}, ""},
		{"wrong root", "sha1ec-root.pem", rsaLeaf, nil, time.Time{}, "chain to --ca"},
		{"rsa after expiry", "sha1-root.pem", rsaLeaf, nil, time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC), "expired"},
		{"ecdsa before validity", "sha1ec-root.pem", ecLeaf, nil, time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC), "not valid before"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &options.Options{CA: readFixture(t, tt.ca)}
			if tt.mod != nil {
				tt.mod(o)
			}
			cfg := mustBuild(t, o)
			if !tt.time.IsZero() {
				cfg.Time = func() time.Time { return tt.time }
			}
			for _, v := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
				srv := &tls.Config{Certificates: []tls.Certificate{tt.leaf}, MaxVersion: v}
				r := handshake(t, cfg, srv)
				if tt.wantErr == "" {
					if r.clientErr != nil || r.serverErr != nil {
						t.Fatalf("%s: client: %v; server: %v", tls.VersionName(v), r.clientErr, r.serverErr)
					}
					continue
				}
				if !errors.Is(r.clientErr, ErrVerify) || !strings.Contains(r.clientErr.Error(), tt.wantErr) {
					t.Fatalf("%s: client err = %v, want ErrVerify mentioning %q", tls.VersionName(v), r.clientErr, tt.wantErr)
				}
			}
		})
	}
}

func TestHandshakeClientCertificates(t *testing.T) {
	root := newCA(t, "Root")
	inter := issue(t, root, certSpec{cn: "Intermediate", ca: true, maxPathLen: -1})
	server := issue(t, root, serverSpec("server"))
	clientSpec := func(cn string) certSpec {
		return certSpec{cn: cn, eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, ku: x509.KeyUsageDigitalSignature}
	}
	keyPEM := func(typ string, der []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}) }

	rsaSpec := clientSpec("rsa-client")
	rsaSpec.key = sharedRSAKey(t)
	rsaClient := issue(t, root, rsaSpec)
	ecClient := issue(t, root, clientSpec("ec-client"))
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	edSpec := clientSpec("ed-client")
	edSpec.key = edPriv
	edClient := issue(t, root, edSpec)
	chained := issue(t, inter, clientSpec("chained-client"))

	pkcs8 := func(c *testCert) []byte {
		der, err := x509.MarshalPKCS8PrivateKey(c.key)
		if err != nil {
			t.Fatal(err)
		}
		return keyPEM("PRIVATE KEY", der)
	}

	tests := []struct {
		name       string
		cert, key  []byte
		extra      []byte
		clientAuth tls.ClientAuthType
		clientCAs  []*testCert
		wantErr    bool
	}{
		{"rsa pkcs1", rsaClient.pem(), keyPEM("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(sharedRSAKey(t))),
			nil, tls.RequireAndVerifyClientCert, []*testCert{root}, false},
		{"rsa pkcs8", rsaClient.pem(), pkcs8(rsaClient), nil, tls.RequireAndVerifyClientCert, []*testCert{root}, false},
		{"ec sec1 with parameters block", ecClient.pem(), append([]byte("-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n"),
			ecSEC1PEM(t, ecClient)...), nil, tls.RequireAndVerifyClientCert, []*testCert{root}, false},
		{"ec pkcs8", ecClient.pem(), pkcs8(ecClient), nil, tls.RequireAndVerifyClientCert, []*testCert{root}, false},
		{"ed25519 pkcs8", edClient.pem(), pkcs8(edClient), nil, tls.RequireAndVerifyClientCert, []*testCert{root}, false},
		{"chain in --cert", append(chained.pem(), inter.pem()...), pkcs8(chained), nil,
			tls.RequireAndVerifyClientCert, []*testCert{root}, false},
		{"chain in --extra-certs", chained.pem(), pkcs8(chained), inter.pem(),
			tls.RequireAndVerifyClientCert, []*testCert{root}, false},
		{"chain missing", chained.pem(), pkcs8(chained), nil, tls.RequireAndVerifyClientCert, []*testCert{root}, true},
		// The server names a CA we are not under: OpenSSL clients send their
		// certificate anyway, and so must we.
		{"sent despite the CA list", ecClient.pem(), pkcs8(ecClient), nil, tls.RequireAnyClientCert,
			[]*testCert{newCA(t, "Unrelated")}, false},
		{"no client cert, optional", nil, nil, nil, tls.VerifyClientCertIfGiven, []*testCert{root}, false},
		{"no client cert, required", nil, nil, nil, tls.RequireAndVerifyClientCert, []*testCert{root}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := caOptions(root)
			o.Cert, o.Key, o.ExtraCerts = tt.cert, tt.key, tt.extra
			cfg := mustBuild(t, o)
			for _, v := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
				srv := serverConfig(server)
				srv.MaxVersion = v
				srv.ClientAuth = tt.clientAuth
				srv.ClientCAs = x509.NewCertPool()
				for _, c := range tt.clientCAs {
					srv.ClientCAs.AddCert(c.cert)
				}
				r := handshake(t, cfg, srv)
				if tt.wantErr {
					if r.serverErr == nil {
						t.Fatalf("%s: server accepted", tls.VersionName(v))
					}
					continue
				}
				if r.clientErr != nil || r.serverErr != nil {
					t.Fatalf("%s: client: %v; server: %v", tls.VersionName(v), r.clientErr, r.serverErr)
				}
			}
		})
	}
}

func ecSEC1PEM(t *testing.T, c *testCert) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(c.key.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}
