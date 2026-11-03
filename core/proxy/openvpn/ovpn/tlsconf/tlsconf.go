// Package tlsconf builds the crypto/tls client configuration an OpenVPN
// client uses on its control channel, and checks the server certificate the
// way OpenVPN does rather than the way a browser does.
//
// OpenVPN does not check host names. It verifies the server's chain against
// --ca, then applies the optional checks: --remote-cert-tls server (extended
// key usage "TLS Web Server Authentication"; key usage, when present, must
// allow digitalSignature or keyEncipherment), --ns-cert-type server
// (Netscape cert type extension 2.16.840.1.113730.1.1 with the SSL server
// bit), --verify-x509-name (subject: the whole subject in OpenVPN's
// "C=US, ST=CA, O=Org, CN=name" form; name: the CN; name-prefix: a CN
// prefix), --crl-verify, --remote-cert-eku, --remote-cert-ku and
// --verify-hash (see checks.go for how each behaves). --peer-fingerprint
// pins the leaf's SHA-256 instead of (or besides) a CA: with fingerprints
// and no CA, a matching fingerprint is the whole chain check; with both,
// the chain must verify and the leaf must match.
//
// Old servers are common, so: TLS 1.0 is allowed unless --tls-version-min
// says otherwise; every cipher suite crypto/tls implements is offered,
// RSA key exchange included; and a chain that fails only because a
// certificate is signed with SHA-1 is verified by hand (RSA PKCS#1 v1.5 or
// ECDSA over SHA-1), since Go's x509 refuses SHA-1 outright.
//
// The client certificate comes from --cert/--key (PEM: PKCS#1, PKCS#8 or
// SEC1 keys) or --pkcs12, with --extra-certs appended to the chain. An
// encrypted key or a password-protected PKCS#12 file is decrypted with
// Options.KeyPassword: traditional PEM encryption (Proc-Type/DEK-Info: DES,
// 3DES, AES-CBC), PKCS#8 "ENCRYPTED PRIVATE KEY" (PBES2 with PBKDF2 and
// AES-CBC, 3DES or DES; the PKCS#12 3DES PBEs; PBES1 with MD5 or SHA-1 and
// DES). Without a password, or with a wrong one, Build fails and says so.
// No SNI is sent.
//
// Where OpenVPN 2.6 (with OpenSSL) behaves differently from the summary
// above, this package follows OpenVPN, as observed against the real binary:
//
//   - With a CA, the leaf must also pass OpenSSL's "SSL server" purpose
//     check even without any option: an extended key usage, if present,
//     must include TLS Web Server Authentication (or Server Gated Crypto);
//     a Netscape cert type, if present, must include SSL server; a key
//     usage, if present, must allow digitalSignature, keyEncipherment or
//     keyAgreement. Intermediates with an extended key usage must allow
//     server authentication too. A client certificate from the same CA
//     therefore cannot pose as the server.
//   - --remote-cert-tls server requires the key usage extension to be
//     present (and to allow one of those three usages).
//   - --ns-cert-type server is that same SSL server purpose check: a
//     certificate without the Netscape extension passes when its extended
//     key usage allows server authentication or is absent.
//   - With fingerprints and no CA, nothing else about the chain is checked:
//     not validity dates, not the purpose. The explicit options
//     (--remote-cert-tls, --ns-cert-type, --verify-x509-name) still apply.
//   - --verify-x509-name name and name-prefix compare the last CN in the
//     subject, converted to UTF-8, with control characters replaced by '_'.
//     The subject form escapes control characters as \XX and a backslash
//     as \\, joins the attributes of a multi-valued RDN with " + ", and
//     names attributes by OpenSSL's short names (unknown ones by OID).
//
// The Config that Build returns reads its own Time field, when set, as the
// clock for certificate validity; clones made from it share that clock
// rather than their own copy of the field.
package tlsconf

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/options"
)

var (
	ErrNoTrust   = errors.New("tlsconf: no ca and no peer-fingerprint to verify the server with")
	ErrVerify    = errors.New("tlsconf: server certificate rejected")
	ErrClientKey = errors.New("tlsconf: unusable client certificate or key")
	// ErrCA reports a --ca that is not PEM or holds no usable certificate.
	ErrCA = errors.New("tlsconf: unusable ca")
	// ErrCRL reports a --crl-verify that holds no usable PEM CRL.
	ErrCRL = errors.New("tlsconf: unusable crl-verify")
)

// Build returns the TLS client configuration for o. The returned config
// verifies the server itself (InsecureSkipVerify with VerifyConnection), so
// callers must not replace those fields.
func Build(o *options.Options) (*tls.Config, error) {
	if o == nil {
		return nil, errors.New("tlsconf: nil options")
	}
	minV, maxV, err := tlsVersions(o.TLSVersionMin, o.TLSVersionMax)
	if err != nil {
		return nil, err
	}
	v, err := newVerifier(o)
	if err != nil {
		return nil, err
	}
	client, p12CAs, err := loadClientCert(o)
	if err != nil {
		return nil, err
	}
	var anchors []*x509.Certificate
	if len(o.CA) > 0 {
		if anchors, err = parseCAs(o.CA); err != nil {
			return nil, err
		}
	} else {
		// Like OpenVPN: without --ca, the CA certificates bundled in the
		// PKCS#12 file are the trust anchors.
		anchors = p12CAs
	}
	if len(anchors) == 0 && len(v.fingerprints) == 0 {
		return nil, ErrNoTrust
	}
	v.setAnchors(anchors)

	cfg := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         minV,
		MaxVersion:         maxV,
		CipherSuites:       cipherSuites(),
	}
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		now := time.Now
		if cfg.Time != nil {
			now = cfg.Time
		}
		return v.verify(cs.PeerCertificates, now())
	}
	if client != nil {
		cfg.Certificates = []tls.Certificate{*client}
		// crypto/tls would send nothing when the chain does not match the
		// server's acceptable CA list; OpenSSL, and so OpenVPN, always
		// sends the configured certificate.
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return client, nil
		}
	}
	return cfg, nil
}

// tlsVersions maps --tls-version-min/--tls-version-max to crypto/tls
// versions. The minimum defaults to TLS 1.0; a trailing "or-highest" is
// accepted and changes nothing, since every version OpenVPN names is
// implemented. A zero maximum means "no maximum".
func tlsVersions(minS, maxS string) (minV, maxV uint16, err error) {
	minV, err = tlsVersion("tls-version-min", minS, true)
	if err != nil {
		return 0, 0, err
	}
	if minV == 0 {
		minV = tls.VersionTLS10
	}
	maxV, err = tlsVersion("tls-version-max", maxS, false)
	if err != nil {
		return 0, 0, err
	}
	if maxV != 0 && maxV < minV {
		return 0, 0, fmt.Errorf("tlsconf: tls-version-max %s is below tls-version-min %s", maxS, minS)
	}
	return minV, maxV, nil
}

func tlsVersion(name, s string, orHighest bool) (uint16, error) {
	f := strings.Fields(s)
	if len(f) == 0 {
		return 0, nil
	}
	if len(f) > 2 || len(f) == 2 && (!orHighest || f[1] != "or-highest") {
		return 0, fmt.Errorf("tlsconf: bad %s %q", name, s)
	}
	switch f[0] {
	case "1.0":
		return tls.VersionTLS10, nil
	case "1.1":
		return tls.VersionTLS11, nil
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	}
	return 0, fmt.Errorf("tlsconf: unknown %s %q", name, s)
}

// cipherSuites lists every TLS 1.0-1.2 suite crypto/tls implements except
// RC4: the secure ones, RSA key exchange (old servers without ECDHE), the
// CBC-SHA256 suites and 3DES. 3DES is kept as a last resort: crypto/tls
// orders it after every AES and ChaCha20 suite, so a server picks it only
// when it shares nothing better, and the control channel carries far too
// little data under one key for 64-bit-block attacks (Sweet32) to matter.
// TLS 1.3 suites are not configurable and always offered.
func cipherSuites() []uint16 {
	var ids []uint16
	for _, s := range tls.CipherSuites() {
		ids = append(ids, s.ID)
	}
	for _, s := range tls.InsecureCipherSuites() {
		if strings.Contains(s.Name, "_RC4_") {
			continue
		}
		ids = append(ids, s.ID)
	}
	return ids
}
