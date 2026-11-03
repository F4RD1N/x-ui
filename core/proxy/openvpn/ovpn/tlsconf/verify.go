package tlsconf

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/options"
)

var (
	oidKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtKeyUsage      = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidNetscapeCertType = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 1}
)

// nsSSLServer is the SSL server bit of the Netscape cert type BIT STRING
// (bit 1, counted from the most significant bit of the first byte).
const nsSSLServer = 0x40

// Limits on the hand-built SHA-1 chain search, so a server sending many
// look-alike certificates cannot make it explode.
const (
	maxChainLen       = 8
	maxIntermediates  = 16
	maxSignatureCheck = 64
)

// verifier holds what is needed to check a server certificate chain.
type verifier struct {
	anchors      []*x509.Certificate // --ca (or the PKCS#12 CAs)
	roots        *x509.CertPool      // anchors as a pool; nil without a CA
	fingerprints [][32]byte

	remoteCertTLS bool
	nsCertType    bool
	nameType      string // "" (no check), "subject", "name", "name-prefix"
	name          string

	crls     []*crl   // --crl-verify
	eku      string   // --remote-cert-eku, "" for none
	kuSet    bool     // --remote-cert-ku given
	ku       []uint16 // its values, OpenSSL bit order
	hashAlgo string   // --verify-hash: "SHA1" or "SHA256", "" for none
	hashes   [][]byte
}

func newVerifier(o *options.Options) (*verifier, error) {
	v := &verifier{fingerprints: o.PeerFingerprints}
	if err := v.setServerChecks(o); err != nil {
		return nil, err
	}
	switch o.RemoteCertTLS {
	case "":
	case "server":
		v.remoteCertTLS = true
	default:
		return nil, fmt.Errorf("tlsconf: remote-cert-tls %q: only \"server\" makes sense for a client", o.RemoteCertTLS)
	}
	switch o.NsCertType {
	case "":
	case "server":
		v.nsCertType = true
	default:
		return nil, fmt.Errorf("tlsconf: ns-cert-type %q: only \"server\" makes sense for a client", o.NsCertType)
	}
	if o.VerifyX509Name != "" {
		switch o.VerifyX509Type {
		case "", "subject":
			v.nameType = "subject"
		case "name", "name-prefix":
			v.nameType = o.VerifyX509Type
		default:
			return nil, fmt.Errorf("tlsconf: unknown verify-x509-name type %q", o.VerifyX509Type)
		}
		v.name = o.VerifyX509Name
	}
	return v, nil
}

func (v *verifier) setAnchors(anchors []*x509.Certificate) {
	v.anchors = anchors
	v.roots = nil
	if len(anchors) > 0 {
		v.roots = x509.NewCertPool()
		for _, c := range anchors {
			v.roots.AddCert(c)
		}
	}
}

// verify checks the chain the server presented (leaf first) at time now.
// Every error wraps ErrVerify and names the check that failed.
func (v *verifier) verify(certs []*x509.Certificate, now time.Time) error {
	if len(certs) == 0 || certs[0] == nil {
		return fmt.Errorf("%w: the server sent no certificate", ErrVerify)
	}
	leaf := certs[0]
	// chains are the verified chains (leaf first, anchor last), or without
	// a CA what the server sent.
	var chains [][]*x509.Certificate
	switch {
	case v.roots != nil:
		if err := sslServerPurpose(leaf); err != nil {
			return fmt.Errorf("%w: not a TLS server certificate: %v", ErrVerify, err)
		}
		var err error
		if chains, err = v.verifyChain(certs, now); err != nil {
			return fmt.Errorf("%w: chain to --ca: %w", ErrVerify, err)
		}
	case len(v.fingerprints) == 0:
		return fmt.Errorf("%w: nothing to verify the server with", ErrVerify)
	default:
		var sent []*x509.Certificate
		for _, c := range certs {
			if c != nil {
				sent = append(sent, c)
			}
		}
		chains = [][]*x509.Certificate{sent}
	}
	if len(v.fingerprints) > 0 {
		sum := sha256.Sum256(leaf.Raw)
		ok := false
		for _, f := range v.fingerprints {
			if f == sum {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("%w: peer-fingerprint: the server certificate's SHA-256 %s matches none of the pinned fingerprints",
				ErrVerify, colonHex(sum[:]))
		}
	}
	if v.remoteCertTLS {
		if err := remoteCertTLSServer(leaf); err != nil {
			return fmt.Errorf("%w: remote-cert-tls server: %v", ErrVerify, err)
		}
	}
	if v.nsCertType {
		if err := sslServerPurpose(leaf); err != nil {
			return fmt.Errorf("%w: ns-cert-type server: %v", ErrVerify, err)
		}
	}
	if v.nameType != "" {
		if err := v.checkName(leaf); err != nil {
			return fmt.Errorf("%w: verify-x509-name: %v", ErrVerify, err)
		}
	}
	if v.eku != "" {
		if err := checkEKU(leaf, v.eku); err != nil {
			return fmt.Errorf("%w: remote-cert-eku: %v", ErrVerify, err)
		}
	}
	if v.kuSet {
		if err := checkKU(leaf, v.ku); err != nil {
			return fmt.Errorf("%w: remote-cert-ku: %v", ErrVerify, err)
		}
	}
	if len(v.crls) > 0 || v.hashAlgo != "" {
		// One chain must pass the checks that depend on the chain.
		var firstErr error
		for _, chain := range chains {
			err := v.checkChain(chain, now)
			if err == nil {
				return nil
			}
			if firstErr == nil {
				firstErr = err
			}
		}
		return fmt.Errorf("%w: %v", ErrVerify, firstErr)
	}
	return nil
}

func (v *verifier) checkName(leaf *x509.Certificate) error {
	if v.nameType == "subject" {
		s, err := subjectString(leaf.RawSubject)
		if err != nil {
			return fmt.Errorf("cannot print the subject: %v", err)
		}
		if s != v.name {
			return fmt.Errorf("subject %q is not %q", s, v.name)
		}
		return nil
	}
	cn, ok, err := commonName(leaf.RawSubject)
	switch {
	case err != nil:
		return fmt.Errorf("cannot read the CN: %v", err)
	case !ok:
		return fmt.Errorf("the certificate has no CN, %q wanted", v.name)
	case v.nameType == "name" && cn != v.name:
		return fmt.Errorf("CN %q is not %q", cn, v.name)
	case v.nameType == "name-prefix" && !strings.HasPrefix(cn, v.name):
		return fmt.Errorf("CN %q does not start with %q", cn, v.name)
	}
	return nil
}

// verifyChain verifies certs[0] up to an anchor, using certs[1:] as
// intermediates, and returns the chains found (leaf first). Host names are
// never checked. Intermediates (and the anchor) with an extended key usage
// must allow server authentication, as with OpenSSL's SSL server purpose.
func (v *verifier) verifyChain(certs []*x509.Certificate, now time.Time) ([][]*x509.Certificate, error) {
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		if c != nil {
			inter.AddCert(c)
		}
	}
	chains, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: inter,
		CurrentTime:   now,
		// Any of these through the whole chain, as OpenSSL's SSL server
		// purpose accepts Server Gated Crypto in place of serverAuth.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageNetscapeServerGatedCrypto, x509.ExtKeyUsageMicrosoftServerGatedCrypto},
	})
	if err == nil {
		return chains, nil
	}
	if !hasSHA1Signature(certs) {
		return nil, err
	}
	// Go refuses SHA-1 signatures outright. Retry with a chain built by
	// hand that accepts them and checks everything else.
	b := &sha1Builder{anchors: v.anchors, now: now, budget: maxSignatureCheck}
	for _, c := range certs[1:] {
		if c != nil && len(b.inter) < maxIntermediates {
			b.inter = append(b.inter, c)
		}
	}
	if ferr := b.build([]*x509.Certificate{certs[0]}); ferr != nil {
		return nil, fmt.Errorf("%w; allowing SHA-1 signatures: %v", err, ferr)
	}
	return [][]*x509.Certificate{b.chain}, nil
}

func isSHA1(a x509.SignatureAlgorithm) bool {
	return a == x509.SHA1WithRSA || a == x509.ECDSAWithSHA1
}

func hasSHA1Signature(certs []*x509.Certificate) bool {
	for _, c := range certs {
		if c != nil && isSHA1(c.SignatureAlgorithm) {
			return true
		}
	}
	return false
}

// sha1Builder searches for a chain from a leaf to an anchor in which SHA-1
// signatures are verified by hand. Every other check crypto/x509 would make
// on the chain is made here too or makes the search fail (name constraints).
type sha1Builder struct {
	anchors []*x509.Certificate
	inter   []*x509.Certificate
	now     time.Time
	budget  int                 // signature checks left
	chain   []*x509.Certificate // the chain found, leaf to anchor
}

var errNoIssuer = errors.New("no issuer found among the intermediates and --ca")

func (b *sha1Builder) build(chain []*x509.Certificate) error {
	child := chain[len(chain)-1]
	lastErr := errNoIssuer
	for _, a := range b.anchors {
		if !bytes.Equal(child.RawIssuer, a.RawSubject) {
			continue
		}
		if err := b.link(child, a); err != nil {
			lastErr = err
			continue
		}
		full := append(chain[:len(chain):len(chain)], a)
		if err := checkChainProperties(full, b.now); err != nil {
			lastErr = err
			continue
		}
		b.chain = full
		return nil
	}
	if len(chain) >= maxChainLen-1 {
		return lastErr
	}
	for _, c := range b.inter {
		if !bytes.Equal(child.RawIssuer, c.RawSubject) || inChain(chain, c) {
			continue
		}
		if err := b.link(child, c); err != nil {
			lastErr = err
			continue
		}
		if err := b.build(append(chain[:len(chain):len(chain)], c)); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	return lastErr
}

func inChain(chain []*x509.Certificate, c *x509.Certificate) bool {
	for _, x := range chain {
		if x.Equal(c) {
			return true
		}
	}
	return false
}

// link checks that parent may sign certificates and signed child.
func (b *sha1Builder) link(child, parent *x509.Certificate) error {
	if b.budget <= 0 {
		return errors.New("too many signature checks")
	}
	b.budget--
	// CheckSignatureFrom checks the parent's basic constraints and key
	// usage before the signature, so an InsecureAlgorithmError means only
	// the SHA-1 signature itself is left to check.
	err := child.CheckSignatureFrom(parent)
	var insecure x509.InsecureAlgorithmError
	if errors.As(err, &insecure) && isSHA1(child.SignatureAlgorithm) {
		err = checkSHA1Signature(child, parent)
	}
	if err != nil {
		return fmt.Errorf("%q signed by %q: %w", child.Subject.String(), parent.Subject.String(), err)
	}
	return nil
}

// checkSHA1Signature verifies child's SHA-1 signature with parent's key.
func checkSHA1Signature(child, parent *x509.Certificate) error {
	digest := sha1.Sum(child.RawTBSCertificate)
	switch pub := parent.PublicKey.(type) {
	case *rsa.PublicKey:
		if child.SignatureAlgorithm != x509.SHA1WithRSA {
			return errors.New("signature algorithm does not match the RSA issuer key")
		}
		return rsa.VerifyPKCS1v15(pub, crypto.SHA1, digest[:], child.Signature)
	case *ecdsa.PublicKey:
		if child.SignatureAlgorithm != x509.ECDSAWithSHA1 {
			return errors.New("signature algorithm does not match the ECDSA issuer key")
		}
		if !ecdsa.VerifyASN1(pub, digest[:], child.Signature) {
			return errors.New("ECDSA-SHA1 signature verification failed")
		}
		return nil
	}
	return fmt.Errorf("unsupported issuer key type %T", parent.PublicKey)
}

// checkChainProperties checks what crypto/x509 checks on a chain besides
// signatures: validity periods, critical extensions, path lengths and
// extended key usages. Name constraints are refused rather than evaluated.
// chain runs from the leaf to the anchor.
func checkChainProperties(chain []*x509.Certificate, now time.Time) error {
	for i, c := range chain {
		if now.Before(c.NotBefore) {
			return fmt.Errorf("%q is not valid before %s", c.Subject.String(), c.NotBefore.UTC().Format(time.RFC3339))
		}
		if now.After(c.NotAfter) {
			return fmt.Errorf("%q expired at %s", c.Subject.String(), c.NotAfter.UTC().Format(time.RFC3339))
		}
		if len(c.UnhandledCriticalExtensions) > 0 {
			return fmt.Errorf("%q has an unhandled critical extension %v", c.Subject.String(), c.UnhandledCriticalExtensions[0])
		}
		if !ekuAllowsServer(c, true) {
			return fmt.Errorf("%q does not allow TLS server authentication", c.Subject.String())
		}
		if i == 0 {
			continue
		}
		// An anchor may be a v1 certificate without basic constraints (as
		// crypto/x509 allows); an intermediate must say it is a CA.
		if i < len(chain)-1 && (!c.BasicConstraintsValid || !c.IsCA) {
			return fmt.Errorf("%q is not a CA certificate", c.Subject.String())
		}
		if c.BasicConstraintsValid && c.MaxPathLen >= 0 && i-1 > c.MaxPathLen {
			return fmt.Errorf("%q allows %d intermediates below it, chain has %d", c.Subject.String(), c.MaxPathLen, i-1)
		}
		if hasNameConstraints(c) {
			return fmt.Errorf("%q has name constraints, which are not evaluated on SHA-1 chains", c.Subject.String())
		}
	}
	return nil
}

func hasNameConstraints(c *x509.Certificate) bool {
	return len(c.PermittedDNSDomains) > 0 || len(c.ExcludedDNSDomains) > 0 ||
		len(c.PermittedIPRanges) > 0 || len(c.ExcludedIPRanges) > 0 ||
		len(c.PermittedEmailAddresses) > 0 || len(c.ExcludedEmailAddresses) > 0 ||
		len(c.PermittedURIDomains) > 0 || len(c.ExcludedURIDomains) > 0
}

// ekuAllowsServer reports whether c's extended key usage, if it has one,
// allows TLS server authentication. anyExtendedKeyUsage counts only when
// allowAny (crypto/x509 chain semantics); OpenSSL's purpose check on a
// leaf does not accept it.
func ekuAllowsServer(c *x509.Certificate, allowAny bool) bool {
	if !hasExtension(c, oidExtKeyUsage) {
		return true
	}
	for _, u := range c.ExtKeyUsage {
		switch u {
		case x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageNetscapeServerGatedCrypto,
			x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			return true
		case x509.ExtKeyUsageAny:
			if allowAny {
				return true
			}
		}
	}
	return false
}

// sslServerPurpose is OpenSSL's "SSL server" purpose check on a leaf, which
// OpenVPN applies to every server certificate verified against a CA and
// which is what --ns-cert-type server means.
func sslServerPurpose(c *x509.Certificate) error {
	if !ekuAllowsServer(c, false) {
		return errors.New("its extended key usage does not include TLS Web Server Authentication")
	}
	if ext := extension(c, oidNetscapeCertType); ext != nil {
		bits, err := netscapeCertType(ext.Value)
		if err != nil {
			return err
		}
		if bits&nsSSLServer == 0 {
			return fmt.Errorf("its Netscape cert type 0x%02x does not include SSL server", bits)
		}
	}
	if hasExtension(c, oidKeyUsage) &&
		c.KeyUsage&(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment|x509.KeyUsageKeyAgreement) == 0 {
		return errors.New("its key usage allows neither digitalSignature, keyEncipherment nor keyAgreement")
	}
	return nil
}

// remoteCertTLSServer is --remote-cert-tls server: a key usage extension
// that allows a TLS server's operations, and the TLS Web Server
// Authentication extended key usage.
func remoteCertTLSServer(c *x509.Certificate) error {
	if !hasExtension(c, oidKeyUsage) {
		return errors.New("the certificate has no key usage extension")
	}
	if c.KeyUsage&(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment|x509.KeyUsageKeyAgreement) == 0 {
		return errors.New("its key usage allows neither digitalSignature, keyEncipherment nor keyAgreement")
	}
	for _, u := range c.ExtKeyUsage {
		if u == x509.ExtKeyUsageServerAuth {
			return nil
		}
	}
	return errors.New("its extended key usage does not include TLS Web Server Authentication")
}

// netscapeCertType returns the first byte of a Netscape cert type
// extension value (a DER BIT STRING), the byte holding the client, server
// and CA bits. Unused-bit padding is not checked, as OpenSSL does not.
func netscapeCertType(der []byte) (byte, error) {
	s := cryptobyte.String(der)
	var bits cryptobyte.String
	if !s.ReadASN1(&bits, cbasn1.BIT_STRING) || !s.Empty() || len(bits) < 1 || bits[0] > 7 {
		return 0, errors.New("malformed Netscape cert type extension")
	}
	if len(bits) < 2 {
		return 0, nil
	}
	return bits[1], nil
}

func extension(c *x509.Certificate, oid asn1.ObjectIdentifier) *pkix.Extension {
	for i := range c.Extensions {
		if c.Extensions[i].Id.Equal(oid) {
			return &c.Extensions[i]
		}
	}
	return nil
}

func hasExtension(c *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	return extension(c, oid) != nil
}

func colonHex(b []byte) string {
	h := hex.EncodeToString(b)
	var s strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			s.WriteByte(':')
		}
		s.WriteString(h[i : i+2])
	}
	return s.String()
}

// parseCAs reads the certificates of a --ca PEM bundle. CRLs and other
// blocks are skipped; a certificate that does not parse is an error, as it
// is for OpenVPN.
func parseCAs(data []byte) ([]*x509.Certificate, error) {
	certs, err := parsePEMCertificates(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCA, err)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("%w: no certificate in the --ca PEM", ErrCA)
	}
	return certs, nil
}

// parsePEMCertificates returns the certificates in data, in order.
// "TRUSTED CERTIFICATE" blocks (OpenSSL's certificate plus trust settings)
// are read for their certificate.
func parsePEMCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for n := 1; ; n++ {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			return certs, nil
		}
		der := b.Bytes
		switch b.Type {
		case "CERTIFICATE", "X509 CERTIFICATE":
		case "TRUSTED CERTIFICATE":
			s := cryptobyte.String(b.Bytes)
			var first cryptobyte.String
			if !s.ReadASN1Element(&first, cbasn1.SEQUENCE) {
				return nil, fmt.Errorf("PEM block %d: malformed TRUSTED CERTIFICATE", n)
			}
			der = first
		default:
			continue
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("PEM block %d: %v", n, err)
		}
		certs = append(certs, c)
	}
}
