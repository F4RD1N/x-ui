package tlsconf

// The server checks a configuration adds to the chain and purpose checks:
// --crl-verify, --remote-cert-eku, --remote-cert-ku and --verify-hash, with
// what OpenVPN 2.6.19 (OpenSSL 3) did with each, as observed:
//
//   - crl-verify: every certificate of the chain except a self-signed
//     anchor is looked up in the CRLs of its issuer. A listed serial is
//     revoked. A CRL of that issuer whose signature does not verify, which
//     is not yet valid or which has expired fails the check. No CRL at all
//     for an issuer is accepted (OpenVPN lets OpenSSL's "unable to get
//     certificate CRL" pass). Only PEM is read.
//   - remote-cert-eku: one of the leaf's extended key usages, as a dotted
//     OID or by OpenSSL's long name ("TLS Web Server Authentication"),
//     compared exactly; short names ("serverAuth") do not match. A leaf
//     without the extension fails.
//   - remote-cert-ku: the leaf must have a key usage extension; with
//     values, its first byte read in OpenSSL's bit order must have every bit
//     of one of them.
//   - verify-hash: the SHA-1 or SHA-256 of the level-1 certificate, the one
//     after the leaf in the verified chain (without a CA: in the chain the
//     server sent).

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/options"
)

// crl is one --crl-verify CRL with its revoked serials as a set.
type crl struct {
	list    *x509.RevocationList
	revoked map[string]bool // serial numbers, in decimal
}

// setServerChecks copies the crl-verify, remote-cert-eku, remote-cert-ku
// and verify-hash settings of o into v.
func (v *verifier) setServerChecks(o *options.Options) error {
	if o.CRLVerify != nil {
		crls, err := parseCRLs(o.CRLVerify)
		if err != nil {
			return err
		}
		v.crls = crls
	}
	v.eku = o.RemoteCertEKU
	v.kuSet, v.ku = o.RemoteCertKUSet, o.RemoteCertKU
	if len(o.VerifyHash) > 0 {
		var size int
		switch o.VerifyHashAlgo {
		case "SHA1":
			size = sha1.Size
		case "SHA256":
			size = sha256.Size
		default:
			return fmt.Errorf("tlsconf: verify-hash: unknown digest %q (SHA1 or SHA256)", o.VerifyHashAlgo)
		}
		for _, h := range o.VerifyHash {
			if len(h) != size {
				return fmt.Errorf("tlsconf: verify-hash: a %s digest has %d bytes, not %d", o.VerifyHashAlgo, size, len(h))
			}
		}
		v.hashAlgo, v.hashes = o.VerifyHashAlgo, o.VerifyHash
	}
	return nil
}

// parseCRLs reads the "X509 CRL" blocks of a --crl-verify PEM file.
func parseCRLs(data []byte) ([]*crl, error) {
	var out []*crl
	for n := 1; ; n++ {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			break
		}
		if b.Type != "X509 CRL" {
			continue
		}
		rl, err := x509.ParseRevocationList(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: PEM block %d: %v", ErrCRL, n, err)
		}
		c := &crl{list: rl, revoked: make(map[string]bool, len(rl.RevokedCertificateEntries))}
		for _, e := range rl.RevokedCertificateEntries {
			if e.SerialNumber != nil {
				c.revoked[e.SerialNumber.String()] = true
			}
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no PEM \"X509 CRL\" block (OpenVPN reads PEM only)", ErrCRL)
	}
	return out, nil
}

// checkChain applies the checks that depend on the chain (leaf first).
func (v *verifier) checkChain(chain []*x509.Certificate, now time.Time) error {
	if len(v.crls) > 0 {
		if err := v.checkCRLs(chain, now); err != nil {
			return fmt.Errorf("crl-verify: %v", err)
		}
	}
	if v.hashAlgo != "" {
		if err := v.checkHash(chain); err != nil {
			return fmt.Errorf("verify-hash: %v", err)
		}
	}
	return nil
}

func (v *verifier) checkCRLs(chain []*x509.Certificate, now time.Time) error {
	for i, c := range chain {
		var issuer *x509.Certificate
		if i+1 < len(chain) {
			issuer = chain[i+1]
		} else if bytes.Equal(c.RawIssuer, c.RawSubject) {
			break // the anchor: nothing above it
		}
		if err := v.crlStatus(c, issuer, now); err != nil {
			return err
		}
	}
	return nil
}

// crlStatus checks c against the CRLs of its issuer (nil when the chain
// does not hold it).
func (v *verifier) crlStatus(c, issuer *x509.Certificate, now time.Time) error {
	var lastErr error
	found, usable := false, false
	for _, l := range v.crls {
		if !bytes.Equal(l.list.RawIssuer, c.RawIssuer) {
			continue
		}
		found = true
		if issuer == nil {
			lastErr = fmt.Errorf("cannot check the signature of the CRL of %q: its issuer is not in the chain", c.Subject.String())
			continue
		}
		if err := l.list.CheckSignatureFrom(issuer); err != nil {
			lastErr = fmt.Errorf("CRL signature failure: the CRL of %q: %v", issuer.Subject.String(), err)
			continue
		}
		if c.SerialNumber != nil && l.revoked[c.SerialNumber.String()] {
			return fmt.Errorf("certificate revoked: %q, serial %s", c.Subject.String(), c.SerialNumber.String())
		}
		switch {
		case now.Before(l.list.ThisUpdate):
			lastErr = fmt.Errorf("the CRL of %q is not yet valid (from %s)", issuer.Subject.String(), l.list.ThisUpdate.UTC().Format(time.RFC3339))
		case !l.list.NextUpdate.IsZero() && now.After(l.list.NextUpdate):
			lastErr = fmt.Errorf("the CRL of %q has expired (at %s)", issuer.Subject.String(), l.list.NextUpdate.UTC().Format(time.RFC3339))
		default:
			usable = true
		}
	}
	if found && !usable {
		return lastErr
	}
	return nil
}

func (v *verifier) checkHash(chain []*x509.Certificate) error {
	if len(chain) < 2 {
		return errors.New("the server certificate has no level-1 (issuer) certificate in its chain")
	}
	c := chain[1]
	var sum []byte
	if v.hashAlgo == "SHA1" {
		s := sha1.Sum(c.Raw)
		sum = s[:]
	} else {
		s := sha256.Sum256(c.Raw)
		sum = s[:]
	}
	for _, h := range v.hashes {
		if bytes.Equal(h, sum) {
			return nil
		}
	}
	return fmt.Errorf("the %s of the level-1 certificate %q, %s, matches none of the given digests",
		v.hashAlgo, c.Subject.String(), colonHex(sum))
}

// ekuLongNames are OpenSSL's long names of extended key usages, as
// "openssl x509 -text" prints them; other OIDs print in dotted form.
var ekuLongNames = map[string]string{
	"1.3.6.1.5.5.7.3.1":      "TLS Web Server Authentication",
	"1.3.6.1.5.5.7.3.2":      "TLS Web Client Authentication",
	"1.3.6.1.5.5.7.3.3":      "Code Signing",
	"1.3.6.1.5.5.7.3.4":      "E-mail Protection",
	"1.3.6.1.5.5.7.3.5":      "IPSec End System",
	"1.3.6.1.5.5.7.3.6":      "IPSec Tunnel",
	"1.3.6.1.5.5.7.3.7":      "IPSec User",
	"1.3.6.1.5.5.7.3.8":      "Time Stamping",
	"1.3.6.1.5.5.7.3.9":      "OCSP Signing",
	"1.3.6.1.5.5.7.3.10":     "dvcs",
	"1.3.6.1.5.5.7.3.17":     "ipsec Internet Key Exchange",
	"1.3.6.1.5.5.7.3.21":     "SSH Client",
	"1.3.6.1.5.5.7.3.22":     "SSH Server",
	"2.5.29.37.0":            "Any Extended Key Usage",
	"1.3.6.1.4.1.311.10.3.3": "Microsoft Server Gated Crypto",
	"2.16.840.1.113730.4.1":  "Netscape Server Gated Crypto",
	"1.3.6.1.4.1.311.2.1.21": "Microsoft Individual Code Signing",
	"1.3.6.1.4.1.311.2.1.22": "Microsoft Commercial Code Signing",
	"1.3.6.1.4.1.311.10.3.1": "Microsoft Trust List Signing",
	"1.3.6.1.4.1.311.10.3.4": "Microsoft Encrypted File System",
	"1.3.6.1.4.1.311.20.2.2": "Microsoft Smartcard Login",
	"1.3.6.1.5.2.3.4":        "PKINIT Client Auth",
	"1.3.6.1.5.2.3.5":        "Signing KDC Response",
}

// checkEKU is --remote-cert-eku want.
func checkEKU(c *x509.Certificate, want string) error {
	ext := extension(c, oidExtKeyUsage)
	if ext == nil {
		return errors.New("the certificate has no extended key usage extension")
	}
	s := cryptobyte.String(ext.Value)
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) || !s.Empty() {
		return errors.New("malformed extended key usage extension")
	}
	var have []string
	for !seq.Empty() {
		var oid asn1.ObjectIdentifier
		if !seq.ReadASN1ObjectIdentifier(&oid) {
			return errors.New("malformed extended key usage extension")
		}
		dotted := oid.String()
		name := dotted
		if n, ok := ekuLongNames[dotted]; ok {
			name = n
		}
		if want == dotted || want == name {
			return nil
		}
		have = append(have, name)
	}
	return fmt.Errorf("its extended key usages (%s) do not include %q", strings.Join(have, ", "), want)
}

// opensslKeyUsage is the first byte of a key usage BIT STRING as OpenSSL
// reads it: 0x80 digitalSignature ... 0x01 encipherOnly.
func opensslKeyUsage(u x509.KeyUsage) uint16 {
	var v uint16
	for i := 0; i < 8; i++ {
		if u&(1<<i) != 0 {
			v |= 0x80 >> i
		}
	}
	return v
}

// checkKU is --remote-cert-ku with the values want.
func checkKU(c *x509.Certificate, want []uint16) error {
	if !hasExtension(c, oidKeyUsage) {
		return errors.New("the certificate has no key usage extension")
	}
	if len(want) == 0 {
		return nil
	}
	ku := opensslKeyUsage(c.KeyUsage)
	for _, w := range want {
		if ku&w == w {
			return nil
		}
	}
	hexes := make([]string, len(want))
	for i, w := range want {
		hexes[i] = fmt.Sprintf("%04x", w)
	}
	return fmt.Errorf("its key usage %04x has every bit of none of %s", ku, strings.Join(hexes, ", "))
}
