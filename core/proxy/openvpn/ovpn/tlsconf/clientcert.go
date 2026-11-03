package tlsconf

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/pkcs12"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/options"
)

var (
	errEncryptedKey = errors.New("the private key is encrypted: its passphrase is needed (keyPassword)")
	errKeyPassword  = errors.New("wrong key password (keyPassword), or a corrupt key")
	errP12NoPass    = errors.New("the file needs a password (keyPassword)")
	errP12WrongPass = errors.New("wrong password for the file (keyPassword)")
)

// loadClientCert returns the client certificate configured by --cert/--key
// or --pkcs12 with --extra-certs appended, or nil when there is none
// (username/password-only servers). p12CAs are the certificates of a
// PKCS#12 file other than the client's own; without --ca they are the trust
// anchors, as in OpenVPN.
func loadClientCert(o *options.Options) (cert *tls.Certificate, p12CAs []*x509.Certificate, err error) {
	havePEM := len(o.Cert) > 0 || len(o.Key) > 0
	if len(o.PKCS12) == 0 && !havePEM {
		if len(o.ExtraCerts) > 0 {
			return nil, nil, fmt.Errorf("%w: --extra-certs without a client certificate", ErrClientKey)
		}
		return nil, nil, nil
	}
	if len(o.PKCS12) > 0 && havePEM {
		return nil, nil, fmt.Errorf("%w: --pkcs12 cannot be combined with --cert/--key", ErrClientKey)
	}

	var key crypto.Signer
	var chain []*x509.Certificate // leaf first
	if len(o.PKCS12) > 0 {
		var leaf *x509.Certificate
		key, leaf, p12CAs, err = decodePKCS12(o.PKCS12, o.KeyPassword)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: --pkcs12: %v", ErrClientKey, err)
		}
		chain = append([]*x509.Certificate{leaf}, p12CAs...)
	} else {
		if len(o.Cert) == 0 {
			return nil, nil, fmt.Errorf("%w: --key without --cert", ErrClientKey)
		}
		if len(o.Key) == 0 {
			return nil, nil, fmt.Errorf("%w: --cert without --key", ErrClientKey)
		}
		// Certificates after the first in --cert are sent as its chain.
		if chain, err = parsePEMCertificates(o.Cert); err != nil {
			return nil, nil, fmt.Errorf("%w: --cert: %v", ErrClientKey, err)
		}
		if len(chain) == 0 {
			return nil, nil, fmt.Errorf("%w: no certificate in --cert", ErrClientKey)
		}
		if key, err = parsePrivateKeyPEM(o.Key, o.KeyPassword); err != nil {
			return nil, nil, fmt.Errorf("%w: --key: %v", ErrClientKey, err)
		}
	}
	if len(o.ExtraCerts) > 0 {
		extra, err := parsePEMCertificates(o.ExtraCerts)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: --extra-certs: %v", ErrClientKey, err)
		}
		chain = append(chain, extra...)
	}
	if !samePublicKey(key.Public(), chain[0].PublicKey) {
		return nil, nil, fmt.Errorf("%w: the private key does not belong to the certificate %q", ErrClientKey, chain[0].Subject.String())
	}
	cert = &tls.Certificate{PrivateKey: key, Leaf: chain[0]}
	for _, c := range chain {
		cert.Certificate = append(cert.Certificate, c.Raw)
	}
	return cert, p12CAs, nil
}

func samePublicKey(a, b crypto.PublicKey) bool {
	eq, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && eq.Equal(b)
}

// parsePrivateKeyPEM reads the first private key in data: PKCS#1
// ("RSA PRIVATE KEY"), SEC1 ("EC PRIVATE KEY") or PKCS#8 ("PRIVATE KEY").
// The label is only a hint, since some tools write PKCS#1 or SEC1 bytes
// under "PRIVATE KEY". An encrypted key ("ENCRYPTED PRIVATE KEY", or a
// Proc-Type/DEK-Info header) is decrypted with password; without one it is
// refused with errEncryptedKey.
func parsePrivateKeyPEM(data []byte, password string) (crypto.Signer, error) {
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			return nil, errors.New("no private key PEM block")
		}
		switch b.Type {
		case "ENCRYPTED PRIVATE KEY":
			if password == "" {
				return nil, errEncryptedKey
			}
			der, err := decryptPKCS8(b.Bytes, password)
			if err != nil {
				return nil, err
			}
			return decryptedKey(der)
		case "RSA PRIVATE KEY", "EC PRIVATE KEY", "PRIVATE KEY":
		default:
			if !strings.HasSuffix(b.Type, "PRIVATE KEY") {
				continue // e.g. "EC PARAMETERS" before an EC key
			}
			return nil, fmt.Errorf("unsupported private key type %q", b.Type)
		}
		if strings.Contains(b.Headers["Proc-Type"], "ENCRYPTED") || b.Headers["DEK-Info"] != "" {
			if password == "" {
				return nil, errEncryptedKey
			}
			// OpenSSL's traditional encryption: deprecated for its weak key
			// derivation and unauthenticated CBC, but what OpenSSL and
			// RouterOS write, and the only way to read those keys.
			der, err := x509.DecryptPEMBlock(b, []byte(password)) //nolint:staticcheck
			if errors.Is(err, x509.IncorrectPasswordError) {
				return nil, errKeyPassword
			}
			if err != nil {
				return nil, fmt.Errorf("cannot decrypt the key: %v", err)
			}
			return decryptedKey(der)
		}
		return parsePrivateKeyDER(b.Bytes)
	}
}

// decryptedKey parses a key just decrypted. CBC padding happens to check
// out for about one wrong password in 256, so a key that does not parse
// is reported as a wrong password.
func decryptedKey(der []byte) (crypto.Signer, error) {
	k, err := parsePrivateKeyDER(der)
	if err != nil {
		return nil, errKeyPassword
	}
	return k, nil
}

// decryptPKCS8 decrypts EncryptedPrivateKeyInfo ::= SEQUENCE {
// encryptionAlgorithm, encryptedData OCTET STRING } with the PKCS#12 reader's
// algorithms.
func decryptPKCS8(der []byte, password string) ([]byte, error) {
	s := cryptobyte.String(der)
	var epki, alg, ct cryptobyte.String
	if !s.ReadASN1(&epki, cbasn1.SEQUENCE) || !s.Empty() ||
		!epki.ReadASN1(&alg, cbasn1.SEQUENCE) || !epki.ReadASN1(&ct, cbasn1.OCTET_STRING) || !epki.Empty() {
		return nil, errors.New("malformed ENCRYPTED PRIVATE KEY")
	}
	p := &p12Parser{passwords: kdfPasswords(password), text: textPasswords(password)}
	out, err := p.decrypt(alg, ct)
	switch {
	case err == nil:
		return out, nil
	case errors.Is(err, errP12Password):
		return nil, errKeyPassword
	case errors.Is(err, errP12Unsupported):
		return nil, fmt.Errorf("the key's encryption is not supported: %v", err)
	}
	return nil, fmt.Errorf("cannot decrypt the key: %v", err)
}

// parsePrivateKeyDER parses a PKCS#8, PKCS#1 or SEC1 private key.
func parsePrivateKeyDER(der []byte) (crypto.Signer, error) {
	var k any
	var err error
	if k, err = x509.ParsePKCS8PrivateKey(der); err != nil {
		if k1, err1 := x509.ParsePKCS1PrivateKey(der); err1 == nil {
			k, err = k1, nil
		} else if k2, err2 := x509.ParseECPrivateKey(der); err2 == nil {
			k, err = k2, nil
		}
	}
	if err != nil {
		return nil, fmt.Errorf("not a PKCS#8, PKCS#1 or SEC1 private key: %v", err)
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("a %T private key cannot sign", k)
	}
	return s, nil
}

// decodePKCS12 reads a PKCS#12 file protected by password ("" for none)
// and returns the private key, the certificate that matches it and the
// other certificates. parsePKCS12 reads it first: it bounds every iteration
// count and handles OpenSSL 3's defaults (PBES2/AES, SHA-256 MAC). Files
// that use RC2 or RC4 (OpenSSL 1.x, "openssl pkcs12 -legacy") then go to
// golang.org/x/crypto/pkcs12, whose MAC and cipher parameters parsePKCS12
// has already checked. A file without a password is read even when one is
// given.
func decodePKCS12(data []byte, password string) (crypto.Signer, *x509.Certificate, []*x509.Certificate, error) {
	keys, certs, err := parsePKCS12(data, password)
	if errors.Is(err, errP12Password) && password != "" {
		if k, c, err2 := parsePKCS12(data, ""); !errors.Is(err2, errP12Password) {
			password, keys, certs, err = "", k, c, err2
		}
	}
	switch {
	case err == nil:
		return assemblePKCS12(keys, certs)
	case errors.Is(err, errP12Unsupported):
		return decodePKCS12Legacy(data, password, err)
	case errors.Is(err, errP12Password):
		return nil, nil, nil, p12PasswordError(password)
	}
	return nil, nil, nil, err
}

func p12PasswordError(password string) error {
	if password == "" {
		return errP12NoPass
	}
	return errP12WrongPass
}

func decodePKCS12Legacy(data []byte, password string, why error) (crypto.Signer, *x509.Certificate, []*x509.Certificate, error) {
	if k, c, err := pkcs12.Decode(data, password); err == nil {
		if s, ok := k.(crypto.Signer); ok && c != nil {
			return s, c, nil, nil
		}
	}
	// Decode insists on one certificate and one key; ToPEM takes chains.
	blocks, err := pkcs12.ToPEM(data, password)
	if err != nil {
		if errors.Is(err, pkcs12.ErrIncorrectPassword) {
			return nil, nil, nil, p12PasswordError(password)
		}
		return nil, nil, nil, fmt.Errorf("%v; x/crypto/pkcs12: %v", why, err)
	}
	var keys, certs [][]byte
	for _, b := range blocks {
		switch {
		case b.Type == "CERTIFICATE":
			certs = append(certs, b.Bytes)
		case strings.HasSuffix(b.Type, "PRIVATE KEY"):
			keys = append(keys, b.Bytes)
		}
	}
	return assemblePKCS12(keys, certs)
}

// assemblePKCS12 pairs the first usable key with its certificate.
func assemblePKCS12(keyDERs, certDERs [][]byte) (crypto.Signer, *x509.Certificate, []*x509.Certificate, error) {
	var certs []*x509.Certificate
	for i, der := range certDERs {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("certificate %d: %v", i+1, err)
		}
		certs = append(certs, c)
	}
	if len(keyDERs) == 0 {
		return nil, nil, nil, errors.New("no private key in the file")
	}
	var firstErr error
	for _, der := range keyDERs {
		key, err := parsePrivateKeyDER(der)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for i, c := range certs {
			if samePublicKey(key.Public(), c.PublicKey) {
				others := append(append([]*x509.Certificate(nil), certs[:i]...), certs[i+1:]...)
				return key, c, others, nil
			}
		}
		if firstErr == nil {
			firstErr = errors.New("no certificate matches the private key")
		}
	}
	return nil, nil, nil, firstErr
}
