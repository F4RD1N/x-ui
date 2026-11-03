package tlsconf

// A PKCS#12 (RFC 7292) reader. golang.org/x/crypto/pkcs12 cannot read
// OpenSSL 3's defaults, PBES2 (PBKDF2 + AES-CBC, RFC 8018) encryption with
// a SHA-256 MAC, and trusts any iteration count a file names. This reader
// handles password-integrity PFX files: key bags, shrouded key bags, X.509
// certificate bags and nested safe contents; data and encryptedData
// content; PBES2 with PBKDF2-HMAC-SHA1/SHA-2 and AES-128/192/256-CBC,
// DES-EDE3-CBC or DES-CBC, PBES1 with MD5 or SHA-1 and DES-CBC, and the
// PKCS#12 3DES PBEs; MACs with SHA-1 or SHA-2. Every iteration count is
// bounded. RC2 and RC4 (the old OpenSSL 1.x default and "openssl pkcs12
// -legacy") are reported as errP12Unsupported after their parameters were
// checked, and left to x/crypto. DER only (no BER indefinite lengths). The
// same decryption reads PKCS#8 "ENCRYPTED PRIVATE KEY" blocks.
//
// The password is used as PKCS#12's KDF wants it, a BMPString with a
// two-byte terminator (also each byte as one character, as OpenSSL before
// 1.1.0 wrote non-ASCII passwords), and as PBES1/PBES2 want it, its UTF-8
// bytes.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"unicode/utf16"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	errP12Password    = errors.New("pkcs12: wrong password")
	errP12Malformed   = errors.New("pkcs12: malformed file")
	errP12Unsupported = errors.New("pkcs12: unsupported algorithm")
)

// maxP12Iterations bounds the MAC and PBE iteration counts a file can ask
// for, so a hostile file cannot stall the client for minutes.
var maxP12Iterations = 1 << 21

const maxP12Depth = 4 // nesting of safeContentsBag

var (
	oidP12Data          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidP12EncryptedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}

	oidKeyBag             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 1}
	oidShroudedKeyBag     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	oidCertBag            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidSafeContentsBag    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 6}
	oidX509CertificateBag = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}

	// pbeWithSHAAnd*: .1 RC4-128, .2 RC4-40, .3 3DES, .4 2-key 3DES,
	// .5 RC2-128, .6 RC2-40.
	oidPKCS12PBE = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1}
	oidPBES2     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	// PBES1 (PKCS#5 v1.5): pbeWithMD5AndDES-CBC, pbeWithSHA1AndDES-CBC.
	oidPBEMD5DES  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 3}
	oidPBESHA1DES = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 10}

	oidAES128CBC   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidDESEDE3CBC  = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
	oidDESCBC      = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 7}
	oidHMACWithSHA = asn1.ObjectIdentifier{1, 2, 840, 113549, 2} // .7 SHA-1, .8-.11 SHA-224..512

	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA2   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2} // .1 SHA-256, .2 SHA-384, .3 SHA-512, .4 SHA-224
	oidPBMAC1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14}
)

// p12EmptyPasswords are the encodings of the empty password for the
// PKCS#12 KDF: a BMPString with its two-byte terminator, or, from some
// writers, no bytes at all.
var p12EmptyPasswords = [][]byte{{0, 0}, {}}

// kdfPasswords are the encodings of password to try with the PKCS#12 KDF.
func kdfPasswords(password string) [][]byte {
	if password == "" {
		return p12EmptyPasswords
	}
	u := utf16.Encode([]rune(password))
	bmp := make([]byte, 0, 2*len(u)+2)
	for _, r := range u {
		bmp = append(bmp, byte(r>>8), byte(r))
	}
	out := [][]byte{append(bmp, 0, 0)}
	for i := 0; i < len(password); i++ {
		if password[i] >= 0x80 {
			// OpenSSL before 1.1.0 took each byte as one character.
			b := make([]byte, 0, 2*len(password)+2)
			for j := 0; j < len(password); j++ {
				b = append(b, 0, password[j])
			}
			out = append(out, append(b, 0, 0))
			break
		}
	}
	return out
}

// textPasswords are the encodings of password to try with PBES1/PBES2,
// which take it as bytes: the empty password is no bytes, though some
// writers used the BMP terminator.
func textPasswords(password string) [][]byte {
	if password == "" {
		return [][]byte{{}, {0, 0}}
	}
	return [][]byte{[]byte(password)}
}

// parsePKCS12 returns the DER PKCS#8 keys and DER certificates of a PFX
// protected by password ("" for none). When some content uses an algorithm
// this reader leaves to x/crypto, it reads what it can and returns an error
// wrapping errP12Unsupported.
func parsePKCS12(der []byte, password string) (keys, certs [][]byte, err error) {
	in := cryptobyte.String(der)
	var pfx, authSafeCI cryptobyte.String
	var version int64
	if !in.ReadASN1(&pfx, cbasn1.SEQUENCE) || !in.Empty() ||
		!pfx.ReadASN1Integer(&version) || !pfx.ReadASN1(&authSafeCI, cbasn1.SEQUENCE) {
		return nil, nil, errP12Malformed
	}
	if version != 3 {
		return nil, nil, fmt.Errorf("pkcs12: version %d, want 3", version)
	}
	ctype, content, err := readContentInfo(authSafeCI)
	if err != nil {
		return nil, nil, err
	}
	if !ctype.Equal(oidP12Data) {
		return nil, nil, fmt.Errorf("pkcs12: authSafe content type %v; only password integrity is supported", ctype)
	}
	var authSafe cryptobyte.String
	if !content.ReadASN1(&authSafe, cbasn1.OCTET_STRING) || !content.Empty() {
		return nil, nil, errP12Malformed
	}

	passwords := kdfPasswords(password)
	if !pfx.Empty() {
		var macData cryptobyte.String
		if !pfx.ReadASN1(&macData, cbasn1.SEQUENCE) || !pfx.Empty() {
			return nil, nil, errP12Malformed
		}
		pw, err := verifyP12MAC(macData, authSafe, passwords)
		if err != nil {
			return nil, nil, err
		}
		passwords = [][]byte{pw}
	}

	p := &p12Parser{passwords: passwords, text: textPasswords(password)}
	s := authSafe
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) || !s.Empty() {
		return nil, nil, errP12Malformed
	}
	for !seq.Empty() {
		var ci cryptobyte.String
		if !seq.ReadASN1(&ci, cbasn1.SEQUENCE) {
			return nil, nil, errP12Malformed
		}
		ctype, content, err := readContentInfo(ci)
		if err != nil {
			return nil, nil, err
		}
		var safeContents []byte
		switch {
		case ctype.Equal(oidP12Data):
			var octets cryptobyte.String
			if !content.ReadASN1(&octets, cbasn1.OCTET_STRING) || !content.Empty() {
				return nil, nil, errP12Malformed
			}
			safeContents = octets
		case ctype.Equal(oidP12EncryptedData):
			if safeContents, err = p.encryptedData(content); err != nil {
				if errors.Is(err, errP12Unsupported) {
					p.unsupported = err
					continue
				}
				return nil, nil, err
			}
		default:
			return nil, nil, fmt.Errorf("pkcs12: unsupported content type %v", ctype)
		}
		if err := p.safeContents(safeContents, 0); err != nil {
			return nil, nil, err
		}
	}
	return p.keys, p.certs, p.unsupported
}

type p12Parser struct {
	passwords   [][]byte // PKCS#12 KDF password encodings to try
	text        [][]byte // PBES1/PBES2 password encodings to try
	keys, certs [][]byte
	unsupported error // the last errP12Unsupported met
}

// readContentInfo reads ContentInfo ::= SEQUENCE { contentType, [0]
// EXPLICIT content } (the outer SEQUENCE already removed) and returns the
// explicit tag's contents.
func readContentInfo(ci cryptobyte.String) (asn1.ObjectIdentifier, cryptobyte.String, error) {
	var ctype asn1.ObjectIdentifier
	var content cryptobyte.String
	if !ci.ReadASN1ObjectIdentifier(&ctype) ||
		!ci.ReadASN1(&content, cbasn1.Tag(0).Constructed().ContextSpecific()) || !ci.Empty() {
		return nil, nil, errP12Malformed
	}
	return ctype, content, nil
}

// encryptedData decrypts EncryptedData ::= SEQUENCE { version,
// EncryptedContentInfo ::= SEQUENCE { contentType, algorithm, [0] IMPLICIT
// OCTET STRING } }.
func (p *p12Parser) encryptedData(content cryptobyte.String) ([]byte, error) {
	var ed, eci, alg cryptobyte.String
	var version int64
	var ctype asn1.ObjectIdentifier
	if !content.ReadASN1(&ed, cbasn1.SEQUENCE) || !content.Empty() ||
		!ed.ReadASN1Integer(&version) || !ed.ReadASN1(&eci, cbasn1.SEQUENCE) ||
		!eci.ReadASN1ObjectIdentifier(&ctype) || !eci.ReadASN1(&alg, cbasn1.SEQUENCE) {
		return nil, errP12Malformed
	}
	var ct []byte
	switch {
	case eci.PeekASN1Tag(cbasn1.Tag(0).ContextSpecific()):
		var prim cryptobyte.String
		if !eci.ReadASN1(&prim, cbasn1.Tag(0).ContextSpecific()) {
			return nil, errP12Malformed
		}
		ct = prim
	case eci.PeekASN1Tag(cbasn1.Tag(0).Constructed().ContextSpecific()):
		// Constructed form: the ciphertext split over OCTET STRINGs.
		var cons cryptobyte.String
		if !eci.ReadASN1(&cons, cbasn1.Tag(0).Constructed().ContextSpecific()) {
			return nil, errP12Malformed
		}
		for !cons.Empty() {
			var part cryptobyte.String
			if !cons.ReadASN1(&part, cbasn1.OCTET_STRING) {
				return nil, errP12Malformed
			}
			ct = append(ct, part...)
		}
	default:
		return nil, errors.New("pkcs12: encrypted data without content")
	}
	if !eci.Empty() || !ctype.Equal(oidP12Data) {
		return nil, errP12Malformed
	}
	return p.decrypt(alg, ct)
}

// safeContents reads SafeContents ::= SEQUENCE OF SafeBag.
func (p *p12Parser) safeContents(der []byte, depth int) error {
	if depth > maxP12Depth {
		return errors.New("pkcs12: safe contents nested too deeply")
	}
	s := cryptobyte.String(der)
	var bags cryptobyte.String
	if !s.ReadASN1(&bags, cbasn1.SEQUENCE) || !s.Empty() {
		return errP12Malformed
	}
	for !bags.Empty() {
		var bag, value cryptobyte.String
		var id asn1.ObjectIdentifier
		if !bags.ReadASN1(&bag, cbasn1.SEQUENCE) || !bag.ReadASN1ObjectIdentifier(&id) ||
			!bag.ReadASN1(&value, cbasn1.Tag(0).Constructed().ContextSpecific()) {
			return errP12Malformed
		}
		// Bag attributes (friendlyName, localKeyId) follow; unused.
		switch {
		case id.Equal(oidKeyBag):
			var pki cryptobyte.String
			if !value.ReadASN1Element(&pki, cbasn1.SEQUENCE) || !value.Empty() {
				return errP12Malformed
			}
			p.keys = append(p.keys, pki)
		case id.Equal(oidShroudedKeyBag):
			var epki, alg, ct cryptobyte.String
			if !value.ReadASN1(&epki, cbasn1.SEQUENCE) || !value.Empty() ||
				!epki.ReadASN1(&alg, cbasn1.SEQUENCE) || !epki.ReadASN1(&ct, cbasn1.OCTET_STRING) || !epki.Empty() {
				return errP12Malformed
			}
			key, err := p.decrypt(alg, ct)
			if errors.Is(err, errP12Unsupported) {
				p.unsupported = err
				continue
			}
			if err != nil {
				return err
			}
			p.keys = append(p.keys, key)
		case id.Equal(oidCertBag):
			var cb, explicit, cert cryptobyte.String
			var certID asn1.ObjectIdentifier
			if !value.ReadASN1(&cb, cbasn1.SEQUENCE) || !value.Empty() ||
				!cb.ReadASN1ObjectIdentifier(&certID) ||
				!cb.ReadASN1(&explicit, cbasn1.Tag(0).Constructed().ContextSpecific()) || !cb.Empty() {
				return errP12Malformed
			}
			if !certID.Equal(oidX509CertificateBag) {
				continue // SDSI certificates
			}
			if !explicit.ReadASN1(&cert, cbasn1.OCTET_STRING) || !explicit.Empty() {
				return errP12Malformed
			}
			p.certs = append(p.certs, cert)
		case id.Equal(oidSafeContentsBag):
			var inner cryptobyte.String
			if !value.ReadASN1Element(&inner, cbasn1.SEQUENCE) || !value.Empty() {
				return errP12Malformed
			}
			if err := p.safeContents(inner, depth+1); err != nil {
				return err
			}
		}
		// CRL and secret bags are ignored.
	}
	return nil
}

// decrypt decrypts ct with the AlgorithmIdentifier alg (outer SEQUENCE
// removed), trying each password encoding until the padding checks.
func (p *p12Parser) decrypt(alg cryptobyte.String, ct []byte) ([]byte, error) {
	var oid asn1.ObjectIdentifier
	if !alg.ReadASN1ObjectIdentifier(&oid) {
		return nil, errP12Malformed
	}
	params := alg
	switch {
	case len(oid) == len(oidPKCS12PBE)+1 && oid[:len(oidPKCS12PBE)].Equal(oidPKCS12PBE):
		var seq, salt cryptobyte.String
		var iter int64
		if !params.ReadASN1(&seq, cbasn1.SEQUENCE) || !params.Empty() ||
			!seq.ReadASN1(&salt, cbasn1.OCTET_STRING) || !seq.ReadASN1Integer(&iter) || !seq.Empty() {
			return nil, errP12Malformed
		}
		if err := checkIterations(iter); err != nil {
			return nil, err
		}
		var keyLen int
		switch oid[len(oid)-1] {
		case 3:
			keyLen = 24
		case 4:
			keyLen = 16
		default:
			return nil, fmt.Errorf("%w: %v (RC2/RC4)", errP12Unsupported, oid)
		}
		for _, pw := range p.passwords {
			key := p12KDF(sha1.New, pw, salt, int(iter), 1, keyLen)
			if keyLen == 16 {
				key = append(key, key[:8]...)
			}
			iv := p12KDF(sha1.New, pw, salt, int(iter), 2, 8)
			block, err := des.NewTripleDESCipher(key)
			if err != nil {
				return nil, err
			}
			if out, err := cbcDecrypt(block, iv, ct); err == nil {
				return out, nil
			}
		}
		return nil, fmt.Errorf("%w (or corrupt data): 3DES decryption failed", errP12Password)
	case oid.Equal(oidPBES2):
		return decryptPBES2(params, ct, p.text)
	case oid.Equal(oidPBEMD5DES), oid.Equal(oidPBESHA1DES):
		return decryptPBES1(oid, params, ct, p.text)
	}
	return nil, fmt.Errorf("%w: encryption %v", errP12Unsupported, oid)
}

// decryptPBES1 decrypts with PKCS#5 v1.5 PBE-params ::= SEQUENCE { salt
// OCTET STRING (8 bytes), iterationCount }: PBKDF1 (MD5 or SHA-1) gives the
// DES key and IV.
func decryptPBES1(oid asn1.ObjectIdentifier, params cryptobyte.String, ct []byte, passwords [][]byte) ([]byte, error) {
	var seq, salt cryptobyte.String
	var iter int64
	if !params.ReadASN1(&seq, cbasn1.SEQUENCE) || !params.Empty() ||
		!seq.ReadASN1(&salt, cbasn1.OCTET_STRING) || !seq.ReadASN1Integer(&iter) || !seq.Empty() || len(salt) != 8 {
		return nil, errP12Malformed
	}
	if err := checkIterations(iter); err != nil {
		return nil, err
	}
	newHash := md5.New
	if oid.Equal(oidPBESHA1DES) {
		newHash = sha1.New
	}
	for _, pw := range passwords {
		h := newHash()
		h.Write(pw)
		h.Write(salt)
		dk := h.Sum(nil)
		for i := int64(1); i < iter; i++ {
			h.Reset()
			h.Write(dk)
			dk = h.Sum(dk[:0])
		}
		block, err := des.NewCipher(dk[:8])
		if err != nil {
			return nil, err
		}
		if out, err := cbcDecrypt(block, dk[8:16], ct); err == nil {
			return out, nil
		}
	}
	return nil, fmt.Errorf("%w (or corrupt data): PBES1 decryption failed", errP12Password)
}

// decryptPBES2 decrypts with PBES2-params ::= SEQUENCE { keyDerivationFunc,
// encryptionScheme }, trying each of passwords.
func decryptPBES2(params cryptobyte.String, ct []byte, passwords [][]byte) ([]byte, error) {
	var seq, kdf, enc cryptobyte.String
	var kdfOID, encOID asn1.ObjectIdentifier
	if !params.ReadASN1(&seq, cbasn1.SEQUENCE) || !params.Empty() ||
		!seq.ReadASN1(&kdf, cbasn1.SEQUENCE) || !seq.ReadASN1(&enc, cbasn1.SEQUENCE) || !seq.Empty() ||
		!kdf.ReadASN1ObjectIdentifier(&kdfOID) || !enc.ReadASN1ObjectIdentifier(&encOID) {
		return nil, errP12Malformed
	}
	if !kdfOID.Equal(oidPBKDF2) {
		return nil, fmt.Errorf("pkcs12: unsupported PBES2 key derivation %v", kdfOID)
	}
	var keyLen int
	var newCipher func([]byte) (cipher.Block, error)
	switch {
	case encOID.Equal(oidAES128CBC):
		keyLen, newCipher = 16, aes.NewCipher
	case encOID.Equal(oidAES192CBC):
		keyLen, newCipher = 24, aes.NewCipher
	case encOID.Equal(oidAES256CBC):
		keyLen, newCipher = 32, aes.NewCipher
	case encOID.Equal(oidDESEDE3CBC):
		keyLen, newCipher = 24, des.NewTripleDESCipher
	case encOID.Equal(oidDESCBC):
		keyLen, newCipher = 8, des.NewCipher
	default:
		return nil, fmt.Errorf("pkcs12: unsupported PBES2 cipher %v", encOID)
	}
	var iv cryptobyte.String
	if !enc.ReadASN1(&iv, cbasn1.OCTET_STRING) || !enc.Empty() {
		return nil, errP12Malformed
	}

	// PBKDF2-params ::= SEQUENCE { salt OCTET STRING, iterationCount,
	// keyLength OPTIONAL, prf AlgorithmIdentifier DEFAULT hmacWithSHA1 }
	var kp, salt cryptobyte.String
	var iter int64
	if !kdf.ReadASN1(&kp, cbasn1.SEQUENCE) || !kdf.Empty() ||
		!kp.ReadASN1(&salt, cbasn1.OCTET_STRING) || !kp.ReadASN1Integer(&iter) {
		return nil, errP12Malformed
	}
	if err := checkIterations(iter); err != nil {
		return nil, err
	}
	if kp.PeekASN1Tag(cbasn1.INTEGER) {
		var kl int64
		if !kp.ReadASN1Integer(&kl) {
			return nil, errP12Malformed
		}
		if kl != int64(keyLen) {
			return nil, fmt.Errorf("pkcs12: PBKDF2 key length %d does not fit the cipher", kl)
		}
	}
	prf := sha1.New
	if !kp.Empty() {
		var prfAlg cryptobyte.String
		var prfOID asn1.ObjectIdentifier
		if !kp.ReadASN1(&prfAlg, cbasn1.SEQUENCE) || !kp.Empty() || !prfAlg.ReadASN1ObjectIdentifier(&prfOID) {
			return nil, errP12Malformed
		}
		if prf = hmacPRF(prfOID); prf == nil {
			return nil, fmt.Errorf("pkcs12: unsupported PBKDF2 PRF %v", prfOID)
		}
	}
	for _, pw := range passwords {
		key, err := pbkdf2.Key(prf, string(pw), salt, int(iter), keyLen)
		if err != nil {
			return nil, err
		}
		block, err := newCipher(key)
		if err != nil {
			return nil, err
		}
		if out, err := cbcDecrypt(block, iv, ct); err == nil {
			return out, nil
		}
	}
	return nil, fmt.Errorf("%w (or corrupt data): PBES2 decryption failed", errP12Password)
}

func hmacPRF(oid asn1.ObjectIdentifier) func() hash.Hash {
	if len(oid) != len(oidHMACWithSHA)+1 || !oid[:len(oidHMACWithSHA)].Equal(oidHMACWithSHA) {
		return nil
	}
	switch oid[len(oid)-1] {
	case 7:
		return sha1.New
	case 8:
		return sha256.New224
	case 9:
		return sha256.New
	case 10:
		return sha512.New384
	case 11:
		return sha512.New
	}
	return nil
}

func digestHash(oid asn1.ObjectIdentifier) func() hash.Hash {
	if oid.Equal(oidSHA1) {
		return sha1.New
	}
	if len(oid) != len(oidSHA2)+1 || !oid[:len(oidSHA2)].Equal(oidSHA2) {
		return nil
	}
	switch oid[len(oid)-1] {
	case 1:
		return sha256.New
	case 2:
		return sha512.New384
	case 3:
		return sha512.New
	case 4:
		return sha256.New224
	}
	return nil
}

func checkIterations(n int64) error {
	if n < 1 || n > int64(maxP12Iterations) {
		return fmt.Errorf("pkcs12: iteration count %d out of range", n)
	}
	return nil
}

// verifyP12MAC checks MacData ::= SEQUENCE { DigestInfo, macSalt, iterations
// DEFAULT 1 } (outer SEQUENCE removed) over the authSafe contents and
// returns the password encoding that matches.
func verifyP12MAC(macData cryptobyte.String, authSafe []byte, passwords [][]byte) ([]byte, error) {
	var di, alg, digest, salt cryptobyte.String
	var oid asn1.ObjectIdentifier
	if !macData.ReadASN1(&di, cbasn1.SEQUENCE) || !di.ReadASN1(&alg, cbasn1.SEQUENCE) ||
		!di.ReadASN1(&digest, cbasn1.OCTET_STRING) || !di.Empty() ||
		!alg.ReadASN1ObjectIdentifier(&oid) || !macData.ReadASN1(&salt, cbasn1.OCTET_STRING) {
		return nil, errP12Malformed
	}
	iter := int64(1)
	if !macData.Empty() && (!macData.ReadASN1Integer(&iter) || !macData.Empty()) {
		return nil, errP12Malformed
	}
	if err := checkIterations(iter); err != nil {
		return nil, err
	}
	if oid.Equal(oidPBMAC1) {
		return nil, errors.New("pkcs12: PBMAC1 integrity is not supported")
	}
	newHash := digestHash(oid)
	if newHash == nil {
		return nil, fmt.Errorf("pkcs12: unsupported MAC digest %v", oid)
	}
	size := newHash().Size()
	if len(digest) != size {
		return nil, errP12Malformed
	}
	for _, pw := range passwords {
		key := p12KDF(newHash, pw, salt, int(iter), 3, size)
		m := hmac.New(newHash, key)
		m.Write(authSafe)
		if subtle.ConstantTimeCompare(m.Sum(nil), digest) == 1 {
			return pw, nil
		}
	}
	return nil, errP12Password
}

// p12KDF is the PKCS#12 key derivation function (RFC 7292 appendix B.2):
// n bytes of key material for purpose id (1 key, 2 IV, 3 MAC key).
func p12KDF(newHash func() hash.Hash, password, salt []byte, iter int, id byte, n int) []byte {
	h := newHash()
	u, v := h.Size(), h.BlockSize()
	fill := func(x []byte) []byte {
		if len(x) == 0 {
			return nil
		}
		out := make([]byte, v*((len(x)+v-1)/v))
		for i := range out {
			out[i] = x[i%len(x)]
		}
		return out
	}
	d := bytes.Repeat([]byte{id}, v)
	i := append(fill(salt), fill(password)...)
	out := make([]byte, 0, n+u)
	b := make([]byte, v)
	a := make([]byte, 0, u)
	for len(out) < n {
		h.Reset()
		h.Write(d)
		h.Write(i)
		a = h.Sum(a[:0])
		for j := 1; j < iter; j++ {
			h.Reset()
			h.Write(a)
			a = h.Sum(a[:0])
		}
		out = append(out, a...)
		if len(out) >= n {
			break
		}
		for k := range b {
			b[k] = a[k%u]
		}
		// Each v-byte block of I becomes (I_j + B + 1) mod 2^(8v).
		for j := 0; j < len(i); j += v {
			carry := 1
			for k := v - 1; k >= 0; k-- {
				sum := int(i[j+k]) + int(b[k]) + carry
				i[j+k] = byte(sum)
				carry = sum >> 8
			}
		}
	}
	return out[:n]
}

// cbcDecrypt decrypts CBC with PKCS#7 padding.
func cbcDecrypt(block cipher.Block, iv, ct []byte) ([]byte, error) {
	bs := block.BlockSize()
	if len(iv) != bs || len(ct) == 0 || len(ct)%bs != 0 {
		return nil, errors.New("pkcs12: bad ciphertext or IV length")
	}
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ct)
	pad := int(out[len(out)-1])
	if pad == 0 || pad > bs {
		return nil, errors.New("pkcs12: bad padding")
	}
	for _, c := range out[len(out)-pad:] {
		if int(c) != pad {
			return nil, errors.New("pkcs12: bad padding")
		}
	}
	return out[:len(out)-pad], nil
}
