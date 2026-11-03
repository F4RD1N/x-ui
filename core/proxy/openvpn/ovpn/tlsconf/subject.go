package tlsconf

import (
	"encoding/asn1"
	"errors"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// attribute is one AttributeTypeAndValue of an X.509 Name, its value kept
// as the raw string type and contents.
type attribute struct {
	oid   asn1.ObjectIdentifier
	tag   cbasn1.Tag
	value []byte
}

var oidCommonName = asn1.ObjectIdentifier{2, 5, 4, 3}

var errBadName = errors.New("malformed X.509 name")

// parseName splits a DER Name into its RDNs, each a list of attributes in
// encoding order. Empty RDNs are dropped (they print as nothing).
func parseName(der []byte) ([][]attribute, error) {
	in := cryptobyte.String(der)
	var seq cryptobyte.String
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) || !in.Empty() {
		return nil, errBadName
	}
	var rdns [][]attribute
	for !seq.Empty() {
		var set cryptobyte.String
		if !seq.ReadASN1(&set, cbasn1.SET) {
			return nil, errBadName
		}
		var rdn []attribute
		for !set.Empty() {
			var atv cryptobyte.String
			var a attribute
			var v cryptobyte.String
			if !set.ReadASN1(&atv, cbasn1.SEQUENCE) ||
				!atv.ReadASN1ObjectIdentifier(&a.oid) ||
				!atv.ReadAnyASN1(&v, &a.tag) || !atv.Empty() {
				return nil, errBadName
			}
			a.value = v
			rdn = append(rdn, a)
		}
		if len(rdn) > 0 {
			rdns = append(rdns, rdn)
		}
	}
	return rdns, nil
}

// subjectString prints a DER Name the way OpenVPN prints and compares a
// certificate subject (OpenSSL's X509_NAME_print_ex with
// XN_FLAG_SEP_CPLUS_SPC | XN_FLAG_FN_SN | ASN1_STRFLGS_UTF8_CONVERT |
// ASN1_STRFLGS_ESC_CTRL): RDNs in certificate order joined by ", ", the
// attributes of a multi-valued RDN joined by " + ", each as
// shortname=value. Values are converted to UTF-8; bytes below 0x20 and 0x7F
// are written as \XX and a backslash as \\. Nothing else is escaped, so
// "CN=a,b" is a CN containing a comma.
func subjectString(der []byte) (string, error) {
	rdns, err := parseName(der)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for i, rdn := range rdns {
		if i > 0 {
			b.WriteString(", ")
		}
		for j, a := range rdn {
			if j > 0 {
				b.WriteString(" + ")
			}
			b.WriteString(attributeName(a.oid))
			b.WriteByte('=')
			v, err := valueUTF8(a.tag, a.value)
			if err != nil {
				return "", err
			}
			for _, c := range v {
				switch {
				case c < 0x20 || c == 0x7f:
					const hexDigits = "0123456789ABCDEF"
					b.WriteByte('\\')
					b.WriteByte(hexDigits[c>>4])
					b.WriteByte(hexDigits[c&0xf])
				case c == '\\':
					b.WriteString(`\\`)
				default:
					b.WriteByte(c)
				}
			}
		}
	}
	return b.String(), nil
}

// commonName returns the last CN of a DER Name as OpenVPN uses it for
// --verify-x509-name name/name-prefix: converted to UTF-8, with bytes below
// 0x20 and 0x7F replaced by '_'. ok is false when there is no CN.
func commonName(der []byte) (cn string, ok bool, err error) {
	rdns, err := parseName(der)
	if err != nil {
		return "", false, err
	}
	var last *attribute
	for _, rdn := range rdns {
		for i := range rdn {
			if rdn[i].oid.Equal(oidCommonName) {
				last = &rdn[i]
			}
		}
	}
	if last == nil {
		return "", false, nil
	}
	v, err := valueUTF8(last.tag, last.value)
	if err != nil {
		return "", false, err
	}
	for i, c := range v {
		if c < 0x20 || c == 0x7f {
			v[i] = '_'
		}
	}
	return string(v), true, nil
}

// valueUTF8 converts an attribute value to UTF-8 as OpenSSL does when
// printing: UTF8String as is (it must be valid), BMPString as UCS-2,
// UniversalString as UCS-4, and every other type one byte per character
// (Latin-1). The result is a fresh slice.
func valueUTF8(tag cbasn1.Tag, v []byte) ([]byte, error) {
	switch tag {
	case cbasn1.UTF8String:
		if !utf8.Valid(v) {
			return nil, errors.New("invalid UTF8String")
		}
		return append([]byte(nil), v...), nil
	case cbasn1.Tag(asn1.TagBMPString):
		if len(v)%2 != 0 {
			return nil, errors.New("invalid BMPString")
		}
		out := make([]byte, 0, len(v))
		for i := 0; i < len(v); i += 2 {
			r := rune(v[i])<<8 | rune(v[i+1])
			if r >= 0xd800 && r <= 0xdfff {
				return nil, errors.New("surrogate in BMPString")
			}
			out = utf8.AppendRune(out, r)
		}
		return out, nil
	case cbasn1.Tag(28): // UniversalString
		if len(v)%4 != 0 {
			return nil, errors.New("invalid UniversalString")
		}
		out := make([]byte, 0, len(v))
		for i := 0; i < len(v); i += 4 {
			r := rune(v[i])<<24 | rune(v[i+1])<<16 | rune(v[i+2])<<8 | rune(v[i+3])
			if r < 0 || r > utf8.MaxRune || r >= 0xd800 && r <= 0xdfff {
				return nil, errors.New("invalid character in UniversalString")
			}
			out = utf8.AppendRune(out, r)
		}
		return out, nil
	}
	out := make([]byte, 0, len(v))
	for _, c := range v {
		out = utf8.AppendRune(out, rune(c))
	}
	return out, nil
}

// attributeName is OpenSSL's short name for an attribute type, or its
// dotted OID when OpenSSL has none.
func attributeName(oid asn1.ObjectIdentifier) string {
	s := oid.String()
	if n, ok := shortNames[s]; ok {
		return n
	}
	return s
}

// shortNames maps the attribute OIDs OpenSSL 3 names to their short names,
// as `openssl x509 -nameopt sname` prints them. It was produced by printing
// a subject holding every OID under 2.5.4, PKCS#9, the pilot attributes
// (0.9.2342.19200300.100.1), jurisdiction*, id-pda and the Russian
// registration numbers.
var shortNames = map[string]string{
	"2.5.4.3": "CN", "2.5.4.4": "SN", "2.5.4.5": "serialNumber", "2.5.4.6": "C",
	"2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.9": "street", "2.5.4.10": "O",
	"2.5.4.11": "OU", "2.5.4.12": "title", "2.5.4.13": "description",
	"2.5.4.14": "searchGuide", "2.5.4.15": "businessCategory",
	"2.5.4.16": "postalAddress", "2.5.4.17": "postalCode", "2.5.4.18": "postOfficeBox",
	"2.5.4.19": "physicalDeliveryOfficeName", "2.5.4.20": "telephoneNumber",
	"2.5.4.21": "telexNumber", "2.5.4.22": "teletexTerminalIdentifier",
	"2.5.4.23": "facsimileTelephoneNumber", "2.5.4.24": "x121Address",
	"2.5.4.25": "internationaliSDNNumber", "2.5.4.26": "registeredAddress",
	"2.5.4.27": "destinationIndicator", "2.5.4.28": "preferredDeliveryMethod",
	"2.5.4.29": "presentationAddress", "2.5.4.30": "supportedApplicationContext",
	"2.5.4.31": "member", "2.5.4.32": "owner", "2.5.4.33": "roleOccupant",
	"2.5.4.34": "seeAlso", "2.5.4.35": "userPassword", "2.5.4.36": "userCertificate",
	"2.5.4.37": "cACertificate", "2.5.4.38": "authorityRevocationList",
	"2.5.4.39": "certificateRevocationList", "2.5.4.40": "crossCertificatePair",
	"2.5.4.41": "name", "2.5.4.42": "GN", "2.5.4.43": "initials",
	"2.5.4.44": "generationQualifier", "2.5.4.45": "x500UniqueIdentifier",
	"2.5.4.46": "dnQualifier", "2.5.4.47": "enhancedSearchGuide",
	"2.5.4.48": "protocolInformation", "2.5.4.49": "distinguishedName",
	"2.5.4.50": "uniqueMember", "2.5.4.51": "houseIdentifier",
	"2.5.4.52": "supportedAlgorithms", "2.5.4.53": "deltaRevocationList",
	"2.5.4.54": "dmdName", "2.5.4.65": "pseudonym", "2.5.4.72": "role",
	"2.5.4.97": "organizationIdentifier", "2.5.4.98": "c3", "2.5.4.99": "n3",
	"2.5.4.100": "dnsName",

	"1.2.840.113549.1.9.1": "emailAddress", "1.2.840.113549.1.9.2": "unstructuredName",
	"1.2.840.113549.1.9.3": "contentType", "1.2.840.113549.1.9.4": "messageDigest",
	"1.2.840.113549.1.9.5": "signingTime", "1.2.840.113549.1.9.6": "countersignature",
	"1.2.840.113549.1.9.7": "challengePassword", "1.2.840.113549.1.9.8": "unstructuredAddress",
	"1.2.840.113549.1.9.9": "extendedCertificateAttributes", "1.2.840.113549.1.9.14": "extReq",
	"1.2.840.113549.1.9.15": "SMIME-CAPS", "1.2.840.113549.1.9.16": "SMIME",
	"1.2.840.113549.1.9.20": "friendlyName", "1.2.840.113549.1.9.21": "localKeyID",

	"0.9.2342.19200300.100.1.1": "UID", "0.9.2342.19200300.100.1.2": "textEncodedORAddress",
	"0.9.2342.19200300.100.1.3": "mail", "0.9.2342.19200300.100.1.4": "info",
	"0.9.2342.19200300.100.1.5": "favouriteDrink", "0.9.2342.19200300.100.1.6": "roomNumber",
	"0.9.2342.19200300.100.1.7": "photo", "0.9.2342.19200300.100.1.8": "userClass",
	"0.9.2342.19200300.100.1.9": "host", "0.9.2342.19200300.100.1.10": "manager",
	"0.9.2342.19200300.100.1.11": "documentIdentifier", "0.9.2342.19200300.100.1.12": "documentTitle",
	"0.9.2342.19200300.100.1.13": "documentVersion", "0.9.2342.19200300.100.1.14": "documentAuthor",
	"0.9.2342.19200300.100.1.15": "documentLocation", "0.9.2342.19200300.100.1.20": "homeTelephoneNumber",
	"0.9.2342.19200300.100.1.21": "secretary", "0.9.2342.19200300.100.1.22": "otherMailbox",
	"0.9.2342.19200300.100.1.23": "lastModifiedTime", "0.9.2342.19200300.100.1.24": "lastModifiedBy",
	"0.9.2342.19200300.100.1.25": "DC", "0.9.2342.19200300.100.1.26": "aRecord",
	"0.9.2342.19200300.100.1.27": "pilotAttributeType27", "0.9.2342.19200300.100.1.28": "mXRecord",
	"0.9.2342.19200300.100.1.29": "nSRecord", "0.9.2342.19200300.100.1.30": "sOARecord",
	"0.9.2342.19200300.100.1.31": "cNAMERecord", "0.9.2342.19200300.100.1.37": "associatedDomain",
	"0.9.2342.19200300.100.1.38": "associatedName", "0.9.2342.19200300.100.1.39": "homePostalAddress",
	"0.9.2342.19200300.100.1.40": "personalTitle", "0.9.2342.19200300.100.1.41": "mobileTelephoneNumber",
	"0.9.2342.19200300.100.1.42": "pagerTelephoneNumber", "0.9.2342.19200300.100.1.43": "friendlyCountryName",
	"0.9.2342.19200300.100.1.44": "uid", "0.9.2342.19200300.100.1.45": "organizationalStatus",
	"0.9.2342.19200300.100.1.46": "janetMailbox", "0.9.2342.19200300.100.1.47": "mailPreferenceOption",
	"0.9.2342.19200300.100.1.48": "buildingName", "0.9.2342.19200300.100.1.49": "dSAQuality",
	"0.9.2342.19200300.100.1.50": "singleLevelQuality", "0.9.2342.19200300.100.1.51": "subtreeMinimumQuality",
	"0.9.2342.19200300.100.1.52": "subtreeMaximumQuality", "0.9.2342.19200300.100.1.53": "personalSignature",
	"0.9.2342.19200300.100.1.54": "dITRedirect", "0.9.2342.19200300.100.1.55": "audio",
	"0.9.2342.19200300.100.1.56": "documentPublisher",

	"1.3.6.1.4.1.311.60.2.1.1": "jurisdictionL", "1.3.6.1.4.1.311.60.2.1.2": "jurisdictionST",
	"1.3.6.1.4.1.311.60.2.1.3": "jurisdictionC",
	"1.3.6.1.5.5.7.9.1":        "id-pda-dateOfBirth", "1.3.6.1.5.5.7.9.2": "id-pda-placeOfBirth",
	"1.3.6.1.5.5.7.9.3": "id-pda-gender", "1.3.6.1.5.5.7.9.4": "id-pda-countryOfCitizenship",
	"1.3.6.1.5.5.7.9.5": "id-pda-countryOfResidence",
	"1.2.643.100.1":     "OGRN", "1.2.643.100.3": "SNILS", "1.2.643.100.5": "OGRNIP",
	"1.2.643.100.111": "subjectSignTool", "1.2.643.100.112": "issuerSignTool",
	"1.2.643.100.113": "classSignTool", "1.2.643.3.131.1.1": "INN",
}
