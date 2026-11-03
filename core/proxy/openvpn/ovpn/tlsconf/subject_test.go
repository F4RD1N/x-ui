package tlsconf

import (
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"testing"
)

type testATV struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue
}

// testRDNSET marshals as SET OF (encoding/asn1 treats slice types whose
// name ends in SET that way).
type testRDNSET []testATV

func rawName(rdns ...testRDNSET) []byte {
	if rdns == nil {
		rdns = []testRDNSET{}
	}
	b, err := asn1.Marshal(rdns)
	if err != nil {
		panic(err)
	}
	return b
}

func str(tag int, s string) asn1.RawValue { return asn1.RawValue{Tag: tag, Bytes: []byte(s)} }
func utf(s string) asn1.RawValue          { return str(asn1.TagUTF8String, s) }
func bmp(s string) asn1.RawValue {
	var b []byte
	for _, r := range s {
		b = append(b, byte(r>>8), byte(r))
	}
	return asn1.RawValue{Tag: asn1.TagBMPString, Bytes: b}
}

func rdn(oid asn1.ObjectIdentifier, v asn1.RawValue) testRDNSET { return testRDNSET{{oid, v}} }

var (
	oC     = asn1.ObjectIdentifier{2, 5, 4, 6}
	oST    = asn1.ObjectIdentifier{2, 5, 4, 8}
	oL     = asn1.ObjectIdentifier{2, 5, 4, 7}
	oO     = asn1.ObjectIdentifier{2, 5, 4, 10}
	oOU    = asn1.ObjectIdentifier{2, 5, 4, 11}
	oCN    = oidCommonName
	oEmail = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
)

type oracleSubject struct {
	raw     []byte
	subject string // as OpenVPN 2.6.19 printed and matched it
	cn      string // as OpenVPN matched --verify-x509-name name; "" = no CN
}

// oracleSubjects are subjects probed against OpenVPN 2.6.19 (OpenSSL 3.0):
// subject is the "VERIFY OK: depth=0, ..." string, which also matched
// --verify-x509-name ... subject, and cn the value that matched "name".
var oracleSubjects = func() map[string]oracleSubject {
	o := func(s ...int) asn1.ObjectIdentifier { return asn1.ObjectIdentifier(s) }
	return map[string]oracleSubject{
		"plain": {rawName(rdn(oC, str(asn1.TagPrintableString, "US")), rdn(oST, utf("California")),
			rdn(oL, utf("San Francisco")), rdn(oO, utf("Org")), rdn(oOU, utf("Unit")), rdn(oCN, utf("server")),
			rdn(oEmail, str(asn1.TagIA5String, "a@b.c"))),
			"C=US, ST=California, L=San Francisco, O=Org, OU=Unit, CN=server, emailAddress=a@b.c", "server"},
		"multi": {rawName(rdn(oC, str(asn1.TagPrintableString, "US")), testRDNSET{{oO, utf("Org")}, {oOU, utf("Unit")}},
			rdn(oCN, utf("server"))), "C=US, O=Org + OU=Unit, CN=server", "server"},
		"utf8":     {rawName(rdn(oCN, utf("Jösé ñ €"))), "CN=Jösé ñ €", "Jösé ñ €"},
		"special":  {rawName(rdn(oCN, utf(`a,b+c=d\e"f<g>h;i#j/k`))), `CN=a,b+c=d\\e"f<g>h;i#j/k`, `a,b+c=d\e"f<g>h;i#j/k`},
		"lead":     {rawName(rdn(oO, utf("-org")), rdn(oCN, utf(" -lead trail "))), "O=-org, CN= -lead trail ", " -lead trail "},
		"leaddash": {rawName(rdn(oCN, utf("-dash"))), "CN=-dash", "-dash"},
		"ctrl":     {rawName(rdn(oCN, utf("a\x01b\x7fc\td"))), `CN=a\01b\7Fc\09d`, "a_b_c_d"},
		"bmp":      {rawName(rdn(oCN, bmp("Bmp é"))), "CN=Bmp é", "Bmp é"},
		"t61":      {rawName(rdn(oCN, str(asn1.TagT61String, "T61 \xe9"))), "CN=T61 é", "T61 é"},
		"names": {rawName(rdn(o(1, 2, 3, 4), utf("foo")), rdn(o(0, 9, 2342, 19200300, 100, 1, 25), str(asn1.TagIA5String, "example")),
			rdn(o(0, 9, 2342, 19200300, 100, 1, 1), utf("uid")), rdn(o(2, 5, 4, 5), str(asn1.TagPrintableString, "1234")),
			rdn(o(2, 5, 4, 12), utf("title")), rdn(o(2, 5, 4, 42), utf("gn")), rdn(o(2, 5, 4, 4), utf("sn")),
			rdn(o(2, 5, 4, 9), utf("street")), rdn(o(2, 5, 4, 17), utf("12345")), rdn(o(2, 5, 4, 13), utf("desc")),
			rdn(o(2, 5, 4, 15), utf("bc")), rdn(o(2, 5, 4, 97), utf("oi")),
			rdn(o(1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 3), str(asn1.TagPrintableString, "US")), rdn(o(2, 5, 4, 65), utf("ps")),
			rdn(o(2, 5, 4, 43), utf("in")), rdn(o(2, 5, 4, 44), utf("gq")), rdn(o(2, 5, 4, 46), utf("dq")),
			rdn(o(2, 5, 4, 41), utf("nm")), rdn(o(1, 2, 840, 113549, 1, 9, 2), utf("un")), rdn(oCN, utf("names"))),
			"1.2.3.4=foo, DC=example, UID=uid, serialNumber=1234, title=title, GN=gn, SN=sn, street=street, " +
				"postalCode=12345, description=desc, businessCategory=bc, organizationIdentifier=oi, jurisdictionC=US, " +
				"pseudonym=ps, initials=in, generationQualifier=gq, dnQualifier=dq, name=nm, unstructuredName=un, CN=names",
			"names"},
		"twocn": {rawName(rdn(oCN, utf("first")), rdn(oCN, utf("second"))), "CN=first, CN=second", "second"},
		"nocn":  {rawName(rdn(oO, utf("Org"))), "O=Org", ""},
	}
}()

func TestSubjectStringOracle(t *testing.T) {
	for name, tt := range oracleSubjects {
		got, err := subjectString(tt.raw)
		if err != nil || got != tt.subject {
			t.Errorf("%s: subject = %q, %v; want %q", name, got, err, tt.subject)
		}
		cn, ok, err := commonName(tt.raw)
		if err != nil || ok != (tt.cn != "") || cn != tt.cn {
			t.Errorf("%s: cn = %q, %v, %v; want %q", name, cn, ok, err, tt.cn)
		}
	}
}

// Cases checked with `openssl x509 -nameopt sep_comma_plus_space,sname,utf8,esc_ctrl`.
func TestSubjectStringOpenSSL(t *testing.T) {
	tests := []struct {
		hexDER string
		want   string
	}{
		{"30173115301306035504031c0c00000055000000e90001f600", "CN=Ué\U0001F600"}, // UniversalString
		{"300f310d300b06035504031e0400410000", `CN=A\00`},                         // BMPString with NUL
		{"300f310d300b0603550403160478e95c79", `CN=x` + "é" + `\\y`},              // IA5String, Latin-1 byte
		{"3000", ""}, // empty subject
	}
	for _, tt := range tests {
		der, _ := hex.DecodeString(tt.hexDER)
		got, err := subjectString(der)
		if err != nil || got != tt.want {
			t.Errorf("%s: %q, %v; want %q", tt.hexDER, got, err, tt.want)
		}
	}
}

func TestSubjectStringErrors(t *testing.T) {
	bad := [][]byte{
		nil,
		{0x30},
		{0x31, 0x00},             // SET, not SEQUENCE
		{0x30, 0x00, 0x00},       // trailing data
		{0x30, 0x02, 0x30, 0x00}, // RDN not a SET
		{0x30, 0x04, 0x31, 0x02, 0x30, 0x00},
		rawName(rdn(oCN, asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte{0xff}})),
		rawName(rdn(oCN, asn1.RawValue{Tag: asn1.TagBMPString, Bytes: []byte{0}})),
		rawName(rdn(oCN, asn1.RawValue{Tag: asn1.TagBMPString, Bytes: []byte{0xd8, 0x00}})),
		rawName(rdn(oCN, asn1.RawValue{Tag: 28, Bytes: []byte{0, 0, 0}})),
		rawName(rdn(oCN, asn1.RawValue{Tag: 28, Bytes: []byte{0, 0x11, 0, 0}})),
	}
	for _, b := range bad {
		if s, err := subjectString(b); err == nil {
			t.Errorf("%x: accepted as %q", b, s)
		}
	}
	if _, err := subjectString(rawName(testRDNSET{}, rdn(oCN, utf("x")))); err != nil {
		t.Errorf("empty RDN: %v", err)
	}
}

func TestAttributeNames(t *testing.T) {
	for oid, name := range shortNames {
		if name == "" || strings.ContainsAny(name, " =,") || oid == name {
			t.Errorf("bad entry %q: %q", oid, name)
		}
	}
	if n := attributeName(asn1.ObjectIdentifier{2, 5, 4, 3}); n != "CN" {
		t.Errorf("CN: %q", n)
	}
	if n := attributeName(asn1.ObjectIdentifier{1, 2, 3, 4, 5}); n != "1.2.3.4.5" {
		t.Errorf("unknown: %q", n)
	}
}

func FuzzSubjectString(f *testing.F) {
	for _, s := range oracleSubjects {
		f.Add(s.raw)
	}
	f.Add([]byte{0x30, 0x00})
	f.Add(loadFixtureCert(f, "sha1-server.pem").RawSubject)
	f.Fuzz(func(t *testing.T, der []byte) {
		s, err := subjectString(der)
		if err == nil {
			for i := 0; i < len(s); i++ {
				if s[i] < 0x20 || s[i] == 0x7f {
					t.Fatalf("control byte in %q", s)
				}
			}
		}
		cn, ok, err := commonName(der)
		if err == nil && ok {
			if strings.ContainsFunc(cn, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
				t.Fatalf("control byte in CN %q", cn)
			}
		}
	})
}

func FuzzNetscapeCertType(f *testing.F) {
	f.Add([]byte{0x03, 0x02, 0x06, 0x40})
	f.Add([]byte{0x03, 0x01, 0x00})
	f.Add([]byte{0x03, 0x82, 0x00, 0x02, 0x00, 0x40})
	f.Fuzz(func(t *testing.T, der []byte) {
		b, err := netscapeCertType(der)
		if err != nil && b != 0 {
			t.Fatal("bits returned with an error")
		}
	})
}

// FuzzPEM feeds arbitrary text to the PEM certificate and key readers.
func FuzzPEM(f *testing.F) {
	f.Add(readFixture(f, "sha1-server.key"))
	f.Add(readFixture(f, "enc-pkcs1.key"))
	f.Add(readFixture(f, "sha1-int.pem"))
	f.Add(pemBlock("TRUSTED CERTIFICATE", []byte{0x30, 0x00}))
	f.Add(pemBlock("EC PRIVATE KEY", []byte{0x30, 0x03, 0x02, 0x01, 0x01}))
	f.Fuzz(func(t *testing.T, data []byte) {
		parsePrivateKeyPEM(data, "")
		parsePEMCertificates(data)
		parseCAs(data)
	})
}

func pemBlock(typ string, der []byte) []byte {
	var b bytes.Buffer
	pem.Encode(&b, &pem.Block{Type: typ, Bytes: der})
	return b.Bytes()
}
