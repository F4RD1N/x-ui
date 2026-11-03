package handshake

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"
	"testing"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/wire"
)

// seqBytes fills b with start, start+1, ... (mod 256).
func seqBytes(b []byte, start int) {
	for i := range b {
		b[i] = byte(start + i)
	}
}

func testClientSource() ClientKeySource {
	var s ClientKeySource
	seqBytes(s.PreMaster[:], 0)
	seqBytes(s.Random1[:], 0x40)
	seqBytes(s.Random2[:], 0x80)
	return s
}

func testServerSource() ServerKeySource {
	var s ServerKeySource
	seqBytes(s.Random1[:], 0xa0)
	seqBytes(s.Random2[:], 0xc0)
	return s
}

// str encodes a key-method 2 string by hand: u16 length with the NUL, the
// bytes, the NUL; "" is the bare u16 0.
func str(s string) []byte {
	if s == "" {
		return []byte{0, 0}
	}
	b := binary.BigEndian.AppendUint16(nil, uint16(len(s)+1))
	b = append(b, s...)
	return append(b, 0)
}

func cat(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

const (
	testOptions  = "V4,dev-type tun,link-mtu 1549,tun-mtu 1500,proto UDPv4,cipher AES-256-GCM,auth [null-digest],keysize 256,key-method 2,tls-client"
	testPeerInfo = "IV_VER=2.6.12\nIV_PLAT=linux\nIV_PROTO=990\n"
)

func TestClientMessageLayout(t *testing.T) {
	src := testClientSource()
	m := ClientMessage{Source: src, Options: testOptions, Username: "alice", Password: "s3cret", PeerInfo: testPeerInfo}
	want := cat([]byte{0, 0, 0, 0, 2}, src.PreMaster[:], src.Random1[:], src.Random2[:],
		str(testOptions), str("alice"), str("s3cret"), str(testPeerInfo))
	if got := m.Marshal(); !bytes.Equal(got, want) {
		t.Fatalf("Marshal:\n got %x\nwant %x", got, want)
	}

	// Without credentials the two empty strings are still written.
	m = ClientMessage{Source: src, Options: "V4", PeerInfo: "IV_PROTO=2\n"}
	want = cat([]byte{0, 0, 0, 0, 2}, src.PreMaster[:], src.Random1[:], src.Random2[:],
		str("V4"), []byte{0, 0}, []byte{0, 0}, str("IV_PROTO=2\n"))
	if got := m.Marshal(); !bytes.Equal(got, want) {
		t.Fatalf("Marshal without credentials:\n got %x\nwant %x", got, want)
	}
}

func TestServerMessageLayout(t *testing.T) {
	src := testServerSource()
	m := ServerMessage{Source: src, Options: "V4,tls-server", PeerInfo: "IV_PROTO=2\n"}
	want := cat([]byte{0, 0, 0, 0, 2}, src.Random1[:], src.Random2[:],
		str("V4,tls-server"), []byte{0, 0}, []byte{0, 0}, str("IV_PROTO=2\n"))
	if got := m.Marshal(); !bytes.Equal(got, want) {
		t.Fatalf("Marshal:\n got %x\nwant %x", got, want)
	}
}

func TestClientMessageRoundTrip(t *testing.T) {
	src := testClientSource()
	long := strings.Repeat("x", 4000)
	tests := []struct {
		name string
		m    ClientMessage
	}{
		{"full", ClientMessage{Source: src, Options: testOptions, Username: "alice", Password: "s3cret", PeerInfo: testPeerInfo}},
		{"no credentials", ClientMessage{Source: src, Options: testOptions, PeerInfo: testPeerInfo}},
		{"all empty", ClientMessage{Source: src}},
		{"password only", ClientMessage{Source: src, Options: "V4", Password: "SESS_ID_token"}},
		{"long", ClientMessage{Source: src, Options: long, Username: long, Password: long, PeerInfo: long}},
		{"binary", ClientMessage{Source: src, Options: "\xff\x01\n", Username: "üñí", Password: "\x7f"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := tt.m.Marshal()
			// Trailing bytes (e.g. the next control message) are not consumed.
			got, n, err := ParseClientMessage(append(b, "PUSH_REQUEST\x00"...))
			if err != nil {
				t.Fatalf("ParseClientMessage: %v", err)
			}
			if n != len(b) {
				t.Fatalf("consumed %d bytes, want %d", n, len(b))
			}
			if *got != tt.m {
				t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, tt.m)
			}
			if got.Source.PreMaster != tt.m.Source.PreMaster {
				t.Fatal("pre-master changed in the round trip")
			}
		})
	}
}

func TestServerMessageRoundTrip(t *testing.T) {
	src := testServerSource()
	tests := []struct {
		name string
		m    ServerMessage
	}{
		{"full", ServerMessage{Source: src, Options: "V4,dev-type tun,tls-server", PeerInfo: "IV_PROTO=2\nIV_NCP=2\n"}},
		{"no peer info", ServerMessage{Source: src, Options: "V4,dev-type tun,tls-server"}},
		{"all empty", ServerMessage{Source: src}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := tt.m.Marshal()
			got, n, err := ParseServerMessage(append(b, "PUSH_REPLY,ping 10\x00"...))
			if err != nil {
				t.Fatalf("ParseServerMessage: %v", err)
			}
			if n != len(b) {
				t.Fatalf("consumed %d bytes, want %d", n, len(b))
			}
			if *got != tt.m {
				t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, tt.m)
			}
		})
	}
}

func TestParseClientTruncation(t *testing.T) {
	m := ClientMessage{Source: testClientSource(), Options: testOptions, Username: "bob", Password: "pw", PeerInfo: testPeerInfo}
	b := m.Marshal()
	for k := range len(b) {
		got, n, err := ParseClientMessage(b[:k])
		if err != ErrShort || got != nil || n != 0 {
			t.Fatalf("ParseClientMessage(b[:%d]) = %v, %d, %v; want nil, 0, ErrShort", k, got, n, err)
		}
	}
	if _, n, err := ParseClientMessage(b); err != nil || n != len(b) {
		t.Fatalf("whole message: n=%d err=%v", n, err)
	}
}

func TestParseServerTruncation(t *testing.T) {
	m := ServerMessage{Source: testServerSource(), Options: "V4,tls-server", PeerInfo: "IV_PROTO=2\n"}
	b := m.Marshal()
	// The message may end after the options, the username or the password.
	endOptions := serverFixedLen + len(str(m.Options))
	boundaries := map[int]bool{endOptions: true, endOptions + 2: true, endOptions + 4: true}
	for k := range len(b) {
		got, n, err := ParseServerMessage(b[:k])
		if boundaries[k] {
			if err != nil || n != k || got.Options != m.Options || got.PeerInfo != "" {
				t.Fatalf("ParseServerMessage(b[:%d]) = %+v, %d, %v; want the options and %d bytes", k, got, n, err, k)
			}
			continue
		}
		if err != ErrShort || got != nil || n != 0 {
			t.Fatalf("ParseServerMessage(b[:%d]) = %v, %d, %v; want nil, 0, ErrShort", k, got, n, err)
		}
	}
}

func TestParseServerShortForms(t *testing.T) {
	src := testServerSource()
	head := cat([]byte{0, 0, 0, 0, 2}, src.Random1[:], src.Random2[:])
	tests := []struct {
		name     string
		b        []byte
		n        int
		options  string
		peerInfo string
	}{
		{"options only", cat(head, str("V4,tls-server")), 0, "V4,tls-server", ""},
		{"empty options only", cat(head, str("")), 0, "", ""},
		{"no peer info", cat(head, str("V4"), str(""), str("")), 0, "V4", ""},
		// A non-empty "username" from a server is skipped, not taken as peer info.
		{"odd username", cat(head, str("V4"), str("someone")), 0, "V4", ""},
		{"full", cat(head, str("V4"), str(""), str(""), str("IV_X=1\n")), 0, "V4", "IV_X=1\n"},
		// Nothing after the third string is read.
		{"trailing", cat(head, str("V4"), str(""), str(""), str("IV_X=1\n"), []byte("PUSH_REPLY,x\x00")),
			len(cat(head, str("V4"), str(""), str(""), str("IV_X=1\n"))), "V4", "IV_X=1\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := tt.n
			if want == 0 {
				want = len(tt.b)
			}
			got, n, err := ParseServerMessage(tt.b)
			if err != nil {
				t.Fatalf("ParseServerMessage: %v", err)
			}
			if n != want || got.Options != tt.options || got.PeerInfo != tt.peerInfo || got.Source != src {
				t.Fatalf("got %+v, %d; want options %q, peer info %q, %d bytes", got, n, tt.options, tt.peerInfo, want)
			}
		})
	}
}

func TestParseFixedFields(t *testing.T) {
	src := testServerSource()
	msg := func(u32 uint32, km byte) []byte {
		b := binary.BigEndian.AppendUint32(nil, u32)
		b = append(b, km)
		return cat(b, src.Random1[:], src.Random2[:], str("V4"))
	}
	tests := []struct {
		name string
		b    []byte
		err  error
	}{
		{"nonzero u32 accepted", msg(0xdeadbeef, 2), nil},
		{"flag bits ignored", msg(0, 0xf2), nil},
		{"key method 1", msg(0, 1), ErrBad},
		{"key method 3", msg(0, 3), ErrBad},
		{"key method 0x20", msg(0, 0x20), ErrBad},
		// The key method fails fast, before the rest of the fixed part.
		{"bad key method, short", msg(0, 1)[:6], ErrBad},
		{"empty", nil, ErrShort},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := ParseServerMessage(tt.b)
			if !errors.Is(err, tt.err) || (tt.err == nil) != (err == nil) {
				t.Fatalf("ParseServerMessage: %v, want %v", err, tt.err)
			}
			if len(tt.b) < 5 {
				return
			}
			// The client parser checks the same fields.
			cb := cat(tt.b[:5], make([]byte, 48), tt.b[5:], str(""), str(""), str(""))
			_, _, err = ParseClientMessage(cb)
			if !errors.Is(err, tt.err) || (tt.err == nil) != (err == nil) {
				t.Fatalf("ParseClientMessage: %v, want %v", err, tt.err)
			}
		})
	}
}

func TestParseStrings(t *testing.T) {
	src := testServerSource()
	head := cat([]byte{0, 0, 0, 0, 2}, src.Random1[:], src.Random2[:])
	tests := []struct {
		name    string
		strs    []byte
		err     error
		options string
	}{
		{"zero length is empty", []byte{0, 0}, nil, ""},
		{"lone NUL is empty", []byte{0, 1, 0}, nil, ""},
		{"no NUL", []byte{0, 3, 'a', 'b', 'c'}, ErrBad, ""},
		{"NUL not last", []byte{0, 3, 'a', 0, 'c'}, ErrBad, ""},
		{"inner NUL ends the string", []byte{0, 4, 'a', 0, 'c', 0}, nil, "a"},
		{"length beyond buffer", []byte{0, 9, 'a', 0}, ErrShort, ""},
		{"length cut", []byte{0}, ErrShort, ""},
		{"bad username", cat(str("V4"), []byte{0, 2, 'x', 'y'}), ErrBad, ""},
		{"cut peer info", cat(str("V4"), str(""), str(""), []byte{0, 5, 'I'}), ErrShort, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, n, err := ParseServerMessage(cat(head, tt.strs))
			if !errors.Is(err, tt.err) || (tt.err == nil) != (err == nil) {
				t.Fatalf("err = %v, want %v", err, tt.err)
			}
			if err != nil {
				if m != nil || n != 0 {
					t.Fatalf("error with a result: %v, %d", m, n)
				}
				return
			}
			if m.Options != tt.options {
				t.Fatalf("options %q, want %q", m.Options, tt.options)
			}
		})
	}
}

func TestStringBudget(t *testing.T) {
	src := testClientSource()
	head := cat([]byte{0, 0, 0, 0, 2}, src.PreMaster[:], src.Random1[:], src.Random2[:])
	biggest := strings.Repeat("o", maxStringLen)

	// Exactly MaxStrings bytes of strings parses.
	b := cat(head, str(biggest), str(""), str(""), []byte{0, 1, 0})
	m, n, err := ParseClientMessage(b)
	if err != nil || n != len(b) || m.Options != biggest {
		t.Fatalf("at the limit: n=%d err=%v", n, err)
	}
	if len(b) > MaxMessageLen {
		t.Fatalf("a message at the limit is %d bytes, MaxMessageLen is %d", len(b), MaxMessageLen)
	}

	// One more byte is rejected as soon as its length is seen, without
	// waiting for the bytes.
	b = cat(head, str(biggest), str(""), str(""), []byte{0, 2})
	if _, _, err := ParseClientMessage(b); !errors.Is(err, ErrBad) {
		t.Fatalf("past the limit: %v, want ErrBad", err)
	}
	sb := cat([]byte{0, 0, 0, 0, 2}, make([]byte, 64), str(biggest), []byte{0, 2})
	if _, _, err := ParseServerMessage(sb); !errors.Is(err, ErrBad) {
		t.Fatalf("server past the limit: %v, want ErrBad", err)
	}
}

func TestMarshalStringEdges(t *testing.T) {
	src := testClientSource()
	// Too long for a u16 length: cut to the longest string one describes.
	huge := strings.Repeat("h", maxStringLen+100)
	m := ClientMessage{Source: src, Options: huge}
	b := m.Marshal()
	got, n, err := ParseClientMessage(b)
	if err != nil || n != len(b) {
		t.Fatalf("ParseClientMessage: n=%d err=%v", n, err)
	}
	if got.Options != huge[:maxStringLen] {
		t.Fatalf("options of %d bytes, want %d", len(got.Options), maxStringLen)
	}

	// An inner NUL ends a string.
	m = ClientMessage{Source: src, Options: "V4", Username: "a\x00b", Password: "\x00", PeerInfo: "IV_X=1\n\x00junk"}
	b = m.Marshal()
	got, n, err = ParseClientMessage(b)
	if err != nil || n != len(b) {
		t.Fatalf("ParseClientMessage: n=%d err=%v", n, err)
	}
	if got.Username != "a" || got.Password != "" || got.PeerInfo != "IV_X=1\n" {
		t.Fatalf("strings not cut at the NUL: %q %q %q", got.Username, got.Password, got.PeerInfo)
	}
	// The cut password is written as an empty string, the bare u16 0.
	if !bytes.Contains(b, cat(str("a"), []byte{0, 0}, str("IV_X=1\n"))) {
		t.Fatal("cut strings not encoded as C strings")
	}
}

type errReader struct{ n int }

func (r *errReader) Read(p []byte) (int, error) {
	if r.n == 0 {
		return 0, io.EOF
	}
	k := min(r.n, len(p))
	for i := range k {
		p[i] = 0x55
	}
	r.n -= k
	return k, nil
}

func TestNewClientKeySource(t *testing.T) {
	seq := make([]byte, 48+32+32)
	seqBytes(seq, 0)
	s, err := NewClientKeySource(bytes.NewReader(seq))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s.PreMaster[:], seq[:48]) || !bytes.Equal(s.Random1[:], seq[48:80]) || !bytes.Equal(s.Random2[:], seq[80:]) {
		t.Fatal("key source not filled in order pre-master, random1, random2")
	}
	for _, n := range []int{0, 10, 48, 100, 111} {
		s, err := NewClientKeySource(&errReader{n: n})
		if err == nil || s != nil {
			t.Fatalf("%d random bytes: got %v, %v; want an error", n, s, err)
		}
		if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("%d random bytes: error %v does not wrap the reader's", n, err)
		}
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The vectors were computed with OpenSSL 3's TLS1-PRF KDF (digest
// MD5-SHA1), an implementation independent of this one, e.g.
//
//	openssl kdf -keylen 37 -kdfopt digest:MD5-SHA1 -kdfopt hexsecret:0102030405 -kdfopt seed:abc TLS1-PRF
//
// The first is the widely published TLS 1.0/1.1 PRF test vector (secret 48
// bytes of 0xab, label "PRF Testvector", seed 64 bytes of 0xcd), which
// OpenSSL reproduces.
func TestTLS1PRFVectors(t *testing.T) {
	tests := []struct {
		name   string
		secret []byte
		seed   []byte
		want   string
	}{
		{
			"published", bytes.Repeat([]byte{0xab}, 48),
			append([]byte("PRF Testvector"), bytes.Repeat([]byte{0xcd}, 64)...),
			`d3d4d1e349b5d515044666d51de32bab258cb521b6b053463e354832fd976754
			 443bcf9a296519bc289abcbc1187e4ebd31e602353776c408aafb74cbc85eff6
			 9255f9788faa184cbb957a9819d84a5d7eb006eb459d3ae8de9810454b8b2d8f
			 1afbc655a8c9a013`,
		},
		{
			"odd secret", []byte{1, 2, 3, 4, 5}, []byte("abc"),
			"1e18dc67a1c5cb6f825781ee519e40b7c94e00b8e4650b49819e7de59ee4739d5a53964f70",
		},
		{"empty secret", nil, []byte("abc"), "f9d4132a3f3c3c3bb110a074f3756d3a8a5eef4f"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := mustHex(t, tt.want)
			got := make([]byte, len(want))
			TLS1PRF(tt.secret, tt.seed, got)
			if !bytes.Equal(got, want) {
				t.Fatalf("TLS1PRF:\n got %x\nwant %x", got, want)
			}
			// A shorter output is a prefix of a longer one.
			short := make([]byte, len(want)/3)
			TLS1PRF(tt.secret, tt.seed, short)
			if !bytes.Equal(short, want[:len(short)]) {
				t.Fatalf("short output %x is not a prefix of %x", short, want)
			}
		})
	}
}

// refPHash is P_hash written out directly from RFC 2246 section 5: build
// A(1..n) first, then concatenate HMAC(secret, A(i) || seed).
func refPHash(h func() hash.Hash, secret, seed []byte, n int) []byte {
	mac := func(parts ...[]byte) []byte {
		m := hmac.New(h, secret)
		for _, p := range parts {
			m.Write(p)
		}
		return m.Sum(nil)
	}
	size := h().Size()
	blocks := (n + size - 1) / size
	a := make([][]byte, blocks+1)
	a[0] = seed
	for i := 1; i <= blocks; i++ {
		a[i] = mac(a[i-1])
	}
	var out []byte
	for i := 1; i <= blocks; i++ {
		out = append(out, mac(a[i], seed)...)
	}
	return out[:n]
}

func TestTLS1PRFStructure(t *testing.T) {
	seed := []byte("some label and seed")
	for slen := 0; slen <= 9; slen++ {
		secret := make([]byte, slen)
		seqBytes(secret, 0x30)
		// The halves, by hand: for 5 bytes S1 = s[0:3] and S2 = s[2:5].
		h := (slen + 1) / 2
		s1, s2 := secret[:h], secret[slen-h:]
		if slen%2 == 1 && slen > 0 && s1[len(s1)-1] != s2[0] {
			t.Fatalf("len %d: halves should share the middle byte", slen)
		}
		for _, n := range []int{0, 1, 15, 16, 20, 21, 48, 100, 256} {
			md := refPHash(md5.New, s1, seed, n)
			sh := refPHash(sha1.New, s2, seed, n)
			want := make([]byte, n)
			for i := range want {
				want[i] = md[i] ^ sh[i]
			}
			got := make([]byte, n)
			TLS1PRF(secret, seed, got)
			if !bytes.Equal(got, want) {
				t.Fatalf("secret len %d, out len %d:\n got %x\nwant %x", slen, n, got, want)
			}
			// pHash itself, both modes.
			p := make([]byte, n)
			pHash(sha1.New, s2, seed, p, false)
			if !bytes.Equal(p, sh) {
				t.Fatalf("pHash(SHA1) len %d:\n got %x\nwant %x", n, p, sh)
			}
			pHash(md5.New, s1, seed, p, true)
			if !bytes.Equal(p, want) {
				t.Fatalf("pHash xor len %d:\n got %x\nwant %x", n, p, want)
			}
		}
	}
}

func testSIDs() (c, s wire.SessionID) {
	seqBytes(c[:], 0x01)
	seqBytes(s[:], 0xf1)
	return c, s
}

// The expected key2 was computed with OpenSSL's TLS1-PRF in the two steps
// of the package doc:
//
//	master = PRF(pre_master, "OpenVPN master secret", c.random1 || s.random1, 48)
//	key2   = PRF(master, "OpenVPN key expansion", c.random2 || s.random2 || csid || ssid, 256)
//
// with pre_master = 00..2f, c.random1 = 40..5f, c.random2 = 80..9f,
// s.random1 = a0..bf, s.random2 = c0..df, csid = 01..08, ssid = f1..f8.
func TestDeriveKey2PRFVector(t *testing.T) {
	c, s := testClientSource(), testServerSource()
	csid, ssid := testSIDs()
	want := mustHex(t, `
		cbbb2cc7b10f1c99794327c27b732418212a6ac99c5a69647f1fed6ebf4c50e3
		a57ea52029ec76ad604981364cb5d438bc40dabd0e4e05d75f6be739470ca30b
		477e2f06d4c390b35c031115e144275cfc403a2ec5eb5c19928afeefadd0bbe3
		f43aa63d93e68253f5ad12f3dcb746c887e11dfadc71d896b8e5891e1667215e
		9acb827bc1b91b167825996a20945d10d802830773a99334947b05f0ef06acda
		66324025209c72f5232cb028881e6d34887c0323b1e66b02ce81c98d85b8a36e
		2f807af8e9e80d5fb2af277ed32ee972bc4b5811344286df216d80f6e978318a
		9f2dae73c2afe2e00ee98754522fdca6da1ff529a9888a08fc7fec0a9716514f`)
	k := DeriveKey2PRF(&c, &s, csid, ssid)
	got := cat(k[0].Cipher[:], k[0].HMAC[:], k[1].Cipher[:], k[1].HMAC[:])
	if !bytes.Equal(got, want) {
		t.Fatalf("DeriveKey2PRF:\n got %x\nwant %x", got, want)
	}

	// The same through TLS1PRF directly, as the package doc spells it.
	master := make([]byte, 48)
	TLS1PRF(c.PreMaster[:], cat([]byte("OpenVPN master secret"), c.Random1[:], s.Random1[:]), master)
	if want := mustHex(t, "ee7017d546df4c2275a79eb7b14a401d9d51e0cbb764b93b1fb11713532002c45e3d921a21277bb6ba2ff9f424757afb"); !bytes.Equal(master, want) {
		t.Fatalf("master:\n got %x\nwant %x", master, want)
	}
}

func TestDeriveKey2PRFInputs(t *testing.T) {
	c, s := testClientSource(), testServerSource()
	csid, ssid := testSIDs()
	base := DeriveKey2PRF(&c, &s, csid, ssid)
	if again := DeriveKey2PRF(&c, &s, csid, ssid); *again != *base {
		t.Fatal("DeriveKey2PRF is not deterministic")
	}
	// Every input matters, and the session ids are not interchangeable.
	mutations := map[string]func(c *ClientKeySource, s *ServerKeySource, csid, ssid *wire.SessionID){
		"pre-master":     func(c *ClientKeySource, _ *ServerKeySource, _, _ *wire.SessionID) { c.PreMaster[47] ^= 1 },
		"client random1": func(c *ClientKeySource, _ *ServerKeySource, _, _ *wire.SessionID) { c.Random1[0] ^= 1 },
		"client random2": func(c *ClientKeySource, _ *ServerKeySource, _, _ *wire.SessionID) { c.Random2[0] ^= 1 },
		"server random1": func(_ *ClientKeySource, s *ServerKeySource, _, _ *wire.SessionID) { s.Random1[31] ^= 1 },
		"server random2": func(_ *ClientKeySource, s *ServerKeySource, _, _ *wire.SessionID) { s.Random2[31] ^= 1 },
		"client sid":     func(_ *ClientKeySource, _ *ServerKeySource, csid, _ *wire.SessionID) { csid[7] ^= 1 },
		"server sid":     func(_ *ClientKeySource, _ *ServerKeySource, _, ssid *wire.SessionID) { ssid[0] ^= 1 },
		"swapped sids":   func(_ *ClientKeySource, _ *ServerKeySource, csid, ssid *wire.SessionID) { *csid, *ssid = *ssid, *csid },
	}
	for name, mutate := range mutations {
		c2, s2, csid2, ssid2 := c, s, csid, ssid
		mutate(&c2, &s2, &csid2, &ssid2)
		if k := DeriveKey2PRF(&c2, &s2, csid2, ssid2); *k == *base {
			t.Errorf("%s does not change key2", name)
		}
	}
}

func TestKey2Orientation(t *testing.T) {
	ekm := make([]byte, EKMLength)
	seqBytes(ekm, 0)
	k, err := Key2FromEKM(ekm)
	if err != nil {
		t.Fatal(err)
	}
	// key2[0] = bytes 0..127 (cipher 0..63, hmac 64..127); key2[1] = 128..255.
	if !bytes.Equal(k[0].Cipher[:], ekm[0:64]) || !bytes.Equal(k[0].HMAC[:], ekm[64:128]) ||
		!bytes.Equal(k[1].Cipher[:], ekm[128:192]) || !bytes.Equal(k[1].HMAC[:], ekm[192:256]) {
		t.Fatal("Key2FromEKM layout is not cipher/hmac per key, key 0 first")
	}
	if k.ClientSend() != &k[0] || k.ClientRecv() != &k[1] {
		t.Fatal("the client must send with key2[0] and receive with key2[1]")
	}
	if k.ClientSend() != k.ServerRecv() || k.ClientRecv() != k.ServerSend() {
		t.Fatal("one side's send key must be the other side's receive key")
	}
	ekm[0] ^= 0xff
	if k[0].Cipher[0] == ekm[0] {
		t.Fatal("Key2FromEKM aliases its input")
	}
	for _, n := range []int{0, 1, 255, 257, 512} {
		if _, err := Key2FromEKM(make([]byte, n)); err == nil {
			t.Errorf("Key2FromEKM accepted %d bytes", n)
		}
	}
}

func TestPeerInfoString(t *testing.T) {
	tests := []struct {
		name string
		p    PeerInfo
		want string
	}{
		{
			"full",
			PeerInfo{
				Version: "2.6.12", Platform: "android",
				Proto:   IVProtoDataV2 | IVProtoRequestPush | IVProtoTLSKeyExport | IVProtoCCExitNotify | IVProtoDNSOption,
				Ciphers: []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"},
				MTU:     1600, Stubs: true, Decompress: true,
				Extra: []string{"IV_GUI_VER=xray", "", "UV_X=1"},
			},
			"IV_VER=2.6.12\nIV_PLAT=android\nIV_PROTO=206\nIV_NCP=2\nIV_CIPHERS=AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305\nIV_MTU=1600\n" +
				"IV_LZO_STUB=1\nIV_COMP_STUB=1\nIV_COMP_STUBv2=1\nIV_LZO=1\nIV_LZ4=1\nIV_LZ4v2=1\nIV_GUI_VER=xray\nUV_X=1\n",
		},
		{
			"minimal",
			PeerInfo{Version: "2.6.12", Platform: "linux", Proto: IVProtoDataV2},
			"IV_VER=2.6.12\nIV_PLAT=linux\nIV_PROTO=2\n",
		},
		{"empty", PeerInfo{}, "IV_PROTO=0\n"},
		{
			"stubs only",
			PeerInfo{Proto: 990, Ciphers: []string{"AES-256-GCM"}, Stubs: true},
			"IV_PROTO=990\nIV_NCP=2\nIV_CIPHERS=AES-256-GCM\nIV_LZO_STUB=1\nIV_COMP_STUB=1\nIV_COMP_STUBv2=1\n",
		},
		{
			"decompress only, all bits",
			PeerInfo{Proto: 1<<10 - 2, Decompress: true},
			"IV_PROTO=1022\nIV_LZO=1\nIV_LZ4=1\nIV_LZ4v2=1\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.String(); got != tt.want {
				t.Fatalf("String():\n got %q\nwant %q", got, tt.want)
			}
		})
	}
}

// The expected strings are what OpenVPN 2.6.19 logs as its "Local Options
// String" at verb 9 for the equivalent client options (noted per case),
// except where noted.
func TestOptionsString(t *testing.T) {
	tests := []struct {
		name string
		o    OCCOptions
		want string
	}{
		{
			"udp aes-256-gcm", // --cipher AES-256-GCM
			OCCOptions{Cipher: "AES-256-GCM", Auth: "[null-digest]", KeySize: 256},
			"V4,dev-type tun,link-mtu 1549,tun-mtu 1500,proto UDPv4,cipher AES-256-GCM,auth [null-digest],keysize 256,key-method 2,tls-client",
		},
		{
			"defaults from the cipher", // --cipher AES-128-GCM --auth SHA256
			OCCOptions{Cipher: "AES-128-GCM", Auth: "SHA256"},
			"V4,dev-type tun,link-mtu 1549,tun-mtu 1500,proto UDPv4,cipher AES-128-GCM,auth [null-digest],keysize 128,key-method 2,tls-client",
		},
		{
			"chacha", // --cipher CHACHA20-POLY1305
			OCCOptions{Cipher: "CHACHA20-POLY1305"},
			"V4,dev-type tun,link-mtu 1534,tun-mtu 1500,proto UDPv4,cipher CHACHA20-POLY1305,auth [null-digest],keysize 256,key-method 2,tls-client",
		},
		{
			"tcp chacha", // --proto tcp-client --cipher CHACHA20-POLY1305
			OCCOptions{TCP: true, Cipher: "CHACHA20-POLY1305"},
			"V4,dev-type tun,link-mtu 1536,tun-mtu 1500,proto TCPv4_CLIENT,cipher CHACHA20-POLY1305,auth [null-digest],keysize 256,key-method 2,tls-client",
		},
		{
			"udp6 names v4", // --remote ::1 --proto udp6 --cipher AES-256-GCM
			OCCOptions{IPv6: true, Cipher: "AES-256-GCM"},
			"V4,dev-type tun,link-mtu 1549,tun-mtu 1500,proto UDPv4,cipher AES-256-GCM,auth [null-digest],keysize 256,key-method 2,tls-client",
		},
		{
			"tcp6 names v4", // --remote ::1 --proto tcp6-client --cipher AES-256-GCM
			OCCOptions{TCP: true, IPv6: true, Cipher: "AES-256-GCM"},
			"V4,dev-type tun,link-mtu 1551,tun-mtu 1500,proto TCPv4_CLIENT,cipher AES-256-GCM,auth [null-digest],keysize 256,key-method 2,tls-client",
		},
		{
			"comp-lzo", // --cipher AES-256-GCM --comp-lzo
			OCCOptions{Cipher: "AES-256-GCM", CompLZO: true},
			"V4,dev-type tun,link-mtu 1550,tun-mtu 1500,proto UDPv4,comp-lzo,cipher AES-256-GCM,auth [null-digest],keysize 256,key-method 2,tls-client",
		},
		{
			"tls-auth keydir 1", // --cipher AES-256-GCM --tls-auth ta.key 1
			OCCOptions{Cipher: "AES-256-GCM", TLSAuth: true, KeyDir: "1"},
			"V4,dev-type tun,link-mtu 1549,tun-mtu 1500,proto UDPv4,keydir 1,cipher AES-256-GCM,auth [null-digest],keysize 256,tls-auth,key-method 2,tls-client",
		},
		{
			"tls-auth keydir 0", // --cipher AES-256-GCM --tls-auth ta.key 0
			OCCOptions{Cipher: "AES-256-GCM", TLSAuth: true, KeyDir: "0"},
			"V4,dev-type tun,link-mtu 1549,tun-mtu 1500,proto UDPv4,keydir 0,cipher AES-256-GCM,auth [null-digest],keysize 256,tls-auth,key-method 2,tls-client",
		},
		{
			"tls-auth no direction", // --cipher AES-256-CBC --auth SHA1 --tls-auth ta.key (2.6 omits the CBC cipher here)
			OCCOptions{Cipher: "AES-256-CBC", Auth: "SHA1", TLSAuth: true},
			"V4,dev-type tun,link-mtu 1557,tun-mtu 1500,proto UDPv4,cipher AES-256-CBC,auth SHA1,keysize 256,tls-auth,key-method 2,tls-client",
		},
		{
			"tun-mtu 1400", // --cipher AES-256-GCM --tun-mtu 1400
			OCCOptions{Cipher: "AES-256-GCM", TunMTU: 1400},
			"V4,dev-type tun,link-mtu 1449,tun-mtu 1400,proto UDPv4,cipher AES-256-GCM,auth [null-digest],keysize 256,key-method 2,tls-client",
		},
		{
			"cbc sha1", // --data-ciphers AES-256-CBC --cipher AES-256-CBC --auth SHA1
			OCCOptions{Cipher: "AES-256-CBC", Auth: "SHA1", KeySize: 256},
			"V4,dev-type tun,link-mtu 1557,tun-mtu 1500,proto UDPv4,cipher AES-256-CBC,auth SHA1,keysize 256,key-method 2,tls-client",
		},
		{
			"cbc default auth", // as above, Auth left to its SHA1 default
			OCCOptions{Cipher: "AES-256-CBC"},
			"V4,dev-type tun,link-mtu 1557,tun-mtu 1500,proto UDPv4,cipher AES-256-CBC,auth SHA1,keysize 256,key-method 2,tls-client",
		},
		{
			"cbc sha256", // --cipher AES-256-CBC --auth SHA256 (link-mtu 1569; 2.6 omits the cipher)
			OCCOptions{Cipher: "AES-256-CBC", Auth: "SHA256"},
			"V4,dev-type tun,link-mtu 1569,tun-mtu 1500,proto UDPv4,cipher AES-256-CBC,auth SHA256,keysize 256,key-method 2,tls-client",
		},
		{
			"tcp cbc sha512", // --proto tcp-client --cipher AES-128-CBC --auth SHA512 (link-mtu 1603; 2.6 omits the cipher)
			OCCOptions{TCP: true, Cipher: "AES-128-CBC", Auth: "SHA512"},
			"V4,dev-type tun,link-mtu 1603,tun-mtu 1500,proto TCPv4_CLIENT,cipher AES-128-CBC,auth SHA512,keysize 128,key-method 2,tls-client",
		},
		{
			"cbc sha384 comp-lzo", // --cipher AES-256-CBC --auth SHA384 --comp-lzo no (link-mtu 1586; 2.6 omits the cipher)
			OCCOptions{Cipher: "AES-256-CBC", Auth: "SHA384", CompLZO: true},
			"V4,dev-type tun,link-mtu 1586,tun-mtu 1500,proto UDPv4,comp-lzo,cipher AES-256-CBC,auth SHA384,keysize 256,key-method 2,tls-client",
		},
		{
			"camellia", // --data-ciphers CAMELLIA-256-CBC --cipher CAMELLIA-256-CBC --auth SHA1
			OCCOptions{Cipher: "CAMELLIA-256-CBC", Auth: "SHA1"},
			"V4,dev-type tun,link-mtu 1557,tun-mtu 1500,proto UDPv4,cipher CAMELLIA-256-CBC,auth SHA1,keysize 256,key-method 2,tls-client",
		},
		{
			"cfb", // --data-ciphers AES-256-CFB --cipher AES-256-CFB --auth SHA1
			OCCOptions{Cipher: "AES-256-CFB", Auth: "SHA1"},
			"V4,dev-type tun,link-mtu 1561,tun-mtu 1500,proto UDPv4,cipher AES-256-CFB,auth SHA1,keysize 256,key-method 2,tls-client",
		},
		{
			"ofb", // --data-ciphers AES-128-OFB --cipher AES-128-OFB --auth SHA256
			OCCOptions{Cipher: "AES-128-OFB", Auth: "SHA256"},
			"V4,dev-type tun,link-mtu 1573,tun-mtu 1500,proto UDPv4,cipher AES-128-OFB,auth SHA256,keysize 128,key-method 2,tls-client",
		},
		{
			"bf-cbc", // --cipher BF-CBC --auth SHA1 (2.6 omits the cipher)
			OCCOptions{Cipher: "BF-CBC", Auth: "SHA1"},
			"V4,dev-type tun,link-mtu 1541,tun-mtu 1500,proto UDPv4,cipher BF-CBC,auth SHA1,keysize 128,key-method 2,tls-client",
		},
		{
			"3des", // --cipher DES-EDE3-CBC --auth SHA1 (2.6 omits the cipher)
			OCCOptions{Cipher: "DES-EDE3-CBC", Auth: "SHA1"},
			"V4,dev-type tun,link-mtu 1541,tun-mtu 1500,proto UDPv4,cipher DES-EDE3-CBC,auth SHA1,keysize 192,key-method 2,tls-client",
		},
		{
			"no cipher set", // no --cipher at all: exact 2.6.19 output
			OCCOptions{},
			"V4,dev-type tun,link-mtu 1541,tun-mtu 1500,proto UDPv4,auth SHA1,keysize 128,key-method 2,tls-client",
		},
		{
			"cipher none", // --data-ciphers none --cipher none --auth SHA1: exact 2.6.19 output
			OCCOptions{Cipher: "none", Auth: "SHA1"},
			"V4,dev-type tun,link-mtu 1525,tun-mtu 1500,proto UDPv4,auth SHA1,keysize 0,key-method 2,tls-client",
		},
		{
			"omitted cbc cipher, explicit numbers", // --proto tcp6-client --cipher AES-256-CBC --auth SHA1 --tls-auth ta.key 1 --comp-lzo: exact
			OCCOptions{TCP: true, IPv6: true, LinkMTU: 1560, KeySize: 256, Auth: "SHA1", CompLZO: true, TLSAuth: true, KeyDir: "1"},
			"V4,dev-type tun,link-mtu 1560,tun-mtu 1500,proto TCPv4_CLIENT,comp-lzo,keydir 1,auth SHA1,keysize 256,tls-auth,key-method 2,tls-client",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := OptionsString(tt.o); got != tt.want {
				t.Fatalf("OptionsString:\n got %q\nwant %q", got, tt.want)
			}
		})
	}
}

func TestSecretsRedacted(t *testing.T) {
	var k2 Key2
	for i := range k2 {
		seqBytes(k2[i].Cipher[:], 0x11)
		seqBytes(k2[i].HMAC[:], 0x11)
	}
	src := testClientSource()
	for i := range src.PreMaster {
		src.PreMaster[i] = 0x11
	}
	msg := ClientMessage{Source: src, Options: "V4", Username: "alice", Password: "hunter2-password", PeerInfo: "IV_PROTO=2\n"}
	values := []any{k2, &k2, k2[0], &k2[0], src, &src, msg, &msg}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%X", "%d", "%q"} {
		for _, v := range values {
			out := fmt.Sprintf(verb, v)
			for _, leak := range []string{"hunter2", "1112131415", "111111", "11 12 13", "17 18 19", "17 17 17"} {
				if strings.Contains(strings.ToLower(out), leak) {
					t.Fatalf("fmt %s of %T leaks secret material: %s", verb, v, out)
				}
			}
			if !strings.Contains(out, "REDACTED") {
				t.Fatalf("fmt %s of %T: %s", verb, v, out)
			}
		}
	}
	if out := fmt.Sprint(msg); !strings.Contains(out, `Username:"alice"`) || !strings.Contains(out, `Options:"V4"`) {
		t.Fatalf("non-secret fields missing from %s", out)
	}
}
