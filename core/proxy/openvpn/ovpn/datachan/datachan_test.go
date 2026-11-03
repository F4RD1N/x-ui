package datachan

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math/rand/v2"
	"runtime"
	"sync"
	"testing"

	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/compress"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/handshake"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/wire"
)

var (
	aeadCiphers = []string{"AES-128-GCM", "AES-192-GCM", "AES-256-GCM", "CHACHA20-POLY1305"}
	cbcCiphers  = []string{"AES-128-CBC", "AES-192-CBC", "AES-256-CBC", "BF-CBC"}
	allDigests  = []string{"MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512"}
	allModes    = []compress.Mode{compress.None, compress.LZO, compress.Swap, compress.V2}
	peerIDs     = []uint32{wire.NoPeerID, 0x123456}
)

// compressReady reports whether package compress, written alongside this
// one, is implemented yet. Until it is, its functions panic with the string
// "TODO" and the tests of the compression framings skip; any other panic
// propagates.
var compressReady = sync.OnceValue(func() (ready bool) {
	defer func() {
		if r := recover(); r != nil {
			if r != "TODO" {
				panic(r)
			}
			ready = false
		}
	}()
	framed := compress.Frame(compress.LZO, nil, []byte{0x45})
	_, _ = compress.Unframe(compress.LZO, nil, framed, 100)
	return true
})

// needCompress skips t if m needs package compress and it is not there yet.
func needCompress(t testing.TB, m compress.Mode) {
	t.Helper()
	if m != compress.None && !compressReady() {
		t.Skip("package compress is not implemented yet")
	}
}

func modeName(m compress.Mode) string {
	switch m {
	case compress.None:
		return "none"
	case compress.LZO:
		return "lzo"
	case compress.Swap:
		return "swap"
	case compress.V2:
		return "v2"
	}
	return fmt.Sprintf("mode%d", int(m))
}

type suite struct{ cipher, digest string }

func (s suite) String() string {
	if s.digest == "" {
		return s.cipher
	}
	return s.cipher + "/" + s.digest
}

func (s suite) aead() bool {
	for _, c := range aeadCiphers {
		if c == s.cipher {
			return true
		}
	}
	return false
}

// allSuites is every AEAD cipher (digest ignored) and every CBC cipher with
// every digest.
func allSuites() []suite {
	var out []suite
	for _, c := range aeadCiphers {
		out = append(out, suite{c, ""})
	}
	for _, c := range cbcCiphers {
		for _, d := range allDigests {
			out = append(out, suite{c, d})
		}
	}
	return out
}

func testKey2(seed uint64) *handshake.Key2 {
	r := rand.New(rand.NewPCG(seed, 0x5eed))
	var k handshake.Key2
	for i := range k {
		for j := range k[i].Cipher {
			k[i].Cipher[j] = byte(r.Uint32())
			k[i].HMAC[j] = byte(r.Uint32())
		}
	}
	return &k
}

// countingReader is a deterministic stand-in for crypto/rand.
type countingReader struct{ n byte }

func (r *countingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.n
		r.n++
	}
	return len(p), nil
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

type pair struct {
	client, server *Channel
	cks, sks       *KeyState
	k2             *handshake.Key2
}

// newPair builds a client and a server channel sharing one key id: the
// server's key state is the client's with the directions swapped.
func newPair(t testing.TB, s suite, keyID uint8, opts Options) *pair {
	t.Helper()
	k2 := testKey2(uint64(keyID) + 1)
	cks, err := NewKeyState(keyID, s.cipher, s.digest, k2.ClientSend(), k2.ClientRecv())
	if err != nil {
		t.Fatalf("client NewKeyState(%v): %v", s, err)
	}
	sks, err := NewKeyState(keyID, s.cipher, s.digest, k2.ServerSend(), k2.ServerRecv())
	if err != nil {
		t.Fatalf("server NewKeyState(%v): %v", s, err)
	}
	p := &pair{client: New(opts), server: New(opts), cks: cks, sks: sks, k2: k2}
	p.client.SetPrimary(cks)
	p.server.SetPrimary(sks)
	return p
}

func testPayloads() [][]byte {
	r := rand.New(rand.NewPCG(1, 2))
	var ps [][]byte
	for _, n := range []int{1, 2, 3, 4, 7, 8, 9, 11, 12, 13, 15, 16, 17, 20, 23, 24, 25, 31, 32, 33, 64, 100, 1279, 1400, 1500, 9000} {
		p := make([]byte, n)
		for i := range p {
			p[i] = byte(r.Uint32())
		}
		p[0] = 0x45
		ps = append(ps, p)
	}
	for _, first := range []byte{0x50, 0xFA, 0xFB, 0x66, 0x69, 0x00, 0x60, 0xFF} {
		ps = append(ps, append([]byte{first}, "framing-sensitive first byte"...))
	}
	ps = append(ps, []byte{0x50}, []byte{0x50, 0x00}, []byte{0x50, 0x01}, []byte{0xFB}, []byte{0xFA})
	// Almost a ping, almost OCC: plain packets.
	ps = append(ps, bytes.Clone(PingPayload[:15]), append(bytes.Clone(PingPayload[:]), 0), bytes.Clone(OCCPrefix[:15]))
	return ps
}

func refHeader(keyID uint8, peerID uint32) []byte {
	if peerID == wire.NoPeerID {
		return []byte{6<<3 | keyID}
	}
	return []byte{9<<3 | keyID, byte(peerID >> 16), byte(peerID >> 8), byte(peerID)}
}

// refSealAEAD builds an AEAD packet independently of the package.
func refSealAEAD(t testing.TB, cipherName string, k *handshake.Key, keyID uint8, peerID, pid uint32, pt []byte) []byte {
	t.Helper()
	var a cipher.AEAD
	var err error
	switch cipherName {
	case "AES-128-GCM", "AES-192-GCM", "AES-256-GCM":
		n := map[string]int{"AES-128-GCM": 16, "AES-192-GCM": 24, "AES-256-GCM": 32}[cipherName]
		var b cipher.Block
		if b, err = aes.NewCipher(k.Cipher[:n]); err == nil {
			a, err = cipher.NewGCM(b)
		}
	case "CHACHA20-POLY1305":
		a, err = chacha20poly1305.New(k.Cipher[:32])
	default:
		t.Fatalf("refSealAEAD: %s", cipherName)
	}
	if err != nil {
		t.Fatal(err)
	}
	hdr := refHeader(keyID, peerID)
	p := binary.BigEndian.AppendUint32(nil, pid)
	ad := p
	if len(hdr) == 4 {
		ad = append(bytes.Clone(hdr), p...)
	}
	nonce := append(bytes.Clone(p), k.HMAC[:8]...)
	sealed := a.Seal(nil, nonce, pt, ad)
	ct, tag := sealed[:len(pt)], sealed[len(pt):]
	out := append(hdr, p...)
	out = append(out, tag...)
	return append(out, ct...)
}

// refSealCBC builds a CBC packet independently of the package. rawPT is
// encrypted as is (pid, payload and padding already in it).
func refSealCBC(t testing.TB, cipherName, digest string, k *handshake.Key, keyID uint8, peerID uint32, iv, rawPT []byte) []byte {
	t.Helper()
	var b cipher.Block
	var err error
	switch cipherName {
	case "AES-128-CBC":
		b, err = aes.NewCipher(k.Cipher[:16])
	case "AES-192-CBC":
		b, err = aes.NewCipher(k.Cipher[:24])
	case "AES-256-CBC":
		b, err = aes.NewCipher(k.Cipher[:32])
	case "BF-CBC":
		b, err = blowfish.NewCipher(k.Cipher[:16])
	default:
		t.Fatalf("refSealCBC: %s", cipherName)
	}
	if err != nil {
		t.Fatal(err)
	}
	ct := make([]byte, len(rawPT))
	cipher.NewCBCEncrypter(b, iv[:b.BlockSize()]).CryptBlocks(ct, rawPT)
	var h func() hash.Hash
	switch digest {
	case "MD5":
		h = md5.New
	case "SHA1":
		h = sha1.New
	case "SHA224":
		h = sha256.New224
	case "SHA256":
		h = sha256.New
	case "SHA384":
		h = sha512.New384
	case "SHA512":
		h = sha512.New
	default:
		t.Fatalf("refSealCBC: %s", digest)
	}
	m := hmac.New(h, k.HMAC[:h().Size()])
	m.Write(iv[:b.BlockSize()])
	m.Write(ct)
	out := refHeader(keyID, peerID)
	out = append(out, m.Sum(nil)...)
	out = append(out, iv[:b.BlockSize()]...)
	return append(out, ct...)
}

func pkcs7(b []byte, bs int) []byte {
	n := bs - len(b)%bs
	return append(b, bytes.Repeat([]byte{byte(n)}, n)...)
}

func blockSizeOf(cipherName string) int {
	if cipherName == "BF-CBC" {
		return 8
	}
	return 16
}

func TestCanonicalCipher(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"AES-256-GCM", "AES-256-GCM", true},
		{"aes-256-gcm", "AES-256-GCM", true},
		{" Aes-256-Gcm ", "AES-256-GCM", true},
		{"id-aes256-GCM", "AES-256-GCM", true},
		{"id-aes192-GCM", "AES-192-GCM", true},
		{"id-aes128-GCM", "AES-128-GCM", true},
		{"AES-128-GCM", "AES-128-GCM", true},
		{"AES-192-GCM", "AES-192-GCM", true},
		{"ChaCha20-Poly1305", "CHACHA20-POLY1305", true},
		{"chacha20-poly1305", "CHACHA20-POLY1305", true},
		{"AES-128-CBC", "AES-128-CBC", true},
		{"aes128", "AES-128-CBC", true},
		{"aes-192-cbc", "AES-192-CBC", true},
		{"AES192", "AES-192-CBC", true},
		{"AES-256-CBC", "AES-256-CBC", true},
		{"aes256", "AES-256-CBC", true},
		{"BF-CBC", "BF-CBC", true},
		{"bf-cbc", "BF-CBC", true},
		{"bf", "BF-CBC", true},
		{"blowfish", "BF-CBC", true},
		{"", "", false},
		{"none", "", false},
		{"AES-256-CFB", "", false},
		{"AES-256-CTR", "", false},
		{"DES-EDE3-CBC", "", false},
		{"AES-256-GCM-SIV", "", false},
	}
	for _, c := range cases {
		got, ok := CanonicalCipher(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("CanonicalCipher(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestCanonicalDigest(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"SHA1", "SHA1", true},
		{"sha1", "SHA1", true},
		{"SHA-1", "SHA1", true},
		{"RSA-SHA1", "SHA1", true},
		{"ssl3-sha1", "SHA1", true},
		{"MD5", "MD5", true},
		{"rsa-md5", "MD5", true},
		{"SHA224", "SHA224", true},
		{"SHA2-224", "SHA224", true},
		{"SHA256", "SHA256", true},
		{"sha-256", "SHA256", true},
		{"SHA-256", "SHA256", true},
		{"RSA-SHA256", "SHA256", true},
		{"SHA2-256", "SHA256", true},
		{"sha384", "SHA384", true},
		{"RSA-SHA384", "SHA384", true},
		{"SHA512", "SHA512", true},
		{"sha-512", "SHA512", true},
		{"", "", false},
		{"none", "", false},
		{"SHA512-224", "", false},
		{"SHA3-256", "", false},
		{"RIPEMD160", "", false},
		{"SHA", "", false},
	}
	for _, c := range cases {
		got, ok := CanonicalDigest(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("CanonicalDigest(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
	for d, n := range map[string]int{"MD5": 16, "SHA1": 20, "SHA224": 28, "SHA256": 32, "SHA384": 48, "SHA512": 64, "sha-256": 32, "none": 0} {
		if got := DigestSize(d); got != n {
			t.Errorf("DigestSize(%q) = %d, want %d", d, got, n)
		}
	}
}

func TestIsAEADAndKeyBits(t *testing.T) {
	cases := []struct {
		cipher string
		aead   bool
		bits   int
	}{
		{"AES-128-GCM", true, 128},
		{"AES-192-GCM", true, 192},
		{"AES-256-GCM", true, 256},
		{"CHACHA20-POLY1305", true, 256},
		{"AES-128-CBC", false, 128},
		{"AES-192-CBC", false, 192},
		{"AES-256-CBC", false, 256},
		{"BF-CBC", false, 128},
		{"none", false, 0},
		{"", false, 0},
	}
	for _, c := range cases {
		if got := IsAEAD(c.cipher); got != c.aead {
			t.Errorf("IsAEAD(%q) = %v", c.cipher, got)
		}
		if got := KeyBits(c.cipher); got != c.bits {
			t.Errorf("KeyBits(%q) = %d, want %d", c.cipher, got, c.bits)
		}
	}
}

func TestNewKeyStateErrors(t *testing.T) {
	k2 := testKey2(9)
	if _, err := NewKeyState(0, "AES-256-CFB", "SHA1", k2.ClientSend(), k2.ClientRecv()); !errors.Is(err, ErrUnsupported) {
		t.Errorf("unknown cipher: %v", err)
	}
	if _, err := NewKeyState(0, "AES-256-CBC", "none", k2.ClientSend(), k2.ClientRecv()); !errors.Is(err, ErrUnsupported) {
		t.Errorf("CBC without digest: %v", err)
	}
	if _, err := NewKeyState(0, "AES-256-CBC", "SHA3-256", k2.ClientSend(), k2.ClientRecv()); !errors.Is(err, ErrUnsupported) {
		t.Errorf("unknown digest: %v", err)
	}
	if _, err := NewKeyState(0, "AES-256-GCM", "none", k2.ClientSend(), k2.ClientRecv()); err != nil {
		t.Errorf("AEAD ignores the digest: %v", err)
	}
	if _, err := NewKeyState(0, "AES-256-GCM", "", nil, k2.ClientRecv()); err == nil {
		t.Error("nil send key accepted")
	}
	if _, err := NewKeyState(0, "AES-256-GCM", "", k2.ClientSend(), nil); err == nil {
		t.Error("nil receive key accepted")
	}
	ks, err := NewKeyState(9, "aes-256-gcm", "", k2.ClientSend(), k2.ClientRecv())
	if err != nil {
		t.Fatal(err)
	}
	if ks.KeyID != 1 || ks.Cipher() != "AES-256-GCM" {
		t.Errorf("KeyID %d cipher %q, want 1 and AES-256-GCM", ks.KeyID, ks.Cipher())
	}
}

func TestRoundTrip(t *testing.T) {
	payloads := testPayloads()
	for _, s := range allSuites() {
		for _, peer := range peerIDs {
			for _, mode := range allModes {
				t.Run(fmt.Sprintf("%v/peer=%06x/%s", s, peer, modeName(mode)), func(t *testing.T) {
					needCompress(t, mode)
					p := newPair(t, s, 1, Options{PeerID: peer, Compression: mode})
					for dir, ends := range [][2]*Channel{{p.client, p.server}, {p.server, p.client}} {
						for i, pl := range payloads {
							orig := bytes.Clone(pl)
							prefix := []byte("dst")
							pkt, err := ends[0].Seal(bytes.Clone(prefix), pl)
							if err != nil {
								t.Fatalf("dir %d payload %d: Seal: %v", dir, i, err)
							}
							if !bytes.Equal(pl, orig) {
								t.Fatalf("dir %d payload %d: Seal modified the payload", dir, i)
							}
							if !bytes.HasPrefix(pkt, prefix) {
								t.Fatalf("dir %d payload %d: Seal lost dst", dir, i)
							}
							pkt = pkt[len(prefix):]
							op, keyID, gotPeer, hl, err := wire.ParseDataHeader(pkt)
							if err != nil || keyID != 1 || gotPeer != peer {
								t.Fatalf("header: op %v key %d peer %x err %v", op, keyID, gotPeer, err)
							}
							if (peer == wire.NoPeerID) != (op == wire.DataV1) {
								t.Fatalf("peer %x sent as %v", peer, op)
							}
							if mode == compress.None {
								var want int
								if s.aead() {
									want = hl + 4 + 16 + len(pl)
								} else {
									bs := blockSizeOf(s.cipher)
									want = hl + DigestSize(s.digest) + bs + (4+len(pl))/bs*bs + bs
								}
								if len(pkt) != want {
									t.Fatalf("payload %d: packet is %d bytes, want %d", i, len(pkt), want)
								}
							}
							got, kind, err := ends[1].Open([]byte("out"), pkt)
							if err != nil {
								t.Fatalf("dir %d payload %d (%d bytes): Open: %v", dir, i, len(pl), err)
							}
							if kind != KindPacket || !bytes.Equal(got, append([]byte("out"), orig...)) {
								t.Fatalf("dir %d payload %d: got kind %v %x, want %x", dir, i, kind, got, orig)
							}
						}
					}
				})
			}
		}
	}
}

func TestEmptyPayload(t *testing.T) {
	for _, s := range []suite{{"AES-256-GCM", ""}, {"AES-128-CBC", "SHA1"}, {"BF-CBC", "MD5"}} {
		for _, mode := range allModes {
			t.Run(s.String()+"/"+modeName(mode), func(t *testing.T) {
				needCompress(t, mode)
				p := newPair(t, s, 0, Options{PeerID: wire.NoPeerID, Compression: mode})
				pkt, err := p.client.Seal(nil, nil)
				if err != nil {
					t.Fatalf("Seal(empty): %v", err)
				}
				got, kind, err := p.server.Open(nil, pkt)
				if mode == compress.Swap {
					// Swap framing of an empty payload is the compress
					// package's call; it only must not panic or yield data.
					if err == nil && len(got) != 0 {
						t.Errorf("empty payload opened to %x", got)
					}
					return
				}
				if err != nil || kind != KindPacket || len(got) != 0 {
					t.Errorf("Open(empty) = %x, %v, %v", got, kind, err)
				}
			})
		}
	}
}

func TestOpenInPlace(t *testing.T) {
	for _, s := range []suite{{"AES-128-GCM", ""}, {"CHACHA20-POLY1305", ""}, {"AES-256-CBC", "SHA256"}, {"BF-CBC", "SHA1"}} {
		for _, peer := range peerIDs {
			for _, mode := range allModes {
				t.Run(fmt.Sprintf("%v/%06x/%s", s, peer, modeName(mode)), func(t *testing.T) {
					needCompress(t, mode)
					p := newPair(t, s, 3, Options{PeerID: peer, Compression: mode})
					for _, pl := range testPayloads() {
						pkt, err := p.client.Seal(nil, pl)
						if err != nil {
							t.Fatal(err)
						}
						got, kind, err := p.server.Open(pkt[:0], pkt)
						if err != nil || kind != KindPacket || !bytes.Equal(got, pl) {
							t.Fatalf("in-place Open of %d bytes = %v, %v", len(pl), kind, err)
						}
					}
				})
			}
		}
	}
}

func TestTamper(t *testing.T) {
	suites := []suite{
		{"AES-128-GCM", ""}, {"AES-192-GCM", ""}, {"AES-256-GCM", ""}, {"CHACHA20-POLY1305", ""},
		{"AES-128-CBC", "SHA1"}, {"AES-192-CBC", "MD5"}, {"AES-256-CBC", "SHA512"},
		{"BF-CBC", "SHA256"}, {"BF-CBC", "SHA224"}, {"AES-128-CBC", "SHA384"},
	}
	payload := []byte("\x45 the quick brown fox jumps over the lazy dog 0123456789")
	for _, s := range suites {
		for _, peer := range peerIDs {
			t.Run(fmt.Sprintf("%v/peer=%06x", s, peer), func(t *testing.T) {
				p := newPair(t, s, 2, Options{PeerID: peer})
				pkt, err := p.client.Seal(nil, payload)
				if err != nil {
					t.Fatal(err)
				}
				hl := 1
				if peer != wire.NoPeerID {
					hl = 4
				}
				for i := range pkt {
					if !s.aead() && i >= 1 && i < hl {
						// CBC's HMAC covers iv || ciphertext only, as in
						// OpenVPN: the peer id is not authenticated.
						continue
					}
					for bit := 0; bit < 8; bit++ {
						bad := bytes.Clone(pkt)
						bad[i] ^= 1 << bit
						dst := []byte("keep")
						got, _, err := p.server.Open(dst, bad)
						if err == nil {
							t.Fatalf("flipped bit %d of byte %d: Open succeeded", bit, i)
						}
						if string(got) != "keep" {
							t.Fatalf("failed Open changed dst to %q", got)
						}
					}
				}
				for n := 0; n < len(pkt); n++ {
					if _, _, err := p.server.Open(nil, pkt[:n]); err == nil {
						t.Fatalf("truncated to %d bytes: Open succeeded", n)
					}
				}
				if _, _, err := p.server.Open(nil, append(bytes.Clone(pkt), 0)); err == nil {
					t.Fatal("extended packet: Open succeeded")
				}
				for _, extra := range [][]byte{bytes.Repeat([]byte{0}, 8), bytes.Repeat([]byte{0}, 16)} {
					if _, _, err := p.server.Open(nil, append(bytes.Clone(pkt), extra...)); err == nil {
						t.Fatalf("packet extended by %d bytes: Open succeeded", len(extra))
					}
				}
				// None of the failures moved the replay window.
				got, kind, err := p.server.Open(nil, pkt)
				if err != nil || kind != KindPacket || !bytes.Equal(got, payload) {
					t.Fatalf("genuine packet after tampering: %v %v", kind, err)
				}
				if _, _, err := p.server.Open(nil, pkt); !errors.Is(err, ErrReplay) {
					t.Fatalf("second Open: %v, want ErrReplay", err)
				}
			})
		}
	}
}

func TestCBCPeerIDNotAuthenticated(t *testing.T) {
	// OpenVPN's CBC mode authenticates iv || ciphertext only, so a rewritten
	// peer id still opens. AEAD covers the P_DATA_V2 header.
	p := newPair(t, suite{"AES-256-CBC", "SHA1"}, 0, Options{PeerID: 5})
	pkt, _ := p.client.Seal(nil, []byte{0x45, 1, 2, 3})
	pkt[3] ^= 1
	if _, _, err := p.server.Open(nil, pkt); err != nil {
		t.Fatalf("CBC with another peer id: %v", err)
	}
	p = newPair(t, suite{"AES-256-GCM", ""}, 0, Options{PeerID: 5})
	pkt, _ = p.client.Seal(nil, []byte{0x45, 1, 2, 3})
	pkt[3] ^= 1
	if _, _, err := p.server.Open(nil, pkt); !errors.Is(err, ErrAuth) {
		t.Fatalf("GCM with another peer id: %v, want ErrAuth", err)
	}
}

func TestReplay(t *testing.T) {
	for _, s := range []suite{{"AES-256-GCM", ""}, {"CHACHA20-POLY1305", ""}, {"AES-128-CBC", "SHA1"}, {"BF-CBC", "SHA512"}} {
		t.Run(s.String(), func(t *testing.T) {
			p := newPair(t, s, 0, Options{PeerID: 77})
			pkts := make([][]byte, 301) // pkts[i] has pid i
			for i := 1; i <= 300; i++ {
				pkt, err := p.client.Seal(nil, []byte{0x45, byte(i), byte(i >> 8)})
				if err != nil {
					t.Fatal(err)
				}
				pkts[i] = pkt
			}
			open := func(pid int) error {
				got, _, err := p.server.Open(nil, pkts[pid])
				if err == nil && (len(got) != 3 || int(got[1])|int(got[2])<<8 != pid) {
					t.Fatalf("pid %d opened to %x", pid, got)
				}
				return err
			}
			want := func(pid int, wantErr error) {
				t.Helper()
				if err := open(pid); !errors.Is(err, wantErr) {
					t.Fatalf("pid %d: %v, want %v", pid, err, wantErr)
				}
			}
			want(1, nil)
			want(1, ErrReplay)
			want(3, nil)
			want(2, nil) // reordered within the window
			want(2, ErrReplay)
			want(3, ErrReplay)
			want(200, nil) // jump ahead
			want(137, nil) // 200-63: oldest id inside a 64-packet window
			want(136, ErrReplay)
			want(4, ErrReplay)
			want(150, nil)
			want(150, ErrReplay)
			want(137, ErrReplay)
			want(199, nil)
			want(201, nil)       // the window is now 138..201
			want(136, ErrReplay) // never seen, but too old
			want(138, nil)

			// A forged packet with a high id must not move the window.
			bad := bytes.Clone(pkts[300])
			bad[len(bad)-1] ^= 0x10
			if _, _, err := p.server.Open(nil, bad); !errors.Is(err, ErrAuth) {
				t.Fatalf("forged pid 300: %v, want ErrAuth", err)
			}
			want(140, nil) // still inside 138..201
			want(300, nil)
			want(236, ErrReplay)
			want(237, nil)
			want(250, nil)
			want(300, ErrReplay)
		})
	}
}

func TestReplayPIDZero(t *testing.T) {
	k2 := testKey2(4)
	for _, c := range aeadCiphers {
		ks, err := NewKeyState(0, c, "", k2.ServerSend(), k2.ServerRecv())
		if err != nil {
			t.Fatal(err)
		}
		ch := New(Options{PeerID: wire.NoPeerID})
		ch.SetPrimary(ks)
		pl := []byte{0x45, 0, 0, 0}
		if _, _, err := ch.Open(nil, refSealAEAD(t, c, k2.ClientSend(), 0, wire.NoPeerID, 0, pl)); !errors.Is(err, ErrReplay) {
			t.Errorf("%s pid 0: %v, want ErrReplay", c, err)
		}
		if got, _, err := ch.Open(nil, refSealAEAD(t, c, k2.ClientSend(), 0, wire.NoPeerID, 0xFFFFFFFF, pl)); err != nil || !bytes.Equal(got, pl) {
			t.Errorf("%s pid 0xFFFFFFFF: %x %v", c, got, err)
		}
	}
	for _, c := range cbcCiphers {
		ks, err := NewKeyState(0, c, "SHA256", k2.ServerSend(), k2.ServerRecv())
		if err != nil {
			t.Fatal(err)
		}
		ch := New(Options{PeerID: wire.NoPeerID})
		ch.SetPrimary(ks)
		iv := bytes.Repeat([]byte{7}, 16)
		pt := pkcs7([]byte{0, 0, 0, 0, 0x45, 1}, blockSizeOf(c))
		if _, _, err := ch.Open(nil, refSealCBC(t, c, "SHA256", k2.ClientSend(), 0, wire.NoPeerID, iv, pt)); !errors.Is(err, ErrReplay) {
			t.Errorf("%s pid 0: %v, want ErrReplay", c, err)
		}
	}
}

func TestReplayWindowSizes(t *testing.T) {
	for _, size := range []int{1, 10, 64, 100, 1000} {
		p := newPair(t, suite{"AES-128-GCM", ""}, 0, Options{PeerID: wire.NoPeerID, ReplayWindow: size})
		pkts := make([][]byte, 2*size+10)
		for i := 1; i < len(pkts); i++ {
			pkts[i], _ = p.client.Seal(nil, []byte{0x45})
		}
		top := len(pkts) - 1
		if _, _, err := p.server.Open(nil, pkts[top]); err != nil {
			t.Fatal(err)
		}
		if size > 1 {
			if _, _, err := p.server.Open(nil, pkts[top-size+1]); err != nil {
				t.Errorf("window %d: oldest id inside the window: %v", size, err)
			}
		}
		if _, _, err := p.server.Open(nil, pkts[top-size]); !errors.Is(err, ErrReplay) {
			t.Errorf("window %d: id just outside the window: %v", size, err)
		}
	}
}

// TestReplayWindowModel checks the bitmap against a map-based model.
func TestReplayWindowModel(t *testing.T) {
	for _, size := range []int{1, 2, 63, 64, 65, 100, 128, 1000} {
		r := rand.New(rand.NewPCG(uint64(size), 3))
		var w replayWindow
		w.init(size)
		seen := map[uint32]bool{}
		var top uint32
		base := uint32(0)
		if size == 100 {
			base = 0xFFFFFFFF - 50000 // run into the top of the id space
		}
		for i := 0; i < 50000; i++ {
			var delta int64
			small := false
			switch r.IntN(10) {
			case 0:
				delta = int64(r.IntN(3*size + 3))
			case 1:
				delta = -int64(r.IntN(2*size + 2))
			case 2:
				small = true
			case 3:
				delta = int64(r.IntN(200000))
			default:
				delta = int64(r.IntN(size+2)) - int64(r.IntN(size+2))
			}
			cand := min(max(int64(top)+delta, 0), 0xFFFFFFFF)
			if small {
				cand = int64(r.IntN(3))
			}
			if top == 0 && base != 0 {
				cand = int64(base)
			}
			pid := uint32(cand)
			wantOK := pid != 0 && (pid > top || (uint64(top-pid) < uint64(size) && !seen[pid]))
			err := w.accept(pid)
			if (err == nil) != wantOK {
				t.Fatalf("size %d step %d: accept(%d) with top %d = %v, want ok=%v", size, i, pid, top, err, wantOK)
			}
			if err == nil {
				seen[pid] = true
				if pid > top {
					top = pid
				}
			}
		}
	}
}

func TestKeyRotation(t *testing.T) {
	k2a, k2b := testKey2(10), testKey2(11)
	mk := func(id uint8, k2 *handshake.Key2, server bool) *KeyState {
		var ks *KeyState
		var err error
		if server {
			ks, err = NewKeyState(id, "AES-256-GCM", "", k2.ServerSend(), k2.ServerRecv())
		} else {
			ks, err = NewKeyState(id, "AES-256-GCM", "", k2.ClientSend(), k2.ClientRecv())
		}
		if err != nil {
			t.Fatal(err)
		}
		return ks
	}
	client := New(Options{PeerID: 1})
	server := New(Options{PeerID: 1})
	if client.HasPrimary() {
		t.Fatal("new channel has a primary key")
	}
	if _, err := client.Seal(nil, []byte{0x45}); !errors.Is(err, ErrNoKey) {
		t.Fatalf("Seal without key: %v", err)
	}
	client.SetPrimary(mk(0, k2a, false))
	server.SetPrimary(mk(0, k2a, true))
	old, _ := client.Seal(nil, []byte{0x45, 0})

	// Renegotiated key 1: the server installs it first; packets with key 0
	// still open.
	server.SetPrimary(mk(1, k2b, true))
	if _, _, err := server.Open(nil, old); err != nil {
		t.Fatalf("old key after rotation: %v", err)
	}
	client.SetPrimary(mk(1, k2b, false))
	pkt, _ := client.Seal(nil, []byte{0x45, 1})
	if _, keyID, _, _, _ := wire.ParseDataHeader(pkt); keyID != 1 {
		t.Fatalf("sealed with key %d, want 1", keyID)
	}
	if got, _, err := server.Open(nil, pkt); err != nil || !bytes.Equal(got, []byte{0x45, 1}) {
		t.Fatalf("new key: %x %v", got, err)
	}

	old2 := refSealAEAD(t, "AES-256-GCM", k2a.ClientSend(), 0, 1, 99, []byte{0x45, 2})
	server.DropKey(0)
	if _, _, err := server.Open(nil, old2); !errors.Is(err, ErrNoKey) {
		t.Fatalf("dropped key: %v, want ErrNoKey", err)
	}
	if !server.HasPrimary() {
		t.Fatal("dropping a non-primary key removed the primary")
	}
	// A packet for a key id never installed.
	if _, _, err := server.Open(nil, refSealAEAD(t, "AES-256-GCM", k2b.ClientSend(), 5, 1, 1, []byte{0x45})); !errors.Is(err, ErrNoKey) {
		t.Fatalf("unknown key id: %v, want ErrNoKey", err)
	}
	// Right key id, wrong key: authentication fails.
	if _, _, err := server.Open(nil, refSealAEAD(t, "AES-256-GCM", k2a.ClientSend(), 1, 1, 50, []byte{0x45})); !errors.Is(err, ErrAuth) {
		t.Fatalf("wrong key material: %v, want ErrAuth", err)
	}
	// Reusing an id replaces the key state.
	server.SetPrimary(mk(1, k2a, true))
	if _, _, err := server.Open(nil, refSealAEAD(t, "AES-256-GCM", k2a.ClientSend(), 1, 1, 50, []byte{0x45})); err != nil {
		t.Fatalf("replaced key id 1: %v", err)
	}
	server.DropKey(1)
	if server.HasPrimary() {
		t.Fatal("primary survives DropKey")
	}
	if _, err := server.SealPing(nil); !errors.Is(err, ErrNoKey) {
		t.Fatalf("SealPing without key: %v", err)
	}
}

func TestPingAndOCC(t *testing.T) {
	for _, s := range []suite{{"AES-256-GCM", ""}, {"CHACHA20-POLY1305", ""}, {"AES-256-CBC", "SHA1"}, {"BF-CBC", "SHA1"}} {
		for _, mode := range allModes {
			for _, peer := range peerIDs {
				name := fmt.Sprintf("%v/%s/%x", s, modeName(mode), peer)
				if mode != compress.None && !compressReady() {
					t.Logf("%s: skipped, package compress is not implemented yet", name)
					continue
				}
				p := newPair(t, s, 0, Options{PeerID: peer, Compression: mode})

				pkt, err := p.client.SealPing(nil)
				if err != nil {
					t.Fatal(err)
				}
				got, kind, err := p.server.Open([]byte("x"), pkt)
				if err != nil || kind != KindPing || string(got) != "x" {
					t.Errorf("%s: ping opened as %v %q %v", name, kind, got, err)
				}

				pkt, err = p.client.SealOCC(nil, OCCExit)
				if err != nil {
					t.Fatal(err)
				}
				got, kind, err = p.server.Open(nil, pkt)
				if err != nil || kind != KindOCC || !bytes.Equal(got, []byte{OCCExit}) {
					t.Errorf("%s: OCC exit opened as %v %x %v", name, kind, got, err)
				}

				msg := append(bytes.Clone(OCCPrefix[:]), 0x01)
				msg = append(msg, "V4,dev-type tun"...)
				pkt, _ = p.server.Seal(nil, msg)
				got, kind, err = p.client.Open(nil, pkt)
				if err != nil || kind != KindOCC || !bytes.Equal(got, msg[16:]) {
					t.Errorf("%s: OCC reply opened as %v %q %v", name, kind, got, err)
				}

				// The ping is exactly 16 bytes; a longer payload starting
				// with it is a packet.
				long := append(bytes.Clone(PingPayload[:]), 0x01)
				pkt, _ = p.server.Seal(nil, long)
				got, kind, err = p.client.Open(nil, pkt)
				if err != nil || kind != KindPacket || !bytes.Equal(got, long) {
					t.Errorf("%s: ping+1 opened as %v %x %v", name, kind, got, err)
				}
			}
		}
	}
}

// TestUnframedPingOCC: a peer that sends keepalives and OCC messages without
// compression framing is still understood under every framing.
func TestUnframedPingOCC(t *testing.T) {
	for _, mode := range allModes {
		p := newPair(t, suite{"AES-256-GCM", ""}, 0, Options{PeerID: wire.NoPeerID, Compression: mode})
		p.client.SetCompression(compress.None)
		pkt, _ := p.client.SealPing(nil)
		if got, kind, err := p.server.Open(nil, pkt); err != nil || kind != KindPing || len(got) != 0 {
			t.Errorf("%s: raw ping opened as %v %x %v", modeName(mode), kind, got, err)
		}
		pkt, _ = p.client.SealOCC(nil, OCCExit)
		if got, kind, err := p.server.Open([]byte("x"), pkt); err != nil || kind != KindOCC || string(got) != "x\x06" {
			t.Errorf("%s: raw OCC opened as %v %x %v", modeName(mode), kind, got, err)
		}
	}
}

func TestConcurrentSeal(t *testing.T) {
	for _, s := range []suite{{"AES-256-GCM", ""}, {"AES-128-CBC", "SHA256"}} {
		t.Run(s.String(), func(t *testing.T) {
			p := newPair(t, s, 0, Options{PeerID: 7, ReplayWindow: 65536})
			const workers, per = 8, 250
			pkts := make(chan []byte, workers*per)
			stop := make(chan struct{})
			var churn sync.WaitGroup
			churn.Add(1)
			go func() {
				defer churn.Done()
				for i := 0; ; i++ {
					select {
					case <-stop:
						return
					default:
					}
					p.client.SetPrimary(p.cks)
					p.client.SetPeerID(uint32(7 + i%2))
					p.client.SetCompression(compress.None)
					_ = p.client.HasPrimary()
					_ = p.client.NeedsRenegotiation()
					runtime.Gosched()
				}
			}()
			done := make(chan error, 1)
			go func() {
				seen := map[string]bool{}
				var firstErr error
				for pkt := range pkts {
					got, kind, err := p.server.Open(nil, pkt)
					if err != nil || kind != KindPacket {
						if firstErr == nil {
							firstErr = fmt.Errorf("Open: %v %v", kind, err)
						}
						continue
					}
					seen[string(got)] = true
				}
				if firstErr == nil && len(seen) != workers*per {
					firstErr = fmt.Errorf("opened %d distinct packets, want %d", len(seen), workers*per)
				}
				done <- firstErr
			}()
			var wg sync.WaitGroup
			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func(w int) {
					defer wg.Done()
					for i := 0; i < per; i++ {
						pkt, err := p.client.Seal(nil, []byte{0x45, byte(w), byte(i), byte(i >> 8)})
						if err != nil {
							t.Error(err)
							return
						}
						pkts <- pkt
					}
				}(w)
			}
			wg.Wait()
			close(stop)
			churn.Wait()
			close(pkts)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if got := p.cks.sendPID.Load(); got != workers*per {
				t.Fatalf("send counter %d, want %d", got, workers*per)
			}
		})
	}
}

func TestConcurrentOpen(t *testing.T) {
	p := newPair(t, suite{"CHACHA20-POLY1305", ""}, 0, Options{PeerID: 7, ReplayWindow: 4096})
	var pkts [][]byte
	for i := 0; i < 2000; i++ {
		pkt, _ := p.client.Seal(nil, []byte{0x45, byte(i), byte(i >> 8)})
		pkts = append(pkts, pkt, pkt) // every packet twice
	}
	var ok, replays sync.Map
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := g; i < len(pkts); i += 4 {
				got, _, err := p.server.Open(nil, pkts[i])
				switch {
				case err == nil:
					if _, dup := ok.LoadOrStore(string(got), true); dup {
						t.Errorf("packet %x opened twice", got)
					}
				case errors.Is(err, ErrReplay):
					replays.Store(i, true)
				default:
					t.Error(err)
				}
			}
		}(g)
	}
	wg.Wait()
	n := 0
	ok.Range(func(any, any) bool { n++; return true })
	if n != 2000 {
		t.Fatalf("%d packets opened once, want 2000", n)
	}
}

func TestPacketIDExhaustion(t *testing.T) {
	for _, s := range []suite{{"AES-256-GCM", ""}, {"AES-256-CBC", "SHA256"}} {
		p := newPair(t, s, 0, Options{PeerID: wire.NoPeerID})
		p.cks.sendPID.Store(renegotiateAbove - 1)
		if p.client.NeedsRenegotiation() {
			t.Fatal("NeedsRenegotiation before the threshold")
		}
		if _, err := p.client.Seal(nil, []byte{0x45}); err != nil {
			t.Fatal(err)
		}
		if p.client.NeedsRenegotiation() {
			t.Fatalf("NeedsRenegotiation at %#x packets", p.cks.sendPID.Load())
		}
		if _, err := p.client.Seal(nil, []byte{0x45}); err != nil {
			t.Fatal(err)
		}
		if !p.client.NeedsRenegotiation() {
			t.Fatalf("no NeedsRenegotiation at %#x packets", p.cks.sendPID.Load())
		}
		if p.server.NeedsRenegotiation() {
			t.Fatal("the peer's counter is independent")
		}

		p.cks.sendPID.Store(0xFFFFFFFD)
		pkt, err := p.client.Seal(nil, []byte{0x45, 0xEE})
		if err != nil {
			t.Fatalf("pid 0xFFFFFFFE: %v", err)
		}
		if got, _, err := p.server.Open(nil, pkt); err != nil || !bytes.Equal(got, []byte{0x45, 0xEE}) {
			t.Fatalf("opening pid 0xFFFFFFFE: %x %v", got, err)
		}
		for i := 0; i < 3; i++ {
			dst := []byte("dst")
			out, err := p.client.Seal(dst, []byte{0x45})
			if !errors.Is(err, ErrPacketIDExhausted) || string(out) != "dst" {
				t.Fatalf("Seal past the id space: %q %v", out, err)
			}
			if _, err := p.client.SealPing(nil); !errors.Is(err, ErrPacketIDExhausted) {
				t.Fatalf("SealPing past the id space: %v", err)
			}
		}
		if !p.client.NeedsRenegotiation() {
			t.Fatal("exhausted key does not need renegotiation")
		}
	}
}

func TestRandomFailure(t *testing.T) {
	p := newPair(t, suite{"AES-128-CBC", "SHA1"}, 0, Options{PeerID: wire.NoPeerID})
	p.cks.rand = errReader{}
	out, err := p.client.Seal([]byte("dst"), []byte{0x45})
	if err == nil || string(out) != "dst" {
		t.Fatalf("Seal with failing rand: %q %v", out, err)
	}
}

// TestKnownAnswer opens and reproduces packets computed with Python's
// cryptography package (OpenSSL), independently of Go's crypto. Key.Cipher
// is 00 01 .. 3f, Key.HMAC 40 41 .. 7f, CBC IVs a0 a1 ..; payload
// "hello openvpn data channel", no compression.
func TestKnownAnswer(t *testing.T) {
	cases := []struct {
		cipher, digest string
		keyID          uint8
		peerID, pid    uint32
		hex            string
	}{
		{"AES-256-GCM", "", 1, 0x123456, 1, "4912345600000001a7a468457f74c6c343f190b957e8c4b7a3ae17d10496c9b970d022071a166c42870c19c298a8fc239620"},
		{"AES-128-GCM", "", 0, wire.NoPeerID, 7, "30000000075032a905848da064357c26cde93c365a5287064ad91468240a426446d99a41077161e98db9c41b35053f"},
		{"CHACHA20-POLY1305", "", 2, 0x123456, 0x01020304, "4a1234560102030442bef66e34c44be44095dd06e27611c2507c4e742f31c2b0012dc25281d42a685dbdc04cb6c1d3db8fdf"},
		{"AES-128-CBC", "SHA1", 0, wire.NoPeerID, 1, "306ab4819a8f466c613ee07d5bb1c6b5256c8e3e5ea0a1a2a3a4a5a6a7a8a9aaabacadaeaf811a30491cc5c2cf8fda147f5ea284cf85511e7af1433f8ce89e34fac71bad3e"},
		{"AES-256-CBC", "SHA512", 3, 0x123456, 5, "4b1234565a16166e609c54b199bcdd5531fb2919c34491828a5599c7a85c389e9ebcfb357fd28563dfe9e68aaa5d5c43e4d17b1f2525000fd2b1f6b892bb71ec6e23b61fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf050d50925544cfcb13e6fccc67d85e92a289eae8fba233eb97e3076f83525f5c"},
		{"BF-CBC", "SHA256", 0, wire.NoPeerID, 2, "30eac613d135fb0d7eee2f487bb0dd661a89c0c4cd5f0a0d251221d1a926a51746a0a1a2a3a4a5a6a7fa23c0204dd2223b7dfb39e379778cf7b1f3203082294048fc012f63d3dc2be3"},
	}
	var kat, other handshake.Key
	for i := range kat.Cipher {
		kat.Cipher[i] = byte(i)
		kat.HMAC[i] = byte(64 + i)
		other.Cipher[i] = 0xEE
		other.HMAC[i] = 0xDD
	}
	payload := []byte("hello openvpn data channel")
	for _, c := range cases {
		want, _ := hex.DecodeString(c.hex)

		sender, err := NewKeyState(c.keyID, c.cipher, c.digest, &kat, &other)
		if err != nil {
			t.Fatal(err)
		}
		sender.sendPID.Store(uint64(c.pid - 1))
		sender.rand = &countingReader{n: 0xa0}
		ch := New(Options{PeerID: c.peerID})
		ch.SetPrimary(sender)
		got, err := ch.Seal(nil, payload)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s/%s: Seal =\n%x, want\n%x (%v)", c.cipher, c.digest, got, want, err)
		}

		receiver, err := NewKeyState(c.keyID, c.cipher, c.digest, &other, &kat)
		if err != nil {
			t.Fatal(err)
		}
		rx := New(Options{PeerID: c.peerID})
		rx.SetPrimary(receiver)
		pt, kind, err := rx.Open(nil, want)
		if err != nil || kind != KindPacket || !bytes.Equal(pt, payload) {
			t.Errorf("%s/%s: Open = %q %v %v", c.cipher, c.digest, pt, kind, err)
		}
	}
}

// TestAEADLayout compares Seal with an independent construction for every
// AEAD cipher, both headers and several packet ids.
func TestAEADLayout(t *testing.T) {
	k2 := testKey2(21)
	for _, c := range aeadCiphers {
		for _, peer := range peerIDs {
			ks, err := NewKeyState(6, c, "", k2.ClientSend(), k2.ClientRecv())
			if err != nil {
				t.Fatal(err)
			}
			ch := New(Options{PeerID: peer})
			ch.SetPrimary(ks)
			for _, pid := range []uint32{1, 2, 255, 256, 0x10000, 0xFFFFFFFE} {
				ks.sendPID.Store(uint64(pid - 1))
				pl := []byte(fmt.Sprintf("\x45payload for pid %d", pid))
				got, err := ch.Seal(nil, pl)
				if err != nil {
					t.Fatal(err)
				}
				want := refSealAEAD(t, c, k2.ClientSend(), 6, peer, pid, pl)
				if !bytes.Equal(got, want) {
					t.Fatalf("%s peer %x pid %d:\n got %x\nwant %x", c, peer, pid, got, want)
				}
			}
		}
	}
}

// TestCBCLayout compares Seal with an independent construction for every
// CBC cipher and digest.
func TestCBCLayout(t *testing.T) {
	k2 := testKey2(22)
	for _, c := range cbcCiphers {
		for _, d := range allDigests {
			for _, peer := range peerIDs {
				ks, err := NewKeyState(4, c, d, k2.ServerSend(), k2.ServerRecv())
				if err != nil {
					t.Fatal(err)
				}
				ch := New(Options{PeerID: peer})
				ch.SetPrimary(ks)
				for _, n := range []int{0, 1, 3, 4, 11, 12, 13, 27, 28, 29, 100} {
					ks.setRand(&countingReader{n: byte(n)})
					pl := bytes.Repeat([]byte{0x45}, n)
					got, err := ch.Seal(nil, pl)
					if err != nil {
						t.Fatal(err)
					}
					iv := make([]byte, 16)
					(&countingReader{n: byte(n)}).Read(iv)
					pid := uint32(ks.sendPID.Load())
					pt := pkcs7(append(binary.BigEndian.AppendUint32(nil, pid), pl...), blockSizeOf(c))
					want := refSealCBC(t, c, d, k2.ServerSend(), 4, peer, iv, pt)
					if !bytes.Equal(got, want) {
						t.Fatalf("%s/%s peer %x len %d:\n got %x\nwant %x", c, d, peer, n, got, want)
					}
				}
			}
		}
	}
}

func TestCBCPadding(t *testing.T) {
	k2 := testKey2(23)
	for _, c := range cbcCiphers {
		bs := blockSizeOf(c)
		ks, err := NewKeyState(0, c, "SHA1", k2.ServerSend(), k2.ServerRecv())
		if err != nil {
			t.Fatal(err)
		}
		ch := New(Options{PeerID: wire.NoPeerID})
		ch.SetPrimary(ks)
		iv := bytes.Repeat([]byte{0x33}, 16)
		pid := uint32(0)
		withPID := func(rest ...byte) []byte {
			pid++
			return append(binary.BigEndian.AppendUint32(nil, pid), rest...)
		}
		bad := map[string][]byte{
			"pad 0":            withPID(append(bytes.Repeat([]byte{0x45}, bs-5), 0)...),
			"pad > block":      withPID(append(bytes.Repeat([]byte{0x45}, bs-5), byte(bs+1))...),
			"pad 0xff":         withPID(append(bytes.Repeat([]byte{0x45}, bs-5), 0xff)...),
			"inconsistent pad": withPID(append(bytes.Repeat([]byte{0x45}, bs-7), 3, 2, 3)...),
			"only padding":     bytes.Repeat([]byte{byte(bs)}, bs),
			"no room for pid":  append([]byte{0, 0, 9}, bytes.Repeat([]byte{byte(bs - 3)}, bs-3)...),
		}
		for name, pt := range bad {
			if len(pt)%bs != 0 {
				t.Fatalf("%s: test plaintext %d bytes", name, len(pt))
			}
			pkt := refSealCBC(t, c, "SHA1", k2.ClientSend(), 0, wire.NoPeerID, iv, pt)
			if _, _, err := ch.Open(nil, pkt); !errors.Is(err, ErrAuth) {
				t.Errorf("%s %s: %v, want ErrAuth", c, name, err)
			}
		}
		good := pkcs7(withPID(0x45, 1, 2), bs)
		got, _, err := ch.Open(nil, refSealCBC(t, c, "SHA1", k2.ClientSend(), 0, wire.NoPeerID, iv, good))
		if err != nil || !bytes.Equal(got, []byte{0x45, 1, 2}) {
			t.Errorf("%s valid padding: %x %v", c, got, err)
		}
		full := withPID(bytes.Repeat([]byte{0x45}, bs-4)...)
		full = append(full, bytes.Repeat([]byte{byte(bs)}, bs)...)
		got, _, err = ch.Open(nil, refSealCBC(t, c, "SHA1", k2.ClientSend(), 0, wire.NoPeerID, iv, full))
		if err != nil || !bytes.Equal(got, bytes.Repeat([]byte{0x45}, bs-4)) {
			t.Errorf("%s full padding block: %x %v", c, got, err)
		}
	}
}

func TestOpenMalformed(t *testing.T) {
	p := newPair(t, suite{"AES-256-GCM", ""}, 0, Options{PeerID: wire.NoPeerID})
	cbc := newPair(t, suite{"AES-256-CBC", "SHA256"}, 0, Options{PeerID: wire.NoPeerID})
	cases := []struct {
		name string
		pkt  []byte
		want error
	}{
		{"empty", nil, ErrShort},
		{"v2 header cut", []byte{9 << 3, 0, 0}, ErrShort},
		{"v1 header only", []byte{6 << 3}, ErrShort},
		{"v2 header only", []byte{9 << 3, 0, 0, 1}, ErrShort},
		{"pid only", []byte{6 << 3, 0, 0, 0, 1}, ErrShort},
		{"tag cut", append([]byte{6 << 3, 0, 0, 0, 1}, make([]byte, 15)...), ErrShort},
		{"empty ciphertext forged", append([]byte{6 << 3, 0, 0, 0, 1}, make([]byte, 16)...), ErrAuth},
	}
	for _, c := range cases {
		if _, _, err := p.server.Open(nil, c.pkt); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
	if _, _, err := p.server.Open(nil, []byte{byte(wire.ControlV1) << 3, 1, 2, 3, 4, 5, 6, 7, 8, 9}); err == nil || errors.Is(err, ErrShort) {
		t.Errorf("control packet: %v", err)
	}
	cbcCases := []struct {
		name string
		pkt  []byte
		want error
	}{
		{"mac only", append([]byte{6 << 3}, make([]byte, 32)...), ErrShort},
		{"no ciphertext", append([]byte{6 << 3}, make([]byte, 32+16)...), ErrShort},
		{"partial block", append([]byte{6 << 3}, make([]byte, 32+16+17)...), ErrAuth},
		{"forged block", append([]byte{6 << 3}, make([]byte, 32+16+16)...), ErrAuth},
	}
	for _, c := range cbcCases {
		if _, _, err := cbc.server.Open(nil, c.pkt); !errors.Is(err, c.want) {
			t.Errorf("CBC %s: %v, want %v", c.name, err, c.want)
		}
	}
}

// TestDecompression checks Open undoes a compressing peer's framing, with
// MaxPayload passed down. The peer here frames by hand and sends with
// compression off.
func TestDecompression(t *testing.T) {
	needCompress(t, compress.V2)
	// LZ4 block: literals "abcd", a 20-byte match at offset 4, then the
	// literals "wxyz!".
	block := []byte{0x4F, 'a', 'b', 'c', 'd', 0x04, 0x00, 0x01, 0x50, 'w', 'x', 'y', 'z', '!'}
	want := []byte("abcdabcdabcdabcdabcdabcdwxyz!")
	cases := []struct {
		mode   compress.Mode
		framed []byte
	}{
		{compress.V2, append([]byte{0x50, 0x01}, block...)},
		{compress.Swap, append(append([]byte{0x69}, block[1:]...), block[0])},
	}
	for _, c := range cases {
		p := newPair(t, suite{"AES-128-GCM", ""}, 0, Options{PeerID: wire.NoPeerID, Compression: c.mode})
		p.client.SetCompression(compress.None) // the "peer" sends its own framing
		pkt, err := p.client.Seal(nil, c.framed)
		if err != nil {
			t.Fatal(err)
		}
		got, kind, err := p.server.Open([]byte("pre"), pkt)
		if err != nil || kind != KindPacket || !bytes.Equal(got, append([]byte("pre"), want...)) {
			t.Errorf("%s: Open = %q %v %v", modeName(c.mode), got, kind, err)
		}

		small := newPair(t, suite{"AES-128-GCM", ""}, 0, Options{PeerID: wire.NoPeerID, Compression: c.mode, MaxPayload: 10})
		small.client.SetCompression(compress.None)
		pkt, _ = small.client.Seal(nil, c.framed)
		if got, _, err := small.server.Open(nil, pkt); err == nil {
			t.Errorf("%s: MaxPayload 10 let %d bytes through", modeName(c.mode), len(got))
		}
	}

	// LZO framing with an unknown flag byte is an error after
	// authentication.
	p := newPair(t, suite{"AES-128-GCM", ""}, 0, Options{PeerID: wire.NoPeerID, Compression: compress.LZO})
	p.client.SetCompression(compress.None)
	pkt, _ := p.client.Seal(nil, []byte{0x45, 1, 2, 3})
	dst := []byte("keep")
	if got, _, err := p.server.Open(dst, pkt); err == nil || string(got) != "keep" {
		t.Errorf("LZO without a flag byte: %q %v", got, err)
	}
}

type fuzzConfig struct {
	s    suite
	mode compress.Mode
	peer uint32
}

// fuzzConfigs are the receiving setups the fuzz tests pick from, covering
// both cipher kinds, both headers and every framing (all None until package
// compress is implemented).
func fuzzConfigs() []fuzzConfig {
	cfgs := []fuzzConfig{
		{suite{"AES-256-GCM", ""}, compress.None, 0x000102},
		{suite{"CHACHA20-POLY1305", ""}, compress.V2, wire.NoPeerID},
		{suite{"AES-128-GCM", ""}, compress.Swap, 5},
		{suite{"AES-128-CBC", "SHA1"}, compress.LZO, wire.NoPeerID},
		{suite{"BF-CBC", "MD5"}, compress.Swap, 9},
		{suite{"AES-256-CBC", "SHA512"}, compress.V2, wire.NoPeerID},
		{suite{"AES-192-CBC", "SHA256"}, compress.None, 0xFFFFFE},
	}
	if !compressReady() {
		for i := range cfgs {
			cfgs[i].mode = compress.None
		}
	}
	return cfgs
}

func fuzzServer(t testing.TB, i int) *Channel {
	cfg := fuzzConfigs()[i%len(fuzzConfigs())]
	k2 := testKey2(99)
	ks, err := NewKeyState(0, cfg.s.cipher, cfg.s.digest, k2.ServerSend(), k2.ServerRecv())
	if err != nil {
		t.Fatal(err)
	}
	ch := New(Options{PeerID: cfg.peer, Compression: cfg.mode, MaxPayload: 4096})
	ch.SetPrimary(ks)
	return ch
}

func FuzzOpen(f *testing.F) {
	k2 := testKey2(99)
	for i, cfg := range fuzzConfigs() {
		ks, err := NewKeyState(0, cfg.s.cipher, cfg.s.digest, k2.ClientSend(), k2.ClientRecv())
		if err != nil {
			f.Fatal(err)
		}
		ch := New(Options{PeerID: cfg.peer, Compression: cfg.mode})
		ch.SetPrimary(ks)
		for _, pl := range [][]byte{{0x45, 1, 2, 3}, PingPayload[:], append(bytes.Clone(OCCPrefix[:]), OCCExit), bytes.Repeat([]byte{0x50}, 40)} {
			pkt, err := ch.Seal(nil, pl)
			if err != nil {
				f.Fatal(err)
			}
			f.Add(byte(i), pkt)
		}
	}
	f.Add(byte(0), []byte{})
	f.Add(byte(3), []byte{6 << 3})
	f.Fuzz(func(t *testing.T, sel byte, pkt []byte) {
		ch := fuzzServer(t, int(sel))
		orig := bytes.Clone(pkt)
		got, kind, err := ch.Open(nil, pkt)
		if err != nil {
			if len(got) != 0 {
				t.Fatalf("failed Open returned %d bytes", len(got))
			}
			if !bytes.Equal(pkt, orig) {
				t.Fatal("failed Open modified the packet")
			}
			return
		}
		if kind == KindPing && len(got) != 0 {
			t.Fatal("ping returned bytes")
		}
		// Only decompression can make a payload larger than its packet, and
		// that is bounded by MaxPayload.
		if len(got) > max(4096, len(pkt)) {
			t.Fatalf("payload of %d bytes from a %d-byte packet", len(got), len(pkt))
		}
		// In place must agree.
		ch2 := fuzzServer(t, int(sel))
		got2, kind2, err2 := ch2.Open(orig[:0], orig)
		if err2 != nil || kind2 != kind || !bytes.Equal(got, got2) {
			t.Fatalf("in-place Open disagrees: %v %v", kind2, err2)
		}
	})
}

// FuzzOpenAuthenticated fuzzes what follows authentication: the decrypted
// plaintext (framing, and for CBC the pid and padding) arrives under valid
// crypto.
func FuzzOpenAuthenticated(f *testing.F) {
	for i := range fuzzConfigs() {
		f.Add(byte(i), uint32(1), []byte{0x45, 1, 2, 3})
		f.Add(byte(i), uint32(7), append([]byte{0xFA}, PingPayload[:]...))
		f.Add(byte(i), uint32(7), []byte{0x50, 0x01, 0x4F, 'a', 'b', 'c', 'd', 0x04, 0x00, 0x01, 0x50, 'w', 'x', 'y', 'z', '!'})
		f.Add(byte(i), uint32(7), []byte{0x69, 0xff, 0xff, 0xff, 0xff, 0x01})
		f.Add(byte(i), uint32(7), []byte{0x66, 0x11, 0x00, 0x00})
		f.Add(byte(i), uint32(2), []byte{0, 0, 0, 2, 0x45, 4, 4, 4, 4})
	}
	k2 := testKey2(99)
	f.Fuzz(func(t *testing.T, sel byte, pid uint32, pt []byte) {
		cfg := fuzzConfigs()[int(sel)%len(fuzzConfigs())]
		ch := fuzzServer(t, int(sel))
		var pkt []byte
		plainLen := len(pt) // what was encrypted
		if cfg.s.aead() {
			pkt = refSealAEAD(t, cfg.s.cipher, k2.ClientSend(), 0, cfg.peer, pid, pt)
		} else {
			// pt is the whole CBC plaintext: pid, payload and padding.
			bs := blockSizeOf(cfg.s.cipher)
			raw := bytes.Clone(pt)
			for len(raw)%bs != 0 {
				raw = append(raw, byte(bs-len(raw)%bs))
			}
			if len(raw) == 0 {
				raw = make([]byte, bs)
			}
			plainLen = len(raw)
			pkt = refSealCBC(t, cfg.s.cipher, cfg.s.digest, k2.ClientSend(), 0, cfg.peer, bytes.Repeat([]byte{1}, 16), raw)
		}
		got, kind, err := ch.Open(nil, pkt)
		if err != nil {
			return
		}
		if kind == KindPing && len(got) != 0 {
			t.Fatal("ping returned bytes")
		}
		// Only decompression can make a payload larger than the plaintext,
		// and that is bounded by MaxPayload.
		if len(got) > max(4096, plainLen) {
			t.Fatalf("payload of %d bytes from %d bytes of plaintext", len(got), plainLen)
		}
		if cfg.s.aead() && cfg.mode == compress.None && kind == KindPacket && !bytes.Equal(got, pt) {
			t.Fatalf("unframed payload %x, want %x", got, pt)
		}
	})
}
