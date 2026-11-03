// Package handshake holds what OpenVPN's key-method 2 exchange carries inside
// the TLS session and how data-channel keys come out of it: the two
// key-method 2 messages, the TLS 1.0 PRF derivation, the TLS keying-material
// exporter alternative, the peer-info block and the OCC options string.
//
// Key-method 2 message, client to server (all integers big-endian):
//
//	u32 0 | u8 2 | pre_master[48] | random1[32] | random2[32]
//	| string options | string username | string password | string peer_info
//
// Server to client is the same without pre_master. A string is a u16 length
// that counts a terminating NUL, then the bytes and the NUL; an empty
// string is just the u16 0. A client without credentials still writes the
// two empty strings, so the peer info can be found after them.
//
// Strings are C strings to the peer: a NUL inside one ends it there, so
// Marshal drops everything from the first NUL of a field on, and the parsers
// do the same with what they read. Parsers reject a string whose last byte
// is not NUL, and a message whose strings together take more than
// MaxStrings bytes.
//
// PRF derivation (OpenVPN's "key-method 2" PRF, TLS 1.0 PRF = P_MD5 xor
// P_SHA1 over the two halves of the secret):
//
//	master = PRF(pre_master, "OpenVPN master secret",
//	             client.random1 || server.random1, 48)
//	key2   = PRF(master, "OpenVPN key expansion",
//	             client.random2 || server.random2 || client_sid || server_sid, 256)
//
// With "key-derivation tls-ekm" key2 is instead the TLS exporter output for
// label "EXPORTER-OpenVPN-datakeys", no context, 256 bytes.
//
// key2 is two Keys of 64 cipher bytes then 64 hmac bytes. The client sends
// with key2[0] and receives with key2[1]; the server the reverse.
//
// Key material (Key, Key2, ClientKeySource) and ClientMessage passwords
// format as "REDACTED" with every fmt verb, so they cannot reach a log by
// accident.
package handshake

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/clientproof"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/wire"
)

const KeyMethod2 = 2

const (
	EKMLabel  = "EXPORTER-OpenVPN-datakeys"
	EKMLength = 256
)

// MaxStrings bounds the bytes all strings of one key-method 2 message take
// together (lengths as on the wire, terminating NULs included). Parsers
// fail with ErrBad beyond it.
const MaxStrings = 64 << 10

// MaxMessageLen is the most bytes a key-method 2 message the parsers accept
// can take: the client's fixed part, four string lengths and MaxStrings. A
// buffer at least this long never makes a parser return ErrShort.
const MaxMessageLen = clientFixedLen + 4*2 + MaxStrings

// IV_PROTO bits of the peer info.
const (
	IVProtoDataV2        = 1 << 1
	IVProtoRequestPush   = 1 << 2
	IVProtoTLSKeyExport  = 1 << 3
	IVProtoAuthPendingKW = 1 << 4
	IVProtoNCPP2P        = 1 << 5
	IVProtoDNSOption     = 1 << 6
	IVProtoCCExitNotify  = 1 << 7
	IVProtoAuthFailTemp  = 1 << 8
	IVProtoDynTLSCrypt   = 1 << 9
)

var (
	// ErrShort means the buffer does not yet hold a whole message.
	ErrShort = errors.New("handshake: message incomplete")
	ErrBad   = errors.New("handshake: malformed key-method 2 message")
)

const (
	keyMethodMask  = 0x0f
	serverFixedLen = 4 + 1 + 32 + 32
	clientFixedLen = 4 + 1 + 48 + 32 + 32
	// maxStringLen is the longest string a u16 length (which counts the NUL)
	// can describe.
	maxStringLen = 0xffff - 1
)

const redacted = "REDACTED"

// ClientKeySource is the client's random contribution.
type ClientKeySource struct {
	PreMaster [48]byte
	Random1   [32]byte
	Random2   [32]byte
}

// Format prints a placeholder so the pre-master secret never reaches a log.
func (ClientKeySource) Format(f fmt.State, _ rune) {
	io.WriteString(f, "handshake.ClientKeySource{"+redacted+"}")
}

// ServerKeySource is the server's random contribution.
type ServerKeySource struct {
	Random1 [32]byte
	Random2 [32]byte
}

// NewClientKeySource fills a ClientKeySource from r (crypto/rand.Reader in
// production).
func NewClientKeySource(r io.Reader) (*ClientKeySource, error) {
	s := new(ClientKeySource)
	for _, b := range [][]byte{s.PreMaster[:], s.Random1[:], s.Random2[:]} {
		if _, err := io.ReadFull(r, b); err != nil {
			*s = ClientKeySource{}
			return nil, fmt.Errorf("handshake: reading key source randomness: %w", err)
		}
	}
	return s, nil
}

// ClientMessage is the client's key-method 2 message.
type ClientMessage struct {
	Source   ClientKeySource
	Options  string
	Username string // both empty: written as two empty strings
	Password string
	PeerInfo string
}

// Format prints the message with its key source and password redacted.
func (m ClientMessage) Format(f fmt.State, _ rune) {
	pw := `""`
	if m.Password != "" {
		pw = redacted
	}
	fmt.Fprintf(f, "handshake.ClientMessage{Source:%s Options:%q Username:%q Password:%s PeerInfo:%q}",
		"{"+redacted+"}", m.Options, m.Username, pw, clientproof.RedactPeerInfo(m.PeerInfo))
}

// Marshal encodes m.
func (m *ClientMessage) Marshal() []byte {
	b := make([]byte, 0, clientFixedLen+4*3+len(m.Options)+len(m.Username)+len(m.Password)+len(m.PeerInfo))
	b = binary.BigEndian.AppendUint32(b, 0)
	b = append(b, KeyMethod2)
	b = append(b, m.Source.PreMaster[:]...)
	b = append(b, m.Source.Random1[:]...)
	b = append(b, m.Source.Random2[:]...)
	b = appendString(b, m.Options)
	b = appendString(b, m.Username)
	b = appendString(b, m.Password)
	return appendString(b, m.PeerInfo)
}

// ParseClientMessage decodes a client message from the front of b and
// returns the bytes consumed (used by test servers). All four strings must
// be present, as every OpenVPN 2.4+ client and Marshal write them.
func ParseClientMessage(b []byte) (*ClientMessage, int, error) {
	if err := checkFixed(b, clientFixedLen); err != nil {
		return nil, 0, err
	}
	m := new(ClientMessage)
	off := 5
	off += copy(m.Source.PreMaster[:], b[off:])
	off += copy(m.Source.Random1[:], b[off:])
	off += copy(m.Source.Random2[:], b[off:])
	r := stringReader{b: b, off: off, budget: MaxStrings}
	fields := []struct {
		dst  *string
		name string
	}{
		{&m.Options, "options"},
		{&m.Username, "username"},
		{&m.Password, "password"},
		{&m.PeerInfo, "peer info"},
	}
	for _, f := range fields {
		s, err := r.next(f.name)
		if err != nil {
			return nil, 0, err
		}
		*f.dst = s
	}
	return m, r.off, nil
}

// ServerMessage is the server's key-method 2 message.
type ServerMessage struct {
	Source   ServerKeySource
	Options  string
	PeerInfo string
}

// Marshal encodes m, with empty username and password strings before the
// peer info as OpenVPN servers write them (used by test servers).
func (m *ServerMessage) Marshal() []byte {
	b := make([]byte, 0, serverFixedLen+4*3+len(m.Options)+len(m.PeerInfo))
	b = binary.BigEndian.AppendUint32(b, 0)
	b = append(b, KeyMethod2)
	b = append(b, m.Source.Random1[:]...)
	b = append(b, m.Source.Random2[:]...)
	b = appendString(b, m.Options)
	b = appendString(b, "")
	b = appendString(b, "")
	return appendString(b, m.PeerInfo)
}

// ParseServerMessage decodes the server's message from the front of b and
// returns the bytes consumed. ErrShort means more bytes are needed. After
// the options string it reads up to three more strings (username,
// password, peer info) as long as b holds them, so a server that stops
// after the options string is accepted too.
//
// "As long as b holds them" is decided at string boundaries: if b ends
// exactly after the options string (or after the username or password) the
// message ends there; if b ends inside one of those strings the result is
// ErrShort. The leading u32 is not checked (OpenVPN ignores it); the low
// nibble of the key-method byte must be 2 and its high bits are ignored.
func ParseServerMessage(b []byte) (*ServerMessage, int, error) {
	if err := checkFixed(b, serverFixedLen); err != nil {
		return nil, 0, err
	}
	m := new(ServerMessage)
	off := 5
	off += copy(m.Source.Random1[:], b[off:])
	off += copy(m.Source.Random2[:], b[off:])
	r := stringReader{b: b, off: off, budget: MaxStrings}
	var err error
	if m.Options, err = r.next("options"); err != nil {
		return nil, 0, err
	}
	// Username and password are always empty from a server; only the peer
	// info is kept.
	for i, name := range []string{"username", "password", "peer info"} {
		if r.off == len(b) {
			break
		}
		s, err := r.next(name)
		if err != nil {
			return nil, 0, err
		}
		if i == 2 {
			m.PeerInfo = s
		}
	}
	return m, r.off, nil
}

// checkFixed checks the fixed part of a message: enough bytes and key
// method 2 (checked as soon as its byte is there, so a stream that is not
// a key-method 2 message fails without waiting for more).
func checkFixed(b []byte, fixed int) error {
	if len(b) < 5 {
		return ErrShort
	}
	if km := b[4] & keyMethodMask; km != KeyMethod2 {
		return fmt.Errorf("%w: key method %d, want %d", ErrBad, km, KeyMethod2)
	}
	if len(b) < fixed {
		return ErrShort
	}
	return nil
}

// stringReader reads key-method 2 strings from b[off:] within a byte
// budget shared by the whole message.
type stringReader struct {
	b      []byte
	off    int
	budget int
}

func (r *stringReader) next(name string) (string, error) {
	if len(r.b)-r.off < 2 {
		return "", ErrShort
	}
	n := int(binary.BigEndian.Uint16(r.b[r.off:]))
	if n == 0 {
		r.off += 2
		return "", nil
	}
	if n > r.budget {
		return "", fmt.Errorf("%w: %s string of %d bytes takes the message's strings past %d bytes", ErrBad, name, n, MaxStrings)
	}
	if len(r.b)-r.off-2 < n {
		return "", ErrShort
	}
	s := r.b[r.off+2 : r.off+2+n]
	if s[n-1] != 0 {
		return "", fmt.Errorf("%w: %s string is not NUL-terminated", ErrBad, name)
	}
	r.budget -= n
	r.off += 2 + n
	return cString(string(s[:n-1])), nil
}

// appendString appends s as a key-method 2 string: cut at its first NUL
// and at the longest length a u16 can describe.
func appendString(b []byte, s string) []byte {
	s = cString(s)
	if len(s) > maxStringLen {
		s = s[:maxStringLen]
	}
	if s == "" {
		return append(b, 0, 0)
	}
	b = binary.BigEndian.AppendUint16(b, uint16(len(s)+1))
	b = append(b, s...)
	return append(b, 0)
}

// cString returns s up to its first NUL, as a C peer reads it.
func cString(s string) string {
	if i := strings.IndexByte(s, 0); i >= 0 {
		return s[:i]
	}
	return s
}

// Key is one direction's key material.
type Key struct {
	Cipher [64]byte
	HMAC   [64]byte
}

// Format prints a placeholder so key material never reaches a log.
func (Key) Format(f fmt.State, _ rune) { io.WriteString(f, "handshake.Key{"+redacted+"}") }

// Key2 is the 256-byte expanded key block.
type Key2 [2]Key

// Format prints a placeholder so key material never reaches a log.
func (Key2) Format(f fmt.State, _ rune) { io.WriteString(f, "handshake.Key2{"+redacted+"}") }

func (k *Key2) ClientSend() *Key { return &k[0] }
func (k *Key2) ClientRecv() *Key { return &k[1] }
func (k *Key2) ServerSend() *Key { return &k[1] }
func (k *Key2) ServerRecv() *Key { return &k[0] }

const (
	masterLabel    = "OpenVPN master secret"
	expansionLabel = "OpenVPN key expansion"
)

// DeriveKey2PRF derives key2 with OpenVPN's PRF.
func DeriveKey2PRF(c *ClientKeySource, s *ServerKeySource, clientSID, serverSID wire.SessionID) *Key2 {
	var master [48]byte
	seed := make([]byte, 0, len(expansionLabel)+2*32+2*len(clientSID))
	seed = append(seed, masterLabel...)
	seed = append(seed, c.Random1[:]...)
	seed = append(seed, s.Random1[:]...)
	TLS1PRF(c.PreMaster[:], seed, master[:])

	seed = append(seed[:0], expansionLabel...)
	seed = append(seed, c.Random2[:]...)
	seed = append(seed, s.Random2[:]...)
	seed = append(seed, clientSID[:]...)
	seed = append(seed, serverSID[:]...)
	var block [EKMLength]byte
	TLS1PRF(master[:], seed, block[:])

	k := key2From(&block)
	clear(master[:])
	clear(block[:])
	return k
}

// Key2FromEKM splits a 256-byte exporter output into key2.
func Key2FromEKM(ekm []byte) (*Key2, error) {
	if len(ekm) != EKMLength {
		return nil, fmt.Errorf("handshake: exporter output is %d bytes, want %d", len(ekm), EKMLength)
	}
	return key2From((*[EKMLength]byte)(ekm)), nil
}

// key2From lays a 256-byte block out as key2: per Key, cipher then hmac.
func key2From(b *[EKMLength]byte) *Key2 {
	k := new(Key2)
	off := 0
	for i := range k {
		off += copy(k[i].Cipher[:], b[off:])
		off += copy(k[i].HMAC[:], b[off:])
	}
	return k
}

// TLS1PRF writes len(out) bytes of the TLS 1.0/1.1 PRF of secret over
// labelAndSeed (the label already prepended to the seed).
//
// It is P_MD5(S1, labelAndSeed) xor P_SHA1(S2, labelAndSeed) (RFC 2246
// section 5), S1 being the first and S2 the last ceil(len(secret)/2) bytes
// of secret; they share the middle byte when the length is odd.
func TLS1PRF(secret, labelAndSeed, out []byte) {
	half := (len(secret) + 1) / 2
	pHash(md5.New, secret[:half], labelAndSeed, out, false)
	pHash(sha1.New, secret[len(secret)-half:], labelAndSeed, out, true)
}

// pHash writes (or, with xor, xors into out) P_hash(secret, seed) as RFC
// 2246 section 5 defines it: HMAC(secret, A(i) || seed) for i = 1, 2, ...
// with A(0) = seed and A(i) = HMAC(secret, A(i-1)).
func pHash(h func() hash.Hash, secret, seed, out []byte, xor bool) {
	mac := hmac.New(h, secret)
	mac.Write(seed)
	a := mac.Sum(nil) // A(1)
	var block []byte
	for len(out) > 0 {
		mac.Reset()
		mac.Write(a)
		mac.Write(seed)
		block = mac.Sum(block[:0])
		n := min(len(out), len(block))
		if xor {
			for i := range n {
				out[i] ^= block[i]
			}
		} else {
			copy(out, block[:n])
		}
		out = out[n:]
		mac.Reset()
		mac.Write(a)
		a = mac.Sum(a[:0])
	}
	clear(a)
	clear(block)
}

// PeerInfo is the client's IV_* block.
type PeerInfo struct {
	Version  string   // IV_VER, e.g. "2.6.12"
	Platform string   // IV_PLAT, e.g. "android" or "linux"
	Proto    uint32   // IV_PROTO bits
	Ciphers  []string // IV_CIPHERS, also implies IV_NCP=2 when non-empty
	MTU      int      // IV_MTU, 0 to omit
	// Compression support announced: IV_LZO_STUB, IV_COMP_STUB,
	// IV_COMP_STUBv2 when Stubs; IV_LZO, IV_LZ4, IV_LZ4v2 when Decompress.
	Stubs      bool
	Decompress bool
	// Extra lines appended verbatim (e.g. "IV_GUI_VER=..."), each "KEY=value".
	Extra []string
}

// String renders the block as newline-terminated KEY=value lines, in this
// order: IV_VER and IV_PLAT (each omitted when empty), IV_PROTO (always,
// decimal), IV_NCP=2 and IV_CIPHERS (colon-separated) when Ciphers is not
// empty, IV_MTU when MTU > 0, the three stub lines, the three decompression
// lines, then the non-empty Extra entries.
func (p *PeerInfo) String() string {
	var b strings.Builder
	line := func(k, v string) {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(v)
		b.WriteByte('\n')
	}
	if p.Version != "" {
		line("IV_VER", p.Version)
	}
	if p.Platform != "" {
		line("IV_PLAT", p.Platform)
	}
	line("IV_PROTO", strconv.FormatUint(uint64(p.Proto), 10))
	if len(p.Ciphers) > 0 {
		line("IV_NCP", "2")
		line("IV_CIPHERS", strings.Join(p.Ciphers, ":"))
	}
	if p.MTU > 0 {
		line("IV_MTU", strconv.Itoa(p.MTU))
	}
	if p.Stubs {
		line("IV_LZO_STUB", "1")
		line("IV_COMP_STUB", "1")
		line("IV_COMP_STUBv2", "1")
	}
	if p.Decompress {
		line("IV_LZO", "1")
		line("IV_LZ4", "1")
		line("IV_LZ4v2", "1")
	}
	for _, e := range p.Extra {
		if e != "" {
			b.WriteString(e)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// OCCOptions describes the OCC options string.
type OCCOptions struct {
	TCP bool // proto TCPv4_CLIENT instead of UDPv4
	// IPv6 does not change the string: OpenVPN 2.4+ names the v4 protocols
	// whatever the address family (2.6.19 sends "proto UDPv4" and
	// "proto TCPv4_CLIENT" over IPv6), and so expects them from its peer.
	IPv6    bool
	TunMTU  int    // default 1500
	LinkMTU int    // default TunMTU + overhead OpenVPN would compute; any plausible value
	Cipher  string // e.g. "AES-256-GCM" or "BF-CBC"
	Auth    string // e.g. "SHA1"; "[null-digest]" for AEAD
	KeySize int    // cipher key bits
	CompLZO bool   // adds ",comp-lzo"
	TLSAuth bool   // adds ",tls-auth"
	// KeyDir adds ",keydir 0" or ",keydir 1" (tls-auth with a key
	// direction, as OpenVPN sends it); "" omits it.
	KeyDir string
}

// OptionsString renders the OCC string a client sends, e.g.
// "V4,dev-type tun,link-mtu 1549,tun-mtu 1500,proto UDPv4,cipher AES-256-GCM,auth [null-digest],keysize 256,key-method 2,tls-client".
//
// The order is OpenVPN's (checked against 2.6.19): V4, dev-type tun,
// link-mtu, tun-mtu, proto, comp-lzo (if CompLZO), keydir (if KeyDir),
// cipher, auth, keysize, tls-auth (if TLSAuth), key-method 2, tls-client.
//
// Defaults for zero fields follow what OpenVPN 2.6 prints:
//   - Cipher "" omits the cipher entry, as OpenVPN does when no --cipher is
//     set (link-mtu and keysize then assume BF-CBC); "none" or
//     "[null-cipher]" omits it too, with keysize 0.
//   - Auth "" is "SHA1"; a known AEAD cipher always gets "[null-digest]".
//   - KeySize 0 is taken from the cipher name (128 when unknown).
//   - LinkMTU 0 is TunMTU plus OpenVPN's overhead estimate: opcode 1,
//     packet id 4 (8 for CFB/OFB), then 12 IV + 16 tag + the block size for
//     AEAD ciphers, or IV + block size + HMAC size otherwise, plus 2 over
//     TCP and 1 with comp-lzo.
func OptionsString(o OCCOptions) string {
	c := cipherInfoFor(o.Cipher)
	tun := o.TunMTU
	if tun <= 0 {
		tun = 1500
	}
	auth := o.Auth
	switch {
	case c.aead:
		auth = "[null-digest]"
	case auth == "":
		auth = "SHA1"
	}
	keySize := o.KeySize
	if keySize <= 0 {
		keySize = c.keyBits
	}
	link := o.LinkMTU
	if link <= 0 {
		link = tun + 1 + c.packetID + c.ivLen + c.block + c.tag
		if !c.aead {
			link += digestLen(auth)
		}
		if o.TCP {
			link += 2
		}
		if o.CompLZO {
			link++
		}
	}

	var b strings.Builder
	b.WriteString("V4,dev-type tun,link-mtu ")
	b.WriteString(strconv.Itoa(link))
	b.WriteString(",tun-mtu ")
	b.WriteString(strconv.Itoa(tun))
	if o.TCP {
		b.WriteString(",proto TCPv4_CLIENT")
	} else {
		b.WriteString(",proto UDPv4")
	}
	if o.CompLZO {
		b.WriteString(",comp-lzo")
	}
	if o.KeyDir != "" {
		b.WriteString(",keydir ")
		b.WriteString(o.KeyDir)
	}
	if c.printed {
		b.WriteString(",cipher ")
		b.WriteString(o.Cipher)
	}
	b.WriteString(",auth ")
	b.WriteString(auth)
	b.WriteString(",keysize ")
	b.WriteString(strconv.Itoa(keySize))
	if o.TLSAuth {
		b.WriteString(",tls-auth")
	}
	b.WriteString(",key-method 2,tls-client")
	return b.String()
}

// cipherInfo is what OptionsString needs to know about a data cipher.
type cipherInfo struct {
	printed  bool // the string carries ",cipher NAME"
	aead     bool
	keyBits  int
	packetID int // 4, or 8 (long form) for CFB/OFB
	ivLen    int
	block    int
	tag      int
}

// cipherInfoFor describes an OpenVPN cipher name. Unknown names are taken
// as a 128-bit cipher with 16-byte blocks in CBC mode.
func cipherInfoFor(name string) cipherInfo {
	n := strings.ToUpper(name)
	switch n {
	case "":
		// No cipher set: OpenVPN computes with its old BF-CBC default.
		return cipherInfo{keyBits: 128, packetID: 4, ivLen: 8, block: 8}
	case "NONE", "[NULL-CIPHER]":
		return cipherInfo{packetID: 4}
	case "CHACHA20-POLY1305":
		return cipherInfo{printed: true, aead: true, keyBits: 256, packetID: 4, ivLen: 12, block: 1, tag: 16}
	}
	c := cipherInfo{printed: true, keyBits: 128, packetID: 4, block: 16}
	parts := strings.Split(n, "-")
	switch parts[0] {
	case "BF", "CAST5", "IDEA", "RC2", "DES", "DESX":
		c.block = 8
	}
	switch {
	case parts[0] == "DES" && len(parts) > 1 && parts[1] == "EDE3":
		c.keyBits = 192
	case parts[0] == "DES" && len(parts) > 1 && parts[1] == "EDE":
		c.keyBits = 128
	case parts[0] == "DES":
		c.keyBits = 64
	case parts[0] == "DESX":
		c.keyBits = 192
	case len(parts) > 1:
		if bits, err := strconv.Atoi(parts[1]); err == nil && bits > 0 && bits <= 512 {
			c.keyBits = bits // AES-256-..., CAMELLIA-128-..., ARIA-192-...
		}
	}
	mode := parts[len(parts)-1]
	switch {
	case mode == "GCM" || mode == "CCM":
		c.aead = true
		c.ivLen = 12
		c.tag = 16
	case strings.HasPrefix(mode, "CFB") || mode == "OFB":
		c.packetID = 8
		c.ivLen = c.block
	default:
		c.ivLen = c.block
	}
	return c
}

// digestLen is the HMAC output size of an OpenVPN digest name; 20 (SHA1)
// when unknown.
func digestLen(name string) int {
	n := strings.ReplaceAll(strings.ToUpper(name), "-", "")
	switch n {
	case "[NULLDIGEST]", "NONE":
		return 0
	case "MD5", "MD4":
		return 16
	case "SHA224", "SHA512224", "SHA3224":
		return 28
	case "SHA256", "SHA512256", "SHA3256", "BLAKE2S256", "SM3":
		return 32
	case "SHA384", "SHA3384":
		return 48
	case "SHA512", "SHA3512", "BLAKE2B512", "WHIRLPOOL":
		return 64
	}
	return 20
}
