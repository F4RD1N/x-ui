// Native ShadowTLS wire implementation from the MIT-licensed protocol specification.
package shadowtls

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/proxy/nativebridge"
	"github.com/xtls/xray-core/transport/internet/stat"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

func newMAC(password string, prefix []byte) hash.Hash {
	h := hmac.New(sha1.New, []byte(password))
	h.Write(prefix)
	return h
}
func matches(h hash.Hash, data, tag []byte) bool {
	h.Write(data)
	return subtle.ConstantTimeCompare(h.Sum(nil)[:len(tag)], tag) == 1
}

// SessionID signs the complete handshake message, not its TLS record header.
func SessionID(hello []byte, password string, custom bool) ([32]byte, error) {
	var sid [32]byte
	if len(hello) < 71 || hello[0] != 1 || hello[38] != 32 {
		return sid, errors.New("ShadowTLS requires a 32-byte ClientHello session ID")
	}
	if _, e := rand.Read(sid[:28]); e != nil {
		return sid, e
	}
	if custom {
		u, e := uuid.Parse(password)
		if e != nil {
			return sid, errors.New("uuidSessionId requires a UUID password")
		}
		copy(sid[12:28], u[:])
	}
	copy(hello[39:71], sid[:])
	mac := newMAC(password, nil)
	mac.Write(hello)
	copy(sid[28:], mac.Sum(nil)[:4])
	copy(hello[39:71], sid[:])
	return sid, nil
}

func readRecord(r io.Reader) (byte, [2]byte, []byte, error) {
	var h [5]byte
	var v [2]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return 0, v, nil, e
	}
	copy(v[:], h[1:3])
	n := int(binary.BigEndian.Uint16(h[3:]))
	if n > 18432 {
		return 0, v, nil, errors.New("oversized ShadowTLS TLS record")
	}
	b := make([]byte, n)
	_, e := io.ReadFull(r, b)
	return h[0], v, b, e
}
func record(t byte, v [2]byte, b []byte) []byte {
	h := []byte{t, v[0], v[1], byte(len(b) >> 8), byte(len(b))}
	return append(h, b...)
}

type handshakeReader struct {
	net.Conn
	password     string
	version      uint32
	pending      []byte
	serverRandom []byte
	xor          [32]byte
	mac          hash.Hash
	v2mac        hash.Hash
	verified     bool
	hijacked     bool
	// v2 only: bytes read from the socket but not yet handed to TLS. The v2
	// tag covers everything read from the socket during the handshake, as the
	// server hashes what it forwards per write: a TLS 1.3 server's session
	// tickets in the same flight as its Finished are part of it.
	v2raw []byte
}

// readHashed reads one record for TLS, hashing whole socket reads (v2).
func (r *handshakeReader) readHashed() (byte, [2]byte, []byte, error) {
	if e := r.fill(5); e != nil {
		return 0, [2]byte{}, nil, e
	}
	n := int(binary.BigEndian.Uint16(r.v2raw[3:5]))
	if n > 18432 {
		return 0, [2]byte{}, nil, errors.New("oversized ShadowTLS TLS record")
	}
	if e := r.fill(5 + n); e != nil {
		return 0, [2]byte{}, nil, e
	}
	t, v := r.v2raw[0], [2]byte{r.v2raw[1], r.v2raw[2]}
	b := append([]byte(nil), r.v2raw[5:5+n]...)
	r.v2raw = r.v2raw[5+n:]
	return t, v, b, nil
}

func (r *handshakeReader) fill(n int) error {
	for len(r.v2raw) < n {
		buf := make([]byte, 32<<10)
		k, e := r.Conn.Read(buf)
		if k > 0 {
			r.v2mac.Write(buf[:k])
			r.v2raw = append(r.v2raw, buf[:k]...)
			continue
		}
		if e == nil {
			e = io.ErrNoProgress
		}
		if e == io.EOF && len(r.v2raw) > 0 {
			e = io.ErrUnexpectedEOF
		}
		return e
	}
	return nil
}

func (r *handshakeReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.pending) == 0 {
		var t byte
		var v [2]byte
		var b []byte
		var e error
		if r.version == 2 {
			t, v, b, e = r.readHashed()
		} else {
			t, v, b, e = readRecord(r.Conn)
		}
		if e != nil {
			return 0, e
		}
		if r.version == 3 {
			if t == 22 && len(b) >= 38 && b[0] == 2 {
				r.serverRandom = append([]byte(nil), b[6:38]...)
				r.mac = newMAC(r.password, r.serverRandom)
				r.xor = sha256.Sum256(append([]byte(r.password), r.serverRandom...))
			}
			if t == 23 {
				if r.mac != nil && len(b) >= 4 && matches(r.mac, b[4:], b[:4]) {
					r.verified = true
					b = append([]byte(nil), b[4:]...)
					for i := range b {
						b[i] ^= r.xor[i%32]
					}
				} else {
					r.hijacked = true
				}
			}
		}
		r.pending = record(t, v, b)
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

type Conn struct {
	net.Conn
	version       uint32
	rmu, wmu      sync.Mutex
	rhash, whash  hash.Hash
	handshakeHash hash.Hash
	switched      bool
	pending       []byte
	firstWrite    bool
	writeClosed   bool
	v2tag         []byte
	// v2 only: the handshake server's leftover TLS 1.3 records (session
	// tickets) are dropped while they still open with its traffic key.
	v2filter *recordFilter
	v2in     io.Reader // v2: bytes the handshake read ahead, then the socket
}

func Handshake(ctx context.Context, raw net.Conn, c *Config) (*Conn, error) {
	version := c.Version
	if version == 0 {
		version = 3
	}
	if version < 1 || version > 3 {
		return nil, errors.New("ShadowTLS supports versions 1, 2 and 3")
	}
	if c.UuidSessionId && version != 3 {
		return nil, errors.New("uuidSessionId is only valid for ShadowTLS v3")
	}
	w := &handshakeReader{Conn: raw, password: c.Password, version: version}
	var secrets *secretLog
	if version == 2 {
		w.v2mac = newMAC(c.Password, nil)
	}
	tc := &utls.Config{ServerName: c.ServerName, InsecureSkipVerify: c.AllowInsecure, MinVersion: utls.VersionTLS12, MaxVersion: utls.VersionTLS13}
	if version == 1 {
		tc.MaxVersion = utls.VersionTLS12
	}
	if c.Strict && version == 3 {
		tc.MinVersion = utls.VersionTLS13
	}
	if c.CaPem != "" {
		pool, e := x509.SystemCertPool()
		if e != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(c.CaPem)) {
			return nil, errors.New("invalid ShadowTLS CA PEM")
		}
		tc.RootCAs = pool
	}
	if version == 2 {
		secrets = &secretLog{}
		tc.KeyLogWriter = secrets
	}
	fingerprint := xtls.GetFingerprint(c.Fingerprint)
	if fingerprint == nil {
		return nil, errors.New("unsupported ShadowTLS fingerprint")
	}
	// A utls preset replaces Config.Min/MaxVersion with the versions in its
	// supported_versions extension, so the version policy goes into the spec.
	var tlsConn *utls.UConn
	if spec := versionCappedSpec(*fingerprint, version, c.Strict); spec != nil {
		tlsConn = utls.UClient(w, tc, utls.HelloCustom)
		if e := tlsConn.ApplyPreset(spec); e != nil {
			return nil, e
		}
	} else {
		tlsConn = utls.UClient(w, tc, *fingerprint)
	}
	if e := tlsConn.BuildHandshakeState(); e != nil {
		return nil, e
	}
	if version == 3 {
		tlsConn.HandshakeState.Hello.SessionId = make([]byte, 32)
		if e := tlsConn.MarshalClientHello(); e != nil {
			return nil, e
		}
		sid, e := SessionID(tlsConn.HandshakeState.Hello.Raw, c.Password, c.UuidSessionId)
		if e != nil {
			return nil, e
		}
		tlsConn.HandshakeState.Hello.SessionId = sid[:]
	}
	if e := tlsConn.HandshakeContext(ctx); e != nil {
		return nil, e
	}
	if len(w.pending) > 0 {
		return nil, errors.New("TLS handshake left a partially consumed record")
	}
	conn := &Conn{Conn: raw, version: version, firstWrite: true}
	if version == 3 {
		// Strict mode needs an authenticated server; non-strict mode (which
		// allows TLS 1.2 handshake servers) only needs the ServerHello random.
		if len(w.serverRandom) != 32 || (c.Strict && (w.hijacked || !w.verified)) {
			sendDecoy(tlsConn, raw, c.ServerName)
			return nil, errors.New("ShadowTLS server authentication failed")
		}
		if c.Strict && tlsConn.ConnectionState().Version != utls.VersionTLS13 {
			return nil, errors.New("strict ShadowTLS requires TLS 1.3")
		}
		conn.handshakeHash = w.mac
		conn.rhash = newMAC(c.Password, append(append([]byte(nil), w.serverRandom...), byte('S')))
		conn.whash = newMAC(c.Password, append(append([]byte(nil), w.serverRandom...), byte('C')))
	}
	if version == 2 {
		conn.v2tag = append([]byte(nil), w.v2mac.Sum(nil)[:8]...)
		conn.v2in = raw
		if len(w.v2raw) > 0 {
			conn.v2in = io.MultiReader(bytes.NewReader(w.v2raw), raw)
		}
		if st := tlsConn.ConnectionState(); st.Version == utls.VersionTLS13 {
			conn.v2filter = newRecordFilter(st.CipherSuite, secrets.get())
		}
	}
	// The TLS connection is deliberately not used or closed after this point:
	// ShadowTLS switches to its authenticated record layer on the same socket.
	return conn, nil
}

func (c *Conn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.writeClosed {
		return 0, net.ErrClosed
	}
	if c.version == 1 {
		return c.Conn.Write(p)
	}
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > 16384 {
			n = 16384
		}
		data := p[:n]
		var body []byte
		if c.version == 3 {
			c.whash.Write(data)
			tag := append([]byte(nil), c.whash.Sum(nil)[:4]...)
			c.whash.Write(tag)
			body = append(tag, data...)
		} else {
			if c.firstWrite {
				body = append(append([]byte(nil), c.v2tag...), data...)
			} else {
				body = data
			}
		}
		c.firstWrite = false
		if e := nativebridge.WriteFull(c.Conn, record(23, [2]byte{3, 3}, body)); e != nil {
			return total, e
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

// CloseWrite preserves TCP's half-close semantics through the record wrapper.
// A request whose response depends on EOF can finish sending while retaining
// the opposite direction. It never closes the readable half as a fallback.
func (c *Conn) CloseWrite() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.writeClosed {
		return nil
	}
	raw := c.Conn
	for {
		if closer, ok := raw.(interface{ CloseWrite() error }); ok {
			if err := closer.CloseWrite(); err != nil {
				return err
			}
			c.writeClosed = true
			return nil
		}
		unwrapped := stat.TryUnwrapStatsConn(raw)
		if unwrapped == raw {
			return errors.New("ShadowTLS underlying connection does not support half-close")
		}
		raw = unwrapped
	}
}

func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.version == 1 {
		return c.Conn.Read(p)
	}
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.pending) == 0 {
		in := io.Reader(c.Conn)
		if c.v2in != nil {
			in = c.v2in
		}
		t, v, b, e := readRecord(in)
		if e != nil {
			return 0, e
		}
		if t == 21 {
			return 0, io.EOF
		}
		if t != 23 {
			return 0, errors.New("unexpected ShadowTLS record type")
		}
		if c.version == 2 {
			if c.v2filter != nil {
				if c.v2filter.drop(t, v, b) {
					continue
				}
				c.v2filter = nil // the data server's records follow; stop for good
			}
			c.pending = b
			continue
		}
		if len(b) < 4 {
			return 0, c.badMAC()
		}
		tag, data := b[:4], b[4:]
		if !c.switched && matches(c.handshakeHash, data, tag) {
			continue
		}
		if !matches(c.rhash, data, tag) {
			return 0, c.badMAC()
		}
		c.rhash.Write(tag)
		c.switched = true
		c.pending = data
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *Conn) badMAC() error {
	c.wmu.Lock()
	_ = c.Conn.SetWriteDeadline(time.Now().Add(time.Second))
	_ = nativebridge.WriteFull(c.Conn, []byte{21, 3, 3, 0, 2, 2, 20})
	c.wmu.Unlock()
	c.Conn.Close()
	return errors.New("ShadowTLS record authentication failed")
}

// versionCappedSpec is the fingerprint's ClientHello with the version policy
// applied: v1 offers TLS 1.2 at most, strict v3 only TLS 1.3. It is nil when
// no cap applies, or when the fingerprint has no fixed spec (Go's own hello
// already honours the Config caps; a randomized one cannot be capped).
func versionCappedSpec(id utls.ClientHelloID, version uint32, strict bool) *utls.ClientHelloSpec {
	if version != 1 && !(version == 3 && strict) {
		return nil
	}
	spec, e := utls.UTLSIdToSpec(id)
	if e != nil {
		return nil
	}
	allowed := func(v uint16) bool {
		if v&0x0f0f == 0x0a0a { // GREASE keeps the fingerprint's shape
			return true
		}
		if version == 1 {
			return v >= utls.VersionTLS10 && v <= utls.VersionTLS12
		}
		return v == utls.VersionTLS13
	}
	for i, ext := range spec.Extensions {
		sv, ok := ext.(*utls.SupportedVersionsExtension)
		if !ok {
			continue
		}
		var vs []uint16
		for _, v := range sv.Versions {
			if allowed(v) {
				vs = append(vs, v)
			}
		}
		spec.Extensions[i] = &utls.SupportedVersionsExtension{Versions: vs}
	}
	if version == 1 {
		if spec.TLSVersMax > utls.VersionTLS12 {
			spec.TLSVersMax = utls.VersionTLS12
		}
		suites := spec.CipherSuites[:0:0]
		for _, cs := range spec.CipherSuites {
			if cs < 0x1301 || cs > 0x1305 { // TLS 1.3-only suites
				suites = append(suites, cs)
			}
		}
		spec.CipherSuites = suites
	}
	return &spec
}

const decoyUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

// sendDecoy ends a handshake whose server failed authentication the way a
// browser's visit would end: a random-length HTTP request on the finished TLS
// session, its response, then close_notify (the v3 "muddled request").
// Everything is best effort and bounded.
func sendDecoy(tlsConn *utls.UConn, raw net.Conn, host string) {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var r [65]byte
	if _, e := rand.Read(r[:]); e != nil {
		return
	}
	path := make([]byte, 8+int(r[64])%57)
	for i := range path {
		path[i] = letters[int(r[i])%len(letters)]
	}
	_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
	req := "GET /" + string(path) + " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: " + decoyUserAgent +
		"\r\nAccept: */*\r\nConnection: close\r\n\r\n"
	if _, e := tlsConn.Write([]byte(req)); e == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(tlsConn, 64<<10))
	}
	_ = tlsConn.Close()
}

// secretLog keeps this connection's server application traffic secret,
// which the v2 record filter needs. It never leaves memory.
type secretLog struct {
	mu     sync.Mutex
	secret []byte
}

func (l *secretLog) Write(p []byte) (int, error) {
	if f := strings.Fields(string(p)); len(f) == 3 && f[0] == "SERVER_TRAFFIC_SECRET_0" {
		if s, e := hex.DecodeString(f[2]); e == nil {
			l.mu.Lock()
			l.secret = s
			l.mu.Unlock()
		}
	}
	return len(p), nil
}

func (l *secretLog) get() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.secret
}

// recordFilter recognises records the TLS 1.3 handshake server sent after its
// Finished (session tickets): they open with its first application traffic
// key, records from the ShadowTLS data server never do. It only decrypts; it
// never writes to the socket.
type recordFilter struct {
	aead cipher.AEAD
	iv   []byte
	seq  uint64
}

func newRecordFilter(suite uint16, secret []byte) *recordFilter {
	if len(secret) == 0 {
		return nil
	}
	newHash, keyLen := sha256.New, 16
	switch suite {
	case utls.TLS_AES_128_GCM_SHA256:
	case utls.TLS_AES_256_GCM_SHA384:
		newHash, keyLen = sha512.New384, 32
	case utls.TLS_CHACHA20_POLY1305_SHA256:
		keyLen = 32
	default:
		return nil
	}
	key := expandLabel(newHash, secret, "key", keyLen)
	iv := expandLabel(newHash, secret, "iv", 12)
	var aead cipher.AEAD
	var e error
	if suite == utls.TLS_CHACHA20_POLY1305_SHA256 {
		aead, e = chacha20poly1305.New(key)
	} else {
		var b cipher.Block
		if b, e = aes.NewCipher(key); e == nil {
			aead, e = cipher.NewGCM(b)
		}
	}
	if e != nil {
		return nil
	}
	return &recordFilter{aead: aead, iv: iv}
}

// expandLabel is HKDF-Expand-Label from RFC 8446 section 7.1, empty context.
func expandLabel(newHash func() hash.Hash, secret []byte, label string, n int) []byte {
	l := "tls13 " + label
	info := []byte{byte(n >> 8), byte(n), byte(len(l))}
	info = append(append(info, l...), 0)
	out := make([]byte, n)
	_, _ = io.ReadFull(hkdf.Expand(newHash, secret, info), out)
	return out
}

func (f *recordFilter) drop(t byte, v [2]byte, b []byte) bool {
	if len(b) < f.aead.Overhead() {
		return false
	}
	nonce := append([]byte(nil), f.iv...)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(f.seq >> (8 * i))
	}
	header := []byte{t, v[0], v[1], byte(len(b) >> 8), byte(len(b))}
	if _, e := f.aead.Open(nil, nonce, b, header); e != nil {
		return false
	}
	f.seq++
	return true
}
