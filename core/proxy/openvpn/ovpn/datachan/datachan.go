// Package datachan seals and opens OpenVPN data-channel packets in TLS mode.
//
// Packet layouts after the data header (wire.AppendDataHeader: 1 byte for
// P_DATA_V1, 4 for P_DATA_V2), pid = 4-byte big-endian packet id from 1:
//
//	AEAD (AES-128/192/256-GCM, CHACHA20-POLY1305):
//	    pid | tag(16) | ciphertext
//	    nonce = pid || implicit_iv, implicit_iv = first 8 bytes of the
//	    direction's Key.HMAC; key = first keylen bytes of Key.Cipher.
//	    additional data = the 4-byte P_DATA_V2 header || pid, or just pid
//	    for P_DATA_V1.
//	CBC (AES-128/192/256-CBC, BF-CBC) with HMAC (--auth, default SHA1):
//	    hmac(digest size) | iv(block size) | ciphertext
//	    plaintext = pid || payload, PKCS#7 padded; iv random per packet;
//	    hmac = HMAC(first digest-size bytes of Key.HMAC, iv || ciphertext);
//	    key = first keylen bytes of Key.Cipher (BF-CBC: 16 bytes).
//
// The payload is the IP packet after compression framing (package
// compress), and keepalive pings and OCC messages travel the same way.
//
// Incoming packet ids go through a sliding replay window per key; a packet
// that fails authentication or replays is dropped with an error and does not
// move the window. Sending stops with ErrPacketIDExhausted before the id
// wraps; NeedsRenegotiation turns true well before that.
package datachan

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/compress"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/handshake"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/wire"
)

// PingPayload is OpenVPN's keepalive ping, sent as a data-channel payload.
var PingPayload = [16]byte{0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48}

// OCCPrefix starts an OCC message; one opcode byte follows.
var OCCPrefix = [16]byte{0x28, 0x7f, 0x34, 0x6b, 0xd4, 0xef, 0x7a, 0x81, 0x2d, 0x56, 0xb8, 0xd3, 0xaf, 0xc5, 0x45, 0x9c}

// OCCExit is the OCC opcode of explicit-exit-notify.
const OCCExit = 6

var (
	ErrUnsupported       = errors.New("datachan: unsupported cipher or digest")
	ErrAuth              = errors.New("datachan: packet failed authentication")
	ErrReplay            = errors.New("datachan: replayed packet")
	ErrNoKey             = errors.New("datachan: no key for packet")
	ErrPacketIDExhausted = errors.New("datachan: packet id space exhausted")
	ErrShort             = errors.New("datachan: packet too short")
)

const (
	pidSize        = 4
	aeadTagSize    = 16
	aeadNonceSize  = 12
	implicitIVSize = aeadNonceSize - pidSize

	// lastPID is the first packet id Seal refuses to use: ids 1 through
	// lastPID-1 are sent, so the 32-bit id never wraps.
	lastPID = 0xFFFFFFFF
	// renegotiateAbove is the send count past which NeedsRenegotiation is
	// true.
	renegotiateAbove = 0xFF000000

	defaultReplayWindow = 64
	// maxReplayWindow bounds the per-key bitmap (OpenVPN's own limit).
	maxReplayWindow   = 65536
	defaultMaxPayload = 65535

	maxDigestSize = sha512.Size
	maxBlockSize  = aes.BlockSize
)

// randReader supplies CBC IVs; NewKeyState copies it into each KeyState so
// tests can inject a deterministic source.
var randReader io.Reader = rand.Reader

// ivBatch is how many random bytes a CBC key reads at a time for its IVs:
// one read per packet would be a getrandom system call per packet on
// kernels without the vDSO one. They come from randReader all the same.
const ivBatch = 4096

// scratch holds one operation's small buffers (AEAD nonce and additional
// data, CBC IV and HMAC). Passed through the cipher and hash interfaces,
// arrays on the stack would escape to the heap on every packet, so they
// come from a pool.
type scratch struct {
	nonce [aeadNonceSize]byte
	ad    [8]byte
	iv    [maxBlockSize]byte
	sum   [maxDigestSize]byte
}

var scratchPool = sync.Pool{New: func() any { return new(scratch) }}

// ivSetter is implemented by the BlockModes crypto/cipher returns for CBC:
// one can be reused for the next packet with a new IV.
type ivSetter interface{ SetIV(iv []byte) }

type cipherInfo struct {
	keyLen   int // bytes taken from Key.Cipher
	keyBits  int
	newAEAD  func(key []byte) (cipher.AEAD, error)
	newBlock func(key []byte) (cipher.Block, error)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func newBlowfish(key []byte) (cipher.Block, error) { return blowfish.NewCipher(key) }

var ciphers = map[string]cipherInfo{
	"AES-128-GCM":       {keyLen: 16, keyBits: 128, newAEAD: newGCM},
	"AES-192-GCM":       {keyLen: 24, keyBits: 192, newAEAD: newGCM},
	"AES-256-GCM":       {keyLen: 32, keyBits: 256, newAEAD: newGCM},
	"CHACHA20-POLY1305": {keyLen: chacha20poly1305.KeySize, keyBits: 256, newAEAD: chacha20poly1305.New},
	"AES-128-CBC":       {keyLen: 16, keyBits: 128, newBlock: aes.NewCipher},
	"AES-192-CBC":       {keyLen: 24, keyBits: 192, newBlock: aes.NewCipher},
	"AES-256-CBC":       {keyLen: 32, keyBits: 256, newBlock: aes.NewCipher},
	"BF-CBC":            {keyLen: 16, keyBits: 128, newBlock: newBlowfish},
}

// cipherAliases maps upper-cased OpenSSL/OpenVPN spellings to canonical
// names.
var cipherAliases = map[string]string{
	"AES-128-GCM":       "AES-128-GCM",
	"ID-AES128-GCM":     "AES-128-GCM",
	"AES-192-GCM":       "AES-192-GCM",
	"ID-AES192-GCM":     "AES-192-GCM",
	"AES-256-GCM":       "AES-256-GCM",
	"ID-AES256-GCM":     "AES-256-GCM",
	"CHACHA20-POLY1305": "CHACHA20-POLY1305",
	"AES-128-CBC":       "AES-128-CBC",
	"AES128":            "AES-128-CBC",
	"AES-192-CBC":       "AES-192-CBC",
	"AES192":            "AES-192-CBC",
	"AES-256-CBC":       "AES-256-CBC",
	"AES256":            "AES-256-CBC",
	"BF-CBC":            "BF-CBC",
	"BF":                "BF-CBC",
	"BLOWFISH":          "BF-CBC",
}

type digestInfo struct {
	size int
	new  func() hash.Hash
}

var digests = map[string]digestInfo{
	"MD5":    {md5.Size, md5.New},
	"SHA1":   {sha1.Size, sha1.New},
	"SHA224": {sha256.Size224, sha256.New224},
	"SHA256": {sha256.Size, sha256.New},
	"SHA384": {sha512.Size384, sha512.New384},
	"SHA512": {sha512.Size, sha512.New},
}

// digestAliases maps upper-cased names with "RSA-" stripped and dashes and
// underscores removed to canonical names.
var digestAliases = map[string]string{
	"MD5":      "MD5",
	"SSL3MD5":  "MD5",
	"SHA1":     "SHA1",
	"SSL3SHA1": "SHA1",
	"SHA224":   "SHA224",
	"SHA2224":  "SHA224",
	"SHA256":   "SHA256",
	"SHA2256":  "SHA256",
	"SHA384":   "SHA384",
	"SHA2384":  "SHA384",
	"SHA512":   "SHA512",
	"SHA2512":  "SHA512",
}

// CanonicalCipher maps a --cipher/--data-ciphers name, case-insensitively, to
// the canonical upper-case name: AES-128-GCM, AES-192-GCM, AES-256-GCM,
// CHACHA20-POLY1305, AES-128-CBC, AES-192-CBC, AES-256-CBC, BF-CBC. ok is
// false for anything else.
func CanonicalCipher(name string) (canonical string, ok bool) {
	canonical, ok = cipherAliases[strings.ToUpper(strings.TrimSpace(name))]
	return canonical, ok
}

// IsAEAD reports whether a canonical cipher name is an AEAD cipher.
func IsAEAD(cipher string) bool {
	info, ok := lookupCipher(cipher)
	return ok && info.newAEAD != nil
}

// KeyBits is the key size of a canonical cipher in bits (BF-CBC: 128).
func KeyBits(cipher string) int {
	info, _ := lookupCipher(cipher)
	return info.keyBits
}

// CanonicalDigest maps an --auth name, case-insensitively, to MD5, SHA1,
// SHA224, SHA256, SHA384 or SHA512 (aliases like "sha-256" or "RSA-SHA1"
// accepted). ok is false otherwise.
func CanonicalDigest(name string) (canonical string, ok bool) {
	s := strings.ToUpper(strings.TrimSpace(name))
	s = strings.TrimPrefix(s, "RSA-")
	s = strings.NewReplacer("-", "", "_", "").Replace(s)
	canonical, ok = digestAliases[s]
	return canonical, ok
}

// DigestSize is the output size in bytes of a canonical digest, or 0 for an
// unknown one.
func DigestSize(digest string) int {
	if c, ok := CanonicalDigest(digest); ok {
		return digests[c].size
	}
	return 0
}

func lookupCipher(name string) (cipherInfo, bool) {
	c, ok := CanonicalCipher(name)
	if !ok {
		return cipherInfo{}, false
	}
	return ciphers[c], true
}

// KeyState is one key id's sealing and opening state.
type KeyState struct {
	KeyID uint8

	cipher string
	aead   *aeadKeys // set for AEAD ciphers
	cbc    *cbcKeys  // set for CBC ciphers
	rand   io.Reader // CBC IV source

	// sendPID is the last packet id handed out (0 before the first).
	sendPID atomic.Uint64

	replayMu sync.Mutex
	replay   replayWindow
}

type aeadKeys struct {
	send, recv     cipher.AEAD
	sendIV, recvIV [implicitIVSize]byte
}

type cbcKeys struct {
	send, recv       cipher.Block
	blockSize        int
	macSize          int
	sendMAC, recvMAC sync.Pool // of hash.Hash (HMAC keyed for the direction)
	enc, dec         sync.Pool // of cipher.BlockMode for send / recv, reused through SetIV

	ivMu  sync.Mutex
	ivBuf [ivBatch]byte // random bytes not yet used, from ivOff
	ivOff int
}

// nextIV fills iv with random bytes from rnd, read ivBatch at a time.
func (k *cbcKeys) nextIV(iv []byte, rnd io.Reader) error {
	k.ivMu.Lock()
	defer k.ivMu.Unlock()
	if k.ivOff+len(iv) > len(k.ivBuf) {
		if _, err := io.ReadFull(rnd, k.ivBuf[:]); err != nil {
			k.ivOff = len(k.ivBuf)
			return err
		}
		k.ivOff = 0
	}
	n := copy(iv, k.ivBuf[k.ivOff:])
	clear(k.ivBuf[k.ivOff : k.ivOff+n])
	k.ivOff += n
	return nil
}

// setRand replaces the key's IV source, dropping IV bytes already read
// from the old one.
func (ks *KeyState) setRand(r io.Reader) {
	ks.rand = r
	if k := ks.cbc; k != nil {
		k.ivMu.Lock()
		k.ivOff = len(k.ivBuf)
		k.ivMu.Unlock()
	}
}

// cbcCrypt runs CBC over buf in place with iv, reusing a BlockMode from
// pool when there is one.
func cbcCrypt(pool *sync.Pool, newMode func(cipher.Block, []byte) cipher.BlockMode, b cipher.Block, iv, buf []byte) {
	if m, ok := pool.Get().(cipher.BlockMode); ok {
		m.(ivSetter).SetIV(iv)
		m.CryptBlocks(buf, buf)
		pool.Put(m)
		return
	}
	m := newMode(b, iv)
	m.CryptBlocks(buf, buf)
	if _, ok := m.(ivSetter); ok {
		pool.Put(m)
	}
}

// NewKeyState prepares a key id's crypto. cipher and digest are canonical
// names; digest is ignored for AEAD ciphers. send and recv are the
// directional keys (for a client: Key2.ClientSend / ClientRecv).
func NewKeyState(keyID uint8, cipher, digest string, send, recv *handshake.Key) (*KeyState, error) {
	if send == nil || recv == nil {
		return nil, errors.New("datachan: missing key material")
	}
	name, ok := CanonicalCipher(cipher)
	if !ok {
		return nil, fmt.Errorf("%w: cipher %q", ErrUnsupported, cipher)
	}
	info := ciphers[name]
	ks := &KeyState{KeyID: keyID & wire.KeyIDMask, cipher: name, rand: randReader}
	ks.replay.init(defaultReplayWindow)

	if info.newAEAD != nil {
		a := &aeadKeys{}
		var err error
		if a.send, err = info.newAEAD(send.Cipher[:info.keyLen]); err != nil {
			return nil, fmt.Errorf("datachan: %s send key: %w", name, err)
		}
		if a.recv, err = info.newAEAD(recv.Cipher[:info.keyLen]); err != nil {
			return nil, fmt.Errorf("datachan: %s receive key: %w", name, err)
		}
		if a.send.NonceSize() != aeadNonceSize || a.send.Overhead() != aeadTagSize {
			return nil, fmt.Errorf("%w: cipher %s has an unexpected nonce or tag size", ErrUnsupported, name)
		}
		copy(a.sendIV[:], send.HMAC[:implicitIVSize])
		copy(a.recvIV[:], recv.HMAC[:implicitIVSize])
		ks.aead = a
		return ks, nil
	}

	dname, ok := CanonicalDigest(digest)
	if !ok {
		return nil, fmt.Errorf("%w: digest %q with cipher %s", ErrUnsupported, digest, name)
	}
	dinfo := digests[dname]
	k := &cbcKeys{macSize: dinfo.size, ivOff: ivBatch}
	var err error
	if k.send, err = info.newBlock(send.Cipher[:info.keyLen]); err != nil {
		return nil, fmt.Errorf("datachan: %s send key: %w", name, err)
	}
	if k.recv, err = info.newBlock(recv.Cipher[:info.keyLen]); err != nil {
		return nil, fmt.Errorf("datachan: %s receive key: %w", name, err)
	}
	k.blockSize = k.send.BlockSize()
	if k.blockSize > maxBlockSize || k.blockSize < 8 {
		return nil, fmt.Errorf("%w: cipher %s block size", ErrUnsupported, name)
	}
	sendMACKey := bytes.Clone(send.HMAC[:dinfo.size])
	recvMACKey := bytes.Clone(recv.HMAC[:dinfo.size])
	k.sendMAC.New = func() any { return hmac.New(dinfo.new, sendMACKey) }
	k.recvMAC.New = func() any { return hmac.New(dinfo.new, recvMACKey) }
	ks.cbc = k
	return ks, nil
}

// Cipher is the canonical name of the key's cipher.
func (ks *KeyState) Cipher() string { return ks.cipher }

// nextPID hands out the next packet id to send.
func (ks *KeyState) nextPID() (uint32, error) {
	// The counter is 64 bits wide, so failed calls past the limit can never
	// wrap it back to valid ids.
	n := ks.sendPID.Add(1)
	if n >= lastPID {
		return 0, ErrPacketIDExhausted
	}
	return uint32(n), nil
}

// setReplayWindow resizes the replay window if nothing was received yet.
func (ks *KeyState) setReplayWindow(n int) {
	ks.replayMu.Lock()
	if ks.replay.top == 0 && ks.replay.size != n {
		ks.replay.init(n)
	}
	ks.replayMu.Unlock()
}

func (ks *KeyState) checkReplay(pid uint32) error {
	ks.replayMu.Lock()
	err := ks.replay.check(pid)
	ks.replayMu.Unlock()
	return err
}

func (ks *KeyState) acceptReplay(pid uint32) error {
	ks.replayMu.Lock()
	err := ks.replay.accept(pid)
	ks.replayMu.Unlock()
	return err
}

// frame appends payload with mode's "not compressed" framing; None has none.
func frame(mode compress.Mode, dst, payload []byte) []byte {
	if mode == compress.None {
		return append(dst, payload...)
	}
	return compress.Frame(mode, dst, payload)
}

// seal appends the whole wire packet: header, then the protected payload.
func (ks *KeyState) seal(dst []byte, peerID uint32, mode compress.Mode, payload []byte) ([]byte, error) {
	pid, err := ks.nextPID()
	if err != nil {
		return dst, err
	}
	start := len(dst)
	out := wire.AppendDataHeader(dst, ks.KeyID, peerID)
	if ks.aead != nil {
		return ks.aead.seal(out, start, pid, mode, payload), nil
	}
	out, err = ks.cbc.seal(out, pid, mode, payload, ks.rand)
	if err != nil {
		return dst[:start], err
	}
	return out, nil
}

// seal appends pid | tag | ciphertext to out, which ends with the data
// header that starts at out[start].
func (a *aeadKeys) seal(out []byte, start int, pid uint32, mode compress.Mode, payload []byte) []byte {
	hdrEnd := len(out)
	adStart := hdrEnd // P_DATA_V1: the pid alone
	if hdrEnd-start == 4 {
		adStart = start // P_DATA_V2: header || pid
	}
	out = binary.BigEndian.AppendUint32(out, pid)
	tagPos := len(out)
	var zero [aeadTagSize]byte
	out = append(out, zero[:]...)
	ptPos := len(out)
	out = frame(mode, out, payload)
	ptLen := len(out) - ptPos
	out = slices.Grow(out, aeadTagSize)

	sc := scratchPool.Get().(*scratch)
	binary.BigEndian.PutUint32(sc.nonce[:pidSize], pid)
	copy(sc.nonce[pidSize:], a.sendIV[:])
	// Seal in place: the result is ciphertext || tag at out[ptPos:].
	sealed := a.send.Seal(out[ptPos:ptPos], sc.nonce[:], out[ptPos:], out[adStart:tagPos])
	scratchPool.Put(sc)
	out = out[:ptPos+len(sealed)]
	copy(out[tagPos:ptPos], out[ptPos+ptLen:])
	return out[:ptPos+ptLen]
}

// seal appends hmac | iv | ciphertext to out, which ends with the header.
func (k *cbcKeys) seal(out []byte, pid uint32, mode compress.Mode, payload []byte, rnd io.Reader) ([]byte, error) {
	bs := k.blockSize
	var zero [maxDigestSize]byte
	macPos := len(out)
	out = append(out, zero[:k.macSize]...)
	ivPos := len(out)
	out = append(out, zero[:bs]...)
	if err := k.nextIV(out[ivPos:ivPos+bs], rnd); err != nil {
		return out, fmt.Errorf("datachan: reading random iv: %w", err)
	}
	ctPos := len(out)
	out = binary.BigEndian.AppendUint32(out, pid)
	out = frame(mode, out, payload)
	pad := bs - (len(out)-ctPos)%bs
	for i := 0; i < pad; i++ {
		out = append(out, byte(pad))
	}
	cbcCrypt(&k.enc, cipher.NewCBCEncrypter, k.send, out[ivPos:ctPos], out[ctPos:])

	h := k.sendMAC.Get().(hash.Hash)
	h.Reset()
	h.Write(out[ivPos:])
	sc := scratchPool.Get().(*scratch)
	mac := h.Sum(sc.sum[:0])
	k.sendMAC.Put(h)
	copy(out[macPos:ivPos], mac)
	scratchPool.Put(sc)
	return out, nil
}

// open authenticates and decrypts packet (whose header is hl bytes) and
// appends the still-framed payload to dst. On error dst is returned as is.
// dst may alias packet's storage (e.g. packet[:0]).
func (ks *KeyState) open(dst, packet []byte, hl int) ([]byte, error) {
	if ks.aead != nil {
		return ks.openAEAD(dst, packet, hl)
	}
	return ks.openCBC(dst, packet, hl)
}

func (ks *KeyState) openAEAD(dst, packet []byte, hl int) ([]byte, error) {
	a := ks.aead
	body := packet[hl:]
	if len(body) < pidSize+aeadTagSize {
		return dst, ErrShort
	}
	pid := binary.BigEndian.Uint32(body)
	if err := ks.checkReplay(pid); err != nil {
		return dst, err
	}
	// Copy what is needed besides the ciphertext before writing to dst,
	// which may share packet's storage.
	sc := scratchPool.Get().(*scratch)
	defer scratchPool.Put(sc)
	copy(sc.nonce[:pidSize], body[:pidSize])
	copy(sc.nonce[pidSize:], a.recvIV[:])
	adStart := hl // P_DATA_V1: the pid alone
	if hl == 4 {
		adStart = 0 // P_DATA_V2: header || pid
	}
	adLen := copy(sc.ad[:], packet[adStart:hl+pidSize])
	var tag [aeadTagSize]byte
	copy(tag[:], body[pidSize:pidSize+aeadTagSize])

	start := len(dst)
	out := append(dst, body[pidSize+aeadTagSize:]...)
	out = append(out, tag[:]...)
	pt, err := a.recv.Open(out[start:start], sc.nonce[:], out[start:], sc.ad[:adLen])
	if err != nil {
		return dst, ErrAuth
	}
	if err := ks.acceptReplay(pid); err != nil {
		return dst, err
	}
	return out[:start+len(pt)], nil
}

func (ks *KeyState) openCBC(dst, packet []byte, hl int) ([]byte, error) {
	k := ks.cbc
	bs := k.blockSize
	body := packet[hl:]
	// At least one ciphertext block: the pid plus at least one pad byte
	// always fit in one.
	if len(body) < k.macSize+bs+bs {
		return dst, ErrShort
	}
	if (len(body)-k.macSize-bs)%bs != 0 {
		return dst, fmt.Errorf("%w: ciphertext is not a whole number of blocks", ErrAuth)
	}

	h := k.recvMAC.Get().(hash.Hash)
	h.Reset()
	h.Write(body[k.macSize:])
	sc := scratchPool.Get().(*scratch)
	defer scratchPool.Put(sc)
	mac := h.Sum(sc.sum[:0])
	k.recvMAC.Put(h)
	if !hmac.Equal(mac, body[:k.macSize]) {
		return dst, ErrAuth
	}

	// The IV is copied out first: dst may share packet's storage.
	copy(sc.iv[:bs], body[k.macSize:])
	start := len(dst)
	out := append(dst, body[k.macSize+bs:]...)
	pt := out[start:]
	cbcCrypt(&k.dec, cipher.NewCBCDecrypter, k.recv, sc.iv[:bs], pt)

	pad := int(pt[len(pt)-1])
	if pad == 0 || pad > bs {
		return dst, fmt.Errorf("%w: bad padding", ErrAuth)
	}
	for _, b := range pt[len(pt)-pad:] {
		if int(b) != pad {
			return dst, fmt.Errorf("%w: bad padding", ErrAuth)
		}
	}
	pt = pt[:len(pt)-pad]
	if len(pt) < pidSize {
		return dst, fmt.Errorf("%w: no packet id", ErrAuth)
	}
	pid := binary.BigEndian.Uint32(pt)
	if err := ks.acceptReplay(pid); err != nil {
		return dst, err
	}
	n := copy(out[start:], pt[pidSize:])
	return out[:start+n], nil
}

// replayWindow is a sliding bitmap over the last size packet ids.
type replayWindow struct {
	size int      // ids top-size+1 .. top are tracked
	top  uint32   // highest id accepted; 0 before the first
	bits []uint64 // ring indexed by id mod (64*len(bits))
}

func (w *replayWindow) init(size int) {
	w.size = size
	w.top = 0
	w.bits = make([]uint64, (size+63)/64)
}

func (w *replayWindow) slot(pid uint32) (int, uint64) {
	i := pid % uint32(len(w.bits)*64)
	return int(i / 64), 1 << (i % 64)
}

// check reports whether pid would be accepted, without changing anything.
func (w *replayWindow) check(pid uint32) error {
	if pid == 0 {
		return ErrReplay
	}
	if pid > w.top {
		return nil
	}
	if uint64(w.top-pid) >= uint64(w.size) {
		return ErrReplay
	}
	if i, m := w.slot(pid); w.bits[i]&m != 0 {
		return ErrReplay
	}
	return nil
}

// accept checks pid and records it.
func (w *replayWindow) accept(pid uint32) error {
	if err := w.check(pid); err != nil {
		return err
	}
	if pid > w.top {
		d := uint64(pid - w.top)
		if d >= uint64(len(w.bits)*64) {
			clear(w.bits)
		} else {
			for i := uint64(1); i <= d; i++ {
				j, m := w.slot(w.top + uint32(i))
				w.bits[j] &^= m
			}
		}
		w.top = pid
	}
	i, m := w.slot(pid)
	w.bits[i] |= m
	return nil
}

// Options configures a Channel.
type Options struct {
	// PeerID is the pushed peer-id, or wire.NoPeerID to send P_DATA_V1.
	PeerID uint32
	// Compression is the negotiated framing.
	Compression compress.Mode
	// ReplayWindow is the replay window in packets. Default 64.
	ReplayWindow int
	// MaxPayload bounds a decompressed payload. Default 65535.
	MaxPayload int
}

// Kind tells what Open found.
type Kind int

const (
	KindPacket Kind = iota // an IP packet
	KindPing               // a keepalive ping
	KindOCC                // an OCC message; the payload starts with the OCC opcode
)

// String names the kind for logs.
func (k Kind) String() string {
	switch k {
	case KindPacket:
		return "packet"
	case KindPing:
		return "ping"
	case KindOCC:
		return "occ"
	}
	return fmt.Sprintf("kind(%d)", int(k))
}

// chanState is an immutable snapshot of a Channel's keys and settings;
// writers replace it as a whole.
type chanState struct {
	keys    [wire.KeyIDMask + 1]*KeyState
	primary *KeyState
	peerID  uint32
	mode    compress.Mode
}

// Channel holds the key states of a session. Seal may be called from many
// goroutines at once, and concurrently with Open and the key methods.
type Channel struct {
	opts Options

	mu    sync.Mutex // serialises writers of state
	state atomic.Pointer[chanState]

	scratch sync.Pool // *[]byte for decompression
}

// New returns a Channel with no keys.
func New(opts Options) *Channel {
	if opts.ReplayWindow <= 0 {
		opts.ReplayWindow = defaultReplayWindow
	}
	if opts.ReplayWindow > maxReplayWindow {
		opts.ReplayWindow = maxReplayWindow
	}
	if opts.MaxPayload <= 0 {
		opts.MaxPayload = defaultMaxPayload
	}
	opts.PeerID &= wire.NoPeerID
	c := &Channel{opts: opts}
	// Decompression never exceeds MaxPayload, so a scratch buffer of that
	// capacity is never outgrown.
	c.scratch.New = func() any {
		b := make([]byte, 0, opts.MaxPayload)
		return &b
	}
	c.state.Store(&chanState{peerID: opts.PeerID, mode: opts.Compression})
	return c
}

// update applies f to a copy of the current state and publishes it.
func (c *Channel) update(f func(s *chanState)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := *c.state.Load()
	f(&s)
	c.state.Store(&s)
}

// SetPrimary installs ks (if not already present) and makes it the key new
// packets are sealed with. Earlier keys stay for opening until dropped.
func (c *Channel) SetPrimary(ks *KeyState) {
	if ks == nil {
		return
	}
	ks.setReplayWindow(c.opts.ReplayWindow)
	c.update(func(s *chanState) {
		s.keys[ks.KeyID&wire.KeyIDMask] = ks
		s.primary = ks
	})
}

// DropKey forgets a key id.
func (c *Channel) DropKey(keyID uint8) {
	c.update(func(s *chanState) {
		id := keyID & wire.KeyIDMask
		if s.primary != nil && s.primary == s.keys[id] {
			s.primary = nil
		}
		s.keys[id] = nil
	})
}

// SetPeerID changes the peer id used by Seal.
func (c *Channel) SetPeerID(peerID uint32) {
	c.update(func(s *chanState) { s.peerID = peerID & wire.NoPeerID })
}

// SetCompression changes the compression framing used by Seal and Open.
func (c *Channel) SetCompression(m compress.Mode) {
	c.update(func(s *chanState) { s.mode = m })
}

// Seal frames, encrypts and heads payload with the primary key and appends
// the wire packet to dst.
func (c *Channel) Seal(dst, payload []byte) ([]byte, error) {
	s := c.state.Load()
	if s.primary == nil {
		return dst, ErrNoKey
	}
	return s.primary.seal(dst, s.peerID, s.mode, payload)
}

// SealPing seals the keepalive ping.
func (c *Channel) SealPing(dst []byte) ([]byte, error) {
	return c.Seal(dst, PingPayload[:])
}

// SealOCC seals an OCC message (OCCPrefix followed by opcode).
func (c *Channel) SealOCC(dst []byte, opcode byte) ([]byte, error) {
	var msg [len(OCCPrefix) + 1]byte
	copy(msg[:], OCCPrefix[:])
	msg[len(OCCPrefix)] = opcode
	return c.Seal(dst, msg[:])
}

// Open authenticates, decrypts and unframes a received data packet (the
// whole wire packet, header included) and appends the payload to dst. For
// KindOCC the returned bytes start at the OCC opcode.
//
// For KindPing nothing is appended. An empty payload is KindPacket with
// nothing appended. A ping or OCC message that arrives without the
// compression framing is still recognised. dst may be packet[:0] to decrypt
// in place; on error dst is returned unchanged in length.
func (c *Channel) Open(dst, packet []byte) ([]byte, Kind, error) {
	_, keyID, _, hl, err := wire.ParseDataHeader(packet)
	if err != nil {
		if errors.Is(err, wire.ErrShort) {
			return dst, KindPacket, ErrShort
		}
		return dst, KindPacket, fmt.Errorf("datachan: not a data packet: %w", err)
	}
	s := c.state.Load()
	ks := s.keys[keyID]
	if ks == nil {
		return dst, KindPacket, fmt.Errorf("%w: key id %d", ErrNoKey, keyID)
	}
	start := len(dst)
	out, err := ks.open(dst, packet, hl)
	if err != nil {
		return dst, KindPacket, err
	}

	// A ping or OCC message sent without compression framing. Their first
	// bytes (0x2a, 0x28) are no LZO or swap flag, and V2 framing leaves them
	// as they are, so a framed payload is never mistaken for one. This runs
	// before Unframe, which may rewrite the buffer even when it fails.
	// Without compression there is no framing to remove.
	if kind := classify(out[start:]); kind != KindPacket || s.mode == compress.None {
		return finish(out, start, kind)
	}
	bp := c.scratch.Get().(*[]byte)
	payload, err := compress.Unframe(s.mode, (*bp)[:0], out[start:], c.opts.MaxPayload)
	if err != nil {
		c.scratch.Put(bp)
		return dst, KindPacket, fmt.Errorf("datachan: unframing payload: %w", err)
	}
	// payload either aliases out[start:] or lives in the scratch buffer;
	// append copies with memmove semantics, so both are safe.
	out = append(out[:start], payload...)
	c.scratch.Put(bp)
	return finish(out, start, classify(out[start:]))
}

// classify tells a keepalive ping (exactly PingPayload) and an OCC message
// (starting with OCCPrefix) from an IP packet.
func classify(p []byte) Kind {
	switch {
	case len(p) == len(PingPayload) && [16]byte(p) == PingPayload:
		return KindPing
	case len(p) >= len(OCCPrefix) && [16]byte(p[:16]) == OCCPrefix:
		return KindOCC
	}
	return KindPacket
}

// finish trims out[start:], an unframed payload of the given kind, to what
// Open returns.
func finish(out []byte, start int, kind Kind) ([]byte, Kind, error) {
	switch kind {
	case KindPing:
		return out[:start], kind, nil
	case KindOCC:
		return append(out[:start], out[start+len(OCCPrefix):]...), kind, nil
	}
	return out, kind, nil
}

// NeedsRenegotiation reports that the primary key has used most of its
// packet id space (more than 0xFF000000 packets) and should be replaced.
func (c *Channel) NeedsRenegotiation() bool {
	p := c.state.Load().primary
	return p != nil && p.sendPID.Load() > renegotiateAbove
}

// HasPrimary reports whether a key is installed for sealing.
func (c *Channel) HasPrimary() bool { return c.state.Load().primary != nil }
