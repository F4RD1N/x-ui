package ctlwrap

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/wire"
)

// timeNow is the clock a new wrapper reads its outgoing time from; tests
// replace it.
var timeNow = time.Now

// errPIDExhausted: 2^32-1 packets were sent with one wrapper.
var errPIDExhausted = errors.New("ctlwrap: outgoing packet id space exhausted")

// Sizes of the fields the wrappers add.
const (
	headLen   = 1 + 8 // op/key byte, session id
	pidLen    = 4 + 4 // replay packet id, time
	cryptTag  = sha256.Size
	cryptHead = headLen + pidLen // the authenticated cleartext of tls-crypt
	aesBlock  = 16               // the AES-256-CTR IV is tag[:aesBlock]
)

// checkPacket rejects a packet Wrap cannot encode faithfully.
func checkPacket(p *wire.ControlPacket) error {
	if p == nil {
		return errors.New("ctlwrap: nil packet")
	}
	if !p.Opcode.IsControl() {
		return fmt.Errorf("ctlwrap: cannot wrap %v: %w", p.Opcode, wire.ErrBadOpcode)
	}
	if p.KeyID > wire.KeyIDMask {
		return fmt.Errorf("ctlwrap: key id %d out of range", p.KeyID)
	}
	if len(p.Acks) > wire.MaxAcks {
		return fmt.Errorf("ctlwrap: %d acks: %w", len(p.Acks), wire.ErrTooMany)
	}
	return nil
}

// bodyLen is the size of wire.AppendBody's output for p.
func bodyLen(p *wire.ControlPacket) int {
	n := 1 + 4*len(p.Acks)
	if len(p.Acks) > 0 {
		n += 8
	}
	if p.HasMessageID() {
		n += 4 + len(p.Payload)
	}
	return n
}

// splitHead checks that b is at least min bytes and starts with a control
// opcode, and returns that opcode and key id.
func splitHead(b []byte, min int, kind string) (wire.Opcode, uint8, error) {
	if len(b) < min {
		return 0, 0, fmt.Errorf("ctlwrap: %s packet of %d bytes, need at least %d: %w", kind, len(b), min, wire.ErrShort)
	}
	op, keyID := wire.SplitHeader(b[0])
	if !op.IsControl() {
		return 0, 0, fmt.Errorf("ctlwrap: %s packet with %v: %w", kind, op, wire.ErrBadOpcode)
	}
	return op, keyID, nil
}

// parsePacket builds the unwrapped packet from its authenticated parts.
func parsePacket(op wire.Opcode, keyID uint8, sid, body []byte) (*wire.ControlPacket, error) {
	p := &wire.ControlPacket{Opcode: op, KeyID: keyID}
	copy(p.SessionID[:], sid)
	if err := wire.ParseBody(p, body); err != nil {
		return nil, fmt.Errorf("ctlwrap: malformed %v: %w", op, err)
	}
	return p, nil
}

// plain is the Wrapper without protection.
type plain struct{}

func (plain) Wrap(p *wire.ControlPacket) ([]byte, error) {
	if err := checkPacket(p); err != nil {
		return nil, err
	}
	return wire.Marshal(p), nil
}

func (plain) Unwrap(b []byte) (*wire.ControlPacket, error) {
	op, keyID, err := splitHead(b, headLen, "plain")
	if err != nil {
		return nil, err
	}
	return parsePacket(op, keyID, b[1:headLen], b[headLen:])
}

func (plain) Overhead() int { return 0 }

// sender numbers outgoing packets: pid 1, 2, ... with a fixed time.
type sender struct {
	time uint32
	last atomic.Uint64
}

func newSender() sender { return sender{time: uint32(timeNow().Unix())} }

func (s *sender) next() (uint32, error) {
	n := s.last.Add(1)
	if n > math.MaxUint32 {
		return 0, errPIDExhausted
	}
	return uint32(n), nil
}

// appendPID appends a fresh pid and the sender's time.
func (s *sender) appendPID(b []byte) ([]byte, error) {
	pid, err := s.next()
	if err != nil {
		return b, err
	}
	b = binary.BigEndian.AppendUint32(b, pid)
	return binary.BigEndian.AppendUint32(b, s.time), nil
}

// replayWindowSize is how many packet ids below the highest one seen (at the
// current time) are still accepted once.
const replayWindowSize = 64

// replayWindow tracks the (time, pid) pairs of authenticated incoming
// packets. A newer time starts a new window, an older time is a replay, and
// within one time the last replayWindowSize ids are remembered.
type replayWindow struct {
	mu     sync.Mutex
	seen   bool
	time   uint32
	maxPID uint32
	bits   uint64 // bit i: maxPID-i was received
}

// accept reports whether (t, pid) is new and, if so, records it.
func (w *replayWindow) accept(t, pid uint32) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	switch {
	case !w.seen || t > w.time:
		w.seen, w.time, w.maxPID, w.bits = true, t, pid, 1
		return true
	case t < w.time:
		return false
	case pid > w.maxPID:
		if d := pid - w.maxPID; d >= replayWindowSize {
			w.bits = 1
		} else {
			w.bits = w.bits<<d | 1
		}
		w.maxPID = pid
		return true
	}
	d := w.maxPID - pid
	if d >= replayWindowSize || w.bits&(1<<d) != 0 {
		return false
	}
	w.bits |= 1 << d
	return true
}

// digest is a tls-auth HMAC hash.
type digest struct {
	new  func() hash.Hash
	size int
}

var digests = map[string]digest{
	"MD5":    {md5.New, md5.Size},
	"SHA1":   {sha1.New, sha1.Size},
	"SHA224": {sha256.New224, sha256.Size224},
	"SHA256": {sha256.New, sha256.Size},
	"SHA384": {sha512.New384, sha512.Size384},
	"SHA512": {sha512.New, sha512.Size},
}

// lookupDigest maps an --auth name to its hash: case-insensitive, "" is
// SHA1, '-' and '_' are ignored and "SHA2-xxx" means "SHAxxx".
func lookupDigest(name string) (digest, bool) {
	n := strings.ToUpper(strings.NewReplacer("-", "", "_", "").Replace(strings.TrimSpace(name)))
	if n == "" {
		n = "SHA1"
	}
	if strings.HasPrefix(n, "SHA2") && len(n) == len("SHA2")+3 {
		n = "SHA" + n[len("SHA2"):]
	}
	d, ok := digests[n]
	return d, ok
}

// tlsAuth is the --tls-auth Wrapper.
type tlsAuth struct {
	digest  digest
	sendKey []byte
	recvKey []byte
	send    sender
	recv    replayWindow
}

func (w *tlsAuth) Overhead() int { return w.digest.size + pidLen }

// mac computes the HMAC over pid time op sid body, given head = op sid and
// rest = pid time body.
func (w *tlsAuth) mac(key, head, rest []byte) []byte {
	m := hmac.New(w.digest.new, key)
	m.Write(rest[:pidLen])
	m.Write(head)
	m.Write(rest[pidLen:])
	return m.Sum(nil)
}

func (w *tlsAuth) Wrap(p *wire.ControlPacket) ([]byte, error) {
	if err := checkPacket(p); err != nil {
		return nil, err
	}
	macLen := w.digest.size
	b := make([]byte, headLen+macLen, headLen+macLen+pidLen+bodyLen(p))
	b[0] = wire.Header(p.Opcode, p.KeyID)
	copy(b[1:headLen], p.SessionID[:])
	b, err := w.send.appendPID(b)
	if err != nil {
		return nil, err
	}
	b = wire.AppendBody(b, p)
	copy(b[headLen:], w.mac(w.sendKey, b[:headLen], b[headLen+macLen:]))
	return b, nil
}

func (w *tlsAuth) Unwrap(b []byte) (*wire.ControlPacket, error) {
	macLen := w.digest.size
	op, keyID, err := splitHead(b, headLen+macLen+pidLen, "tls-auth")
	if err != nil {
		return nil, err
	}
	head, got, rest := b[:headLen], b[headLen:headLen+macLen], b[headLen+macLen:]
	if !hmac.Equal(got, w.mac(w.recvKey, head, rest)) {
		return nil, ErrAuth
	}
	if !w.recv.accept(binary.BigEndian.Uint32(rest[4:]), binary.BigEndian.Uint32(rest)) {
		return nil, ErrReplay
	}
	return parsePacket(op, keyID, head[1:], rest[pidLen:])
}

// tlsCrypt is the --tls-crypt Wrapper, and the tls-crypt-v2 client Wrapper
// when wkc is set.
type tlsCrypt struct {
	sendBlock cipher.Block
	recvBlock cipher.Block
	sendMAC   []byte
	recvMAC   []byte
	send      sender
	recv      replayWindow
	wkc       []byte
}

func (w *tlsCrypt) Overhead() int { return pidLen + cryptTag + len(w.wkc) }

// carriesWKc reports whether a tls-crypt-v2 client appends WKc to op.
func carriesWKc(op wire.Opcode) bool {
	return op == wire.ControlHardResetClientV3 || op == wire.ControlWKCV1
}

// tag is HMAC-SHA256(key, head body), head being op sid pid time.
func tag(key, head, body []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(head)
	m.Write(body)
	return m.Sum(nil)
}

func (w *tlsCrypt) Wrap(p *wire.ControlPacket) ([]byte, error) {
	if err := checkPacket(p); err != nil {
		return nil, err
	}
	var wkc []byte
	if w.wkc != nil && carriesWKc(p.Opcode) {
		wkc = w.wkc
	}
	b := make([]byte, headLen, cryptHead+cryptTag+bodyLen(p)+len(wkc))
	b[0] = wire.Header(p.Opcode, p.KeyID)
	copy(b[1:headLen], p.SessionID[:])
	b, err := w.send.appendPID(b)
	if err != nil {
		return nil, err
	}
	b = b[:cryptHead+cryptTag]
	b = wire.AppendBody(b, p)
	body := b[cryptHead+cryptTag:]
	t := tag(w.sendMAC, b[:cryptHead], body)
	copy(b[cryptHead:], t)
	cipher.NewCTR(w.sendBlock, t[:aesBlock]).XORKeyStream(body, body)
	return append(b, wkc...), nil
}

func (w *tlsCrypt) Unwrap(b []byte) (*wire.ControlPacket, error) {
	op, keyID, err := splitHead(b, cryptHead+cryptTag, "tls-crypt")
	if err != nil {
		return nil, err
	}
	clearPart, got, ct := b[:cryptHead], b[cryptHead:cryptHead+cryptTag], b[cryptHead+cryptTag:]
	body := make([]byte, len(ct))
	cipher.NewCTR(w.recvBlock, got[:aesBlock]).XORKeyStream(body, ct)
	if !hmac.Equal(got, tag(w.recvMAC, clearPart, body)) {
		return nil, ErrAuth
	}
	if !w.recv.accept(binary.BigEndian.Uint32(clearPart[headLen+4:]), binary.BigEndian.Uint32(clearPart[headLen:])) {
		return nil, ErrReplay
	}
	return parsePacket(op, keyID, clearPart[1:headLen], body)
}
