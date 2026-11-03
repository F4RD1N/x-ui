// Independently implemented from the public Mieru protocol description.
package mieru

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"math/bits"
	mrand "math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/proxy/nativebridge"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
)

const (
	openRequest   = 2
	openResponse  = 3
	closeRequest  = 4
	closeResponse = 5
	dataClient    = 6
	dataServer    = 7
	ackClient     = 8
	ackServer     = 9
)

func Key(username, password string, t time.Time) []byte {
	h := sha256.Sum256([]byte(password + "\x00" + username))
	var b [8]byte
	epoch := uint64((t.Unix() + 60) / 120 * 120)
	binary.BigEndian.PutUint64(b[:], epoch)
	salt := sha256.Sum256(b[:])
	return pbkdf2.Key(h[:], salt[:], 64, 32, sha256.New)
}
func increment(n []byte) {
	for i := len(n) - 1; i >= 0; i-- {
		n[i]++
		if n[i] != 0 {
			break
		}
	}
}

func UUIDTrailer(username string, encrypted []byte) ([16]byte, error) {
	u, e := uuid.Parse(username)
	if e != nil {
		return [16]byte{}, errors.New("uuidMetadataTrailer requires a UUID username")
	}
	t := [16]byte(u)
	if len(encrypted) > 0 {
		for i := range t {
			t[i] ^= encrypted[i%len(encrypted)]
		}
	}
	return t, nil
}

type segment struct {
	kind                byte
	session, seq, unack uint32
	payload             []byte
	// window is the sender's free receive capacity in segments. It is only
	// meaningful when windowSet; otherwise data and ACK segments carry 65535.
	window    uint16
	windowSet bool
}

func metadata(s segment) []byte {
	m := make([]byte, 32)
	m[0] = s.kind
	binary.BigEndian.PutUint32(m[2:6], uint32(time.Now().Unix()/60))
	binary.BigEndian.PutUint32(m[6:10], s.session)
	binary.BigEndian.PutUint32(m[10:14], s.seq)
	if s.kind >= dataClient {
		binary.BigEndian.PutUint32(m[14:18], s.unack)
		window := uint16(65535)
		if s.windowSet {
			window = s.window
		}
		binary.BigEndian.PutUint16(m[18:20], window)
		binary.BigEndian.PutUint16(m[22:24], uint16(len(s.payload)))
	} else {
		binary.BigEndian.PutUint16(m[15:17], uint16(len(s.payload)))
	}
	return m
}

func parseMetadata(m []byte) (segment, int, int, error) {
	if len(m) != 32 || m[0] < openRequest || m[0] > ackServer {
		return segment{}, 0, 0, errors.New("invalid Mieru metadata")
	}
	now := time.Now().Unix() / 60
	ts := int64(binary.BigEndian.Uint32(m[2:6]))
	if ts < now-5 || ts > now+5 {
		return segment{}, 0, 0, errors.New("Mieru metadata timestamp outside acceptance window")
	}
	s := segment{kind: m[0], session: binary.BigEndian.Uint32(m[6:10]), seq: binary.BigEndian.Uint32(m[10:14])}
	prefix, suffix, n := 0, 0, 0
	if s.kind >= dataClient {
		s.unack = binary.BigEndian.Uint32(m[14:18])
		s.window, s.windowSet = binary.BigEndian.Uint16(m[18:20]), true
		prefix = int(m[21])
		n = int(binary.BigEndian.Uint16(m[22:24]))
		suffix = int(m[24])
	} else {
		if m[14] != 0 {
			return s, 0, 0, errors.New("Mieru peer returned a non-success status")
		}
		n = int(binary.BigEndian.Uint16(m[15:17]))
		suffix = int(m[17])
	}
	if n > 32768 || (s.kind < dataClient && n > 1024) {
		return s, 0, 0, errors.New("Mieru payload length exceeds protocol limit")
	}
	s.payload = make([]byte, n)
	return s, prefix, suffix, nil
}

// Padding. The reference client pads every segment by default; it is not part
// of the optional traffic-pattern tuning. Without it every connection would
// open with a fixed-length, fully random-looking first flight (and every UDP
// ACK would be the same size), which is exactly what "fully encrypted traffic"
// DPI rules look for.
//
//   - Open/close segments get a suffix shaped by a strategy fixed per
//     username: either a printable run of asciiRun bytes inside random bytes,
//     or bits biased towards the segment's majority bit, so the segment's
//     rarer bit falls to about entropyTarget of the whole.
//   - Data and ACK segments get random bytes of random length both before the
//     payload (prefix) and after it (suffix).
//
// Over UDP a segment, padding included, stays within udpMTU, the reference
// default MTU, so it fits the server's datagram buffer. Padding is never
// encrypted and carries no secret, so it comes from math/rand (seeded by the
// runtime from the OS) rather than a system call per segment.
const (
	maxPadding     = 255          // one length byte
	udpMTU         = 1400         // the reference default MTU
	packetOverhead = 24 + 48 + 16 // nonce, sealed metadata, payload tag
	entropyTarget  = 0.325        // the rarer bit's share after entropy padding

	// Over UDP, a data segment of at least udpBulkPayload bytes carries at
	// most udpBulkPadding bytes of padding in all (see paddingRoom).
	udpBulkPayload = 512
	udpBulkPadding = 32
)

// asciiRun is the printable run length, 24 to 40 bytes, fixed per process as
// the reference fixes it per host.
var asciiRun = 24 + mrand.IntN(17)

type wire struct {
	dequeue              func(segment)         // inbound mux accounting callback, nil on clients
	activity             *signal.ActivityTimer // immutable server underlay idle tracker; nil on clients
	parent               *wire                 // inbound multiplexed sessions share serialized framing
	incoming             <-chan segment
	sessionDone          <-chan struct{}
	conn                 net.Conn
	username, password   string
	udp, custom          bool
	server               bool
	asciiPadding         bool // the open/close padding strategy for this username
	wm, rm               sync.Mutex
	send                 cipher.AEAD
	recv                 cipher.AEAD
	sendNonce, recvNonce []byte
	keys                 map[int64]cipher.AEAD // receive keys by time window
	rbuf                 []byte                // UDP datagram buffer, reused
	lastWrite            atomic.Int64          // monoNow() when the last segment was sent
}

func newWire(c net.Conn, username, password string, udp, custom bool) (*wire, error) {
	a, e := chacha20poly1305.NewX(Key(username, password, time.Now()))
	if e != nil {
		return nil, e
	}
	// The server normally answers with the window the client used, so the
	// send key is the first receive key tried.
	w := &wire{conn: c, username: username, password: password, udp: udp, custom: custom, send: a, recv: a}
	// Like the reference, a user's open/close segments always use the same
	// padding strategy, chosen by a hash of the username.
	h := sha256.Sum256([]byte("mieru padding strategy\x00" + username))
	w.asciiPadding = h[0]&1 == 0
	w.lastWrite.Store(monoNow())
	return w, nil
}

// sinceSent is how long ago the last segment was written.
func (w *wire) sinceSent() time.Duration { return time.Duration(monoNow() - w.lastWrite.Load()) }

// clockBase anchors monoNow. Timestamps kept in atomics are durations since
// it rather than wall-clock times: a time.Time rebuilt from UnixNano loses Go's
// monotonic reading, so a phone's clock being set (a network time sync, a
// manual change) would make an idle session look silent for hours and close
// it, or never idle at all.
var clockBase = time.Now()

// monoNow is the monotonic time since clockBase, in nanoseconds.
func monoNow() int64 { return int64(time.Since(clockBase)) }

// paddingRoom is the most padding a segment may carry beside a payload of
// payload bytes and used bytes of padding already chosen.
func (w *wire) paddingRoom(payload, used int) int {
	if !w.udp {
		return maxPadding
	}
	room := udpMTU - packetOverhead - payload - used
	if w.custom && !w.server {
		room -= 16
	}
	if payload >= udpBulkPayload {
		// A full-size data segment already varies in length and is not what
		// a length rule keys on; padding it as fully as a small one would add
		// about a fifth to every bulk transfer over UDP. A few bytes keep its
		// length from being exact.
		room = min(room, udpBulkPadding-used)
	}
	return min(max(room, 0), maxPadding)
}

// randomPadding returns up to maxLen random bytes, of uniformly random length.
func randomPadding(maxLen int) []byte {
	p := make([]byte, mrand.IntN(maxLen+1))
	fillRandom(p)
	return p
}

func fillRandom(p []byte) {
	for i := 0; i < len(p); i += 8 {
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], mrand.Uint64())
		copy(p[i:], b[:])
	}
}

// sessionPaddingLen picks the length of an open/close segment's suffix,
// before the segment is sealed (the length is part of the metadata). size is
// the length of everything else the segment carries.
func (w *wire) sessionPaddingLen(size, maxLen int) int {
	if maxLen <= 0 {
		return 0
	}
	if w.asciiPadding {
		run := min(asciiRun, maxLen)
		return run + mrand.IntN(maxLen-run+1)
	}
	// Ciphertext holds about as many one bits as zero bits: the suffix must
	// be long enough to bring the rarer bit down to entropyTarget.
	n := size * 8
	need := max((int(float64(n/2)/entropyTarget)-n+7)/8, 0)
	if need >= maxLen {
		return maxLen
	}
	return need + mrand.IntN(maxLen-need+1)
}

// sessionPadding builds an open/close suffix of n bytes for the sealed bytes
// sent before it.
func (w *wire) sessionPadding(sent []byte, n int) []byte {
	p := make([]byte, n)
	if n == 0 {
		return p
	}
	if w.asciiPadding {
		fillRandom(p)
		run := min(asciiRun, n)
		start := mrand.IntN(n - run + 1)
		for i := start; i < start+run; i++ {
			p[i] = '!' + p[i]%94 // '!' to '~'
		}
		return p
	}
	// Mostly the majority bit, with just enough of the rarer bit, at random
	// places, that it makes up entropyTarget of sent plus padding.
	ones := 0
	for _, b := range sent {
		ones += bits.OnesCount8(b)
	}
	total := len(sent) * 8
	rare, rareBit := ones, byte(1)
	if total-ones < ones {
		rare, rareBit = total-ones, 0
	}
	if rareBit == 0 {
		for i := range p {
			p[i] = 0xFF
		}
	}
	flips := min(max(int(float64(total+n*8)*entropyTarget)-rare, 0), n*8)
	for i := 0; i < flips; i++ {
		j := mrand.IntN(n * 8)
		if rareBit == 1 {
			p[j/8] |= 1 << (j % 8)
		} else {
			p[j/8] &^= 1 << (j % 8)
		}
	}
	return p
}
func (w *wire) nonce() ([]byte, error) {
	n := make([]byte, 24)
	if _, e := rand.Read(n); e != nil {
		return nil, e
	}
	digest := sha256.Sum256(append([]byte(w.username), n[:16]...))
	copy(n[20:24], digest[:4])
	return n, nil
}

func (w *wire) write(s segment) error {
	if w.parent != nil {
		select {
		case <-w.sessionDone:
			return net.ErrClosed
		default:
		}
		err := w.parent.write(s)
		if err == nil {
			w.lastWrite.Store(monoNow())
		}
		return err
	}
	w.wm.Lock()
	defer w.wm.Unlock()
	if w.server && !w.udp {
		// A stalled reader cannot monopolize the shared underlay writer forever.
		_ = w.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		defer w.conn.SetWriteDeadline(time.Time{})
	}
	var prefix []byte
	if w.udp || w.sendNonce == nil {
		n, e := w.nonce()
		if e != nil {
			return e
		}
		w.sendNonce = n
		prefix = append(prefix, n...)
	}
	m := metadata(s)
	// Padding lengths go into the metadata, so they are chosen first. Open
	// and close segments have only a suffix; data and ACKs have both.
	session := s.kind < dataClient
	var padPrefix []byte
	suffixLen := 0
	if session {
		size := len(prefix) + 48
		if w.custom && !w.server {
			size += 16
		}
		if len(s.payload) > 0 {
			size += len(s.payload) + 16
		}
		suffixLen = w.sessionPaddingLen(size, w.paddingRoom(len(s.payload), 0))
		m[17] = byte(suffixLen)
	} else {
		padPrefix = randomPadding(w.paddingRoom(len(s.payload), 0))
		suffixLen = mrand.IntN(w.paddingRoom(len(s.payload), len(padPrefix)) + 1)
		m[21], m[24] = byte(len(padPrefix)), byte(suffixLen)
	}
	encrypted := w.send.Seal(nil, w.sendNonce, m, nil)
	if !w.udp {
		increment(w.sendNonce)
	}
	b := append(prefix, encrypted...)
	if w.custom && !w.server {
		t, e := UUIDTrailer(w.username, b)
		if e != nil {
			return e
		}
		b = append(b, t[:]...)
	}
	b = append(b, padPrefix...)
	if len(s.payload) > 0 {
		b = append(b, w.send.Seal(nil, w.sendNonce, s.payload, nil)...)
		if !w.udp {
			increment(w.sendNonce)
		}
	}
	if session {
		b = append(b, w.sessionPadding(b, suffixLen)...)
	} else {
		suffix := make([]byte, suffixLen)
		fillRandom(suffix)
		b = append(b, suffix...)
	}
	if e := nativebridge.WriteFull(w.conn, b); e != nil {
		// TCP records share implicit nonce and framing state across sessions.
		// A partial write cannot be recovered by resetting only one stream.
		if w.server && !w.udp {
			_ = w.conn.Close()
		}
		return e
	}
	w.lastWrite.Store(monoNow())
	if w.activity != nil {
		w.activity.Update()
	}
	return nil
}

// keyWindow is the 120-second window Key derives its salt from.
func keyWindow(t time.Time) int64 { return (t.Unix() + 60) / 120 * 120 }

// windowKey returns the receive AEAD for t's key window, deriving it (PBKDF2)
// only once per window.
func (w *wire) windowKey(t time.Time) cipher.AEAD {
	k := keyWindow(t)
	if a, ok := w.keys[k]; ok {
		return a
	}
	a, e := chacha20poly1305.NewX(Key(w.username, w.password, t))
	if e != nil {
		return nil
	}
	if w.keys == nil {
		w.keys = make(map[int64]cipher.AEAD)
	}
	for old := range w.keys {
		if old < k-240 || old > k+240 {
			delete(w.keys, old)
		}
	}
	w.keys[k] = a
	return a
}

func (w *wire) initialDecrypt(n, encrypted []byte) ([]byte, error) {
	if w.recv != nil {
		if m, e := w.recv.Open(nil, n, encrypted, nil); e == nil {
			return m, nil
		}
	}
	now := time.Now()
	for _, shift := range []int{0, -1, 1} {
		a := w.windowKey(now.Add(time.Duration(shift) * 120 * time.Second))
		if a == nil || a == w.recv {
			continue
		}
		if m, e := a.Open(nil, n, encrypted, nil); e == nil {
			w.recv = a
			return m, nil
		}
	}
	return nil, errors.New("Mieru metadata authentication failed")
}

// read returns the next segment. Over UDP a datagram that is not a valid
// segment from the server's address (junk, truncated, stale, forged or from
// another host) is dropped and the next one is read; only a socket error ends
// it. TCP framing errors still fail, since the stream is then out of sync.
func (w *wire) read() (segment, error) {
	if w.incoming != nil {
		select {
		case s := <-w.incoming:
			if w.dequeue != nil {
				w.dequeue(s)
			}
			return s, nil
		case <-w.sessionDone:
			return segment{}, net.ErrClosed
		}
	}
	w.rm.Lock()
	defer w.rm.Unlock()
	if !w.udp {
		return w.parse(w.conn)
	}
	if w.rbuf == nil {
		w.rbuf = make([]byte, 65535)
	}
	pc, _ := w.conn.(net.PacketConn)
	for {
		var n int
		var from net.Addr
		var e error
		if pc != nil {
			n, from, e = pc.ReadFrom(w.rbuf)
		} else {
			n, e = w.conn.Read(w.rbuf)
		}
		if e != nil {
			return segment{}, e
		}
		if from != nil && !sameAddr(from, w.conn.RemoteAddr()) {
			continue
		}
		// parse copies everything it keeps, so the buffer can be reused.
		if s, e := w.parse(&sliceReader{p: w.rbuf[:n]}); e == nil {
			return s, nil
		}
	}
}

func sameAddr(a, b net.Addr) bool {
	ua, ok1 := a.(*net.UDPAddr)
	ub, ok2 := b.(*net.UDPAddr)
	if !ok1 || !ok2 {
		return true // nothing to compare against
	}
	return ua.Port == ub.Port && ua.IP.Equal(ub.IP)
}

func (w *wire) parse(reader io.Reader) (segment, error) {
	first := w.udp || w.recvNonce == nil
	if first {
		n := make([]byte, 24)
		if _, e := io.ReadFull(reader, n); e != nil {
			return segment{}, e
		}
		w.recvNonce = n
	}
	e := make([]byte, 48)
	if _, err := io.ReadFull(reader, e); err != nil {
		return segment{}, err
	}
	var m []byte
	var err error
	if first {
		m, err = w.initialDecrypt(w.recvNonce, e)
	} else {
		m, err = w.recv.Open(nil, w.recvNonce, e, nil)
	}
	if err != nil {
		return segment{}, err
	}
	if w.custom && w.server {
		envelope := e
		if first {
			envelope = append(append([]byte(nil), w.recvNonce...), e...)
		}
		want, trailerErr := UUIDTrailer(w.username, envelope)
		if trailerErr != nil {
			return segment{}, trailerErr
		}
		var got [16]byte
		if _, err := io.ReadFull(reader, got[:]); err != nil {
			return segment{}, err
		}
		if subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
			return segment{}, errors.New("Mieru UUID metadata authentication failed")
		}
	}
	if !w.udp {
		increment(w.recvNonce)
	}
	s, prefix, suffix, err := parseMetadata(m)
	if err != nil {
		return segment{}, err
	}
	if prefix > 0 {
		if _, err = io.CopyN(io.Discard, reader, int64(prefix)); err != nil {
			return segment{}, err
		}
	}
	if len(s.payload) > 0 {
		encrypted := make([]byte, len(s.payload)+16)
		if _, err = io.ReadFull(reader, encrypted); err != nil {
			return segment{}, err
		}
		s.payload, err = w.recv.Open(s.payload[:0], w.recvNonce, encrypted, nil)
		if err != nil {
			return segment{}, err
		}
		if !w.udp {
			increment(w.recvNonce)
		}
	}
	if suffix > 0 {
		if _, err = io.CopyN(io.Discard, reader, int64(suffix)); err != nil {
			return segment{}, err
		}
	}
	return s, nil
}

type sliceReader struct{ p []byte }

func (r *sliceReader) Read(p []byte) (int, error) {
	if len(r.p) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.p)
	r.p = r.p[n:]
	return n, nil
}
