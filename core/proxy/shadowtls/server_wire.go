package shadowtls

// This server implements the published ShadowTLS v1/v2/v3 wire design using
// the record primitives shared with this package's independent client. It does
// not embed a separate server process or a third-party server implementation.

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/proxy/nativebridge"
)

var ErrUnauthenticated = errors.New("ShadowTLS connection was not authenticated")

const maxHandshakeBytes = 1 << 20

// ServerHandshake owns handshake and always closes it. The caller owns raw and
// must give it a bounded handshake deadline. Cancellation interrupts both
// directions. On success only the returned authenticated stream remains alive.
func ServerHandshake(ctx context.Context, raw, handshake net.Conn, c *ServerConfig) (*Conn, *ServerUser, error) {
	if raw == nil || handshake == nil || c == nil {
		return nil, nil, errors.New("missing ShadowTLS handshake parameters")
	}
	defer handshake.Close()
	stop := context.AfterFunc(ctx, func() {
		_ = handshake.Close()
		_ = raw.SetDeadline(time.Now())
	})
	defer stop()
	switch c.Version {
	case 1:
		return serverHandshakeV1(raw, handshake)
	case 2:
		return serverHandshakeV2(raw, handshake, c.Password)
	case 0, 3:
		return serverHandshakeV3(raw, handshake, c)
	default:
		return nil, nil, errors.New("unsupported ShadowTLS server version")
	}
}

func serverHandshakeV1(raw, peer net.Conn) (*Conn, *ServerUser, error) {
	done := make(chan error, 1)
	go func() { done <- relayTLS12Flight(raw, peer) }()
	err := relayTLS12Flight(peer, raw)
	if err != nil {
		_ = peer.Close()
	}
	other := <-done
	if err != nil {
		return nil, nil, err
	}
	if other != nil {
		return nil, nil, other
	}
	return &Conn{Conn: raw, version: 1}, nil, nil
}

// TLS 1.2 sends a ChangeCipherSpec followed by the encrypted Finished. The
// record after that belongs to the data stream and must not be read ahead.
func relayTLS12Flight(dst, src net.Conn) error {
	changed, total := false, 0
	for total < maxHandshakeBytes {
		t, v, b, err := readRecord(src)
		if err != nil {
			return err
		}
		if t != 20 && t != 22 {
			return errors.New("ShadowTLS v1 requires a TLS 1.2 handshake")
		}
		if err := nativebridge.WriteFull(dst, record(t, v, b)); err != nil {
			return err
		}
		total += len(b) + 5
		if changed && t == 22 {
			return nil
		}
		if t == 20 {
			if len(b) != 1 || b[0] != 1 || changed {
				return errors.New("invalid TLS ChangeCipherSpec")
			}
			changed = true
		}
	}
	return errors.New("ShadowTLS handshake exceeds size limit")
}

// Each checkpoint is a prefix the peer actually wrote. Keeping a small bounded
// history accommodates TLS tickets that race the client's first data record.
type challengeHistory struct {
	mu            sync.Mutex
	mac           hash.Hash
	password      string
	transcript    []byte
	partialChecks int
	tags          [32][8]byte
	next, count   int
}

// A failed/finished camouflage flight must wake the client's record reader.
// The same flight is deliberately stopped when data authentication succeeds;
// synchronize that transition so cleanup cannot expire the live data stream.
type handshakeFlightState struct {
	mu       sync.Mutex
	switched bool
}

func (s *handshakeFlightState) finished(raw net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.switched {
		_ = raw.SetReadDeadline(time.Now())
	}
}

func (s *handshakeFlightState) accept(raw net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.switched = true
	_ = raw.SetReadDeadline(time.Time{})
}

func (h *challengeHistory) add(p []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.mac.Write(p)
	h.transcript = append(h.transcript, p...)
	copy(h.tags[h.next][:], h.mac.Sum(nil)[:8])
	h.next = (h.next + 1) % len(h.tags)
	if h.count < len(h.tags) {
		h.count++
	}
}

func (h *challengeHistory) match(tag []byte) bool {
	if len(tag) != 8 {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	matched := 0
	for i := 0; i < h.count; i++ {
		matched |= subtle.ConstantTimeCompare(h.tags[i][:], tag)
	}
	if matched == 1 {
		return true
	}
	// A TLS client can finish after a socket read that also contains only a
	// prefix of the following session-ticket record. Its challenge then covers
	// that partial prefix. Record-boundary digests alone reject valid clients.
	// Check at most four candidate client records and the last two maximum TLS
	// record lengths. The transcript itself is bounded by maxHandshakeBytes;
	// neither an invalid password nor a long stream can cause unbounded work.
	if h.partialChecks >= 4 || len(h.transcript) == 0 {
		return false
	}
	h.partialChecks++
	start := len(h.transcript) - 2*(18432+5)
	if start < 0 {
		start = 0
	}
	mac := newMAC(h.password, nil)
	mac.Write(h.transcript[:start])
	var one [1]byte
	var sum [20]byte
	for _, b := range h.transcript[start:] {
		one[0] = b
		mac.Write(one[:])
		if subtle.ConstantTimeCompare(mac.Sum(sum[:0])[:8], tag) == 1 {
			return true
		}
	}
	return false
}

func serverHandshakeV2(raw, peer net.Conn, password string) (*Conn, *ServerUser, error) {
	history := &challengeHistory{mac: newMAC(password, nil), password: password}
	state := new(handshakeFlightState)
	done := make(chan error, 1)
	go func() {
		defer state.finished(raw)
		total := 0
		for total < maxHandshakeBytes {
			t, v, b, err := readRecord(peer)
			if err != nil {
				done <- err
				return
			}
			frame := record(t, v, b)
			if len(frame) > maxHandshakeBytes-total {
				done <- errors.New("ShadowTLS handshake exceeds size limit")
				return
			}
			history.add(frame)
			if err = nativebridge.WriteFull(raw, frame); err != nil {
				done <- err
				return
			}
			total += len(frame)
		}
		done <- errors.New("ShadowTLS handshake exceeds size limit")
	}()
	// Closing peer stops the flight reader, and waiting prevents its final
	// handshake write from racing the data protocol's first write.
	defer func() { _ = peer.Close(); <-done }()
	total := 0
	for total < maxHandshakeBytes {
		t, v, b, err := readRecord(raw)
		if err != nil {
			return nil, nil, err
		}
		total += len(b) + 5
		if t == 23 && len(b) >= 8 && history.match(b[:8]) {
			state.accept(raw)
			return &Conn{Conn: raw, version: 2, pending: append([]byte(nil), b[8:]...)}, nil, nil
		}
		if err := nativebridge.WriteFull(peer, record(t, v, b)); err != nil {
			return nil, nil, err
		}
	}
	return nil, nil, errors.New("ShadowTLS handshake exceeds size limit")
}

// readHello collects exactly the first handshake message, bounded independently
// of the TLS record length. It retains the original records for transparent
// camouflage forwarding, including any trailing handshake messages in a record.
func readHello(r io.Reader, kind byte) (hello, frames []byte, err error) {
	for len(hello) < 4 || len(hello) < 4+int(hello[1])<<16+int(hello[2])<<8+int(hello[3]) {
		t, v, b, e := readRecord(r)
		if e != nil {
			return nil, frames, e
		}
		frames = append(frames, record(t, v, b)...)
		if t != 22 || len(b) == 0 {
			return nil, frames, errors.New("expected TLS handshake record")
		}
		hello = append(hello, b...)
		if len(hello) > 65536 || len(frames) > 70000 {
			return nil, frames, errors.New("oversized TLS hello")
		}
		if len(hello) >= 4 {
			n := 4 + int(hello[1])<<16 + int(hello[2])<<8 + int(hello[3])
			if hello[0] != kind || n > 65536 {
				return nil, frames, errors.New("invalid TLS hello")
			}
			if len(hello) >= n {
				return hello[:n], frames, nil
			}
		}
	}
	return hello, frames, nil
}

func authenticatedHello(hello []byte, users []*ServerUser) *ServerUser {
	if len(hello) < 71 || hello[0] != 1 || hello[38] != 32 {
		return nil
	}
	tag := append([]byte(nil), hello[67:71]...)
	signed := append([]byte(nil), hello...)
	clear(signed[67:71])
	for _, user := range users {
		if user == nil {
			continue
		}
		h := newMAC(user.Password, nil)
		h.Write(signed)
		if subtle.ConstantTimeCompare(h.Sum(nil)[:4], tag) != 1 {
			continue
		}
		if user.RequireUuidSessionId {
			id, err := uuid.Parse(user.Password)
			if err != nil || subtle.ConstantTimeCompare(hello[51:67], id[:]) != 1 {
				continue
			}
		}
		return user
	}
	return nil
}

func serverHelloTLS13(hello []byte) bool {
	if len(hello) < 39 || hello[0] != 2 {
		return false
	}
	p := 39 + int(hello[38]) + 3 // session ID, cipher and compression
	if p+2 > len(hello) {
		return false
	}
	n := int(binary.BigEndian.Uint16(hello[p:]))
	p += 2
	if p+n != len(hello) {
		return false
	}
	end := p + n
	for p+4 <= end {
		typ, size := binary.BigEndian.Uint16(hello[p:]), int(binary.BigEndian.Uint16(hello[p+2:]))
		p += 4
		if p+size > end {
			return false
		}
		if typ == 43 && size == 2 {
			return hello[p] == 3 && hello[p+1] == 4
		}
		p += size
	}
	return false
}

func serverHandshakeV3(raw, peer net.Conn, c *ServerConfig) (*Conn, *ServerUser, error) {
	hello, frames, err := readHello(raw, 1)
	if err != nil {
		return nil, nil, err
	}
	user := authenticatedHello(hello, c.Clients)
	if err := nativebridge.WriteFull(peer, frames); err != nil {
		return nil, nil, err
	}
	if user == nil {
		return nil, nil, camouflage(raw, peer)
	}
	serverHello, flight, err := readHello(peer, 2)
	if err != nil {
		return nil, nil, err
	}
	if len(serverHello) < 38 {
		return nil, nil, errors.New("invalid TLS ServerHello")
	}
	if err := nativebridge.WriteFull(raw, flight); err != nil {
		return nil, nil, err
	}
	if c.Strict && !serverHelloTLS13(serverHello) {
		return nil, nil, camouflage(raw, peer)
	}
	observer := new(serverHelloObserver)
	if _, err := observer.observe(22, serverHello); err != nil {
		return nil, nil, err
	}
	// A TLS 1.3 retry uses a sentinel random. Derive data authentication from
	// the final ServerHello, which can arrive after compatibility CCS records.
	// The channel publishes an immutable copy before that final hello reaches
	// the client; only the flight goroutine mutates the observer and its MAC.
	finalRandom := make(chan []byte, 1)
	if observer.final {
		finalRandom <- append([]byte(nil), observer.random...)
	}
	state := new(handshakeFlightState)
	done := make(chan error, 1)
	go func() {
		defer state.finished(raw)
		xor := sha256.Sum256(append([]byte(user.Password), observer.random...))
		handshakeMAC := newMAC(user.Password, observer.random)
		total := len(flight)
		for total < maxHandshakeBytes {
			t, v, b, err := readRecord(peer)
			if err != nil {
				done <- err
				return
			}
			total += len(b) + 5
			changed, err := observer.observe(t, b)
			if err != nil {
				done <- err
				return
			}
			if changed {
				xor = sha256.Sum256(append([]byte(user.Password), observer.random...))
				handshakeMAC = newMAC(user.Password, observer.random)
				if observer.final {
					finalRandom <- append([]byte(nil), observer.random...)
				}
			}
			if t == 23 {
				if !observer.final {
					done <- errors.New("ShadowTLS encrypted flight arrived before final ServerHello")
					return
				}
				for i := range b {
					b[i] ^= xor[i%len(xor)]
				}
				handshakeMAC.Write(b)
				b = append(append([]byte(nil), handshakeMAC.Sum(nil)[:4]...), b...)
			}
			if err := nativebridge.WriteFull(raw, record(t, v, b)); err != nil {
				done <- err
				return
			}
		}
		done <- errors.New("ShadowTLS handshake exceeds size limit")
	}()
	defer func() { _ = peer.Close(); <-done }()
	var random []byte
	total := len(frames)
	for total < maxHandshakeBytes {
		t, v, b, err := readRecord(raw)
		if err != nil {
			return nil, nil, err
		}
		total += len(b) + 5
		if random == nil {
			select {
			case random = <-finalRandom:
			default:
			}
		}
		if t == 23 && len(b) >= 4 && random != nil {
			mac := newMAC(user.Password, append(append([]byte(nil), random...), 'C'))
			if matches(mac, b[4:], b[:4]) {
				mac.Write(b[:4])
				state.accept(raw)
				return &Conn{Conn: raw, version: 3, switched: true, rhash: mac,
					whash:   newMAC(user.Password, append(append([]byte(nil), random...), 'S')),
					pending: append([]byte(nil), b[4:]...)}, user, nil
			}
		}
		if err := nativebridge.WriteFull(peer, record(t, v, b)); err != nil {
			return nil, nil, err
		}
	}
	return nil, nil, errors.New("ShadowTLS handshake exceeds size limit")
}

// Unauthenticated traffic is forwarded only to the explicitly configured
// camouflage peer. Both copy goroutines finish before returning.
func camouflage(raw, peer net.Conn) error {
	done := make(chan struct{}, 1)
	go func() { _, _ = io.Copy(raw, peer); _ = raw.SetReadDeadline(time.Now()); done <- struct{}{} }()
	_, _ = io.Copy(peer, raw)
	_ = peer.Close()
	<-done
	return ErrUnauthenticated
}
