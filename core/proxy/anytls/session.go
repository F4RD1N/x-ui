// Native AnyTLS session framing, implemented from the published protocol.
package anytls

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	xerrors "github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/nativebridge"
)

const (
	cmdWaste byte = iota
	cmdSYN
	cmdPSH
	cmdFIN
	cmdSettings
	cmdAlert
	cmdPadding
	cmdSYNACK
	cmdHeartRequest
	cmdHeartResponse
	cmdServerSettings
)

func Auth(password string, custom bool) [32]byte {
	a := sha256.Sum256([]byte(password))
	if custom {
		if u, e := uuid.Parse(password); e == nil {
			copy(a[8:24], u[:])
		}
	}
	return a
}

func frame(cmd byte, id uint32, p []byte) []byte {
	b := make([]byte, 7+len(p))
	b[0] = cmd
	binary.BigEndian.PutUint32(b[1:5], id)
	binary.BigEndian.PutUint16(b[5:7], uint16(len(p)))
	copy(b[7:], p)
	return b
}

type muxSession struct {
	conn      net.Conn
	owner     *Client
	wmu       sync.Mutex
	mu        sync.Mutex
	closed    bool
	err       error
	streams   map[uint32]*stream
	next      uint32
	busy      bool
	sequence  uint64
	idleAt    time.Time
	packets   int
	pad       *padding
	version   int
	done      chan struct{}
	heartbeat chan struct{}
	// cancel ends the ctx the carrier was dialed on; nil when there is none.
	cancel context.CancelFunc
}

// openTimeout bounds the frames that open a stream, as the ACK wait is.
const openTimeout = 10 * time.Second

func newSession(conn net.Conn, c *Client, p *padding, cancel context.CancelFunc) (*muxSession, error) {
	s := &muxSession{conn: conn, owner: c, pad: p, streams: make(map[uint32]*stream), idleAt: time.Now(), done: make(chan struct{}), heartbeat: make(chan struct{}, 1), cancel: cancel}
	a := Auth(c.config.Password, c.config.UuidHashMiddle)
	n := 0
	if ranges := p.rules[0]; len(ranges) > 0 {
		n = ranges[0].size()
	}
	b := append(a[:], byte(n>>8), byte(n))
	pad := make([]byte, n)
	if _, e := rand.Read(pad); e != nil {
		return nil, e
	}
	b = append(b, pad...)
	if e := nativebridge.WriteFull(conn, b); e != nil {
		return nil, e
	}
	s.packets = 1
	go s.readLoop()
	return s, nil
}

func (s *muxSession) writePacketLocked(p []byte) error {
	packet := s.packets
	s.packets++
	if packet >= s.pad.stop {
		return nativebridge.WriteFull(s.conn, p)
	}
	for _, r := range s.pad.rules[packet] {
		if r.check {
			if len(p) == 0 {
				return nil
			}
			continue
		}
		n := r.size()
		if n == 0 {
			continue
		}
		send := n
		if send > len(p) {
			send = len(p)
		}
		b := append([]byte(nil), p[:send]...)
		p = p[send:]
		if gap := n - len(b); gap >= 7 {
			b = append(b, frame(cmdWaste, 0, make([]byte, gap-7))...)
		}
		if len(b) > 0 {
			if e := nativebridge.WriteFull(s.conn, b); e != nil {
				return e
			}
		}
	}
	if len(p) > 0 {
		return nativebridge.WriteFull(s.conn, p)
	}
	return nil
}

func (s *muxSession) send(cmd byte, id uint32, p []byte) error {
	if len(p) > 65535 {
		return errors.New("AnyTLS frame too large")
	}
	s.wmu.Lock()
	e := s.writePacketLocked(frame(cmd, id, p))
	s.wmu.Unlock()
	if e != nil {
		s.fail(e)
	}
	return e
}

func (s *muxSession) open(ctx context.Context, destination []byte) (*stream, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, net.ErrClosed
	}
	s.next++
	id := s.next
	if id == 0 {
		s.mu.Unlock()
		s.fail(errors.New("AnyTLS stream IDs exhausted"))
		return nil, net.ErrClosed
	}
	r, w := net.Pipe()
	st := &stream{session: s, id: id, read: r, deliver: w, ack: make(chan struct{}), closed: make(chan struct{})}
	s.streams[id] = st
	s.busy = true
	s.mu.Unlock()
	// The opening frames are bound to this request: its cancellation fails
	// the session (a half-written frame leaves the carrier unusable), also
	// while waiting for the writer, and the write has a deadline. Once they
	// are out the stream lives on its own.
	stop := context.AfterFunc(ctx, func() { s.fail(ctx.Err()) })
	deadline := time.Now().Add(openTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	s.wmu.Lock()
	_ = s.conn.SetWriteDeadline(deadline)
	b := frame(cmdSYN, id, nil)
	if id == 1 {
		b = append(frame(cmdSettings, 0, []byte("v=2\nclient=xray-native/1\npadding-md5="+s.pad.digest())), b...)
	}
	b = append(b, frame(cmdPSH, id, destination)...)
	e := s.writePacketLocked(b)
	_ = s.conn.SetWriteDeadline(time.Time{})
	s.wmu.Unlock()
	if !stop() && e == nil {
		e = ctx.Err()
	}
	if e != nil {
		s.fail(e)
		st.Close()
		return nil, e
	}
	go st.watchACK()
	return st, nil
}

func (s *muxSession) readLoop() {
	defer nativebridge.RecoverWorker(s.fail)
	for {
		var h [7]byte
		if _, e := io.ReadFull(s.conn, h[:]); e != nil {
			s.fail(e)
			return
		}
		cmd := h[0]
		id := binary.BigEndian.Uint32(h[1:5])
		p := make([]byte, binary.BigEndian.Uint16(h[5:]))
		if _, e := io.ReadFull(s.conn, p); e != nil {
			s.fail(e)
			return
		}
		s.mu.Lock()
		st := s.streams[id]
		s.mu.Unlock()
		switch cmd {
		case cmdWaste:
		case cmdHeartResponse:
			select {
			case s.heartbeat <- struct{}{}:
			default:
			}
		case cmdHeartRequest:
			if e := s.send(cmdHeartResponse, id, nil); e != nil {
				return
			}
		case cmdServerSettings:
			s.mu.Lock()
			s.version = 1
			for _, line := range splitLines(string(p)) {
				if line == "v=2" {
					s.version = 2
				}
			}
			s.mu.Unlock()
		case cmdPadding:
			// Like the reference client, a scheme that cannot be used is
			// only logged: the session and the current scheme stay.
			pad, e := parsePadding(string(p))
			if e != nil {
				xerrors.LogWarningInner(context.Background(), e, "AnyTLS: ignoring padding scheme update from server")
				continue
			}
			s.owner.mu.Lock()
			s.owner.padding = pad
			s.owner.mu.Unlock()
		case cmdPSH:
			if st != nil {
				if e := nativebridge.WriteFull(st.deliver, p); e != nil {
					continue
				}
			}
		case cmdFIN:
			if len(p) != 0 {
				s.fail(errors.New("AnyTLS FIN has payload"))
				return
			}
			if st != nil {
				st.deliver.Close()
			}
		case cmdSYNACK:
			if st != nil {
				st.ackOnce.Do(func() { close(st.ack) })
			}
			if len(p) > 0 && st != nil {
				st.deliver.Close()
				st.read.Close()
				s.drop(id)
			}
		case cmdAlert:
			msg := boundedText(p)
			xerrors.LogWarning(context.Background(), "AnyTLS server alert: ", msg)
			s.fail(fmt.Errorf("AnyTLS server rejected session: %s", msg))
			return
		default:
			s.fail(errors.New("unknown AnyTLS frame command"))
			return
		}
	}
}

func splitLines(s string) []string {
	var a []string
	start := 0
	for i := range s {
		if s[i] == '\n' {
			a = append(a, s[start:i])
			start = i + 1
		}
	}
	return append(a, s[start:])
}
func boundedText(p []byte) string {
	if len(p) > 256 {
		p = p[:256]
	}
	return string(p)
}
func (s *muxSession) drop(id uint32) {
	s.mu.Lock()
	delete(s.streams, id)
	if len(s.streams) == 0 {
		s.busy = false
		s.idleAt = time.Now()
	}
	s.mu.Unlock()
}

// failure is the reason the session closed, or nil while it is open.
func (s *muxSession) failure() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func (s *muxSession) fail(e error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.err = e
	streams := s.streams
	s.streams = make(map[uint32]*stream)
	close(s.done)
	s.mu.Unlock()
	s.conn.Close()
	if s.cancel != nil {
		s.cancel()
	}
	for _, st := range streams {
		st.read.Close()
		st.deliver.Close()
	}
}

type stream struct {
	session       *muxSession
	id            uint32
	read, deliver net.Conn
	once          sync.Once
	ackOnce       sync.Once
	ack, closed   chan struct{}
}

func (s *muxSession) checkHealth(ctx context.Context) error {
	s.mu.Lock()
	version := s.version
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	if version < 2 {
		return nil
	}
	clear := nativebridge.SetupDeadline(ctx, s.conn, 5*time.Second)
	defer clear()
	if e := s.send(cmdHeartRequest, 0, nil); e != nil {
		return e
	}
	t := time.NewTimer(5 * time.Second)
	defer t.Stop()
	select {
	case <-s.heartbeat:
		return nil
	case <-s.done:
		return net.ErrClosed
	case <-ctx.Done():
		s.fail(ctx.Err())
		return ctx.Err()
	case <-t.C:
		s.fail(errors.New("AnyTLS idle session heartbeat timed out"))
		return net.ErrClosed
	}
}

func (s *stream) watchACK() {
	defer nativebridge.RecoverWorker(s.session.fail)
	t := time.NewTimer(10 * time.Second)
	defer t.Stop()
	select {
	case <-s.ack:
	case <-s.closed:
	case <-s.session.done:
	case <-t.C:
		s.session.mu.Lock()
		v := s.session.version
		s.session.mu.Unlock()
		if v >= 2 {
			s.session.fail(errors.New("AnyTLS stream acknowledgement timed out"))
		}
	}
}

func (s *stream) Read(p []byte) (int, error) { return s.read.Read(p) }
func (s *stream) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > 32768 {
			n = 32768
		}
		if e := s.session.send(cmdPSH, s.id, p[:n]); e != nil {
			return total, e
		}
		total += n
		p = p[n:]
	}
	return total, nil
}
func (s *stream) Close() error {
	s.once.Do(func() {
		close(s.closed)
		s.read.Close()
		s.deliver.Close()
		_ = s.session.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_ = s.session.send(cmdFIN, s.id, nil)
		_ = s.session.conn.SetWriteDeadline(time.Time{})
		s.session.drop(s.id)
	})
	return nil
}
func (s *stream) LocalAddr() net.Addr                { return s.session.conn.LocalAddr() }
func (s *stream) RemoteAddr() net.Addr               { return s.session.conn.RemoteAddr() }
func (s *stream) SetReadDeadline(t time.Time) error  { return s.read.SetReadDeadline(t) }
func (s *stream) SetWriteDeadline(t time.Time) error { return s.session.conn.SetWriteDeadline(t) }
func (s *stream) SetDeadline(t time.Time) error {
	_ = s.read.SetReadDeadline(t)
	return s.session.conn.SetWriteDeadline(t)
}
