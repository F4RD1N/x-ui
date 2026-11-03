package session

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/xtls/xray-core/proxy/orbit/internal/guard"
	"github.com/xtls/xray-core/proxy/orbit/internal/protocol"
)

// Stream is a reference virtual socket. Type 10 closes the entire virtual
// socket; consequently CloseWrite cannot promise a TCP half-close. CloseRead
// maps to type 30 and lets the opposite direction continue.
type Stream struct {
	session          *Session
	id               uint32
	metadata         uint16
	destination      protocol.Address
	incoming         bool
	mu               sync.Mutex
	writeMu          sync.Mutex
	changed          chan struct{}
	opened           chan struct{}
	openOnce         sync.Once
	openErr          error
	state            int
	err              error
	localClosed      bool
	localReadClosed  bool
	remoteReadClosed bool
	remoteFull       bool
	remoteFullOffset uint64
	full             bool
	chunks           [][]byte
	buffered         int
	received         uint64
	consumed         uint64
	sent             uint64
	sequence         uint64
	readDeadline     time.Time
	writeDeadline    time.Time
	closeTimer       *time.Timer
	closeStarted     time.Time
}

var _ net.Conn = (*Stream)(nil)

func newStream(s *Session, id uint32, metadata uint16, destination protocol.Address, incoming bool) *Stream {
	return &Stream{session: s, id: id, metadata: metadata, destination: destination,
		incoming: incoming, state: 2, changed: make(chan struct{}), opened: make(chan struct{})}
}
func (s *Stream) ID() uint32                    { return s.id }
func (s *Stream) Destination() protocol.Address { return s.destination }
func (s *Stream) LocalAddr() net.Addr           { return s.session.LocalAddr() }
func (s *Stream) RemoteAddr() net.Addr          { return virtualAddr{s.destination} }

type virtualAddr struct{ address protocol.Address }

func (virtualAddr) Network() string { return "tcp" }
func (a virtualAddr) String() string {
	v, err := a.address.NetworkAddress()
	if err != nil {
		return "invalid"
	}
	return v
}
func (s *Stream) signalLocked() { close(s.changed); s.changed = make(chan struct{}) }
func (s *Stream) finishOpenLocked(err error) {
	s.openOnce.Do(func() { s.openErr = err; close(s.opened) })
}

func (s *Stream) Accept() error {
	s.mu.Lock()
	if !s.incoming || s.state != 2 || s.localClosed {
		s.mu.Unlock()
		return ErrConnect
	}
	s.state = 3
	s.finishOpenLocked(nil)
	s.signalLocked()
	s.mu.Unlock()
	return s.session.send(s.session.ctx, protocol.SocketConnectResponse{SocketID: s.id, Metadata: s.metadata}.Frame())
}
func (s *Stream) Reject() error { return s.Close() }
func (s *Stream) connected() {
	s.mu.Lock()
	if s.state == 2 && !s.incoming {
		s.state = 3
		s.finishOpenLocked(nil)
		s.signalLocked()
	}
	s.mu.Unlock()
}
func (s *Stream) repeatConnect() {
	s.mu.Lock()
	connected := s.state == 3
	s.mu.Unlock()
	if connected {
		s.session.notify(protocol.SocketConnectResponse{SocketID: s.id, Metadata: s.metadata}.Frame())
	}
}

func (s *Stream) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err == nil {
		s.err = err
	}
	s.localClosed = true
	s.finishOpenLocked(err)
	if s.closeTimer != nil {
		s.closeTimer.Stop()
	}
	if s.buffered != 0 {
		s.session.buffered.Add(-int64(s.buffered))
		s.buffered = 0
		s.chunks = nil
	}
	s.signalLocked()
}

func (s *Stream) expiryLocked() {
	if s.closeTimer != nil {
		return
	}
	s.closeStarted = time.Now()
	delay := time.Second
	if s.session.options.CloseTimeout < delay {
		delay = s.session.options.CloseTimeout
	}
	s.closeTimer = time.AfterFunc(delay, s.guardedCloseTick)
}

// guardedCloseTick runs closeTick on its timer goroutine: a panic there ends
// this stream's session, not the process.
func (s *Stream) guardedCloseTick() {
	defer func() {
		if recover() != nil {
			defer func() { _ = recover() }()
			s.session.shutdown(guard.ErrInternal)
		}
	}()
	s.closeTick()
}

func (s *Stream) closeTick() {
	s.mu.Lock()
	if s.state != 6 {
		s.mu.Unlock()
		return
	}
	remaining := s.session.options.CloseTimeout - time.Since(s.closeStarted)
	if remaining <= 0 {
		s.mu.Unlock()
		s.session.remove(s.id, s)
		s.fail(net.ErrClosed)
		return
	}
	delay := time.Second
	if remaining < delay {
		delay = remaining
	}
	s.closeTimer = time.AfterFunc(delay, s.guardedCloseTick)
	s.mu.Unlock()
	s.session.notify(protocol.SocketClose{SocketID: s.id}.Frame())
}

func (s *Stream) Close() error {
	s.mu.Lock()
	if s.localClosed {
		s.mu.Unlock()
		return nil
	}
	s.localClosed = true
	peerClosed := s.state == 4
	s.state = 6
	s.finishOpenLocked(ErrConnect)
	if s.buffered != 0 {
		s.session.buffered.Add(-int64(s.buffered))
		s.buffered = 0
		s.chunks = nil
	}
	s.signalLocked()
	if !peerClosed {
		s.expiryLocked()
	}
	s.mu.Unlock()
	if peerClosed {
		s.session.remove(s.id, s)
	} else {
		s.session.notify(protocol.SocketClose{SocketID: s.id}.Frame())
	}
	return nil
}

// CloseWrite uses the only recovered sender-FIN operation (whole-socket close).
// Applications requiring true TCP half-close must treat this limitation explicitly.
func (s *Stream) CloseWrite() error { return s.Close() }

func (s *Stream) CloseRead() error {
	s.mu.Lock()
	if s.localReadClosed || s.localClosed {
		s.mu.Unlock()
		return nil
	}
	s.localReadClosed = true
	if s.buffered != 0 {
		s.session.buffered.Add(-int64(s.buffered))
		s.buffered = 0
		s.chunks = nil
	}
	s.signalLocked()
	s.mu.Unlock()
	s.session.notify(protocol.SocketReadClose{SocketID: s.id}.Frame())
	return nil
}

func (s *Stream) peerClose() {
	s.mu.Lock()
	old := s.state
	flag := old == 4 || old == 5 || old == 6
	if old == 2 {
		s.finishOpenLocked(ErrConnect)
	}
	if old == 2 || old == 3 {
		s.state = 4
	}
	if old == 5 || old == 6 {
		s.state = 0
		if s.closeTimer != nil {
			s.closeTimer.Stop()
		}
	}
	s.signalLocked()
	s.mu.Unlock()
	s.session.notify(protocol.SocketClose{SocketID: s.id, Flag: flag}.Frame())
	if old == 5 || old == 6 {
		s.session.remove(s.id, s)
	}
}

func (s *Stream) peerReadClose() {
	s.mu.Lock()
	s.remoteReadClosed = true
	s.signalLocked()
	s.mu.Unlock()
}
func (s *Stream) peerBuffer(offset uint64, full bool) {
	s.mu.Lock()
	if offset >= s.remoteFullOffset {
		s.remoteFullOffset = offset
		s.remoteFull = full
		s.signalLocked()
	}
	s.mu.Unlock()
}
func (s *Stream) allocatedNodesLocked() uint64 {
	return (s.received+bufferNodeBytes-1)/bufferNodeBytes - s.consumed/bufferNodeBytes
}

func (s *Stream) receive(d protocol.DataChunk) error {
	s.mu.Lock()
	if s.localClosed && !s.session.server {
		// The client closed this flow (or gave up on it). Data the server sent
		// before it saw the close is still arriving: drop it, as a closed
		// socket would, instead of failing the whole session over it.
		s.mu.Unlock()
		return nil
	}
	if s.state != 3 {
		s.mu.Unlock()
		return errors.New("session: data outside connected state")
	}
	if d.Offset != s.received {
		s.mu.Unlock()
		return ErrOffset
	}
	if ^uint64(0)-s.received < uint64(len(d.Data)) {
		s.mu.Unlock()
		return ErrOffset
	}
	if s.localReadClosed {
		s.received += uint64(len(d.Data))
		s.consumed = s.received
		s.mu.Unlock()
		return nil
	}
	limit := maxFlowBufferBytes
	if !s.session.server {
		limit = maxClientFlowBufferBytes
	}
	if s.buffered+len(d.Data) > limit {
		s.mu.Unlock()
		return s.overflow()
	}
	if len(d.Data) != 0 {
		if s.session.buffered.Add(int64(len(d.Data))) > s.session.options.MaxBufferedBytes {
			s.session.buffered.Add(-int64(len(d.Data)))
			s.mu.Unlock()
			return s.overflow()
		}
		s.chunks = append(s.chunks, d.Data)
		s.buffered += len(d.Data)
		s.received += uint64(len(d.Data))
	}
	nodes := s.allocatedNodesLocked()
	notify := !s.full && nodes >= receiveFullNodes
	if notify {
		s.full = true
	}
	end := s.received
	s.signalLocked()
	s.mu.Unlock()
	if notify {
		s.session.notify(protocol.SocketBuffer{SocketID: s.id, Value64: end, Value32: uint32(nodes * bufferNodeBytes), Flag: true}.Frame())
	}
	return nil
}

// overflow handles data beyond a receive limit. The server half keeps
// VPN-Core's rule (the session ends). On the client the limit is reached when
// this flow's reader stopped (a paused player, an app that stopped reading)
// while the server still had data in flight: only this flow fails, with
// ErrBufferLimit, and the session and its other flows go on.
func (s *Stream) overflow() error {
	if s.session.server {
		return ErrBufferLimit
	}
	s.mu.Lock()
	if s.err == nil {
		s.err = ErrBufferLimit
	}
	s.mu.Unlock()
	_ = s.Close()
	return nil
}

func waitChange(ch <-chan struct{}, done <-chan struct{}, deadline time.Time) error {
	if deadline.IsZero() {
		select {
		case <-ch:
			return nil
		case <-done:
			return ErrClosed
		}
	}
	duration := time.Until(deadline)
	if duration <= 0 {
		return os.ErrDeadlineExceeded
	}
	t := time.NewTimer(duration)
	defer t.Stop()
	select {
	case <-ch:
		return nil
	case <-done:
		return ErrClosed
	case <-t.C:
		return os.ErrDeadlineExceeded
	}
}

func (s *Stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		s.mu.Lock()
		if s.localClosed || s.localReadClosed {
			err := s.err
			if err == nil {
				err = net.ErrClosed
			}
			s.mu.Unlock()
			return 0, err
		}
		if !s.readDeadline.IsZero() && !time.Now().Before(s.readDeadline) {
			s.mu.Unlock()
			return 0, os.ErrDeadlineExceeded
		}
		if s.buffered > 0 {
			n := 0
			for n < len(p) && len(s.chunks) > 0 {
				copied := copy(p[n:], s.chunks[0])
				n += copied
				s.chunks[0] = s.chunks[0][copied:]
				if len(s.chunks[0]) == 0 {
					s.chunks[0] = nil
					s.chunks = s.chunks[1:]
				}
			}
			s.buffered -= n
			s.consumed += uint64(n)
			s.session.buffered.Add(-int64(n))
			nodes := s.allocatedNodesLocked()
			notify := s.full && nodes <= receiveResumeNodes
			if notify {
				s.full = false
			}
			end := s.received
			s.mu.Unlock()
			if notify {
				s.session.notify(protocol.SocketBuffer{SocketID: s.id, Value64: end, Value32: uint32(nodes * bufferNodeBytes)}.Frame())
			}
			return n, nil
		}
		if s.state == 4 {
			s.mu.Unlock()
			return 0, io.EOF
		}
		ch, deadline := s.changed, s.readDeadline
		s.mu.Unlock()
		if err := waitChange(ch, s.session.done, deadline); err != nil {
			return 0, err
		}
	}
}

func (s *Stream) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	written := 0
	for len(p) > 0 {
		s.mu.Lock()
		if s.localClosed || s.state == 4 {
			s.mu.Unlock()
			return written, net.ErrClosed
		}
		if s.remoteReadClosed {
			s.mu.Unlock()
			return written, ErrPeerReadClosed
		}
		if !s.writeDeadline.IsZero() && !time.Now().Before(s.writeDeadline) {
			s.mu.Unlock()
			return written, os.ErrDeadlineExceeded
		}
		if s.state != 3 || s.remoteFull {
			ch, deadline := s.changed, s.writeDeadline
			s.mu.Unlock()
			if err := waitChange(ch, s.session.done, deadline); err != nil {
				return written, err
			}
			continue
		}
		n := len(p)
		if n > protocol.MaxDataSize {
			n = protocol.MaxDataSize
		}
		if ^uint64(0)-s.sent < uint64(n) || s.sequence == ^uint64(0) {
			s.mu.Unlock()
			return written, ErrOffset
		}
		frame, _ := (protocol.DataChunk{SocketID: s.id, Sequence: s.sequence, Offset: s.sent, Data: p[:n]}).Frame()
		ctx, cancel := context.WithCancel(s.session.ctx)
		deadline := s.writeDeadline
		s.mu.Unlock()
		done, err := s.queueData(ctx, frame)
		if err != nil {
			cancel()
			return written, err
		}
		for err == nil {
			s.mu.Lock()
			changed := s.changed
			deadline = s.writeDeadline
			closed := s.localClosed || s.state == 4
			s.mu.Unlock()
			if closed {
				err = net.ErrClosed
				break
			}
			var timer *time.Timer
			var timeout <-chan time.Time
			if !deadline.IsZero() {
				d := time.Until(deadline)
				if d <= 0 {
					err = os.ErrDeadlineExceeded
					break
				}
				timer = time.NewTimer(d)
				timeout = timer.C
			}
			select {
			case err = <-done:
				if timer != nil {
					timer.Stop()
				}
				cancel()
				if err != nil {
					return written, err
				}
				s.mu.Lock()
				s.sent += uint64(n)
				s.sequence++
				s.mu.Unlock()
				written += n
				p = p[n:]
				goto nextChunk
			case <-changed:
			case <-timeout:
				err = os.ErrDeadlineExceeded
			case <-s.session.done:
				err = s.session.Err()
			}
			if timer != nil {
				timer.Stop()
			}
		}
		cancel()
		_ = s.Close()
		return written, err
	nextChunk:
	}
	return written, nil
}

// Hold the stream lock only for nonblocking admission. This ensures Close
// cannot overtake a newly queued data frame while keeping queue pressure and
// changing stream deadlines interruptible.
func (s *Stream) queueData(ctx context.Context, frame protocol.Frame) (<-chan error, error) {
	r := writeRequest{frame: frame, done: make(chan error, 1), ctx: ctx}
	for {
		s.mu.Lock()
		if s.localClosed || s.state == 4 {
			s.mu.Unlock()
			return nil, net.ErrClosed
		}
		if s.remoteReadClosed {
			s.mu.Unlock()
			return nil, ErrPeerReadClosed
		}
		deadline, changed := s.writeDeadline, s.changed
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			s.mu.Unlock()
			return nil, os.ErrDeadlineExceeded
		}
		if s.state == 3 && !s.remoteFull {
			select {
			case s.session.out <- r:
				s.mu.Unlock()
				return r.done, nil
			default:
			}
		}
		s.mu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		var err error
		select {
		case <-changed:
		case <-s.session.space:
		case <-s.session.done:
			err = s.session.Err()
		case <-ctx.Done():
			err = ctx.Err()
		case <-timeout:
			err = os.ErrDeadlineExceeded
		}
		if timer != nil {
			timer.Stop()
		}
		if err != nil {
			return nil, err
		}
	}
}

func (s *Stream) SetDeadline(t time.Time) error {
	s.mu.Lock()
	s.readDeadline = t
	s.writeDeadline = t
	s.signalLocked()
	s.mu.Unlock()
	return nil
}
func (s *Stream) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	s.readDeadline = t
	s.signalLocked()
	s.mu.Unlock()
	return nil
}
func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	s.writeDeadline = t
	s.signalLocked()
	s.mu.Unlock()
	return nil
}
