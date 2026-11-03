// Package session multiplexes the recovered connection and virtual-socket
// protocol on an established transport. It deliberately does not substitute
// additive credits or TCP half-close messages for the reference behavior.
package session

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/proxy/orbit/internal/guard"
	"github.com/xtls/xray-core/proxy/orbit/internal/protocol"
)

var (
	ErrAuthentication = errors.New("session: authentication rejected")
	ErrClosed         = errors.New("session: closed")
	ErrFlowLimit      = errors.New("session: flow limit reached")
	ErrConnect        = errors.New("session: destination connection rejected")
	ErrOffset         = errors.New("session: noncontiguous stream offset")
	ErrBufferLimit    = errors.New("session: receive buffer limit exceeded")
	ErrPeerReadClosed = errors.New("session: peer stopped reading")
)

// Retain Go's monotonic clock component when storing activity in atomics. A
// wall-clock correction must not expire an active tunnel or suppress keepalive.
var activityEpoch = time.Now()

func activityTime(now time.Time) int64 { return now.Sub(activityEpoch).Nanoseconds() }

func activityAge(now time.Time, last int64) time.Duration {
	return time.Duration(activityTime(now) - last)
}

// Buffer thresholds reproduce the native 4096-byte allocation nodes: receive
// full at 256 nodes, resume at 128, and up to 128 send nodes may be in flight.
const (
	bufferNodeBytes    = 4096
	receiveFullNodes   = 256
	receiveResumeNodes = 128
	maxFlowBufferBytes = (receiveFullNodes + 128) * bufferNodeBytes
	// maxClientFlowBufferBytes is the client's own per-flow cap. The 'full'
	// notice still goes out at 1 MiB, but the server stops only when that
	// notice arrives: what it already queued, in its socket buffer and on
	// the path still lands, which on a deep mobile or CDN path is more than
	// the native 512 KiB margin. Past this cap the client fails that one flow
	// (see Stream.overflow); the session-wide MaxBufferedBytes still bounds
	// the total.
	maxClientFlowBufferBytes = 4 << 20
)

type Options struct {
	MaxFlows          int
	MaxBufferedBytes  int64
	HandshakeTimeout  time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	HeartbeatInterval time.Duration
	CloseTimeout      time.Duration
	UDPQueue          int
	AppQueue          int
}

func (o Options) normalized() (Options, error) {
	if o.MaxFlows == 0 {
		o.MaxFlows = 128
	}
	if o.MaxBufferedBytes == 0 {
		o.MaxBufferedBytes = 32 << 20
	}
	if o.HandshakeTimeout == 0 {
		o.HandshakeTimeout = 30 * time.Second
	}
	if o.WriteTimeout == 0 {
		o.WriteTimeout = 30 * time.Second
	}
	if o.IdleTimeout == 0 {
		o.IdleTimeout = 35 * time.Second
	}
	if o.HeartbeatInterval == 0 {
		o.HeartbeatInterval = 25 * time.Second
	}
	if o.CloseTimeout == 0 {
		o.CloseTimeout = 4 * time.Second
	}
	if o.UDPQueue == 0 {
		o.UDPQueue = 128
	}
	if o.AppQueue == 0 {
		o.AppQueue = 128
	}
	if o.MaxFlows < 1 || o.MaxFlows > 65536 || o.MaxBufferedBytes < bufferNodeBytes || o.UDPQueue < 1 || o.UDPQueue > 65536 ||
		o.AppQueue < 1 || o.AppQueue > 65536 ||
		o.HandshakeTimeout <= 0 || o.WriteTimeout <= 0 || o.IdleTimeout <= 0 || o.HeartbeatInterval <= 0 || o.CloseTimeout <= 0 {
		return o, errors.New("session: invalid resource limits or timeouts")
	}
	return o, nil
}

type ClientOptions struct {
	// NativeCompatibility permits the provider's bounded pre-connect control
	// notifications. They never replace a connection response or reach ACK.
	// The orbit outbound never sets it.
	NativeCompatibility bool
	User                protocol.UserInfo
	ChannelID           [16]byte
	ConnectionID        uint32
	Options             Options
	// AllocateSocketID lets physical connections share a channel-wide ID space.
	// The callback must be concurrency-safe, nonblocking, and return increasing
	// nonzero IDs; this preserves the native channel's monotonic ID counter.
	AllocateSocketID func() (uint32, error)
	// InitialReachID pipelines only the existing payload-free type-1 reach
	// request after ConnectRequest. Zero preserves the original handshake.
	// The session still requires ConnectResponse; the caller must separately
	// verify the matching reach reply before advertising application readiness.
	InitialReachID uint32
}

type ServerOptions struct {
	Authenticate     func(context.Context, protocol.UserInfo) error
	AuthorizeRequest func(context.Context, protocol.UserInfo, protocol.ConnectRequest) error
	// RouteMetadata preserves the terminal transport's opaque proxy path. Native
	// servers pass it to their application-owned channel policy callback.
	RouteMetadata []byte
	Options       Options
}

type writeRequest struct {
	frame     protocol.Frame
	done      chan error
	ctx       context.Context
	heartbeat bool
}

type Session struct {
	conn            net.Conn
	options         Options
	user            protocol.UserInfo
	channelID       [16]byte
	connectionID    uint32
	routeMetadata   []byte
	server          bool
	ctx             context.Context
	cancel          context.CancelFunc
	done            chan struct{}
	finish          sync.Once
	mu              sync.Mutex
	err             error
	streams         map[uint32]*Stream
	nextID          uint32
	allocateID      func() (uint32, error)
	lastAllocatedID uint32
	out             chan writeRequest
	space           chan struct{}
	incoming        chan *Stream
	udp             chan protocol.UDPEnvelope
	app             chan protocol.AppMessage
	buffered        atomic.Int64
	lastRead        atomic.Int64
	lastWrite       atomic.Int64
	heartbeatQueued atomic.Bool
	droppedUDP      atomic.Uint64
}

func handshake(ctx context.Context, conn net.Conn, duration time.Duration, fn func() error) error {
	if ctx == nil || conn == nil {
		return errors.New("session: context and connection required")
	}
	deadline := time.Now().Add(duration)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	err := fn()
	stop()
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		err = conn.SetDeadline(time.Time{})
	}
	if err != nil {
		_ = conn.Close()
	}
	return err
}

// Client authenticates an already established transport. The caller remains
// responsible for transport selection, credentials and reconnect policy.
func Client(ctx context.Context, conn net.Conn, cfg ClientOptions) (*Session, error) {
	o, err := cfg.Options.normalized()
	if err != nil {
		return nil, err
	}
	identity, err := protocol.EncodeUserInfo(cfg.User, nil)
	if err != nil {
		return nil, err
	}
	if cfg.ChannelID == [16]byte{} {
		if cfg.ChannelID, err = protocol.NewChannelID(); err != nil {
			return nil, err
		}
	}
	if cfg.ConnectionID == 0 {
		var b [4]byte
		if _, err = rand.Read(b[:]); err != nil {
			return nil, err
		}
		cfg.ConnectionID = binary.LittleEndian.Uint32(b[:])
		if cfg.ConnectionID == 0 {
			cfg.ConnectionID = 1
		}
	}
	req := protocol.ConnectRequest{UserInfo: identity, ConnectionID: cfg.ConnectionID, ChannelID: cfg.ChannelID}
	err = handshake(ctx, conn, o.HandshakeTimeout, func() error {
		var sent <-chan error
		if cfg.InitialReachID == 0 {
			if err := protocol.WriteFrame(conn, req.Frame(protocol.ConnectFlags)); err != nil {
				return err
			}
		} else {
			// Read concurrently with the coalesced write: old servers may send
			// ConnectResponse before reading the next frame, including over an
			// unbuffered net.Conn. Closing on an invalid reply reaps the writer.
			data, err := req.Frame(protocol.ConnectFlags).MarshalBinary()
			if err != nil {
				return err
			}
			reach, _ := (protocol.AppMessage{Type: 1, RequestID: cfg.InitialReachID}).Frame()
			next, _ := reach.MarshalBinary()
			data = append(data, next...)
			written := make(chan error, 1)
			guard.Go(func() { _, err := io.Copy(conn, bytes.NewReader(data)); written <- err }, func() { written <- guard.ErrInternal })
			sent = written
		}
		err := readConnectionResponse(conn, cfg.NativeCompatibility)
		if sent != nil {
			if err != nil {
				_ = conn.Close()
			}
			if writeErr := <-sent; err == nil {
				err = writeErr
			}
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	s := newSession(ctx, conn, o, protocol.NormalizeIdentity(cfg.User), req, false, nil)
	s.allocateID = cfg.AllocateSocketID
	return s, nil
}

func readConnectionResponse(conn net.Conn, native bool) error {
	// The native dispatcher accepts notifications before the connection reply.
	// In particular it ignores a subtype-2 landing notification while the VPN
	// is still connecting. Replaying it after authentication would allow a
	// stale zero-ID notification to satisfy the later reach check incorrectly.
	// Without native compatibility (every orbit session) the first frame must
	// be the empty connection response or a kick-out, exactly as before.
	const maxStartupControls = 16
	for controls := 0; ; controls++ {
		f, err := protocol.ReadFrame(conn)
		if err != nil {
			return err
		}
		switch f.Type {
		case protocol.TypeKickOut:
			if _, err := protocol.ParseKickOut(f); err != nil {
				return err
			}
			return ErrAuthentication
		case protocol.TypeConnectResponse:
			if native || len(f.Payload) == 0 {
				return nil
			}
		case protocol.TypeHeartbeat:
			if native && len(f.Payload) == 0 && controls < maxStartupControls {
				continue
			}
		case protocol.TypeApp:
			if native && controls < maxStartupControls {
				if _, err := protocol.ParseAppMessage(f); err != nil {
					return err
				}
				continue
			}
		}
		return fmt.Errorf("%w: expected connection response (type=%d flags=%d payload_bytes=%d)", protocol.ErrMalformed, f.Type, f.Flags, len(f.Payload))
	}
}

// Server validates the encrypted identity before accepting flow frames. The
// fixed embedded record key is not a substitute for Authenticate.
func Server(ctx context.Context, conn net.Conn, cfg ServerOptions) (*Session, error) {
	o, err := cfg.Options.normalized()
	if err != nil {
		return nil, err
	}
	if cfg.Authenticate == nil {
		return nil, errors.New("session: Authenticate is required")
	}
	var req protocol.ConnectRequest
	var user protocol.UserInfo
	err = handshake(ctx, conn, o.HandshakeTimeout, func() error {
		f, err := protocol.ReadFrame(conn)
		if err != nil {
			return err
		}
		req, err = protocol.ParseConnectRequest(f)
		if err != nil {
			return err
		}
		user, err = protocol.DecodeUserInfo(req.UserInfo[:])
		if err != nil {
			return err
		}
		if err := cfg.Authenticate(ctx, user); err != nil {
			// 500 is an owned-server rejection policy, not a recovered reason map.
			_ = protocol.WriteFrame(conn, protocol.KickOut(500))
			return ErrAuthentication
		}
		if cfg.AuthorizeRequest != nil {
			if err := cfg.AuthorizeRequest(ctx, user, req); err != nil {
				_ = protocol.WriteFrame(conn, protocol.KickOut(500))
				return ErrAuthentication
			}
		}
		return protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeConnectResponse})
	})
	if err != nil {
		return nil, err
	}
	return newSession(ctx, conn, o, user, req, true, cfg.RouteMetadata), nil
}

func newSession(parent context.Context, conn net.Conn, o Options, user protocol.UserInfo, req protocol.ConnectRequest, server bool, routeMetadata []byte) *Session {
	ctx, cancel := context.WithCancel(parent)
	s := &Session{conn: conn, options: o, user: user, channelID: req.ChannelID, connectionID: req.ConnectionID,
		server: server, routeMetadata: append([]byte(nil), routeMetadata...), ctx: ctx, cancel: cancel, done: make(chan struct{}), streams: make(map[uint32]*Stream),
		nextID: 1, out: make(chan writeRequest, 256), space: make(chan struct{}, 1), incoming: make(chan *Stream, o.MaxFlows), udp: make(chan protocol.UDPEnvelope, o.UDPQueue), app: make(chan protocol.AppMessage, o.AppQueue)}
	now := activityTime(time.Now())
	s.lastRead.Store(now)
	s.lastWrite.Store(now)
	s.conn = &activityConn{Conn: conn, session: s}
	fail := func() { s.shutdown(guard.ErrInternal) }
	guard.Go(s.writeLoop, fail)
	guard.Go(s.readLoop, fail)
	guard.Go(s.maintenance, fail)
	guard.Go(func() { <-ctx.Done(); s.shutdown(ctx.Err()) }, nil)
	return s
}

func (s *Session) User() protocol.UserInfo { return s.user }
func (s *Session) ChannelID() [16]byte     { return s.channelID }
func (s *Session) ConnectionID() uint32    { return s.connectionID }
func (s *Session) RouteMetadata() []byte   { return append([]byte(nil), s.routeMetadata...) }
func (s *Session) Done() <-chan struct{}   { return s.done }
func (s *Session) Err() error              { s.mu.Lock(); defer s.mu.Unlock(); return s.err }
func (s *Session) DroppedUDP() uint64      { return s.droppedUDP.Load() }
func (s *Session) BufferedBytes() int64    { return s.buffered.Load() }
func (s *Session) LocalAddr() net.Addr     { return s.conn.LocalAddr() }
func (s *Session) RemoteAddr() net.Addr    { return s.conn.RemoteAddr() }

func (s *Session) Close() error { s.shutdown(ErrClosed); return nil }
func (s *Session) shutdown(err error) {
	s.finish.Do(func() {
		if err == nil {
			err = ErrClosed
		}
		s.mu.Lock()
		s.err = err
		streams := make([]*Stream, 0, len(s.streams))
		for _, stream := range s.streams {
			streams = append(streams, stream)
		}
		s.streams = make(map[uint32]*Stream)
		s.mu.Unlock()
		close(s.done)
		s.cancel()
		_ = s.conn.Close()
		for _, stream := range streams {
			stream.fail(err)
		}
	})
}

func (s *Session) queue(ctx context.Context, f protocol.Frame) (<-chan error, error) {
	if ctx == nil {
		return nil, errors.New("session: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r := writeRequest{frame: f, done: make(chan error, 1), ctx: ctx}
	select {
	case <-s.done:
		return nil, s.Err()
	default:
	}
	select {
	case s.out <- r:
		return r.done, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.done:
		return nil, s.Err()
	}
}
func (s *Session) send(ctx context.Context, f protocol.Frame) error {
	done, err := s.queue(ctx, f)
	if err != nil {
		return err
	}
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return s.Err()
	}
}

// Control notifications cannot block the frame reader; a saturated bounded
// control queue terminates the session instead of deadlocking both peers.
func (s *Session) notify(f protocol.Frame) {
	r := writeRequest{frame: f, done: make(chan error, 1), ctx: s.ctx}
	select {
	case <-s.done:
		return
	default:
	}
	select {
	case s.out <- r:
	default:
		s.shutdown(ErrBufferLimit)
	}
}

func (s *Session) writeLoop() {
	for {
		select {
		case <-s.done:
			return
		case r := <-s.out:
			select {
			case s.space <- struct{}{}:
			default:
			}
			if err := r.ctx.Err(); err != nil {
				if r.heartbeat {
					s.heartbeatQueued.Store(false)
				}
				r.done <- err
				continue
			}
			// Traffic ahead of a queued heartbeat may already have refreshed the
			// native send-idle timer. Do not send an unnecessary control packet.
			if r.heartbeat && activityAge(time.Now(), s.lastWrite.Load()) < s.options.HeartbeatInterval {
				s.heartbeatQueued.Store(false)
				r.done <- nil
				continue
			}
			deadline := time.Now().Add(s.options.WriteTimeout)
			if d, ok := r.ctx.Deadline(); ok && d.Before(deadline) {
				deadline = d
			}
			err := s.conn.SetWriteDeadline(deadline)
			if err == nil {
				err = protocol.WriteFrame(s.conn, r.frame)
			}
			if r.heartbeat {
				s.heartbeatQueued.Store(false)
			}
			r.done <- err
			if err != nil {
				s.shutdown(err)
				return
			}
		}
	}
}

func (s *Session) readLoop() {
	for {
		f, err := protocol.ReadFrame(s.conn)
		if err != nil {
			s.shutdown(err)
			return
		}
		if err := s.handle(f); err != nil {
			s.shutdown(err)
			return
		}
	}
}

func (s *Session) maintenance() {
	// The native connected-state timer polls every 500 ms. Honor explicitly
	// shorter intervals used by embedders/tests without changing the defaults.
	interval := 500 * time.Millisecond
	if interval > s.options.HeartbeatInterval {
		interval = s.options.HeartbeatInterval
	}
	if interval > s.options.IdleTimeout/2 {
		interval = s.options.IdleTimeout / 2
	}
	if interval <= 0 {
		interval = time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			s.maintain(time.Now())
		}
	}
}

// maintain implements the reference TCP activity rules: receive expiry wins
// over sending; heartbeats occur only when outbound traffic has been idle.
// One pending heartbeat bounds the control queue even if a writer stalls.
func (s *Session) maintain(now time.Time) {
	if activityAge(now, s.lastRead.Load()) >= s.options.IdleTimeout {
		s.shutdown(errors.New("session: peer idle timeout"))
		return
	}
	if activityAge(now, s.lastWrite.Load()) < s.options.HeartbeatInterval || !s.heartbeatQueued.CompareAndSwap(false, true) {
		return
	}
	r := writeRequest{frame: protocol.Frame{Type: protocol.TypeHeartbeat}, done: make(chan error, 1), ctx: s.ctx, heartbeat: true}
	select {
	case <-s.done:
		s.heartbeatQueued.Store(false)
	case s.out <- r:
	default:
		s.heartbeatQueued.Store(false)
		s.shutdown(ErrBufferLimit)
	}
}

// Activity is recorded for actual bytes, including a fragmented frame that is
// not yet complete. The reference refreshes receive time in its data callback,
// not only after parsing a whole frame. Failed/zero-byte I/O is not activity.
type activityConn struct {
	net.Conn
	session *Session
}

func (c *activityConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.session.lastRead.Store(activityTime(time.Now()))
	}
	return n, err
}

func (c *activityConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.session.lastWrite.Store(activityTime(time.Now()))
	}
	return n, err
}

func (s *Session) lookup(id uint32) *Stream { s.mu.Lock(); defer s.mu.Unlock(); return s.streams[id] }
func (s *Session) remove(id uint32, expected *Stream) {
	s.mu.Lock()
	if s.streams[id] == expected {
		delete(s.streams, id)
	}
	s.mu.Unlock()
}

func (s *Session) handle(f protocol.Frame) error {
	switch f.Type {
	case protocol.TypeHeartbeat:
		if len(f.Payload) != 0 {
			return protocol.ErrMalformed
		}
		return nil
	case protocol.TypeLeave:
		if len(f.Payload) != 0 {
			return protocol.ErrMalformed
		}
		return io.EOF
	case protocol.TypeKickOut:
		if _, err := protocol.ParseKickOut(f); err != nil {
			return err
		}
		return ErrAuthentication
	case protocol.TypeSocketConnect:
		request, err := protocol.ParseSocketConnect(f)
		if err != nil {
			return err
		}
		if !s.server || request.Address == nil || request.Address.Port == 0 {
			s.notify(protocol.SocketClose{SocketID: request.SocketID}.Frame())
			return nil
		}
		if old := s.lookup(request.SocketID); old != nil {
			old.repeatConnect()
			return nil
		}
		s.mu.Lock()
		if len(s.streams) >= s.options.MaxFlows {
			s.mu.Unlock()
			s.notify(protocol.SocketClose{SocketID: request.SocketID}.Frame())
			return nil
		}
		stream := newStream(s, request.SocketID, request.Metadata, *request.Address, true)
		s.streams[request.SocketID] = stream
		s.mu.Unlock()
		select {
		case s.incoming <- stream:
		default:
			_ = stream.Reject()
		}
		return nil
	case protocol.TypeSocketConnectResponse:
		r, err := protocol.ParseSocketConnectResponse(f)
		if err != nil {
			return err
		}
		if stream := s.lookup(r.SocketID); stream != nil {
			stream.connected()
		}
		return nil
	case protocol.TypeSocketClose:
		r, err := protocol.ParseSocketClose(f)
		if err != nil {
			return err
		}
		if stream := s.lookup(r.SocketID); stream != nil {
			stream.peerClose()
		} else if !r.Flag {
			s.notify(protocol.SocketClose{SocketID: r.SocketID, Flag: true}.Frame())
		}
		return nil
	case protocol.TypeSocketReadClose:
		r, err := protocol.ParseSocketReadClose(f)
		if err != nil {
			return err
		}
		if stream := s.lookup(r.SocketID); stream != nil {
			stream.peerReadClose()
		}
		return nil
	case protocol.TypeSocketBuffer:
		r, err := protocol.ParseSocketBuffer(f)
		if err != nil {
			return err
		}
		if stream := s.lookup(r.SocketID); stream != nil {
			stream.peerBuffer(r.Value64, r.Flag)
		}
		return nil
	case protocol.TypeData:
		r, err := protocol.ParseDataChunk(f)
		if err != nil {
			return err
		}
		if stream := s.lookup(r.SocketID); stream != nil {
			return stream.receive(r)
		}
		return nil
	case protocol.TypeApp:
		r, err := protocol.ParseAppMessage(f)
		if err != nil {
			return err
		}
		select {
		case s.app <- r:
			return nil
		default:
			return fmt.Errorf("%w: app-message queue", ErrBufferLimit)
		}
	case protocol.TypeUDP:
		r, err := protocol.ParseUDPFrame(f)
		if err != nil {
			return err
		}
		select {
		case s.udp <- r:
		default:
			s.droppedUDP.Add(1)
		}
		return nil
	default:
		return fmt.Errorf("%w: session message %d", protocol.ErrUnsupported, f.Type)
	}
}

func (s *Session) Open(ctx context.Context, host string, port uint16) (*Stream, error) {
	if ctx == nil {
		return nil, errors.New("session: nil context")
	}
	if s.server {
		return nil, errors.New("session: server-initiated opens are not enabled")
	}
	if port == 0 {
		return nil, protocol.ErrMalformed
	}
	a, err := protocol.NewAddress(host, port)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.err != nil {
		err := s.err
		s.mu.Unlock()
		return nil, err
	}
	if len(s.streams) >= s.options.MaxFlows || (s.allocateID == nil && s.nextID == 0) {
		s.mu.Unlock()
		return nil, ErrFlowLimit
	}
	id := s.nextID
	if s.allocateID != nil {
		id, err = s.allocateID()
		if err != nil {
			s.mu.Unlock()
			return nil, err
		}
		if id == 0 || id <= s.lastAllocatedID || s.streams[id] != nil {
			s.mu.Unlock()
			return nil, errors.New("session: socket allocator returned zero, duplicate, or non-increasing ID")
		}
		s.lastAllocatedID = id
	} else {
		s.nextID++
	}
	stream := newStream(s, id, 0, a, false)
	s.streams[id] = stream
	s.mu.Unlock()
	if err = s.send(ctx, protocol.SocketConnect{SocketID: id, Address: &a}.Frame()); err != nil {
		stream.fail(err)
		s.remove(id, stream)
		return nil, err
	}
	select {
	case <-stream.opened:
		stream.mu.Lock()
		err = stream.openErr
		stream.mu.Unlock()
		if err != nil {
			_ = stream.Close()
			return nil, err
		}
		return stream, nil
	case <-ctx.Done():
		_ = stream.Close()
		return nil, ctx.Err()
	case <-s.done:
		return nil, s.Err()
	}
}

func (s *Session) Accept(ctx context.Context) (*Stream, error) {
	if ctx == nil {
		return nil, errors.New("session: nil context")
	}
	if !s.server {
		return nil, errors.New("session: only servers accept flows")
	}
	for {
		select {
		case stream := <-s.incoming:
			stream.mu.Lock()
			alive := stream.state == 2 && !stream.localClosed
			stream.mu.Unlock()
			if alive {
				return stream, nil
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.done:
			return nil, s.Err()
		}
	}
}
func (s *Session) SendUDP(ctx context.Context, u protocol.UDPEnvelope) error {
	f, err := u.Frame()
	if err != nil {
		return err
	}
	return s.send(ctx, f)
}
func (s *Session) ReceiveUDP(ctx context.Context) (protocol.UDPEnvelope, error) {
	if ctx == nil {
		return protocol.UDPEnvelope{}, errors.New("session: nil context")
	}
	select {
	case u := <-s.udp:
		return u, nil
	case <-ctx.Done():
		return protocol.UDPEnvelope{}, ctx.Err()
	case <-s.done:
		return protocol.UDPEnvelope{}, s.Err()
	}
}

// SendApp sends the native type25 application-control envelope. Application
// semantics (reachability, path statistics, ads state) belong to the owner.
func (s *Session) SendApp(ctx context.Context, message protocol.AppMessage) error {
	f, err := message.Frame()
	if err != nil {
		return err
	}
	return s.send(ctx, f)
}

func (s *Session) ReceiveApp(ctx context.Context) (protocol.AppMessage, error) {
	if ctx == nil {
		return protocol.AppMessage{}, errors.New("session: nil context")
	}
	select {
	case m := <-s.app:
		return m, nil
	case <-ctx.Done():
		return protocol.AppMessage{}, ctx.Err()
	case <-s.done:
		return protocol.AppMessage{}, s.Err()
	}
}
