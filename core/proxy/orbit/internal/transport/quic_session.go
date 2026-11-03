package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/proxy/orbit/internal/guard"
	"github.com/xtls/xray-core/proxy/orbit/internal/protocol"

	quic "github.com/quic-go/quic-go"
)

// UDPTooLargeError distinguishes the codec limit from the current QUIC path
// limit. The native sender also rejects a datagram exceeding its current MSS;
// it does not introduce application-level fragmentation.
type UDPTooLargeError struct {
	PayloadSize, MaxPayloadSize int
	cause                       error
}

func (e *UDPTooLargeError) Error() string {
	return fmt.Sprintf("transport: UDP payload %d exceeds current QUIC maximum %d", e.PayloadSize, e.MaxPayloadSize)
}
func (e *UDPTooLargeError) Unwrap() error { return e.cause }

// MaxUDPPayloadSize is the conservative configured-path ceiling, including
// the native envelope. It does not claim the larger codec ceiling is routable.
func (s *QUICSession) MaxUDPPayloadSize() int {
	return maxQUICDatagramPayload - protocol.UDPHeaderSize - protocol.HeaderSize
}

const (
	typeUDPControl      byte = 12
	typeUDPControlReady byte = 13
)

type quicLogical struct {
	server         bool
	accept         chan *QUICStream
	udp            chan protocol.UDPEnvelope
	app            chan protocol.AppMessage
	ready          chan struct{}
	readyOnce      sync.Once
	mu             sync.Mutex
	control        *QUICStream
	controlWrite   chan struct{}
	nextID         atomic.Uint32
	dropped        atomic.Uint64
	heartbeatTicks atomic.Uint32
	ids            map[uint32]bool
	handshakes     chan struct{}
	// flows counts the client's own open flows, capped at the server's
	// per-session MaxFlows (the TCP session's ErrFlowLimit rule).
	flows atomic.Int32
	// ackWait is closed by the next heartbeat acknowledgement (Probe).
	ackMu   sync.Mutex
	ackWait chan struct{}
	period  time.Duration
}

// ErrFlowLimit is the QUIC twin of the TCP session's flow limit: the server
// grants MaxFlows streams per session plus the UDP-control stream, and an
// open beyond that would block in OpenStreamSync until a flow ends. Failing
// that one open at once, as the TCP session does, keeps the other flows and
// the session untouched.
var ErrFlowLimit = errors.New("transport: flow limit reached")

// heartbeatPeriod is the native heartbeat timer's period. A client session
// copies it when it starts; a test shortens it.
var heartbeatPeriod = time.Second

func (q *quicLogical) nextAck() <-chan struct{} {
	q.ackMu.Lock()
	defer q.ackMu.Unlock()
	if q.ackWait == nil {
		q.ackWait = make(chan struct{})
	}
	return q.ackWait
}

func (q *quicLogical) acked() {
	q.ackMu.Lock()
	if q.ackWait != nil {
		close(q.ackWait)
		q.ackWait = nil
	}
	q.ackMu.Unlock()
}

func (s *QUICSession) startLogical(server bool) error {
	u, err := protocol.DecodeUserInfo(s.Metadata.UserInfo[:])
	if err != nil {
		return err
	}
	s.user = u
	options := s.serverOptions.defaults()
	s.logical = &quicLogical{server: server, accept: make(chan *QUICStream, options.MaxFlows), udp: make(chan protocol.UDPEnvelope, 128), app: make(chan protocol.AppMessage, 128), controlWrite: make(chan struct{}, 1), ready: make(chan struct{}), ids: make(map[uint32]bool), handshakes: make(chan struct{}, options.MaxHandshakes)}
	if !server {
		s.logical.period = heartbeatPeriod
	}
	fail := func() { s.Close() }
	guard.Go(s.acceptLogicalStreams, fail)
	guard.Go(s.receiveLogicalDatagrams, fail)
	if !server {
		guard.Go(s.startUDPControl, fail)
	}
	return nil
}

func (s *QUICSession) User() protocol.UserInfo { return s.user }
func (s *QUICSession) ChannelID() [16]byte     { return s.Metadata.ChannelID }
func (s *QUICSession) ConnectionID() uint32    { return s.Metadata.ConnectionID }
func (s *QUICSession) RouteMetadata() []byte   { return append([]byte(nil), s.Metadata.ProxyBuffer...) }
func (s *QUICSession) Done() <-chan struct{}   { return s.connection.Context().Done() }
func (s *QUICSession) Err() error              { return context.Cause(s.connection.Context()) }
func (s *QUICSession) DroppedUDP() uint64      { return s.logical.dropped.Load() }
func (s *QUICSession) BufferedBytes() int64    { return 0 } // quic-go manages receive flow control internally.

func (s *QUICSession) waitReady(ctx context.Context) error {
	select {
	case <-s.logical.ready:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-s.Done():
		return s.Err()
	}
}

func (s *QUICSession) Open(ctx context.Context, host string, port uint16) (*QUICStream, error) {
	if s.logical.server {
		return nil, errors.New("transport: server-initiated sockets are not enabled")
	}
	if port == 0 {
		return nil, protocol.ErrMalformed
	}
	a, err := protocol.NewAddress(host, port)
	if err != nil {
		return nil, err
	}
	if int(s.logical.flows.Add(1)) > s.serverOptions.defaults().MaxFlows {
		s.logical.flows.Add(-1)
		return nil, ErrFlowLimit
	}
	release := sync.OnceFunc(func() { s.logical.flows.Add(-1) })
	if err = s.waitReady(ctx); err != nil {
		release()
		return nil, err
	}
	st, err := s.OpenStream(ctx)
	if err != nil {
		release()
		return nil, err
	}
	st.release = release
	var id uint32
	if s.allocateSocketID != nil {
		id, err = s.allocateSocketID()
		if err != nil {
			st.Reset()
			return nil, err
		}
	} else {
		id = s.logical.nextID.Add(1)
	}
	if id == 0 {
		st.Reset()
		s.Close()
		return nil, errors.New("transport: socket ID exhausted")
	}
	st.socketID = id
	st.destination = a
	finish, err := handshakeLifetime(ctx, st, 15*time.Second)
	if err != nil {
		st.Reset()
		return nil, err
	}
	err = protocol.WriteFrame(st, protocol.SocketConnect{SocketID: id, Address: &a}.Frame())
	if err == nil {
		var f protocol.Frame
		f, err = protocol.ReadFrame(st)
		if err == nil {
			var response protocol.SocketConnectResponse
			response, err = protocol.ParseSocketConnectResponse(f)
			// Metadata is echoed peer metadata, not a success/error status.
			if err == nil && response.SocketID != id {
				err = protocol.ErrMalformed
			}
		}
	}
	if e := finish(err == nil); e != nil {
		err = e
	}
	if err != nil {
		st.Reset()
		return nil, err
	}
	st.decided = true
	return st, nil
}

func (s *QUICSession) Accept(ctx context.Context) (*QUICStream, error) {
	select {
	case st := <-s.logical.accept:
		return st, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.Done():
		return nil, s.Err()
	}
}
func (s *QUICStream) Destination() protocol.Address { return s.destination }
func (s *QUICStream) SocketID() uint32              { return s.socketID }
func (s *QUICStream) Accept() error {
	s.decisionMu.Lock()
	defer s.decisionMu.Unlock()
	if s.decided {
		return errors.New("transport: socket decision already made")
	}
	s.decided = true
	err := protocol.WriteFrame(s, protocol.SocketConnectResponse{SocketID: s.socketID, Metadata: s.metadata}.Frame())
	if err == nil {
		err = s.SetDeadline(time.Time{})
	}
	if err != nil {
		s.Reset()
	}
	return err
}
func (s *QUICStream) Reject() error {
	s.decisionMu.Lock()
	defer s.decisionMu.Unlock()
	s.decided = true
	s.Reset()
	return nil
}

func (s *QUICSession) acceptLogicalStreams() {
	for {
		st, err := s.AcceptStream(s.Context())
		if err != nil {
			return
		}
		select {
		case s.logical.handshakes <- struct{}{}:
			guard.Go(func() { defer func() { <-s.logical.handshakes }(); s.acceptLogicalStream(st) }, func() { s.Close() })
		default:
			st.Reset()
		}
	}
}
func (s *QUICSession) acceptLogicalStream(st *QUICStream) {
	_ = st.SetDeadline(time.Now().Add(s.serverOptions.defaults().HandshakeTimeout))
	f, err := protocol.ReadFrame(st)
	if err != nil {
		st.Reset()
		return
	}
	if f.Type == typeUDPControl && s.logical.server && f.Flags == 0 && len(f.Payload) == 0 {
		s.logical.mu.Lock()
		exists := s.logical.control != nil
		if !exists {
			s.logical.control = st
		}
		s.logical.mu.Unlock()
		if exists {
			st.Reset()
			return
		}
		if err = protocol.WriteFrame(st, protocol.Frame{Type: typeUDPControlReady}); err != nil {
			s.Close()
			return
		}
		_ = st.SetDeadline(time.Time{})
		s.logical.readyOnce.Do(func() { close(s.logical.ready) })
		guard.Go(func() { s.controlLoop(st) }, func() { s.Close() })
		return
	}
	if !s.logical.server {
		st.Reset()
		return
	}
	c, err := protocol.ParseSocketConnect(f)
	if err != nil || c.Address == nil || c.SocketID == 0 {
		st.Reset()
		return
	}
	if _, err = c.Address.Host(); err != nil || c.Address.Port == 0 {
		st.Reset()
		return
	}
	s.logical.mu.Lock()
	duplicate := s.logical.ids[c.SocketID]
	if !duplicate && len(s.logical.ids) < s.serverOptions.defaults().MaxFlows {
		s.logical.ids[c.SocketID] = true
	} else {
		duplicate = true
	}
	s.logical.mu.Unlock()
	if duplicate {
		st.Reset()
		return
	}
	st.socketID = c.SocketID
	st.metadata = c.Metadata
	st.release = func() { s.logical.mu.Lock(); delete(s.logical.ids, c.SocketID); s.logical.mu.Unlock() }
	st.destination = *c.Address
	select {
	case s.logical.accept <- st:
	case <-s.Done():
		st.Reset()
	default:
		st.Reset()
	}
}

func (s *QUICSession) startUDPControl() {
	st, err := s.OpenStream(s.Context())
	if err != nil {
		s.Close()
		return
	}
	// Native vl_xqc_stream::start starts a 5000ms one-shot timer for the
	// type12/type13 control exchange, independent of the QUIC TLS handshake.
	_ = st.SetDeadline(time.Now().Add(5 * time.Second))
	if err = protocol.WriteFrame(st, protocol.Frame{Type: typeUDPControl}); err != nil {
		s.Close()
		return
	}
	f, err := protocol.ReadFrame(st)
	if err != nil || f.Type != typeUDPControlReady || f.Flags != 0 || len(f.Payload) != 0 {
		s.Close()
		return
	}
	_ = st.SetDeadline(time.Time{})
	s.logical.mu.Lock()
	s.logical.control = st
	s.logical.mu.Unlock()
	s.logical.heartbeatTicks.Store(0)
	s.logical.readyOnce.Do(func() { close(s.logical.ready) })
	guard.Go(func() { s.heartbeatLoop(st) }, func() { s.Close() })
	s.controlLoop(st)
}

func (s *QUICSession) writeControl(st *QUICStream, f protocol.Frame) error {
	return s.writeControlContext(s.Context(), st, f)
}
func (s *QUICSession) writeControlContext(ctx context.Context, st *QUICStream, f protocol.Frame) error {
	select {
	case s.logical.controlWrite <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	case <-s.Done():
		return s.Err()
	}
	defer func() { <-s.logical.controlWrite }()
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = st.SetWriteDeadline(deadline)
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = st.SetWriteDeadline(time.Now()); close(interrupted) })
	err := protocol.WriteFrame(st, f)
	if !stop() {
		<-interrupted
	}
	_ = st.SetWriteDeadline(time.Time{})
	if err != nil {
		s.Close()
	}
	return err
}
func (s *QUICSession) controlLoop(st *QUICStream) {
	for {
		f, err := protocol.ReadFrame(st)
		if err != nil {
			s.Close()
			return
		}
		switch f.Type {
		case protocol.TypeApp:
			m, err := protocol.ParseAppMessage(f)
			if err != nil {
				s.Close()
				return
			}
			select {
			case s.logical.app <- m:
			case <-s.Done():
				return
			default:
				s.Close()
				return
			}
		case protocol.TypeHeartbeat:
			if len(f.Payload) != 0 {
				s.Close()
				return
			}
			if f.Flags&1 != 0 {
				// Only an acknowledgement resets the native heartbeat counter.
				// A peer's own request must not mask a missing acknowledgement.
				s.logical.heartbeatTicks.Store(0)
				s.logical.acked()
			} else {
				if err = s.writeControl(st, protocol.Frame{Type: protocol.TypeHeartbeat, Flags: 1}); err != nil {
					s.Close()
					return
				}
			}
		case protocol.TypeLeave, protocol.TypeKickOut:
			s.Close()
			return
		default:
			// Reference app/control extensions are not application stream bytes.
			// Ignore bounded unknown controls as the native switch does.
		}
	}
}
func (s *QUICSession) heartbeatLoop(st *QUICStream) {
	t := time.NewTicker(s.logical.period)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			ping, expired := s.logical.heartbeatTick()
			if expired {
				s.Close()
				return
			}
			if ping {
				if err := s.writeControl(st, protocol.Frame{Type: protocol.TypeHeartbeat}); err != nil {
					s.Close()
					return
				}
			}
		case <-s.Done():
			return
		}
	}
}

// Probe asks the server for a heartbeat acknowledgement on the UDP-control
// stream and waits for it: proof that the session's path still carries
// packets both ways. A flow open that is slow to answer proves nothing about
// the session (the destination may be slow); a probe that gets no answer does.
func (s *QUICSession) Probe(ctx context.Context) error {
	if err := s.waitReady(ctx); err != nil {
		return err
	}
	s.logical.mu.Lock()
	st := s.logical.control
	s.logical.mu.Unlock()
	if st == nil {
		return errors.New("transport: no UDP-control stream to probe")
	}
	ack := s.logical.nextAck()
	if err := s.writeControlContext(ctx, st, protocol.Frame{Type: protocol.TypeHeartbeat}); err != nil {
		return err
	}
	select {
	case <-ack:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-s.Done():
		return s.Err()
	}
}

// The native timer counts callbacks, not elapsed wall time. Coalescing missed
// ticks after a suspended app must not immediately expire a healthy connection.
// Atomic Add/Store linearize ticks and received ACKs without losing a reset.
func (q *quicLogical) heartbeatTick() (ping, expired bool) {
	tick := q.heartbeatTicks.Add(1)
	return tick == 30, tick >= 38
}

func (s *QUICSession) SendUDP(ctx context.Context, u protocol.UDPEnvelope) error {
	if err := s.waitReady(ctx); err != nil {
		return err
	}
	f, err := u.Frame()
	if err != nil {
		return err
	}
	b, err := f.MarshalBinary()
	if err != nil {
		return err
	}
	err = s.SendDatagram(b)
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(err, &tooLarge) {
		return &UDPTooLargeError{PayloadSize: len(u.Data), MaxPayloadSize: max(0, int(tooLarge.MaxDatagramPayloadSize)-(len(b)-len(u.Data))), cause: err}
	}
	return err
}
func (s *QUICSession) ReceiveUDP(ctx context.Context) (protocol.UDPEnvelope, error) {
	select {
	case u := <-s.logical.udp:
		return u, nil
	case <-ctx.Done():
		return protocol.UDPEnvelope{}, ctx.Err()
	case <-s.Done():
		return protocol.UDPEnvelope{}, s.Err()
	}
}
func (s *QUICSession) receiveLogicalDatagrams() {
	for {
		b, err := s.ReceiveDatagram(s.Context())
		if err != nil {
			return
		}
		f, err := protocol.ParseFrame(b)
		if err != nil {
			s.logical.dropped.Add(1)
			continue
		}
		if f.Type == protocol.TypeApp {
			m, err := protocol.ParseAppMessage(f)
			if err != nil {
				s.logical.dropped.Add(1)
				continue
			}
			select {
			case s.logical.app <- m:
			case <-s.Done():
				return
			default:
				s.logical.dropped.Add(1)
			}
			continue
		}
		if f.Type != protocol.TypeUDP {
			continue
		}
		u, err := protocol.ParseUDPFrame(f)
		if err != nil {
			s.logical.dropped.Add(1)
			continue
		}
		select {
		case s.logical.udp <- u:
		case <-s.Done():
			return
		default:
			s.logical.dropped.Add(1)
		}
	}
}

// SendApp follows send_app_msg: use the existing ready UDP-control stream, or
// a QUIC datagram while that stream is not ready. It creates no extra stream.
func (s *QUICSession) SendApp(ctx context.Context, m protocol.AppMessage) error {
	if ctx == nil {
		return errors.New("transport: nil context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	f, err := m.Frame()
	if err != nil {
		return err
	}
	select {
	case <-s.logical.ready:
		s.logical.mu.Lock()
		st := s.logical.control
		s.logical.mu.Unlock()
		if st != nil {
			return s.writeControlContext(ctx, st, f)
		}
	default:
	}
	b, err := f.MarshalBinary()
	if err != nil {
		return err
	}
	return s.SendDatagram(b)
}

func (s *QUICSession) ReceiveApp(ctx context.Context) (protocol.AppMessage, error) {
	if ctx == nil {
		return protocol.AppMessage{}, errors.New("transport: nil context")
	}
	select {
	case m := <-s.logical.app:
		return m, nil
	case <-ctx.Done():
		return protocol.AppMessage{}, ctx.Err()
	case <-s.Done():
		return protocol.AppMessage{}, s.Err()
	}
}

var _ io.ReadWriteCloser = (*QUICStream)(nil)
