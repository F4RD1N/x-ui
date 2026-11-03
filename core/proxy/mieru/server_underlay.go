package mieru

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/nativebridge"
)

// A standard client can multiplex reliable sessions over one underlay. Only
// this loop reads/decrypts underlay records; every session owns its sequence,
// congestion, application destination and cancellation state.
func (s *Server) serveUnderlay(ctx context.Context, w *wire, first segment, user *protocol.MemoryUser, dispatcher routing.Dispatcher) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = w.conn.Close() })
	defer stop()
	idle := signal.CancelAfterInactivity(ctx, cancel, s.underlayIdle)
	w.activity = idle
	defer idle.SetTimeout(0)
	sessions := map[uint32]*inboundSession{}
	seen := map[uint32]struct{}{}
	var wg sync.WaitGroup
	budget := new(atomic.Int64)
	defer func() {
		cancel()
		_ = w.conn.Close()
		for _, entry := range sessions {
			entry.close()
		}
		wg.Wait()
	}()
	deliver := func(seg segment) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		for sid, entry := range sessions {
			select {
			case <-entry.done:
				delete(sessions, sid)
			default:
			}
		}
		entry := sessions[seg.session]
		if entry == nil {
			if seg.kind != openRequest || seg.session == 0 {
				return nil
			}
			if _, used := seen[seg.session]; used {
				return nil
			}
			if len(sessions) >= 128 || len(seen) >= 4096 {
				return errors.New("Mieru underlay session limit reached")
			}
			seen[seg.session] = struct{}{}
			sessionCtx, sessionCancel := context.WithCancel(ctx)
			sessionCtx = privateRouteContext(sessionCtx)

			entry = &inboundSession{parent: w.conn, done: make(chan struct{}), incoming: make(chan segment, 256), cancel: sessionCancel, budget: budget}
			childWire := &wire{conn: entry, username: w.username, password: w.password, udp: w.udp, custom: w.custom, server: true, parent: w, incoming: entry.incoming, sessionDone: entry.done, dequeue: entry.dequeue}
			childWire.lastWrite.Store(monoNow())
			conn, err := acceptSession(childWire, seg)
			if err != nil {
				entry.close()
				return err
			}
			entry.conn = conn
			sessions[seg.session] = entry
			wg.Add(1)
			go func(entry *inboundSession, sessionCtx context.Context) {
				defer wg.Done()
				defer entry.close()
				defer nativebridge.RecoverWorker(func(error) { entry.close() })
				_ = s.serveSession(sessionCtx, entry.conn, user, dispatcher)
				_ = entry.conn.Close()
			}(entry, sessionCtx)
			return nil
		}
		// A slow stream cannot consume unbounded per-session or underlay
		// payload bytes. UDP overflow is recovered by its reliable transport.
		if !entry.enqueue(seg) && !w.udp {
			entry.conn.abort(errors.New("Mieru session receive queue exhausted"))
		}

		return nil
	}
	if err := deliver(first); err != nil {
		return err
	}
	for {
		seg, err := w.read()
		if err != nil {
			return err
		}
		idle.Update()
		if err = deliver(seg); err != nil {
			return err
		}
	}
}

type inboundSession struct {
	parent   net.Conn
	done     chan struct{}
	incoming chan segment
	cancel   context.CancelFunc
	conn     *Conn
	once     sync.Once
	queueMu  sync.Mutex
	bytes    atomic.Int64
	budget   *atomic.Int64
}

const serverSessionPendingBytes = 256 << 10
const serverUnderlayPendingBytes = 2 << 20

func segmentCost(s segment) int64 { return int64(len(s.payload) + 64) }
func (s *inboundSession) dequeue(seg segment) {
	n := segmentCost(seg)
	s.bytes.Add(-n)
	s.budget.Add(-n)
}
func (s *inboundSession) enqueue(seg segment) bool {
	s.queueMu.Lock()
	defer s.queueMu.Unlock()
	select {
	case <-s.done:
		return false
	default:
	}
	n := segmentCost(seg)
	if s.bytes.Add(n) > serverSessionPendingBytes {
		s.bytes.Add(-n)
		return false
	}
	if s.budget.Add(n) > serverUnderlayPendingBytes {
		s.budget.Add(-n)
		s.bytes.Add(-n)
		return false
	}
	select {
	case s.incoming <- seg:
		return true
	default:
		s.dequeue(seg)
		return false
	}
}
func (s *inboundSession) close() {
	s.once.Do(func() {
		s.queueMu.Lock()
		defer s.queueMu.Unlock()
		close(s.done)
		s.cancel()
		for {
			select {
			case seg := <-s.incoming:
				s.dequeue(seg)
			default:
				return
			}
		}
	})
}
func (s *inboundSession) Close() error              { s.close(); return nil }
func (s *inboundSession) Read([]byte) (int, error)  { return 0, io.ErrClosedPipe }
func (s *inboundSession) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (s *inboundSession) LocalAddr() net.Addr       { return s.parent.LocalAddr() }
func (s *inboundSession) RemoteAddr() net.Addr      { return s.parent.RemoteAddr() }

// Deadlines belong to individual reliable sessions, not the shared underlay.
func (s *inboundSession) SetDeadline(time.Time) error      { return nil }
func (s *inboundSession) SetReadDeadline(time.Time) error  { return nil }
func (s *inboundSession) SetWriteDeadline(time.Time) error { return nil }

// Dispatcher/sniffer state is mutable. Keep each multiplexed session and UDP
// destination independent while retaining the inbound tag and authenticated user.
func privateRouteContext(ctx context.Context) context.Context {
	if in := session.InboundFromContext(ctx); in != nil {
		copied := *in
		if in.User != nil {
			copied.User = cloneMemoryUser(in.User)
		}
		ctx = session.ContextWithInbound(ctx, &copied)
	}
	content := new(session.Content)
	if old := session.ContentFromContext(ctx); old != nil {
		*content = *old
		if old.Attributes != nil {
			content.Attributes = make(map[string]string, len(old.Attributes))
			for k, v := range old.Attributes {
				content.Attributes[k] = v
			}
		}
	}
	ctx = session.ContextWithContent(ctx, content)
	oldOutbounds := session.OutboundsFromContext(ctx)
	copied := make([]*session.Outbound, len(oldOutbounds))
	for i, ob := range oldOutbounds {
		if ob != nil {
			value := *ob
			copied[i] = &value
		} else {
			copied[i] = new(session.Outbound)
		}
	}
	if len(copied) == 0 {
		copied = []*session.Outbound{{}}
	}
	return session.ContextWithOutbounds(ctx, copied)
}
