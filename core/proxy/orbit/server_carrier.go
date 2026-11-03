package orbit

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xprotocol "github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/nativebridge"
	"github.com/xtls/xray-core/proxy/orbit/internal/protocol"
	otransport "github.com/xtls/xray-core/proxy/orbit/internal/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type closeWriteConn struct {
	net.Conn
	writer interface{ CloseWrite() error }
}

func (c closeWriteConn) CloseWrite() error { return c.writer.CloseWrite() }
func realityHalfClose(c net.Conn) net.Conn {
	if _, ok := c.(interface{ CloseWrite() error }); ok {
		return c
	}
	if w, ok := stat.TryUnwrapStatsConn(c).(interface{ CloseWrite() error }); ok {
		return closeWriteConn{c, w}
	}
	return c
}

// hijackWriter exposes exactly this accepted connection to gorilla's upgrade.
// No auxiliary listener or HTTP server is opened.
type hijackWriter struct {
	conn   net.Conn
	rw     *bufio.ReadWriter
	header http.Header
	status int
}

func (w *hijackWriter) Header() http.Header                          { return w.header }
func (w *hijackWriter) WriteHeader(status int)                       { w.status = status }
func (w *hijackWriter) Write(b []byte) (int, error)                  { return w.rw.Write(b) }
func (w *hijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) { return w.conn, w.rw, nil }

func (s *Server) acceptWebSocket(ctx context.Context, raw net.Conn) (net.Conn, error) {
	deadline := time.Now().Add(time.Duration(s.cfg.HandshakeTimeout) * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := raw.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if s.outerTLS != nil {
		secure := tls.Server(raw, s.outerTLS)
		if err := secure.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		raw = secure
	}
	// Read the bounded header a byte at a time into a buffered reader. Retaining
	// that reader is essential when the first WebSocket frame is coalesced.
	r := bufio.NewReaderSize(raw, 8192)
	header := make([]byte, 0, 1024)
	for len(header) < 8192 {
		b, e := r.ReadByte()
		if e != nil {
			return nil, e
		}
		header = append(header, b)
		if len(header) >= 4 && string(header[len(header)-4:]) == "\r\n\r\n" {
			break
		}
	}
	if !strings.HasSuffix(string(header), "\r\n\r\n") {
		return nil, errors.New("orbit: WebSocket header exceeds limit")
	}
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(string(header))))
	if err != nil {
		return nil, errors.New("orbit: invalid WebSocket request")
	}
	defer req.Body.Close()
	host := req.Host
	if h, p, e := net.SplitHostPort(host); e == nil {
		if p != "80" && p != "443" {
			return nil, errors.New("orbit: WebSocket host mismatch")
		}
		host = h
	}
	if req.Method != "GET" || req.URL.Path != s.cfg.Path || req.URL.RawPath != "" || req.URL.RawQuery != "" || !strings.EqualFold(host, s.cfg.Host) || req.ContentLength > 0 || len(req.TransferEncoding) != 0 {
		return nil, errors.New("orbit: WebSocket route mismatch")
	}
	w := &hijackWriter{conn: raw, rw: bufio.NewReadWriter(r, bufio.NewWriter(raw)), header: make(http.Header)}
	ws, err := otransport.AcceptWebSocket(ctx, w, req)
	if err != nil {
		return nil, err
	}
	if err = raw.SetDeadline(time.Time{}); err != nil {
		ws.Close()
		return nil, err
	}
	return ws, nil
}

// workerPacketConn converts the Xray UDP worker's packet-preserving buf.Reader
// to the net.PacketConn interface quic-go needs. A small bounded reader queue
// supplies actual deadlines even though UDP worker deadlines are no-ops.
type workerPacketConn struct {
	raw      net.Conn
	packets  chan []byte
	done     chan struct{}
	readDone chan struct{}
	once     sync.Once
	mu       sync.Mutex
	deadline time.Time
	changed  chan struct{}
}

func newWorkerPacketConn(raw net.Conn) *workerPacketConn {
	p := &workerPacketConn{raw: raw, packets: make(chan []byte, 64), done: make(chan struct{}), readDone: make(chan struct{}), changed: make(chan struct{})}
	go func() {
		defer close(p.readDone)
		defer close(p.packets)
		defer nativebridge.RecoverWorker(func(error) {})
		r := buf.NewReader(raw)
		for {
			mb, err := r.ReadMultiBuffer()
			for _, b := range mb {
				data := append([]byte(nil), b.Bytes()...)
				select {
				case p.packets <- data:
				case <-p.done:
					buf.ReleaseMulti(mb)
					return
				}
			}
			buf.ReleaseMulti(mb)
			if err != nil {
				return
			}
		}
	}()
	return p
}
func (p *workerPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		p.mu.Lock()
		deadline, changed := p.deadline, p.changed
		p.mu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			if !time.Now().Before(deadline) {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		select {
		case data, ok := <-p.packets:
			if timer != nil {
				timer.Stop()
			}
			if !ok {
				return 0, nil, net.ErrClosed
			}
			if len(data) > len(b) {
				return 0, nil, io.ErrShortBuffer
			}
			return copy(b, data), p.raw.RemoteAddr(), nil
		case <-p.done:
			if timer != nil {
				timer.Stop()
			}
			return 0, nil, net.ErrClosed
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
			continue
		case <-timeout:
			return 0, nil, os.ErrDeadlineExceeded
		}
	}
}
func (p *workerPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if addr == nil || addr.String() != p.raw.RemoteAddr().String() {
		return 0, errors.New("orbit: QUIC peer address mismatch")
	}
	return p.raw.Write(b)
}
func (p *workerPacketConn) Close() error {
	var err error
	p.once.Do(func() { close(p.done); err = p.raw.Close(); <-p.readDone })
	return err
}
func (p *workerPacketConn) LocalAddr() net.Addr { return p.raw.LocalAddr() }
func (p *workerPacketConn) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	p.deadline = t
	close(p.changed)
	p.changed = make(chan struct{})
	p.mu.Unlock()
	return nil
}
func (p *workerPacketConn) SetWriteDeadline(t time.Time) error { return p.raw.SetWriteDeadline(t) }
func (p *workerPacketConn) SetDeadline(t time.Time) error {
	_ = p.SetReadDeadline(t)
	return p.SetWriteDeadline(t)
}

func (s *Server) processQUIC(ctx context.Context, conn net.Conn, run *serverRun, d routing.Dispatcher) error {
	raw := newWorkerPacketConn(conn)
	defer raw.Close()
	var authMu sync.Mutex
	var authenticated *xprotocol.MemoryUser
	listener, err := otransport.ListenQUICWithOptions(raw, s.tls, func(m otransport.QUICMetadata, _ net.Addr) error {
		if !terminalMetadata(m.ProxyBuffer) {
			return errors.New("orbit: relay metadata is not allowed")
		}
		u, e := protocol.DecodeUserInfo(m.UserInfo[:])
		if e != nil {
			return e
		}
		user, e := s.authorize(u)
		if e != nil {
			return e
		}
		authMu.Lock()
		defer authMu.Unlock()
		if authenticated != nil && authenticated != user {
			return errors.New("orbit: account generation changed during handshake")
		}
		authenticated = user
		return nil
	}, otransport.QUICServerOptions{MaxSessions: 1, MaxHandshakes: min(64, int(s.cfg.MaxFlows)+1), MaxFlows: int(s.cfg.MaxFlows), HandshakeTimeout: time.Duration(s.cfg.HandshakeTimeout) * time.Second})
	if err != nil {
		return err
	}
	defer listener.Close()
	hctx, cancel := context.WithTimeout(ctx, time.Duration(s.cfg.HandshakeTimeout)*time.Second)
	p, err := listener.Accept(hctx)
	cancel()
	if err != nil {
		return err
	}
	defer p.Close()
	authMu.Lock()
	user := authenticated
	authMu.Unlock()
	return s.servePeer(ctx, serverQUICPeer{p}, run, user, d)
}
