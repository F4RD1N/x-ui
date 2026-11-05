package dnstt

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/nativebridge"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/proxy/vless"
	vencoding "github.com/xtls/xray-core/proxy/vless/encoding"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/noise"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, value interface{}) (out interface{}, err error) {
		defer nativebridge.Recover(&err, nil)
		return NewServer(ctx, value.(*ServerConfig))
	}))
}

type serverResponse struct {
	message *dns.Message
	writer  net.Conn
	peer    *serverPeer
}

// Server is a native authoritative DNS/KCP/Noise/smux inbound. Its inner proxy
// is an ordinary Xray handler with no socket or external process of its own.
type Server struct {
	cfg            *ServerConfig
	domain         dns.Name
	key            []byte
	inner          proxy.Inbound
	socksOnly      bool
	ctx            context.Context
	cancel         context.CancelFunc
	mu             sync.Mutex
	closed         bool
	started        bool
	queue          *authorityQueue
	listener       *kcp.Listener
	responses      chan *serverResponse
	pendingStreams chan struct{}
	associations   map[net.Conn]struct{}
	sessions       map[*kcp.UDPSession]*serverPeer
	wg             sync.WaitGroup
	closeOnce      sync.Once
}

func NewServer(ctx context.Context, input *ServerConfig) (*Server, error) {
	cfg, err := NormalizeServerConfig(input)
	if err != nil {
		return nil, err
	}
	value, err := cfg.Inner.GetInstance()
	if err != nil {
		return nil, err
	}
	// Existing SOCKS construction expects the inbound worker's cone setting.
	ctx = context.WithValue(ctx, "cone", false)
	object, err := common.CreateObject(ctx, value)
	if err != nil {
		return nil, err
	}
	inner, ok := object.(proxy.Inbound)
	if !ok {
		return nil, errors.New("dnstt: inner proxy is not an inbound")
	}
	domain, err := dns.ParseName(cfg.Domain)
	if err != nil {
		return nil, err
	}
	key, _ := hex.DecodeString(cfg.PrivateKey)
	_, socksOnly := value.(*socks.ServerConfig)
	life, cancel := context.WithCancel(context.Background())
	return &Server{cfg: cfg, domain: domain, key: key, inner: inner, socksOnly: socksOnly, ctx: life, cancel: cancel, responses: make(chan *serverResponse, 256), pendingStreams: make(chan struct{}, min(256, max(32, int(cfg.MaxSessions)*2))), associations: make(map[net.Conn]struct{}), sessions: make(map[*kcp.UDPSession]*serverPeer)}, nil
}

func (s *Server) Network() []xnet.Network { return []xnet.Network{xnet.Network_UDP} }

// start runs under mu; constructors remain passive and close cannot race a
// WaitGroup.Add on an otherwise empty instance.
func (s *Server) start(dispatcher routing.Dispatcher) error {
	if s.started {
		return nil
	}
	s.queue = newAuthorityQueue(s.ctx, int(s.cfg.MaxSessions))
	s.queue.pendingLifetime = time.Duration(s.cfg.HandshakeTimeout)*time.Second + 5*time.Second
	ln, err := kcp.ServeConn(nil, 0, 0, s.queue)
	if err != nil {
		_ = s.queue.Close()
		return err
	}
	s.listener = ln
	s.started = true
	context.AfterFunc(s.ctx, func() { _ = ln.Close(); _ = s.queue.Close() })
	s.wg.Add(3)
	go s.acceptSessions(dispatcher)
	go s.sendResponses()
	go s.expirePeers()
	return nil
}

func (s *Server) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) (err error) {
	defer nativebridge.Recover(&err, func() { _ = conn.Close() })
	if network != xnet.Network_UDP {
		return errors.New("dnstt: authoritative inbound requires UDP")
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	associationLimit := min(8192, max(64, int(s.cfg.MaxSessions)*32))
	if len(s.associations) >= associationLimit {
		s.mu.Unlock()
		return errors.New("dnstt: recursive source capacity reached")
	}
	if err = s.start(dispatcher); err != nil {
		s.mu.Unlock()
		return err
	}
	s.associations[conn] = struct{}{}
	s.wg.Add(1)
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.associations, conn); s.mu.Unlock(); s.wg.Done() }()
	stop := context.AfterFunc(s.ctx, func() { _ = conn.Close() })
	defer stop()
	stopFlow := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopFlow()
	// udpConn.Read intentionally panics in the Xray worker. It implements
	// buf.Reader, and each buffer below is one complete UDP datagram.
	idle := time.AfterFunc(3*time.Second, func() { _ = conn.Close() })
	defer idle.Stop()
	reader := buf.NewReader(stat.TryUnwrapStatsConn(conn))
	base := privateServerContext(context.WithoutCancel(ctx))
	for {
		mb, readErr := reader.ReadMultiBuffer()
		if len(mb) > 0 {
			idle.Reset(3 * time.Second)
		}
		for _, b := range mb {
			if b != nil && b.Len() <= 4096 {
				s.receive(b.Bytes(), conn, base)
			}
		}
		buf.ReleaseMulti(mb)
		if readErr != nil {
			return readErr
		}
		if err = s.ctx.Err(); err != nil {
			return err
		}
	}
}

func privateServerContext(ctx context.Context) context.Context {
	in := new(session.Inbound)
	if old := session.InboundFromContext(ctx); old != nil {
		*in = *old
	}
	in.Conn = nil
	in.Timer = nil
	in.User = nil
	in.CanSpliceCopy = 3
	ctx = session.ContextWithInbound(ctx, in)
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
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{}})
	return ctx
}

func (s *Server) receive(data []byte, conn net.Conn, ctx context.Context) {
	query, err := dns.MessageFromWireFormat(data)
	if err != nil {
		return
	}
	response, payload := responseFor(&query, s.domain, int(s.cfg.Mtu))
	if response == nil {
		return
	}
	record := &serverResponse{message: response, writer: conn}
	if response.Rcode() == dns.RcodeNoError {
		var id turbotunnel.ClientID
		if len(payload) < len(id) {
			response.Flags |= dns.RcodeNameError
		} else {
			copy(id[:], payload)
			payload = payload[len(id):]
			peer, evicted := s.queue.admit(id, ctx, conn.LocalAddr(), conn.RemoteAddr())
			if evicted != nil {
				s.closePeer(evicted)
			}
			if peer == nil {
				// SERVFAIL is an explicit bounded-capacity failure, not an empty
				// success that could be mistaken for a usable transport.
				response.Flags |= 2
			} else {
				record.peer = peer
				reader := bytes.NewReader(payload)
				for {
					packet, e := nextPacket(reader)
					if e != nil {
						break
					}
					if len(packet) > 0 {
						s.queue.queue(packet, id)
					}
				}
			}
		}
	}
	select {
	case <-s.ctx.Done():
	case s.responses <- record:
	default:
	}
}

func (s *Server) sendResponses() {
	defer s.wg.Done()
	defer nativebridge.RecoverWorker(func(error) { s.cancel() })
	budget := computeMaxEncodedPayload(int(s.cfg.Mtu))
	var next *serverResponse
	for {
		rec := next
		next = nil
		if rec == nil {
			select {
			case <-s.ctx.Done():
				return
			case rec = <-s.responses:
			}
		}
		if rec.peer != nil && rec.message.Rcode() == dns.RcodeNoError && len(rec.message.Question) == 1 {
			var payload bytes.Buffer
			timer := time.NewTimer(time.Second)
			collecting := true
			for collecting {
				var packet []byte
				select {
				case packet = <-rec.peer.stash:
				default:
					select {
					case packet = <-rec.peer.stash:
					case packet = <-rec.peer.outgoing:
					default:
						if payload.Len() != 0 {
							collecting = false
							break
						}
						select {
						case <-s.ctx.Done():
							timer.Stop()
							return
						case packet = <-rec.peer.stash:
						case packet = <-rec.peer.outgoing:
						case next = <-s.responses:
							collecting = false
						case <-timer.C:
							collecting = false
						}
					}
				}
				if len(packet) == 0 {
					continue
				}
				if len(packet)+2 > budget {
					continue
				} // impossible with admitted KCP MTU
				if payload.Len()+2+len(packet) > budget {
					select {
					case rec.peer.stash <- packet:
					default:
					}
					break
				}
				_ = binary.Write(&payload, binary.BigEndian, uint16(len(packet)))
				_, _ = payload.Write(packet)
			}
			timer.Stop()
			question := rec.message.Question[0]
			rec.message.Answer = []dns.RR{{Name: question.Name, Type: question.Type, Class: question.Class, TTL: responseTTL, Data: dns.EncodeRDataTXT(payload.Bytes())}}
		}
		wire, err := rec.message.WireFormat()
		if err != nil {
			continue
		}
		if len(wire) > int(s.cfg.Mtu) {
			// Return a syntactically valid truncated DNS message, never a sliced
			// resource record whose declared length exceeds the received packet.
			rec.message.Flags |= 0x0200
			rec.message.Answer = nil
			rec.message.Authority = nil
			wire, err = rec.message.WireFormat()
			if err != nil {
				continue
			}
			if len(wire) > int(s.cfg.Mtu) {
				rec.message.Question = nil
				rec.message.Additional = nil
				wire, err = rec.message.WireFormat()
			}
			if err != nil {
				continue
			}
		}
		// One stale recursive-source association must not stop other clients.
		_, _ = rec.writer.Write(wire)
	}
}

func (s *Server) acceptSessions(dispatcher routing.Dispatcher) {
	defer s.wg.Done()
	defer nativebridge.RecoverWorker(func(error) { s.cancel() })
	mtu := computeMaxEncodedPayload(int(s.cfg.Mtu)) - 2
	for {
		conn, err := s.listener.AcceptKCP()
		if err != nil {
			return
		}
		id, ok := conn.RemoteAddr().(turbotunnel.ClientID)
		var peer *serverPeer
		if ok {
			peer = s.queue.peer(id)
		}
		s.mu.Lock()
		if s.closed || s.ctx.Err() != nil || peer == nil || len(s.sessions) >= int(s.cfg.MaxSessions)+s.queue.pendingLimit {
			s.mu.Unlock()
			_ = conn.Close()
			continue
		}
		s.sessions[conn] = peer
		s.wg.Add(1)
		s.mu.Unlock()
		conn.SetStreamMode(true)
		conn.SetNoDelay(0, 0, 0, 1)
		conn.SetWindowSize(64, 64)
		if !conn.SetMtu(mtu) {
			_ = conn.Close()
			s.mu.Lock()
			delete(s.sessions, conn)
			s.mu.Unlock()
			s.wg.Done()
			continue
		}
		go s.serveSession(conn, peer, dispatcher)
	}
}

func (s *Server) serveSession(conn *kcp.UDPSession, peer *serverPeer, dispatcher routing.Dispatcher) {
	defer s.wg.Done()
	defer func() {
		_ = conn.Close()
		s.mu.Lock()
		delete(s.sessions, conn)
		stillActive := false
		for _, other := range s.sessions {
			if other == peer {
				stillActive = true
				break
			}
		}
		if !stillActive {
			s.queue.remove(peer)
		}
		s.mu.Unlock()
	}()
	defer nativebridge.RecoverWorker(func(error) { _ = conn.Close() })
	stop := context.AfterFunc(s.ctx, func() { _ = conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(time.Duration(s.cfg.HandshakeTimeout) * time.Second))
	rw, err := noise.NewServer(conn, s.key)
	if err != nil {
		return
	}
	defer func() { _ = rw.Close(); _, _ = io.Copy(io.Discard, rw) }()
	_ = conn.SetDeadline(time.Time{})
	config := smux.DefaultConfig()
	config.Version = 2
	config.KeepAliveTimeout = serverIdleTimeout
	config.MaxStreamBuffer = 1 << 20
	mux, err := smux.Server(rw, config)
	if err != nil {
		return
	}
	ctx, cancel := context.WithCancel(s.ctx)
	var streams sync.WaitGroup
	defer func() { cancel(); _ = mux.Close(); streams.Wait() }()
	slots := make(chan struct{}, int(s.cfg.MaxStreams))
	for {
		stream, err := mux.AcceptStream()
		if err != nil {
			return
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = stream.Close()
			continue
		}
		releasePending := func() {}
		if !s.queue.isAuthenticated(peer) {
			select {
			case s.pendingStreams <- struct{}{}:
			default:
				_ = stream.Close()
				<-slots
				continue
			}
			var released sync.Once
			releasePending = func() { released.Do(func() { <-s.pendingStreams }) }
		}
		streams.Add(1)
		go func() {
			wrapped := &serverStream{Stream: stream, local: tcpAddress(peer.local), remote: tcpAddress(peer.remote), socksOnly: s.socksOnly}
			defer streams.Done()
			defer releasePending()
			// Admission covers the complete synchronous FIN write, including a
			// cancellation callback that may already be closing this stream.
			defer func() { _ = wrapped.Close(); <-slots }()
			defer nativebridge.RecoverWorker(func(error) { _ = wrapped.Close() })
			flow, flowCancel := context.WithCancel(privateServerContext(peer.ctx))
			defer flowCancel()
			stop := context.AfterFunc(ctx, flowCancel)
			defer stop()
			closeStream := context.AfterFunc(flow, func() { _ = wrapped.Close() })
			defer closeStream()
			inbound := session.InboundFromContext(flow)
			if !inbound.Gateway.IsValid() {
				inbound.Gateway = xnet.TCPDestination(xnet.IPAddress(wrapped.local.IP), xnet.Port(wrapped.local.Port))
			}
			_ = s.inner.Process(flow, xnet.Network_TCP, wrapped, &authenticatedDispatcher{Dispatcher: dispatcher, eagerVLESSResponse: !s.socksOnly, promote: func() bool {
				if !s.queue.promote(peer) {
					return false
				}
				releasePending()
				return true
			}})
		}()
	}
}

type serverStream struct {
	*smux.Stream
	local, remote      *net.TCPAddr
	socksOnly, checked bool
	closeOnce          sync.Once
	closeError         error
}

func (s *serverStream) Close() error {
	s.closeOnce.Do(func() { s.closeError = s.Stream.Close() })
	return s.closeError
}

func (s *serverStream) Read(p []byte) (int, error) {
	n, err := s.Stream.Read(p)
	if n > 0 && !s.checked {
		s.checked = true
		if s.socksOnly && p[0] != 5 {
			return 0, errors.New("dnstt: inner requires authenticated SOCKS5")
		}
	}
	return n, err
}

func (s *serverStream) LocalAddr() net.Addr  { return s.local }
func (s *serverStream) RemoteAddr() net.Addr { return s.remote }
func tcpAddress(addr net.Addr) *net.TCPAddr {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return &net.TCPAddr{IP: a.IP, Port: a.Port, Zone: a.Zone}
	case *net.TCPAddr:
		return a
	}
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

func (s *Server) expirePeers() {
	defer s.wg.Done()
	defer nativebridge.RecoverWorker(func(error) { s.cancel() })
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-ticker.C:
			for _, peer := range s.queue.expire(now) {
				s.closePeer(peer)
			}
		}
	}
}

func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.cancel()
		if s.listener != nil {
			_ = s.listener.Close()
		}
		if s.queue != nil {
			_ = s.queue.Close()
		}
		for c := range s.associations {
			_ = c.Close()
		}
		for c := range s.sessions {
			_ = c.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
		if c, ok := s.inner.(io.Closer); ok {
			_ = c.Close()
		}
	})
	return nil
}

func (s *Server) AddUser(ctx context.Context, u *protocol.MemoryUser) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	if u == nil {
		return errors.New("dnstt: invalid inner user")
	}
	a, ok := u.Account.(*vless.MemoryAccount)
	if !ok || a.ID == nil || a.ID.String() == "00000000-0000-0000-0000-000000000000" || a.Flow != "" || a.Reverse != nil || a.Dialect != 0 || (a.Encryption != "" && a.Encryption != "none") {
		return errors.New("dnstt: only ordinary VLESS UUID users support live changes")
	}
	if m, ok := s.inner.(proxy.UserManager); ok {
		return m.AddUser(ctx, u)
	}
	return errors.New("dnstt: inner users require configuration reload")
}
func (s *Server) RemoveUser(ctx context.Context, email string) error {
	if m, ok := s.inner.(proxy.UserManager); ok {
		return m.RemoveUser(ctx, email)
	}
	return errors.New("dnstt: inner users require configuration reload")
}
func (s *Server) GetUser(ctx context.Context, email string) *protocol.MemoryUser {
	if m, ok := s.inner.(proxy.UserManager); ok {
		return m.GetUser(ctx, email)
	}
	return nil
}
func (s *Server) GetUsers(ctx context.Context) []*protocol.MemoryUser {
	if m, ok := s.inner.(proxy.UserManager); ok {
		return m.GetUsers(ctx)
	}
	return nil
}
func (s *Server) GetUsersCount(ctx context.Context) int64 {
	if m, ok := s.inner.(proxy.UserManager); ok {
		return m.GetUsersCount(ctx)
	}
	return 0
}

// Authentication is performed by the existing private inner handler before it
// reaches Dispatch/DispatchLink. Noise alone is deliberately not sufficient.
type authenticatedDispatcher struct {
	routing.Dispatcher
	promote            func() bool
	eagerVLESSResponse bool
}

func (d *authenticatedDispatcher) Dispatch(ctx context.Context, target xnet.Destination) (*transport.Link, error) {
	if !d.promote() {
		return nil, errors.New("dnstt: authenticated session capacity reached")
	}
	return d.Dispatcher.Dispatch(ctx, target)
}
func (d *authenticatedDispatcher) DispatchLink(ctx context.Context, target xnet.Destination, link *transport.Link) error {
	if !d.promote() {
		return errors.New("dnstt: authenticated session capacity reached")
	}
	if d.eagerVLESSResponse {
		if !target.IsValid() {
			return errors.New("dnstt: invalid inner destination")
		}
		// The ordinary VLESS handler has authenticated the user and encoded its
		// response by this point, but buffers that header until target payload.
		// Slow DNS uploads can outlive a client's first-response deadline when
		// the destination waits for the complete request body. Flush the existing
		// header here, without changing its bytes or the shared VLESS handler.
		writer := link.Writer
		if packets, ok := writer.(*vencoding.MultiLengthPacketWriter); ok {
			writer = packets.Writer
		}
		buffered, ok := writer.(*buf.BufferedWriter)
		if !ok {
			return errors.New("dnstt: unexpected inner VLESS response writer")
		}
		if err := buffered.Flush(); err != nil {
			return err
		}
	}
	return d.Dispatcher.DispatchLink(ctx, target, link)
}
func (s *Server) closePeer(peer *serverPeer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for conn, owner := range s.sessions {
		if owner == peer {
			_ = conn.Close()
		}
	}
}
