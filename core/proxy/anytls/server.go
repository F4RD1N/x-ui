package anytls

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/nativebridge"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const (
	maxServerSessions  = 128
	maxServerStreams   = 1024
	streamQueueBytes   = 256 * 1024
	serverWriteTimeout = 10 * time.Second
)

// Server owns only authenticated AnyTLS carriers. All destinations go through
// the ordinary Xray dispatcher, including each destination in a UDP stream.
type Server struct {
	mu          sync.Mutex
	users       map[[32]byte]*protocol.MemoryUser
	emails      map[string][32]byte
	sessions    map[*serverSession]struct{}
	closed      bool
	timeout     time.Duration
	maxStreams  uint32
	streamSlots chan struct{}
	policy      policy.Manager
}

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, c interface{}) (result interface{}, err error) {
		defer nativebridge.Recover(&err, nil)
		return NewServer(ctx, c.(*ServerConfig))
	}))
}

func NewServer(ctx context.Context, c *ServerConfig) (*Server, error) {
	if c == nil {
		return nil, errors.New("AnyTLS server configuration is required")
	}
	if c.HandshakeTimeout > 300 || c.MaxStreams > 1024 {
		return nil, errors.New("AnyTLS handshakeTimeout must be <=300 and maxStreams <=1024")
	}
	timeout := c.HandshakeTimeout
	if timeout == 0 {
		timeout = 10
	}
	limit := c.MaxStreams
	if limit == 0 {
		limit = 128
	}
	s := &Server{users: make(map[[32]byte]*protocol.MemoryUser), emails: make(map[string][32]byte), sessions: make(map[*serverSession]struct{}), timeout: time.Duration(timeout) * time.Second, maxStreams: limit, streamSlots: make(chan struct{}, maxServerStreams), policy: core.MustFromContext(ctx).GetFeature(policy.ManagerType()).(policy.Manager)}
	for _, u := range c.Users {
		if u == nil {
			return nil, errors.New("AnyTLS nil user")
		}
		user, err := u.ToMemoryUser()
		if err != nil {
			return nil, err
		}
		if err = s.AddUser(ctx, user); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func cloneAnyTLSUser(u *protocol.MemoryUser) *protocol.MemoryUser {
	if u == nil {
		return nil
	}
	out := *u
	a := *(u.Account.(*MemoryAccount))
	out.Account = &a
	return &out
}
func (s *Server) AddUser(_ context.Context, u *protocol.MemoryUser) error {
	if u == nil {
		return errors.New("AnyTLS nil user")
	}
	a, ok := u.Account.(*MemoryAccount)
	if !ok {
		return errors.New("AnyTLS account type required")
	}
	account, err := (&Account{Password: a.Password, UuidHashMiddle: a.UUIDHashMiddle}).AsAccount()
	if err != nil {
		return err
	}
	saved := &protocol.MemoryUser{Account: account, Email: u.Email, Level: u.Level}
	key := account.(*MemoryAccount).Key
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	if len(s.users) >= 65536 {
		return errors.New("AnyTLS user limit reached")
	}
	if _, ok := s.users[key]; ok {
		return errors.New("duplicate AnyTLS authentication identity")
	}
	if saved.Email != "" {
		if _, ok := s.emails[saved.Email]; ok {
			return errors.New("duplicate AnyTLS email")
		}
		s.emails[saved.Email] = key
	}
	s.users[key] = saved
	return nil
}
func (s *Server) RemoveUser(_ context.Context, email string) error {
	s.mu.Lock()
	key, ok := s.emails[email]
	if !ok {
		s.mu.Unlock()
		return errors.New("AnyTLS user not found")
	}
	user := s.users[key]
	delete(s.users, key)
	delete(s.emails, email)
	var active []*serverSession
	for c := range s.sessions {
		if c.user == user {
			active = append(active, c)
		}
	}
	s.mu.Unlock()
	for _, c := range active {
		c.close()
	}
	for _, c := range active {
		c.wg.Wait()
	}
	return nil
}
func (s *Server) GetUser(_ context.Context, email string) *protocol.MemoryUser {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, ok := s.emails[email]
	if !ok {
		return nil
	}
	return cloneAnyTLSUser(s.users[key])
}
func (s *Server) GetUsers(context.Context) []*protocol.MemoryUser {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*protocol.MemoryUser, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, cloneAnyTLSUser(u))
	}
	return out
}
func (s *Server) GetUsersCount(context.Context) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return int64(len(s.users))
}
func (s *Server) Network() []xnet.Network { return []xnet.Network{xnet.Network_TCP} }
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	active := make([]*serverSession, 0, len(s.sessions))
	for c := range s.sessions {
		active = append(active, c)
	}
	s.mu.Unlock()
	for _, c := range active {
		c.close()
	}
	for _, c := range active {
		c.wg.Wait()
	}
	return nil
}

func (s *Server) Process(ctx context.Context, network xnet.Network, conn stat.Connection, d routing.Dispatcher) (err error) {
	if network != xnet.Network_TCP {
		return errors.New("AnyTLS inbound requires TCP")
	}
	ctx, cancel := context.WithCancel(ctx)
	c := &serverSession{owner: s, ctx: ctx, cancel: cancel, conn: conn, dispatcher: d, streams: make(map[uint32]*serverStream)}
	defer nativebridge.Recover(&err, func() { c.close() })
	s.mu.Lock()
	if s.closed || len(s.sessions) >= maxServerSessions {
		s.mu.Unlock()
		cancel()
		conn.Close()
		return errors.New("AnyTLS session capacity unavailable")
	}
	s.sessions[c] = struct{}{}
	s.mu.Unlock()
	stop := context.AfterFunc(ctx, c.close)
	defer func() {
		stop()
		c.close()
		c.wg.Wait()
		s.mu.Lock()
		delete(s.sessions, c)
		s.mu.Unlock()
	}()
	if err = conn.SetReadDeadline(time.Now().Add(s.timeout)); err != nil {
		return err
	}
	var auth [32]byte
	if _, err = io.ReadFull(conn, auth[:]); err != nil {
		return err
	}
	s.mu.Lock()
	c.user = s.users[auth]
	user := c.user
	s.mu.Unlock()
	if user == nil {
		return errors.New("AnyTLS authentication rejected")
	}
	var length [2]byte
	if _, err = io.ReadFull(conn, length[:]); err != nil {
		return err
	}
	if _, err = io.CopyN(io.Discard, conn, int64(binary.BigEndian.Uint16(length[:]))); err != nil {
		return err
	}
	if err = conn.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	// Each authenticated carrier has a finite idle lifetime, independent of
	// client-controlled heartbeats. Actual stream payload renews activity.
	idle := s.policy.ForLevel(user.Level).Timeouts.ConnectionIdle
	if idle <= 0 {
		idle = 5 * time.Minute
	}
	c.activity = signal.CancelAfterInactivity(ctx, c.close, idle)
	defer c.activity.SetTimeout(0)
	return c.readLoop()
}

type serverSession struct {
	owner      *Server
	ctx        context.Context
	cancel     context.CancelFunc
	conn       net.Conn
	dispatcher routing.Dispatcher
	user       *protocol.MemoryUser // assigned/read under owner.mu before streams start
	wmu        sync.Mutex
	mu         sync.Mutex
	streams    map[uint32]*serverStream
	closed     bool
	wg         sync.WaitGroup
	activity   *signal.ActivityTimer
	settings   bool
	version    int
	lastID     uint32
}

func (c *serverSession) close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	streams := make([]*serverStream, 0, len(c.streams))
	for _, s := range c.streams {
		streams = append(streams, s)
	}
	c.mu.Unlock()
	c.cancel()
	c.conn.Close()
	for _, s := range streams {
		s.close(false)
	}
}
func (c *serverSession) send(cmd byte, id uint32, p []byte) error {
	if len(p) > 65535 {
		return errors.New("AnyTLS server frame too large")
	}
	c.wmu.Lock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(serverWriteTimeout))
	err := nativebridge.WriteFull(c.conn, frame(cmd, id, p))
	_ = c.conn.SetWriteDeadline(time.Time{})
	c.wmu.Unlock()
	if err != nil {
		c.close()
	}
	return err
}
func (c *serverSession) readLoop() error {
	for {
		var h [7]byte
		if _, err := io.ReadFull(c.conn, h[:]); err != nil {
			return err
		}
		cmd, id, n := h[0], binary.BigEndian.Uint32(h[1:5]), binary.BigEndian.Uint16(h[5:])
		p := make([]byte, n)
		if _, err := io.ReadFull(c.conn, p); err != nil {
			return err
		}
		switch cmd {
		case cmdWaste:
		case cmdSettings:
			if c.settings || id != 0 || len(p) > 4096 {
				return errors.New("invalid AnyTLS settings")
			}
			c.settings = true
			c.version = 1
			for _, line := range strings.Split(string(p), "\n") {
				if line == "v=2" {
					c.version = 2
				}
			}
			if c.version == 2 {
				if err := c.send(cmdServerSettings, 0, []byte("v=2")); err != nil {
					return err
				}
			}
		case cmdSYN:
			if !c.settings || n != 0 || id == 0 || id <= c.lastID {
				return errors.New("invalid AnyTLS stream ID or missing settings")
			}
			c.lastID = id
			if err := c.open(id); err != nil {
				return err
			}
		case cmdPSH:
			if id == 0 {
				return errors.New("invalid AnyTLS data stream")
			}
			c.mu.Lock()
			s := c.streams[id]
			c.mu.Unlock()
			if s != nil && len(p) > 0 {
				if !s.enqueue(p) {
					s.close(true)
				} else {
					c.activity.Update()
				}
			}
		case cmdFIN:
			if n != 0 || id == 0 {
				return errors.New("invalid AnyTLS FIN")
			}
			c.mu.Lock()
			s := c.streams[id]
			c.mu.Unlock()
			if s != nil {
				s.close(false)
			}
		case cmdHeartRequest:
			if n != 0 || id != 0 || !c.settings || c.version < 2 {
				return errors.New("invalid AnyTLS heartbeat")
			}
			if err := c.send(cmdHeartResponse, 0, nil); err != nil {
				return err
			}
		default:
			return errors.New("unexpected AnyTLS client command")
		}
	}
}

func (c *serverSession) open(id uint32) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return net.ErrClosed
	}
	if len(c.streams) >= int(c.owner.maxStreams) {
		c.mu.Unlock()
		return errors.New("AnyTLS stream capacity exceeded")
	}
	select {
	case c.owner.streamSlots <- struct{}{}:
	default:
		c.mu.Unlock()
		return errors.New("AnyTLS global stream capacity exceeded")
	}
	r, w := net.Pipe()
	ctx, cancel := context.WithCancel(c.ctx)
	s := &serverStream{session: c, id: id, read: r, deliver: w, queue: make(chan []byte, 8), ctx: ctx, cancel: cancel, pumpDone: make(chan struct{})}
	c.streams[id] = s
	c.wg.Add(2)
	c.mu.Unlock()
	go func() {
		defer c.wg.Done()
		defer close(s.pumpDone)
		defer nativebridge.RecoverWorker(func(error) { s.close(true) })
		s.pump()
	}()
	go func() {
		defer c.wg.Done()
		defer nativebridge.RecoverWorker(func(error) { s.close(false) })
		defer s.finish()
		c.serve(s)
	}()
	return nil
}

type serverStream struct {
	session       *serverSession
	id            uint32
	read, deliver net.Conn
	ctx           context.Context
	cancel        context.CancelFunc
	once          sync.Once
	writeMu       sync.Mutex
	queue         chan []byte
	mu            sync.Mutex
	queued        int
	closed        bool
	pumpDone      chan struct{}
	notifyFIN     bool
}

func (s *serverStream) enqueue(p []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.queued+len(p) > streamQueueBytes {
		return false
	}
	select {
	case s.queue <- p:
		s.queued += len(p)
		return true
	default:
		return false
	}
}
func (s *serverStream) pump() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case p := <-s.queue:
			err := nativebridge.WriteFull(s.deliver, p)
			s.mu.Lock()
			s.queued -= len(p)
			s.mu.Unlock()
			if err != nil {
				return
			}
		}
	}
}
func (s *serverStream) close(notify bool) {
	s.once.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.notifyFIN = notify
		s.mu.Unlock()
		s.cancel()
		s.read.Close()
		s.deliver.Close()
	})
}

// Admission covers the complete worker lifetime, including blocked FIN writes.
// Releasing in close() would let a non-reading peer create unbounded workers
// whose streams were closed but whose response writers were still waiting.
func (s *serverStream) finish() {
	defer func() {
		<-s.pumpDone
		s.session.mu.Lock()
		delete(s.session.streams, s.id)
		s.session.mu.Unlock()
		<-s.session.owner.streamSlots
	}()
	s.close(true)
	s.mu.Lock()
	notify := s.notifyFIN
	s.mu.Unlock()
	if notify {
		_ = s.session.send(cmdFIN, s.id, nil)
	}
}
func (s *serverStream) Read(p []byte) (int, error) { return s.read.Read(p) }
func (s *serverStream) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	total := 0
	for len(p) > 0 {
		n := min(len(p), 32768)
		if err := s.session.send(cmdPSH, s.id, p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
		s.session.activity.Update()
	}
	return total, nil
}

func (c *serverSession) serve(st *serverStream) {
	_ = st.read.SetReadDeadline(time.Now().Add(c.owner.timeout))
	target, err := nativebridge.ReadAddress(st)
	if err != nil {
		return
	}
	inbound := &session.Inbound{Name: "anytls", User: cloneAnyTLSUser(c.user)}
	if previous := session.InboundFromContext(st.ctx); previous != nil {
		*inbound = *previous
		inbound.Name = "anytls"
		inbound.User = cloneAnyTLSUser(c.user)
	}
	if !inbound.Source.IsValid() {
		if remote, ok := c.conn.RemoteAddr().(*net.TCPAddr); ok {
			inbound.Source = xnet.TCPDestination(xnet.IPAddress(remote.IP), xnet.Port(remote.Port))
		}
	}
	ctx := session.ContextWithInbound(st.ctx, inbound)
	inbound.CanSpliceCopy = 3
	content := &session.Content{}
	if previous := session.ContentFromContext(st.ctx); previous != nil {
		*content = *previous
		if previous.Attributes != nil {
			content.Attributes = make(map[string]string, len(previous.Attributes))
			for key, value := range previous.Attributes {
				content.Attributes[key] = value
			}
		}
	}
	ctx = session.ContextWithContent(ctx, content)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{}})
	p := c.owner.policy.ForLevel(c.user.Level)
	ctx = policy.ContextWithBufferPolicy(ctx, p.Buffer)
	if target.Address.Family() == xnet.AddressFamilyDomain && target.Address.Domain() == "sp.v2.udp-over-tcp.arpa" && target.Port == 0 {
		c.serveUDP(ctx, st)
		return
	}
	if target.Port == 0 || (target.Address.Family() == xnet.AddressFamilyDomain && target.Address.Domain() == "sp.udp-over-tcp.arpa") {
		return
	}
	target.Network = xnet.Network_TCP
	link, err := c.dispatcher.Dispatch(ctx, target)
	if err != nil {
		if c.version >= 2 {
			_ = c.send(cmdSYNACK, st.id, []byte("destination unavailable"))
		}
		return
	}
	defer common.Interrupt(link.Reader)
	defer common.Interrupt(link.Writer)
	_ = st.read.SetReadDeadline(time.Time{})
	if c.version >= 2 {
		if err = c.send(cmdSYNACK, st.id, nil); err != nil {
			return
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	idle := signal.CancelAfterInactivity(ctx, cancel, p.Timeouts.ConnectionIdle)
	defer idle.SetTimeout(0)
	stop := context.AfterFunc(ctx, func() { st.close(true); common.Interrupt(link.Reader); common.Interrupt(link.Writer) })
	defer stop()
	var workers sync.WaitGroup
	workers.Add(2)
	up := func() (err error) {
		defer workers.Done()
		defer nativebridge.Recover(&err, func() { st.close(true) })
		defer idle.SetTimeout(p.Timeouts.DownlinkOnly)
		if err = buf.Copy(buf.NewReader(st), link.Writer, buf.UpdateActivity(idle)); err != nil {
			return err
		}
		return common.Close(link.Writer)
	}
	down := func() (err error) {
		defer workers.Done()
		defer nativebridge.Recover(&err, func() { st.close(true) })
		defer idle.SetTimeout(p.Timeouts.UplinkOnly)
		return buf.Copy(link.Reader, buf.NewWriter(st), buf.UpdateActivity(idle))
	}
	_ = task.Run(ctx, up, down)
	// task.Run returns on the first error/cancellation. Keep stream admission
	// until both copies have actually left their shared-carrier write paths.
	cancel()
	st.close(true)
	common.Interrupt(link.Reader)
	common.Interrupt(link.Writer)
	workers.Wait()
}

// UDP links are per destination so route rules are evaluated for every target,
// rather than reusing the first target's outbound for unrelated datagrams.
func (c *serverSession) serveUDP(ctx context.Context, st *serverStream) {
	var mode [1]byte
	if _, err := io.ReadFull(st, mode[:]); err != nil || mode[0] > 1 {
		return
	}
	initial, err := nativebridge.ReadAddress(st)
	if err != nil {
		return
	}
	connected := mode[0] == 1
	if connected && initial.Port == 0 {
		return
	}
	_ = st.read.SetReadDeadline(time.Time{})
	if c.version >= 2 {
		if c.send(cmdSYNACK, st.id, nil) != nil {
			return
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	links := make(map[xnet.Destination]*transport.Link)
	defer func() {
		cancel()
		for _, link := range links {
			common.Interrupt(link.Reader)
			common.Interrupt(link.Writer)
		}
		wg.Wait()
	}()
	stop := context.AfterFunc(ctx, func() { st.read.Close() })
	defer stop()
	p := c.owner.policy.ForLevel(c.user.Level)
	timer := signal.CancelAfterInactivity(ctx, cancel, p.Timeouts.ConnectionIdle)
	defer timer.SetTimeout(0)
	for {
		destination := initial
		var payload []byte
		if connected {
			var n [2]byte
			if _, err = io.ReadFull(st, n[:]); err != nil {
				return
			}
			payload = make([]byte, binary.BigEndian.Uint16(n[:]))
			if _, err = io.ReadFull(st, payload); err != nil {
				return
			}
		} else {
			codec := uotConn{Conn: &serverStreamConn{serverStream: st}}
			payload, destination, err = codec.ReadPacket()
			if err != nil {
				return
			}
		}
		if destination.Port == 0 {
			return
		}
		timer.Update()
		link := links[destination]
		if link == nil {
			if len(links) >= 64 {
				return
			}
			// Dispatcher and sniffers mutate their outbound/content records.
			// Separate destination flows must never share those records.
			routeCtx := session.ContextWithOutbounds(ctx, []*session.Outbound{{}})
			if parent := session.ContentFromContext(ctx); parent != nil {
				child := *parent
				child.Attributes = make(map[string]string, len(parent.Attributes))
				for k, v := range parent.Attributes {
					child.Attributes[k] = v
				}
				routeCtx = session.ContextWithContent(routeCtx, &child)
			}
			if parent := session.InboundFromContext(ctx); parent != nil {
				child := *parent
				routeCtx = session.ContextWithInbound(routeCtx, &child)
			}
			link, err = c.dispatcher.Dispatch(routeCtx, destination)
			if err != nil {
				return
			}
			links[destination] = link
			tracked := link
			context.AfterFunc(ctx, func() { common.Interrupt(tracked.Reader); common.Interrupt(tracked.Writer) })
			wg.Add(1)
			go func(link *transport.Link, destination xnet.Destination) {
				defer wg.Done()
				defer nativebridge.RecoverWorker(func(error) { cancel() })
				defer cancel()
				for {
					mb, readErr := link.Reader.ReadMultiBuffer()
					for i, b := range mb {
						if b.Len() > 65535 {
							buf.ReleaseMulti(mb[i:])
							return
						}
						source := destination
						if b.UDP != nil {
							source = *b.UDP
						}
						var data []byte
						var writeErr error
						if connected {
							data = binary.BigEndian.AppendUint16(nil, uint16(b.Len()))
							data = append(data, b.Bytes()...)
						} else {
							data, writeErr = nativebridge.Address(source)
							if writeErr == nil {
								switch data[0] {
								case 1:
									data[0] = 0
								case 4:
									data[0] = 1
								case 3:
									data[0] = 2
								}
								data = binary.BigEndian.AppendUint16(data, uint16(b.Len()))
								data = append(data, b.Bytes()...)
							}
						}
						if writeErr == nil {
							_, writeErr = st.Write(data)
						}
						b.Release()
						if writeErr != nil {
							buf.ReleaseMulti(mb[i+1:])
							return
						}
						timer.Update()
					}
					if readErr != nil {
						return
					}
				}
			}(link, destination)
		}
		packet := buf.FromBytes(payload)
		packet.UDP = &destination
		if err = link.Writer.WriteMultiBuffer(buf.MultiBuffer{packet}); err != nil {
			return
		}
	}
}

type serverStreamConn struct{ *serverStream }

func (s *serverStreamConn) Close() error                      { s.close(false); return nil }
func (s *serverStreamConn) LocalAddr() net.Addr               { return s.session.conn.LocalAddr() }
func (s *serverStreamConn) RemoteAddr() net.Addr              { return s.session.conn.RemoteAddr() }
func (s *serverStreamConn) SetDeadline(t time.Time) error     { return s.read.SetReadDeadline(t) }
func (s *serverStreamConn) SetReadDeadline(t time.Time) error { return s.read.SetReadDeadline(t) }
func (s *serverStreamConn) SetWriteDeadline(time.Time) error {
	return errors.New("AnyTLS logical write deadlines are session bounded")
}
