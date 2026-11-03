package mieru

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/nativebridge"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"golang.org/x/crypto/chacha20poly1305"
	"google.golang.org/protobuf/proto"
)

const maxServerUsers = 1024
const maxServerConnections = 4096
const maxUDPDestinations = 64

func (a *Account) Equals(other protocol.Account) bool {
	b, ok := other.(*Account)
	return ok && a.Username == b.Username && a.Password == b.Password && a.UuidMetadataTrailer == b.UuidMetadataTrailer
}
func (a *Account) ToProto() proto.Message { return a }
func (a *Account) AsAccount() (protocol.Account, error) {
	if a == nil || a.Username == "" || a.Password == "" || len(a.Username) > 256 || len(a.Password) > 4096 {
		return nil, errors.New("Mieru username/password are required and must fit protocol limits")
	}
	if a.UuidMetadataTrailer {
		if _, err := uuid.Parse(a.Username); err != nil {
			return nil, errors.New("uuidMetadataTrailer requires a UUID username")
		}
	}
	return a, nil
}

type serverUser struct {
	user    *protocol.MemoryUser
	account *Account
	mu      sync.Mutex
	epoch   int64
	keys    []cipher.AEAD
}

func (u *serverUser) authKeys(now time.Time) []cipher.AEAD {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.keys == nil || u.epoch != keyWindow(now) {
		keys := make([]cipher.AEAD, 0, 3)
		for _, shift := range []int{0, -1, 1} {
			a, _ := chacha20poly1305.NewX(Key(u.account.Username, u.account.Password, now.Add(time.Duration(shift)*120*time.Second)))
			keys = append(keys, a)
		}
		u.keys = keys
		u.epoch = keyWindow(now)
	}
	return u.keys
}

// Server is a native Xray handler. Listeners, socket policy and dispatch remain
// owned by Xray; no subprocess or independent network listener is started here.
type Server struct {
	config        *ServerConfig
	policy        policy.Manager
	mu            sync.RWMutex
	users         map[string]*serverUser
	active        map[*ownedConn]struct{}
	closed        bool
	handshakes    chan struct{}
	replays       map[[32]byte]time.Time
	replayCleanup time.Time
	underlayIdle  time.Duration
}

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, c interface{}) (result interface{}, err error) {
		defer nativebridge.Recover(&err, nil)
		return NewServer(ctx, c.(*ServerConfig))
	}))
}
func NewServer(ctx context.Context, c *ServerConfig) (*Server, error) {
	if c == nil || (c.Transport != "" && c.Transport != "tcp" && c.Transport != "udp") || c.HandshakeTimeout > 300 {
		return nil, errors.New("invalid Mieru server transport or handshake timeout")
	}
	if len(c.Users) == 0 || len(c.Users) > maxServerUsers {
		return nil, errors.New("Mieru requires 1..1024 users")
	}
	s := &Server{config: proto.Clone(c).(*ServerConfig), users: make(map[string]*serverUser), active: make(map[*ownedConn]struct{}), handshakes: make(chan struct{}, 64), replays: make(map[[32]byte]time.Time), underlayIdle: time.Minute}
	s.policy = core.MustFromContext(ctx).GetFeature(policy.ManagerType()).(policy.Manager)
	for _, u := range c.Users {
		if u == nil {
			return nil, errors.New("nil Mieru user")
		}
		m, err := u.ToMemoryUser()
		if err != nil {
			return nil, err
		}
		if err = s.AddUser(ctx, m); err != nil {
			return nil, err
		}
	}
	return s, nil
}
func (s *Server) Network() []xnet.Network {
	if s.config.Transport == "udp" {
		return []xnet.Network{xnet.Network_UDP}
	}
	return []xnet.Network{xnet.Network_TCP}
}
func cloneMemoryUser(u *protocol.MemoryUser) *protocol.MemoryUser {
	return &protocol.MemoryUser{Email: u.Email, Level: u.Level, Account: proto.Clone(u.Account.ToProto()).(*Account)}
}
func (s *Server) AddUser(_ context.Context, u *protocol.MemoryUser) error {
	if u == nil {
		return errors.New("nil Mieru user")
	}
	a, ok := u.Account.(*Account)
	if !ok {
		return errors.New("invalid Mieru account type")
	}
	if _, err := a.AsAccount(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	if len(s.users) >= maxServerUsers {
		return errors.New("Mieru user limit reached")
	}
	for _, old := range s.users {
		if old.account.Username == a.Username || (u.Email != "" && strings.EqualFold(old.user.Email, u.Email)) {
			return errors.New("duplicate Mieru user")
		}
	}
	u = cloneMemoryUser(u)
	a = u.Account.(*Account)
	s.users[a.Username] = &serverUser{user: u, account: a}
	return nil
}
func (s *Server) RemoveUser(_ context.Context, email string) error {
	s.mu.Lock()
	var removed *serverUser
	for name, u := range s.users {
		if strings.EqualFold(u.user.Email, email) {
			removed = u
			delete(s.users, name)
			break
		}
	}
	var conns []*ownedConn
	if removed != nil {
		for c := range s.active {
			if c.owner == removed {
				conns = append(conns, c)
			}
		}
	}
	s.mu.Unlock()
	if removed == nil {
		return errors.New("Mieru user not found")
	}
	// Cancel outside the users lock: close callbacks may finish a Process and
	// remove its admission entry. Immutable generations prevent a re-added
	// username from reviving an old authenticated underlay.
	for _, c := range conns {
		c.cancel()
		_ = c.Close()
	}
	return nil
}
func (s *Server) GetUser(_ context.Context, email string) *protocol.MemoryUser {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if strings.EqualFold(u.user.Email, email) {
			return cloneMemoryUser(u.user)
		}
	}
	return nil
}
func (s *Server) GetUsers(_ context.Context) []*protocol.MemoryUser {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*protocol.MemoryUser, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, cloneMemoryUser(u.user))
	}
	return out
}
func (s *Server) GetUsersCount(context.Context) int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return int64(len(s.users))
}
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	conns := make([]*ownedConn, 0, len(s.active))
	for c := range s.active {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		c.cancel()
		_ = c.Close()
	}
	return nil
}

// ownedConn makes close safe when authentication, cancellation and shutdown race.
type ownedConn struct {
	net.Conn
	once   sync.Once
	owner  *serverUser // guarded by Server.mu
	cancel context.CancelFunc
}

func (c *ownedConn) Close() error {
	var err error
	c.once.Do(func() { err = c.Conn.Close() })
	return err
}

// packetReaderConn adapts Xray's UDP worker, whose Read deliberately panics.
// Each buffer is one datagram; never concatenate multiple buffers into a frame.
type packetReaderConn struct {
	net.Conn
	reader  buf.Reader
	pending buf.MultiBuffer
	readErr error
	mu      sync.Mutex
}

func (c *packetReaderConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.pending) == 0 {
		if c.readErr != nil {
			return 0, c.readErr
		}
		c.pending, c.readErr = c.reader.ReadMultiBuffer()
	}
	b := c.pending[0]
	c.pending[0] = nil
	c.pending = c.pending[1:]
	defer b.Release()
	if int(b.Len()) > len(p) {
		return 0, errors.New("Mieru datagram buffer too small")
	}
	return copy(p, b.Bytes()), nil
}
func (c *packetReaderConn) Close() error {
	err := c.Conn.Close()
	c.mu.Lock()
	buf.ReleaseMulti(c.pending)
	c.pending = nil
	c.readErr = net.ErrClosed
	c.mu.Unlock()
	return err
}

type replayConn struct {
	net.Conn
	prefix   []byte
	datagram bool
}

func (c *replayConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		if c.datagram && len(p) < len(c.prefix) {
			return 0, io.ErrShortBuffer
		}
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

func (s *Server) authenticate(raw *ownedConn, udp bool) (*wire, *protocol.MemoryUser, segment, error) {
	first := make([]byte, 72)
	if udp {
		first = make([]byte, 65535)
		n, e := raw.Read(first)
		if e != nil {
			return nil, nil, segment{}, e
		}
		first = first[:n]
	} else if _, e := io.ReadFull(raw, first); e != nil {
		return nil, nil, segment{}, e
	}
	if len(first) < 72 {
		return nil, nil, segment{}, errors.New("truncated Mieru authentication")
	}
	s.mu.RLock()
	users := make([]*serverUser, 0, len(s.users))
	for _, u := range s.users {
		users = append(users, u)
	}
	s.mu.RUnlock()
	for _, u := range users {
		for _, key := range u.authKeys(time.Now()) {
			m, e := key.Open(nil, first[:24], first[24:72], nil)
			if e != nil {
				continue
			}
			header, _, _, e := parseMetadata(m)
			if e != nil || header.kind != openRequest || header.session == 0 {
				return nil, nil, segment{}, errors.New("invalid Mieru opening segment")
			}
			w, e := newWire(&replayConn{Conn: raw, prefix: first, datagram: udp}, u.account.Username, u.account.Password, udp, u.account.UuidMetadataTrailer)
			if e != nil {
				return nil, nil, segment{}, e
			}
			w.server = true
			w.recv = key
			w.send = key
			// Authenticate the entire opening record, including optional UUID trailer.
			// Do not use read's invalid-datagram retry loop during authentication.
			var opening segment
			if udp {
				opening, e = w.parse(bytes.NewReader(first))
				w.conn = raw
			} else {
				opening, e = w.parse(w.conn)
			}
			if e != nil {
				return nil, nil, segment{}, e
			}
			if err := s.rememberOpening(first[:72]); err != nil {
				return nil, nil, segment{}, err
			}
			s.mu.Lock()
			current := !s.closed && s.users[u.account.Username] == u
			if current {
				raw.owner = u
			}
			s.mu.Unlock()
			if !current {
				return nil, nil, segment{}, errors.New("Mieru account was revoked during authentication")
			}
			return w, cloneMemoryUser(u.user), opening, nil
		}
	}
	return nil, nil, segment{}, errors.New("Mieru authentication failed")
}

// Reject replay of an authenticated opening on a different underlay. A UDP
// retry on the established underlay is handled by the session and remains valid.
func (s *Server) rememberOpening(envelope []byte) error {
	key := sha256.Sum256(envelope)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if now.Sub(s.replayCleanup) > time.Minute {
		for old, until := range s.replays {
			if !until.After(now) {
				delete(s.replays, old)
			}
		}
		s.replayCleanup = now
	}
	if until, exists := s.replays[key]; exists && until.After(now) {
		return errors.New("replayed Mieru opening")
	}
	if len(s.replays) >= 65536 {
		return errors.New("Mieru authentication replay window is full")
	}
	s.replays[key] = now.Add(10 * time.Minute)
	return nil
}

func acceptSession(w *wire, opening segment) (*Conn, error) {
	c := &Conn{wire: w, sid: opening.session, next: 1, expected: 1, opened: make(chan struct{}), done: make(chan struct{})}
	c.cond = sync.NewCond(&c.mu)
	if w.udp {
		growReadBuffer(w.conn)
		c.ooo = make(map[uint32][]byte)
		c.cwnd, c.ssthresh = udpInitWindow, udpMaxWindow
		c.peerWindow = udpMaxWindow
		c.advertised = recvCapacity
		c.kick = make(chan struct{}, 1)
		c.live = udpLiveness
		c.heartbeat = c.live.next()
		c.lastRecv.Store(monoNow())
	}
	if len(opening.payload) > 0 {
		c.queue = append(c.queue, opening.payload)
		c.queued = len(opening.payload)
	}
	if err := w.write(segment{kind: openResponse, session: c.sid}); err != nil {
		return nil, err
	}
	c.openOnce.Do(func() { close(c.opened) })
	go c.receive()
	if w.udp {
		go c.retransmit()
	}
	return c, nil
}

func (s *Server) Process(ctx context.Context, network xnet.Network, raw stat.Connection, dispatcher routing.Dispatcher) (err error) {
	defer nativebridge.Recover(&err, nil)
	if network != s.Network()[0] {
		return errors.New("Mieru underlay does not match configured transport")
	}
	if network == xnet.Network_UDP {
		if reader, ok := raw.(buf.Reader); ok {
			raw = &packetReaderConn{Conn: raw, reader: reader}
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	owned := &ownedConn{Conn: raw, cancel: cancel}
	defer owned.Close()
	s.mu.Lock()
	if s.closed || len(s.active) >= maxServerConnections {
		s.mu.Unlock()
		return errors.New("Mieru inbound unavailable or connection limit reached")
	}
	s.active[owned] = struct{}{}
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.active, owned); s.mu.Unlock() }()
	stop := context.AfterFunc(ctx, func() { _ = owned.Close() })
	defer stop()
	select {
	case s.handshakes <- struct{}{}:
	default:
		return errors.New("Mieru handshake limit reached")
	}
	timeout := s.config.HandshakeTimeout
	if timeout == 0 {
		timeout = 10
	}
	timer := time.AfterFunc(time.Duration(timeout)*time.Second, func() { _ = owned.Close() })
	defer timer.Stop()
	_ = owned.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	w, user, opening, e := func() (*wire, *protocol.MemoryUser, segment, error) {
		defer func() { <-s.handshakes }()
		return s.authenticate(owned, network == xnet.Network_UDP)
	}()
	if e != nil {
		return e
	}
	timer.Stop()
	_ = owned.SetDeadline(time.Time{})
	inbound := session.InboundFromContext(ctx)
	if inbound != nil {
		copyInbound := *inbound
		copyInbound.Name = "mieru"
		copyInbound.User = user
		copyInbound.CanSpliceCopy = 3
		ctx = session.ContextWithInbound(ctx, &copyInbound)
	} else {
		ctx = session.ContextWithInbound(ctx, &session.Inbound{Name: "mieru", User: user, CanSpliceCopy: 3})
	}
	return s.serveUnderlay(ctx, w, opening, user, dispatcher)
}

func (s *Server) serveSession(ctx context.Context, conn *Conn, user *protocol.MemoryUser, dispatcher routing.Dispatcher) error {
	timeout := s.config.HandshakeTimeout
	if timeout == 0 {
		timeout = 10
	}
	timer := time.AfterFunc(time.Duration(timeout)*time.Second, func() { _ = conn.Close() })
	defer timer.Stop()
	var e error
	var hdr [3]byte
	if _, e = io.ReadFull(conn, hdr[:]); e != nil {
		return e
	}
	if hdr[0] != 5 || hdr[2] != 0 || (hdr[1] != 1 && hdr[1] != 3) {
		return errors.New("invalid Mieru SOCKS request")
	}
	dest, e := nativebridge.ReadAddress(conn)
	if e != nil {
		return e
	}
	timer.Stop()
	if err := ctx.Err(); err != nil {
		return err
	}
	reply := []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	if hdr[1] == 1 {
		if dest.Port == 0 {
			return errors.New("Mieru TCP destination port is zero")
		}
		dest.Network = xnet.Network_TCP
		link, e := dispatcher.Dispatch(ctx, dest)
		if e != nil {
			reply[1] = 1
			_ = nativebridge.WriteFull(conn, reply)
			return e
		}
		defer common.Interrupt(link.Reader)
		defer common.Interrupt(link.Writer)
		if e = nativebridge.WriteFull(conn, reply); e != nil {
			return e
		}
		return nativebridge.Relay(ctx, link, conn, nil, dest, s.policy.ForLevel(user.Level))
	}
	if e = nativebridge.WriteFull(conn, reply); e != nil {
		return e
	}
	return s.relayUDP(ctx, conn, dispatcher, s.policy.ForLevel(user.Level))
}

type udpRoute struct {
	link   *transport.Link
	last   atomic.Int64
	dead   atomic.Bool
	cancel context.CancelFunc
}

func (r *udpRoute) close() {
	r.cancel()
	common.Interrupt(r.link.Reader)
	common.Interrupt(r.link.Writer)
}
func (s *Server) relayUDP(ctx context.Context, conn *Conn, dispatcher routing.Dispatcher, p policy.Session) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { conn.abort(ctx.Err()) })
	defer stop()
	timer := signal.CancelAfterInactivity(ctx, cancel, p.Timeouts.ConnectionIdle)
	defer timer.SetTimeout(0)
	packets := &packetConn{Conn: conn}
	var writers sync.Mutex
	var workers sync.WaitGroup
	routes := map[string]*udpRoute{}
	defer func() {
		cancel()
		for _, r := range routes {
			r.close()
		}
		_ = conn.Close()
		workers.Wait()
	}()
	for {
		data, dest, e := packets.ReadPacket()
		timer.Update()
		if e != nil {
			return e
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if dest.Port == 0 {
			return errors.New("Mieru UDP destination port is zero")
		}
		if len(data) > int(buf.Size) {
			return errors.New("Mieru UDP datagram exceeds Xray buffer size")
		}
		dest.Network = xnet.Network_UDP
		now := monoNow()
		for key, r := range routes {
			if r.dead.Load() || time.Duration(now-r.last.Load()) > s.underlayIdle {
				r.close()
				delete(routes, key)
			}
		}
		key := dest.String()
		r := routes[key]
		if r == nil {
			if len(routes) >= maxUDPDestinations {
				return errors.New("Mieru UDP destination limit reached")
			}
			routeCtx, routeCancel := context.WithCancel(privateRouteContext(ctx))
			link, e := dispatcher.Dispatch(routeCtx, dest)
			if e != nil {
				routeCancel()
				continue
			}
			r = &udpRoute{link: link, cancel: routeCancel}
			routes[key] = r
			workers.Add(1)
			go func(r *udpRoute, target xnet.Destination) {
				defer workers.Done()
				defer r.dead.Store(true)
				defer nativebridge.RecoverWorker(func(error) { cancel(); _ = conn.Close() })
				for {
					mb, e := r.link.Reader.ReadMultiBuffer()
					for i, b := range mb {
						from := target
						if b.UDP != nil {
							from = *b.UDP
						}
						writers.Lock()
						writeErr := packets.WritePacket(b.Bytes(), from)
						if writeErr == nil {
							timer.Update()
							r.last.Store(monoNow())
						}
						writers.Unlock()
						b.Release()
						mb[i] = nil
						if writeErr != nil {
							buf.ReleaseMulti(mb)
							cancel()
							_ = conn.Close()
							return
						}
					}
					if e != nil {
						return
					}
				}
			}(r, dest)
		}
		r.last.Store(now)
		b := buf.New()
		_, _ = b.Write(data)
		b.UDP = &dest
		if e = r.link.Writer.WriteMultiBuffer(buf.MultiBuffer{b}); e != nil {
			r.close()
			delete(routes, key)
		}
	}
}
