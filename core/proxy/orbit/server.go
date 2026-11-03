package orbit

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	xprotocol "github.com/xtls/xray-core/common/protocol"
	xsession "github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/nativebridge"
	"github.com/xtls/xray-core/proxy/orbit/internal/protocol"
	osession "github.com/xtls/xray-core/proxy/orbit/internal/session"
	otransport "github.com/xtls/xray-core/proxy/orbit/internal/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"google.golang.org/protobuf/proto"
)

type incomingFlow interface {
	net.Conn
	Destination() protocol.Address
	Accept() error
	Reject() error
}
type serverPeer interface {
	peer
	User() protocol.UserInfo
	ChannelID() [16]byte
	Accept(context.Context) (incomingFlow, error)
}
type serverTCPPeer struct{ *osession.Session }

func (p serverTCPPeer) Open(ctx context.Context, h string, port uint16) (net.Conn, error) {
	return p.Session.Open(ctx, h, port)
}
func (p serverTCPPeer) Accept(ctx context.Context) (incomingFlow, error) {
	return p.Session.Accept(ctx)
}

type serverQUICPeer struct{ *otransport.QUICSession }

func (p serverQUICPeer) Open(ctx context.Context, h string, port uint16) (net.Conn, error) {
	return p.QUICSession.Open(ctx, h, port)
}
func (p serverQUICPeer) Accept(ctx context.Context) (incomingFlow, error) {
	return p.QUICSession.Accept(ctx)
}

// Server owns no sockets or workers until Process receives an Xray connection.
// In particular QUIC runs on the inbound worker's datagrams, never an extra port.
type Server struct {
	processWG      sync.WaitGroup
	cfg            *ServerConfig
	tls, outerTLS  *tls.Config
	pin            [32]byte
	policy         policy.Manager
	mu             sync.Mutex
	users          map[string]*xprotocol.MemoryUser
	emails         map[string]string
	active         map[*serverRun]struct{}
	channels       map[channelKey]*serverChannel
	closed         bool
	slots          chan struct{}
	realityMu      sync.Mutex
	reality        *otransport.RealityServer
	realityPending chan struct{}
	realityErr     error
	realityRetry   time.Time
}
type serverRun struct {
	cancel context.CancelFunc
	conn   net.Conn
	uid    string
	user   *xprotocol.MemoryUser
}

func serverCertificate(c *Certificate) (*tls.Config, [32]byte, error) {
	var pin [32]byte
	if c == nil || len(c.Certificate) == 0 || len(c.Key) == 0 {
		return nil, pin, errors.New("orbit: certificate and private key are required")
	}
	cert, err := tls.X509KeyPair([]byte(strings.Join(c.Certificate, "\n")), []byte(strings.Join(c.Key, "\n")))
	if err != nil {
		return nil, pin, errors.New("orbit: invalid certificate or private key")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil || leaf.IsCA || len(leaf.UnhandledCriticalExtensions) != 0 {
		return nil, pin, errors.New("orbit: invalid leaf certificate")
	}
	pin = sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, pin, nil
}

// ValidateServerConfig performs offline validation; it opens no listeners and
// does not probe a REALITY cover server.
func ValidateServerConfig(c *ServerConfig) error {
	_, err := NewServer(context.Background(), c)
	return err
}

func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	if config == nil {
		return nil, errors.New("orbit: server settings required")
	}
	c := proto.Clone(config).(*ServerConfig)
	if c.Transport == "" {
		c.Transport = "tcp"
	}
	switch c.Transport {
	case "tcp", "quic", "ws", "wss":
	default:
		return nil, errors.New("orbit: invalid server transport")
	}
	if c.HandshakeTimeout == 0 {
		c.HandshakeTimeout = 15
	}
	if c.MaxSessions == 0 {
		c.MaxSessions = 1000
	}
	if c.MaxFlows == 0 {
		c.MaxFlows = 128
	}
	if c.UdpIdleTimeout == 0 {
		c.UdpIdleTimeout = 60
	}
	if len(c.Users) > 10000 {
		return nil, errors.New("orbit: account limit reached")
	}
	if c.HandshakeTimeout > 90 || c.MaxSessions > 10000 || c.MaxFlows > 4096 || c.UdpIdleTimeout > 3600 {
		return nil, errors.New("orbit: server limit out of range")
	}
	if c.Security != "" && c.Security != "reality" {
		return nil, errors.New("orbit: invalid server security")
	}
	if c.Security == "reality" {
		if c.Transport != "tcp" || c.Reality == nil {
			return nil, errors.New("orbit: REALITY requires TCP and reality settings")
		}
		key, e := base64.RawURLEncoding.Strict().DecodeString(c.Reality.PrivateKey)
		if e != nil || len(key) != 32 {
			return nil, errors.New("orbit: invalid REALITY private key")
		}
		if _, _, e = net.SplitHostPort(c.Reality.Dest); e != nil {
			return nil, errors.New("orbit: invalid REALITY destination")
		}
		if len(c.Reality.ServerNames) == 0 || len(c.Reality.ServerNames) > 32 || len(c.Reality.ShortIds) == 0 || len(c.Reality.ShortIds) > 32 {
			return nil, errors.New("orbit: REALITY names and short IDs required")
		}
		names := make(map[string]bool)
		for i, name := range c.Reality.ServerNames {
			normalized, ok := dnsHost(name)
			if !ok || names[normalized] {
				return nil, errors.New("orbit: invalid REALITY server name")
			}
			names[normalized] = true
			c.Reality.ServerNames[i] = normalized
		}
		for _, id := range c.Reality.ShortIds {
			b, e := hex.DecodeString(id)
			if e != nil || len(b) > 8 {
				return nil, errors.New("orbit: invalid REALITY short ID")
			}
		}
	} else if c.Reality != nil {
		return nil, errors.New("orbit: reality settings require security reality")
	}
	ws := c.Transport == "ws" || c.Transport == "wss"
	if ws {
		if c.Host == "" {
			return nil, errors.New("orbit: WebSocket host required")
		}
		if _, ok := connectionHost(c.Host); !ok {
			return nil, errors.New("orbit: invalid WebSocket host")
		}
		c.Host = strings.ToLower(c.Host)
		if c.Path == "" {
			c.Path = "/core"
		}
		if !validWebSocketPath(c.Path) {
			return nil, errors.New("orbit: invalid WebSocket path")
		}
	} else if c.Host != "" || c.Path != "" || c.OuterTls != nil {
		return nil, errors.New("orbit: WebSocket settings on a non-WebSocket listener")
	}
	if c.Transport != "wss" && c.OuterTls != nil {
		return nil, errors.New("orbit: outerTls requires wss")
	}
	s := &Server{cfg: c, users: make(map[string]*xprotocol.MemoryUser), emails: make(map[string]string), active: make(map[*serverRun]struct{}), channels: make(map[channelKey]*serverChannel), slots: make(chan struct{}, c.MaxSessions)}
	var err error
	if c.Security != "reality" {
		s.tls, s.pin, err = serverCertificate(c.Tls)
		if err != nil {
			return nil, err
		}
	} else if c.Tls != nil {
		return nil, errors.New("orbit: REALITY replaces inner TLS; remove tls settings")
	}
	if c.Transport == "wss" {
		s.outerTLS, _, err = serverCertificate(c.OuterTls)
		if err != nil {
			return nil, err
		}
	}
	if c.Transport == "quic" {
		s.tls.MinVersion = tls.VersionTLS13
	}
	if v := core.FromContext(ctx); v != nil {
		s.policy, _ = v.GetFeature(policy.ManagerType()).(policy.Manager)
	}
	for _, u := range c.Users {
		if u == nil {
			return nil, errors.New("orbit: invalid user")
		}
		m, e := u.ToMemoryUser()
		if e != nil {
			return nil, e
		}
		if e = s.AddUser(ctx, m); e != nil {
			return nil, e
		}
	}
	return s, nil
}

func (s *Server) Network() []xnet.Network {
	if s.cfg.Transport == "quic" {
		return []xnet.Network{xnet.Network_UDP}
	}
	return []xnet.Network{xnet.Network_TCP}
}
func (s *Server) AddUser(_ context.Context, u *xprotocol.MemoryUser) error {
	if u == nil {
		return errors.New("orbit: user required")
	}
	a, ok := u.Account.(*MemoryAccount)
	if !ok || a == nil {
		return errors.New("orbit: invalid user account")
	}
	if s.cfg.Security != "reality" && subtle.ConstantTimeCompare(a.pin[:], s.pin[:]) != 1 {
		return errors.New("orbit: account key pin does not match listener certificate")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("orbit: server closed")
	}
	if _, ok = s.users[a.uid]; ok {
		return errors.New("orbit: duplicate account")
	}
	if len(s.users) >= 10000 {
		return errors.New("orbit: account limit reached")
	}
	if u.Email != "" {
		if _, ok = s.emails[u.Email]; ok {
			return errors.New("orbit: duplicate user email")
		}
		s.emails[u.Email] = a.uid
	}
	copyUser := *u
	s.users[a.uid] = &copyUser
	return nil
}
func (s *Server) RemoveUser(_ context.Context, email string) error {
	s.mu.Lock()
	uid, ok := s.emails[email]
	if !ok || email == "" {
		s.mu.Unlock()
		return errors.New("orbit: user not found")
	}
	removed := s.users[uid]
	delete(s.emails, email)
	delete(s.users, uid)
	var cancel []context.CancelFunc
	for run := range s.active {
		if run.user == removed {
			cancel = append(cancel, run.cancel)
		}
	}
	s.mu.Unlock()
	for _, fn := range cancel {
		fn()
	}
	return nil
}
func (s *Server) GetUser(_ context.Context, email string) *xprotocol.MemoryUser {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.users[s.emails[email]]
	if u == nil {
		return nil
	}
	v := *u
	return &v
}
func (s *Server) GetUsers(context.Context) []*xprotocol.MemoryUser {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := make([]*xprotocol.MemoryUser, 0, len(s.users))
	for _, u := range s.users {
		v := *u
		r = append(r, &v)
	}
	return r
}
func (s *Server) GetUsersCount(context.Context) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return int64(len(s.users))
}
func (s *Server) authorize(u protocol.UserInfo) (*xprotocol.MemoryUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.authorizeLocked(u)
}

// Caller holds s.mu. Returned records are private immutable generations; public
// UserManager reads return copies instead.
func (s *Server) authorizeLocked(u protocol.UserInfo) (*xprotocol.MemoryUser, error) {
	m := s.users[u.UID]
	if m == nil {
		return nil, osession.ErrAuthentication
	}
	a := m.Account.(*MemoryAccount)
	h := sha256.Sum256([]byte(u.Token))
	if subtle.ConstantTimeCompare(h[:], a.token[:]) != 1 || subtle.ConstantTimeCompare([]byte(u.DeviceID), []byte(a.device)) != 1 || a.expires != 0 && time.Now().Unix() >= a.expires {
		return nil, osession.ErrAuthentication
	}
	return m, nil
}

func (s *Server) admit(run *serverRun, wire protocol.UserInfo, expected *xprotocol.MemoryUser) (*xprotocol.MemoryUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.active[run]; !ok || s.closed {
		return nil, osession.ErrClosed
	}
	u, err := s.authorizeLocked(wire)
	if err != nil || expected == nil || u != expected {
		return nil, osession.ErrAuthentication
	}
	run.uid, run.user = wire.UID, u
	return u, nil
}
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	var runs []*serverRun
	for r := range s.active {
		runs = append(runs, r)
	}
	s.mu.Unlock()
	for _, r := range runs {
		r.cancel()
	}
	s.processWG.Wait()
	return nil
}

func (s *Server) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) (err error) {
	defer nativebridge.Recover(&err, func() { _ = conn.Close() })
	if network != s.Network()[0] {
		return errors.New("orbit: incompatible inbound network")
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return errors.New("orbit: session limit reached")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	run := &serverRun{cancel: cancel, conn: conn}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("orbit: server closed")
	}
	s.active[run] = struct{}{}
	s.processWG.Add(1)
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.active, run); s.mu.Unlock(); s.processWG.Done() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if network == xnet.Network_UDP {
		return s.processQUIC(ctx, conn, run, dispatcher)
	}
	raw := net.Conn(conn)
	if s.cfg.Transport == "ws" || s.cfg.Transport == "wss" {
		raw, err = s.acceptWebSocket(ctx, raw)
		if err != nil {
			return err
		}
		defer raw.Close()
	}
	if s.cfg.Security == "reality" {
		var r *otransport.RealityServer
		r, err = s.realityServer(ctx)
		if err != nil {
			return err
		}
		raw, err = r.Accept(ctx, realityHalfClose(raw))
		if err != nil {
			return err
		}
	}
	wrapped, metadata, err := otransport.HTTPServer(ctx, raw, otransport.HTTPServerOptions{Options: otransport.Options{Timeout: time.Duration(s.cfg.HandshakeTimeout) * time.Second}, TLSConfig: s.tls})
	if err != nil {
		return err
	}
	defer wrapped.Close()
	if !terminalMetadata(metadata) {
		return errors.New("orbit: relay metadata is not allowed")
	}
	var authenticated *xprotocol.MemoryUser
	p, err := osession.Server(ctx, wrapped, osession.ServerOptions{RouteMetadata: metadata, Options: osession.Options{MaxFlows: int(s.cfg.MaxFlows), HandshakeTimeout: time.Duration(s.cfg.HandshakeTimeout) * time.Second}, Authenticate: func(_ context.Context, u protocol.UserInfo) error {
		var e error
		authenticated, e = s.authorize(u)
		return e
	}})
	if err != nil {
		return err
	}
	defer p.Close()
	return s.servePeer(ctx, serverTCPPeer{p}, run, authenticated, dispatcher)
}

func (s *Server) realityServer(ctx context.Context) (*otransport.RealityServer, error) {
	for {
		s.realityMu.Lock()
		if s.reality != nil {
			r := s.reality
			s.realityMu.Unlock()
			return r, nil
		}
		if pending := s.realityPending; pending != nil {
			s.realityMu.Unlock()
			select {
			case <-pending:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if time.Now().Before(s.realityRetry) {
			err := s.realityErr
			s.realityMu.Unlock()
			return nil, err
		}
		pending := make(chan struct{})
		s.realityPending = pending
		s.realityMu.Unlock()
		c := s.cfg.Reality
		initCtx, cancel := context.WithTimeout(ctx, time.Duration(s.cfg.HandshakeTimeout)*time.Second)
		r, err := func() (r *otransport.RealityServer, err error) {
			defer nativebridge.Recover(&err, nil)
			return otransport.NewRealityServer(initCtx, otransport.RealityServerOptions{PrivateKey: c.PrivateKey, ServerNames: c.ServerNames, ShortIDs: c.ShortIds, Target: c.Dest})
		}()
		cancel()
		s.realityMu.Lock()
		if err == nil {
			s.reality = r
		} else {
			s.realityErr = err
			s.realityRetry = time.Now().Add(time.Second)
		}
		close(pending)
		s.realityPending = nil
		s.realityMu.Unlock()
		return r, err
	}
}

func inboundContext(ctx context.Context, user *xprotocol.MemoryUser) context.Context {
	in := &xsession.Inbound{}
	if old := xsession.InboundFromContext(ctx); old != nil {
		*in = *old
	}
	u := *user
	in.User = &u
	in.Name = "orbit"
	in.CanSpliceCopy = 3
	ctx = xsession.ContextWithInbound(ctx, in)
	// Dispatcher mutates both the last outbound and content during sniffing.
	// Multiplexed flows must never share these mutable records.
	if old := xsession.OutboundsFromContext(ctx); len(old) != 0 {
		out := make([]*xsession.Outbound, len(old))
		for i, value := range old {
			out[i] = &xsession.Outbound{}
			if value != nil {
				*out[i] = *value
			}
		}
		ctx = xsession.ContextWithOutbounds(ctx, out)
	}
	if old := xsession.ContentFromContext(ctx); old != nil {
		content := *old
		content.SniffingRequest.ExcludeForDomain = append([]string(nil), old.SniffingRequest.ExcludeForDomain...)
		content.SniffingRequest.OverrideDestinationForProtocol = append([]string(nil), old.SniffingRequest.OverrideDestinationForProtocol...)
		if old.Attributes != nil {
			content.Attributes = make(map[string]string, len(old.Attributes))
			for key, value := range old.Attributes {
				content.Attributes[key] = value
			}
		}
		ctx = xsession.ContextWithContent(ctx, &content)
	}
	return ctx
}

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, c interface{}) (interface{}, error) {
		return NewServer(ctx, c.(*ServerConfig))
	}))
}
