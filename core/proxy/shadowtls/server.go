package shadowtls

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/nativebridge"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	ss2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/proxy/vless"
	vlessin "github.com/xtls/xray-core/proxy/vless/inbound"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"google.golang.org/protobuf/proto"
)

type Server struct {
	config      *ServerConfig
	inner       proxy.Inbound
	mu          sync.Mutex
	users       []*ServerUser // immutable entries; replaced under mu
	connections map[net.Conn]*serverConnection
	workers     sync.WaitGroup
	closed      bool
}

type serverConnection struct {
	cancel context.CancelFunc
	user   *ServerUser // immutable generation selected at final admission
}

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, c interface{}) (result interface{}, err error) {
		defer nativebridge.Recover(&err, nil)
		return NewServer(ctx, c.(*ServerConfig))
	}))
}

func validateServerUser(u *ServerUser) error {
	if u == nil || u.Password == "" {
		return errors.New("ShadowTLS client password is required")
	}
	if u.RequireUuidSessionId {
		if _, err := uuid.Parse(u.Password); err != nil {
			return errors.New("requireUuidSessionId requires a UUID password")
		}
	}
	return nil
}

// ValidateServerConfig is shared by JSON and protobuf constructors, so API and
// restored configurations cannot bypass the same version and inner policy.
func ValidateServerConfig(c *ServerConfig) error {
	if c == nil {
		return errors.New("missing ShadowTLS server settings")
	}
	if c.Version < 1 || c.Version > 3 {
		return errors.New("ShadowTLS version must be 1, 2 or 3")
	}
	if strings.TrimSpace(c.HandshakeAddress) == "" || c.HandshakePort == 0 || c.HandshakePort > 65535 {
		return errors.New("valid ShadowTLS handshake address and port are required")
	}
	if c.HandshakeTimeout > 300 {
		return errors.New("ShadowTLS handshakeTimeout must not exceed 300 seconds")
	}
	if c.Version == 2 && c.Password == "" {
		return errors.New("ShadowTLS v2 password is required")
	}
	if c.Version != 3 && len(c.Clients) != 0 {
		return errors.New("ShadowTLS clients require version 3; use password for version 2")
	}
	// Empty is a valid deny-all state after the panel filters expired users.
	// It must not prevent unrelated inbounds from starting.
	if c.Version == 3 && len(c.Clients) > 10000 {
		return errors.New("ShadowTLS v3 allows at most 10000 clients")
	}
	emails, passwords := map[string]bool{}, map[string]bool{}
	for _, u := range c.Clients {
		if err := validateServerUser(u); err != nil {
			return err
		}
		email := strings.ToLower(u.Email)
		if u.Email != "" && emails[email] {
			return errors.New("duplicate ShadowTLS client email")
		}
		if passwords[u.Password] {
			return errors.New("duplicate ShadowTLS client password")
		}
		emails[email], passwords[u.Password] = true, true
	}
	if c.Inner == nil {
		return errors.New("ShadowTLS requires an authenticated inner proxy")
	}
	inner, err := c.Inner.GetInstance()
	if err != nil {
		return err
	}
	switch cfg := inner.(type) {
	case *socks.ServerConfig:
		if cfg.AuthType != socks.AuthType_PASSWORD || cfg.UdpEnabled {
			return errors.New("ShadowTLS inner SOCKS requires password authentication and udp:false")
		}
		for user, pass := range cfg.Accounts {
			if user == "" || pass == "" || len(user) > 255 || len(pass) > 255 {
				return errors.New("invalid ShadowTLS inner SOCKS account")
			}
		}
	case *vlessin.Config:
		if len(cfg.Fallbacks) > 0 || cfg.Decryption != "none" {
			return errors.New("ShadowTLS inner VLESS requires decryption:none and no fallbacks")
		}
		for _, u := range cfg.Clients {
			a, err := u.GetTypedAccount()
			if err != nil {
				return err
			}
			va, ok := a.(*vless.MemoryAccount)
			if !ok || va.Flow != "" {
				return errors.New("ShadowTLS inner VLESS does not support Vision flow")
			}
		}
	case *shadowsocks.ServerConfig:
		if err := validateInnerSSNetworks(cfg.Network); err != nil {
			return err
		}
		for _, user := range cfg.Users {
			if user == nil || user.Account == nil {
				return errors.New("invalid ShadowTLS inner Shadowsocks user")
			}
			account, err := user.Account.GetInstance()
			if err != nil {
				return err
			}
			a, ok := account.(*shadowsocks.Account)
			if !ok || a.Password == "" || a.CipherType < shadowsocks.CipherType_AES_128_GCM || a.CipherType > shadowsocks.CipherType_XCHACHA20_POLY1305 {
				return errors.New("ShadowTLS inner Shadowsocks requires an AEAD cipher and password")
			}
		}
	case *ss2022.ServerConfig:
		if err := validateInnerSSNetworks(cfg.Network); err != nil {
			return err
		}
		if err := validateInner2022Key(cfg.Method, cfg.Key, false); err != nil {
			return err
		}
	case *ss2022.MultiUserServerConfig:
		if err := validateInnerSSNetworks(cfg.Network); err != nil {
			return err
		}
		if err := validateInner2022Key(cfg.Method, cfg.Key, true); err != nil {
			return err
		}
		for _, user := range cfg.Users {
			if user == nil || user.Account == nil {
				return errors.New("invalid ShadowTLS inner SS2022 user")
			}
			account, err := user.Account.GetInstance()
			if err != nil {
				return err
			}
			a, ok := account.(*ss2022.Account)
			if !ok {
				return errors.New("invalid ShadowTLS inner SS2022 account")
			}
			if err := validateInner2022Key(cfg.Method, a.Key, true); err != nil {
				return err
			}
		}
	default:
		return errors.New("ShadowTLS inner protocol must be socks, vless or AEAD shadowsocks")
	}
	return nil
}

func validateInnerSSNetworks(networks []xnet.Network) error {
	for _, network := range networks {
		if network != xnet.Network_TCP {
			return errors.New("ShadowTLS inner Shadowsocks network must be tcp; use UoT for UDP")
		}
	}
	return nil
}

func validateInner2022Key(method, key string, multi bool) error {
	size := 32
	switch method {
	case "2022-blake3-aes-128-gcm":
		size = 16
	case "2022-blake3-aes-256-gcm":
	case "2022-blake3-chacha20-poly1305":
		if multi {
			return errors.New("ShadowTLS inner multi-user SS2022 requires AES-GCM")
		}
	default:
		return errors.New("unsupported ShadowTLS inner SS2022 cipher")
	}
	b, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(b) != size {
		return errors.New("invalid ShadowTLS inner SS2022 key length or encoding")
	}
	return nil
}

func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	if config == nil {
		return nil, errors.New("missing ShadowTLS server settings")
	}
	c := proto.Clone(config).(*ServerConfig)
	if c.Version == 0 {
		c.Version = 3
	}
	if c.HandshakePort == 0 {
		c.HandshakePort = 443
	}
	if err := ValidateServerConfig(c); err != nil {
		return nil, err
	}
	innerConfig, err := c.Inner.GetInstance()
	if err != nil {
		return nil, err
	}
	// SOCKS expects the same cone context provided by the normal loader. This
	// private context does not mutate existing protocol configuration or state.
	if ctx.Value("cone") == nil {
		ctx = context.WithValue(ctx, "cone", false)
	}
	inner, err := common.CreateObject(ctx, innerConfig)
	if err != nil {
		return nil, err
	}
	p, ok := inner.(proxy.Inbound)
	if !ok {
		_ = common.Close(inner)
		return nil, errors.New("invalid ShadowTLS inner inbound")
	}
	return &Server{config: c, inner: p, users: c.Clients, connections: make(map[net.Conn]*serverConnection)}, nil
}

func (s *Server) Network() []xnet.Network { return []xnet.Network{xnet.Network_TCP} }

func (s *Server) Process(ctx context.Context, network xnet.Network, raw stat.Connection, dispatcher routing.Dispatcher) (err error) {
	defer nativebridge.Recover(&err, nil)
	if network != xnet.Network_TCP {
		return errors.New("ShadowTLS requires TCP; encapsulate UDP in the inner VLESS protocol")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	cfg := proto.Clone(s.config).(*ServerConfig)
	cfg.Clients = append([]*ServerUser(nil), s.users...)
	s.connections[raw] = &serverConnection{cancel: cancel}
	s.workers.Add(1)
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.connections, raw); s.mu.Unlock(); _ = raw.Close(); s.workers.Done() }()
	timeout := cfg.HandshakeTimeout
	if timeout == 0 {
		timeout = 10
	}
	handshakeCtx, handshakeCancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer handshakeCancel()
	clearDeadline := nativebridge.SetupDeadline(handshakeCtx, raw, time.Duration(timeout)*time.Second)
	dest := xnet.TCPDestination(xnet.ParseAddress(cfg.HandshakeAddress), xnet.Port(cfg.HandshakePort))
	peer, err := internet.DialSystem(handshakeCtx, dest, nil)
	if err != nil {
		clearDeadline()
		return err
	}
	_ = peer.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	conn, user, err := ServerHandshake(handshakeCtx, raw, peer, cfg)
	clearDeadline()
	handshakeCancel()
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err := s.admit(raw, user); err != nil {
		return err
	}
	if in := session.InboundFromContext(ctx); in != nil {
		copyIn := *in
		copyIn.Name, copyIn.Conn, copyIn.CanSpliceCopy = "shadowtls", conn, 3
		ctx = session.ContextWithInbound(ctx, &copyIn)
	}
	carrier := &carrierDispatcher{Dispatcher: dispatcher, user: user}
	stopCarrier := context.AfterFunc(ctx, carrier.interrupt)
	defer func() { cancel(); stopCarrier(); carrier.interrupt(); carrier.workers.Wait() }()
	return s.inner.Process(ctx, xnet.Network_TCP, conn, carrier)
}

func (s *Server) admit(raw net.Conn, user *ServerUser) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	connection, ok := s.connections[raw]
	if !ok || s.closed {
		return net.ErrClosed
	}
	if s.config.Version == 3 {
		valid := false
		for _, active := range s.users {
			if active == user {
				valid = true
				break
			}
		}
		if !valid {
			return ErrUnauthenticated
		}
		connection.user = user
	}
	return nil
}

// The inner decoder supplies the destination, while the authenticated carrier
// account remains the panel's identity for routing, quota and traffic counters.
type carrierDispatcher struct {
	routing.Dispatcher
	user    *ServerUser
	workers sync.WaitGroup
	mu      sync.Mutex
	links   []*transport.Link
	closed  bool
}

func (d *carrierDispatcher) track(link *transport.Link) *transport.Link {
	d.mu.Lock()
	if !d.closed {
		d.links = append(d.links, link)
		d.mu.Unlock()
		return link
	}
	d.mu.Unlock()
	_ = common.Interrupt(link.Reader)
	_ = common.Interrupt(link.Writer)
	return link
}
func (d *carrierDispatcher) interrupt() {
	d.mu.Lock()
	d.closed = true
	links := d.links
	d.links = nil
	d.mu.Unlock()
	for _, link := range links {
		_ = common.Interrupt(link.Reader)
		_ = common.Interrupt(link.Writer)
	}
}

func (d *carrierDispatcher) context(ctx context.Context) context.Context {
	if in := session.InboundFromContext(ctx); in != nil {
		copied := *in
		copied.Name, copied.CanSpliceCopy = "shadowtls", 3
		if d.user != nil {
			copied.User = serverMemoryUser(d.user)
		}
		return session.ContextWithInbound(ctx, &copied)
	}
	return ctx
}
func (d *carrierDispatcher) Dispatch(ctx context.Context, target xnet.Destination) (*transport.Link, error) {
	ctx = d.context(ctx)
	if version := shadowTLSUOTVersion(target); version != 0 {
		// Serialize worker admission with interrupt so shutdown cannot wait
		// on an empty group while an embedded handler starts a late UoT flow.
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.closed || ctx.Err() != nil {
			return nil, net.ErrClosed
		}
		link := shadowTLSUOTLink(ctx, d.Dispatcher, version, &d.workers)
		d.links = append(d.links, link)
		return link, nil
	}
	link, err := d.Dispatcher.Dispatch(ctx, target)
	if err != nil {
		return nil, err
	}
	return d.track(link), nil
}
func (d *carrierDispatcher) DispatchLink(ctx context.Context, target xnet.Destination, link *transport.Link) error {
	d.track(link)
	return d.Dispatcher.DispatchLink(d.context(ctx), target, link)
}

func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	connections := s.connections
	s.connections = make(map[net.Conn]*serverConnection)
	s.mu.Unlock()
	for conn, state := range connections {
		state.cancel()
		_ = conn.Close()
	}
	s.workers.Wait()
	return common.Close(s.inner)
}

func (u *ServerUser) AsAccount() (protocol.Account, error) {
	if err := validateServerUser(u); err != nil {
		return nil, err
	}
	return &serverAccount{value: proto.Clone(u).(*ServerUser)}, nil
}

type serverAccount struct{ value *ServerUser }

func (a *serverAccount) Equals(b protocol.Account) bool {
	other, ok := b.(*serverAccount)
	return ok && a.value.Password == other.value.Password && a.value.RequireUuidSessionId == other.value.RequireUuidSessionId
}
func (a *serverAccount) ToProto() proto.Message { return proto.Clone(a.value) }
func serverMemoryUser(u *ServerUser) *protocol.MemoryUser {
	return &protocol.MemoryUser{Email: u.Email, Level: u.Level, Account: &serverAccount{value: proto.Clone(u).(*ServerUser)}}
}
func (s *Server) AddUser(_ context.Context, user *protocol.MemoryUser) error {
	if user == nil {
		return errors.New("missing ShadowTLS user")
	}
	a, ok := user.Account.(*serverAccount)
	if !ok {
		return errors.New("invalid ShadowTLS account type")
	}
	u := proto.Clone(a.value).(*ServerUser)
	u.Email, u.Level = user.Email, user.Level
	if err := validateServerUser(u); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	if s.config.Version != 3 {
		return errors.New("ShadowTLS dynamic users require version 3")
	}
	if len(s.users) >= 10000 {
		return errors.New("ShadowTLS client limit reached")
	}
	for _, old := range s.users {
		if old.Password == u.Password || (u.Email != "" && strings.EqualFold(old.Email, u.Email)) {
			return errors.New("duplicate ShadowTLS user")
		}
	}
	s.users = append(s.users, u)
	return nil
}
func (s *Server) RemoveUser(_ context.Context, email string) error {
	s.mu.Lock()
	for i, u := range s.users {
		if strings.EqualFold(u.Email, email) {
			s.users = append(s.users[:i:i], s.users[i+1:]...)
			active := make(map[net.Conn]*serverConnection)
			for conn, state := range s.connections {
				if state.user == u {
					active[conn] = state
				}
			}
			s.mu.Unlock()
			for conn, state := range active {
				state.cancel()
				_ = conn.Close()
			}
			return nil
		}
	}
	s.mu.Unlock()
	return errors.New("ShadowTLS user not found")
}
func (s *Server) GetUser(_ context.Context, email string) *protocol.MemoryUser {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if strings.EqualFold(u.Email, email) {
			return serverMemoryUser(u)
		}
	}
	return nil
}
func (s *Server) GetUsers(_ context.Context) []*protocol.MemoryUser {
	s.mu.Lock()
	defer s.mu.Unlock()
	users := make([]*protocol.MemoryUser, 0, len(s.users))
	for _, u := range s.users {
		users = append(users, serverMemoryUser(u))
	}
	return users
}
func (s *Server) GetUsersCount(context.Context) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return int64(len(s.users))
}

var _ proxy.Inbound = (*Server)(nil)
var _ proxy.UserManager = (*Server)(nil)
