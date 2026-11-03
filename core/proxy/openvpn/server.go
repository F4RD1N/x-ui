package openvpn

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/nativebridge"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/ctlwrap"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/handshake"
	ovserver "github.com/xtls/xray-core/proxy/openvpn/ovpn/server"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, c interface{}) (interface{}, error) {
		return NewServer(ctx, c.(*ServerConfig))
	}))
}

// Server is a native OpenVPN inbound. Each accepted peer owns a separate engine,
// address lease, packet stack and routing context; unrelated protocols are untouched.
type Server struct {
	settings  *ServerSettings
	tlsConfig *tls.Config
	policy    policy.Manager
	mu        sync.Mutex
	closed    bool
	users     map[string]ServerUser // indexed by authenticated certificate CN
	peers     map[*serverPeer]struct{}
	perIP     map[string]int
	leases    map[uint32]bool
	wg        sync.WaitGroup
}
type serverPeer struct {
	cancel     context.CancelFunc
	user       ServerUser
	index      uint32
	remote     string
	ipv4, ipv6 netip.Addr
}

func NewServer(ctx context.Context, c *ServerConfig) (*Server, error) {
	v := core.MustFromContext(ctx)
	return newServer(c, v.GetFeature(policy.ManagerType()).(policy.Manager))
}
func newServer(c *ServerConfig, pm policy.Manager) (*Server, error) {
	if c == nil {
		return nil, errors.New("OpenVPN server config missing")
	}
	settings, e := ParseServerSettings(c.Settings)
	if e != nil {
		return nil, e
	}
	tc, e := settings.tlsConfig()
	if e != nil {
		return nil, e
	}
	s := &Server{settings: settings, tlsConfig: tc, policy: pm, users: map[string]ServerUser{}, peers: map[*serverPeer]struct{}{}, perIP: map[string]int{}, leases: map[uint32]bool{}}
	for _, u := range settings.Clients {
		s.users[u.CommonName] = u
	}
	return s, nil
}
func (s *Server) Network() []xnet.Network {
	if s.settings.Network == "tcp" {
		return []xnet.Network{xnet.Network_TCP}
	}
	return []xnet.Network{xnet.Network_UDP}
}
func (s *Server) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) (err error) {
	defer nativebridge.Recover(&err, func() { _ = conn.Close() })
	if network != s.Network()[0] {
		return errors.New("OpenVPN transport mismatch")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	peer, e := s.acquire(conn.RemoteAddr(), cancel)
	if e != nil {
		return e
	}
	defer s.release(peer)
	pc := newServerPacketConn(conn, network == xnet.Network_TCP)
	stop := context.AfterFunc(ctx, func() { _ = pc.Close() })
	defer stop()
	defer pc.Close()
	cfg, e := s.engineConfig(ctx, peer)
	if e != nil {
		return e
	}
	sess, e := ovserver.Serve(ctx, pc, cfg)
	if e != nil {
		return e
	}
	defer sess.Close()
	return s.routeSession(ctx, peer, sess, dispatcher)
}
func (s *Server) acquire(addr net.Addr, cancel context.CancelFunc) (*serverPeer, error) {
	remote, _, e := net.SplitHostPort(addr.String())
	if e != nil {
		remote = addr.String()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("OpenVPN server closed")
	}
	if len(s.peers) >= s.settings.Limits.MaxSessions || s.perIP[remote] >= s.settings.Limits.MaxSessionsPerIP {
		return nil, errors.New("OpenVPN session limit reached")
	}
	var index uint32
	for i := uint32(2); i < uint32(s.settings.Limits.MaxSessions)+2; i++ {
		if !s.leases[i] {
			index = i
			break
		}
	}
	if index == 0 {
		return nil, errors.New("OpenVPN address pool exhausted")
	}
	p4 := netip.MustParsePrefix(s.settings.Tunnel.IPv4)
	p := &serverPeer{cancel: cancel, index: index, remote: remote, ipv4: addAddress(p4.Addr(), index)}
	if s.settings.Tunnel.IPv6 != "" {
		p.ipv6 = addAddress(netip.MustParsePrefix(s.settings.Tunnel.IPv6).Addr(), index)
	}
	s.leases[index] = true
	s.peers[p] = struct{}{}
	s.perIP[remote]++
	s.wg.Add(1)
	return p, nil
}
func addAddress(a netip.Addr, n uint32) netip.Addr {
	for n > 0 {
		a = a.Next()
		n--
	}
	return a
}
func (s *Server) release(p *serverPeer) {
	s.mu.Lock()
	delete(s.peers, p)
	delete(s.leases, p.index)
	s.perIP[p.remote]--
	if s.perIP[p.remote] == 0 {
		delete(s.perIP, p.remote)
	}
	s.mu.Unlock()
	s.wg.Done()
}
func (s *Server) engineConfig(ctx context.Context, p *serverPeer) (ovserver.Config, error) {
	conf := s.settings
	c := ovserver.Config{TLSConfig: s.tlsConfig, Ciphers: conf.Crypto.DataCiphers, Auth: conf.Crypto.AuthHash, TCP: conf.Network == "tcp", Renegotiate: time.Duration(conf.RenegotiationSeconds) * time.Second, HandshakeTimeout: time.Duration(conf.Limits.HandshakeSeconds) * time.Second, IdleTimeout: time.Duration(conf.Limits.IdleSeconds) * time.Second, KeyDirection: ctlwrap.Bidirectional, PeerID: p.index}
	switch {
	case conf.Certificates.TLSAuth != "":
		c.Wrapper = "tls-auth"
		c.StaticKey, _ = ctlwrap.ParseStaticKey([]byte(conf.Certificates.TLSAuth))
		if conf.Certificates.KeyDirection != nil {
			c.KeyDirection = ctlwrap.Direction(*conf.Certificates.KeyDirection)
		}
	case conf.Certificates.TLSCrypt != "":
		c.Wrapper = "tls-crypt"
		c.StaticKey, _ = ctlwrap.ParseStaticKey([]byte(conf.Certificates.TLSCrypt))
	case conf.Certificates.TLSCryptV2 != "":
		c.Wrapper = "tls-crypt-v2"
		var e error
		c.TLSCryptV2Key, e = ctlwrap.ParseTLSCryptV2ServerKey([]byte(conf.Certificates.TLSCryptV2))
		if e != nil {
			return c, errors.New("invalid OpenVPN TLS-crypt-v2 server key")
		}
	}
	c.Authenticate = func(authctx context.Context, m *handshake.ClientMessage, cs tls.ConnectionState) (ovserver.Admission, error) {
		deny := errors.New("OpenVPN client authentication rejected")
		if authctx.Err() != nil || ctx.Err() != nil || len(cs.PeerCertificates) == 0 {
			return ovserver.Admission{}, deny
		}
		s.mu.Lock()
		u, ok := s.users[cs.PeerCertificates[0].Subject.CommonName]
		closed := s.closed
		s.mu.Unlock()
		if !ok || closed || authenticateUser(u, m, cs) != nil {
			return ovserver.Admission{}, deny
		}
		s.mu.Lock()
		if current, ok := s.users[u.CommonName]; !ok || !sameUser(current, u) || s.closed {
			s.mu.Unlock()
			return ovserver.Admission{}, deny
		}
		if p.user.Email != "" && !sameUser(p.user, u) {
			s.mu.Unlock()
			return ovserver.Admission{}, deny
		}
		// The authenticated identity is immutable for the whole tunnel. A
		// rekey cannot relabel already active or newly dispatched flows.
		if p.user.Email == "" {
			p.user = u
		}
		s.mu.Unlock()
		return ovserver.Admission{Identity: u.Email, Push: s.pushOptions(p)}, nil
	}
	return c, nil
}
func sameUser(a, b ServerUser) bool {
	aa, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(aa) == string(bb)
}
func (s *Server) pushOptions(p *serverPeer) []string {
	prefix := netip.MustParsePrefix(s.settings.Tunnel.IPv4)
	mask := net.CIDRMask(prefix.Bits(), 32)
	out := []string{"topology subnet", fmt.Sprintf("ifconfig %s %s", p.ipv4, net.IP(mask).String()), "route-gateway " + prefix.Addr().Next().String(), "ping 10", fmt.Sprintf("ping-restart %d", s.settings.Limits.IdleSeconds), fmt.Sprintf("tun-mtu %d", s.settings.Tunnel.MTU)}
	if p.ipv6.IsValid() {
		v6 := netip.MustParsePrefix(s.settings.Tunnel.IPv6)
		out = append(out, fmt.Sprintf("ifconfig-ipv6 %s/%d %s", p.ipv6, v6.Bits(), v6.Addr().Next()))
	}
	for _, d := range s.settings.Tunnel.DNS {
		out = append(out, "dhcp-option DNS "+d)
	}
	return out
}
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		s.wg.Wait()
		return nil
	}
	s.closed = true
	cancel := make([]context.CancelFunc, 0, len(s.peers))
	for p := range s.peers {
		cancel = append(cancel, p.cancel)
	}
	s.mu.Unlock()
	for _, f := range cancel {
		f()
	}
	s.wg.Wait()
	return nil
}
func (s *Server) AddUser(_ context.Context, u *protocol.MemoryUser) error {
	if u == nil {
		return errors.New("OpenVPN user missing")
	}
	a, ok := u.Account.(*MemoryServerAccount)
	if !ok {
		return errors.New("OpenVPN account type required")
	}
	c := a.User
	if c.ClientProof != nil {
		proof := *c.ClientProof
		c.ClientProof = &proof
	}
	c.Email = u.Email
	c.Level = u.Level
	if e := c.validate(s.settings.ClientProof.Required); e != nil {
		return e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("OpenVPN server closed")
	}
	if len(s.users) >= 4096 {
		return errors.New("OpenVPN client limit")
	}
	for _, existing := range s.users {
		if existing.Email == c.Email || existing.CommonName == c.CommonName || (existing.ClientProof != nil && c.ClientProof != nil && existing.ClientProof.KeyID == c.ClientProof.KeyID) {
			return errors.New("duplicate OpenVPN client")
		}
	}
	s.users[c.CommonName] = c
	return nil
}
func (s *Server) RemoveUser(_ context.Context, email string) error {
	s.mu.Lock()
	found := false
	for cn, u := range s.users {
		if u.Email == email {
			delete(s.users, cn)
			found = true
			break
		}
	}
	var cancel []context.CancelFunc
	for p := range s.peers {
		if p.user.Email == email {
			cancel = append(cancel, p.cancel)
		}
	}
	s.mu.Unlock()
	for _, f := range cancel {
		f()
	}
	if !found {
		return errors.New("OpenVPN client not found")
	}
	return nil
}
func memoryServerUser(u ServerUser) *protocol.MemoryUser {
	if u.ClientProof != nil {
		p := *u.ClientProof
		u.ClientProof = &p
	}
	return &protocol.MemoryUser{Email: u.Email, Level: u.Level, Account: &MemoryServerAccount{User: u}}
}
func (s *Server) GetUser(_ context.Context, email string) *protocol.MemoryUser {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.Email == email {
			return memoryServerUser(u)
		}
	}
	return nil
}
func (s *Server) GetUsers(context.Context) []*protocol.MemoryUser {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*protocol.MemoryUser, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, memoryServerUser(u))
	}
	return out
}
func (s *Server) GetUsersCount(context.Context) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return int64(len(s.users))
}
