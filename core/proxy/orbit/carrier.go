package orbit

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/nativebridge"
	"github.com/xtls/xray-core/proxy/orbit/internal/connectionkey"
	"github.com/xtls/xray-core/proxy/orbit/internal/datagram"
	"github.com/xtls/xray-core/proxy/orbit/internal/pki"
	"github.com/xtls/xray-core/proxy/orbit/internal/protocol"
	"github.com/xtls/xray-core/proxy/orbit/internal/session"
	"github.com/xtls/xray-core/proxy/orbit/internal/transport"
	"github.com/xtls/xray-core/transport/internet"
)

// This file is VPN-Core's engine.Dial/dialOne for one carrier of a private
// link (config.ClientFromConnection): TCP type 2 (pinned TLS, then the
// recovered HTTP upgrade prefix and the header exchange) for tcp/ws/wss, the
// native QUIC Initial envelope and UDP-control stream for quic, the account
// handshake, the reach request, the application-message drain and the UDP
// hub. What changes is only where sockets come from: every TCP, WebSocket and
// QUIC UDP socket is dialed through the outbound's Xray dialer.

// peer is engine.Peer without the server-only Accept.
type peer interface {
	Open(context.Context, string, uint16) (net.Conn, error)
	SendUDP(context.Context, protocol.UDPEnvelope) error
	ReceiveUDP(context.Context) (protocol.UDPEnvelope, error)
	SendApp(context.Context, protocol.AppMessage) error
	ReceiveApp(context.Context) (protocol.AppMessage, error)
	Done() <-chan struct{}
	Err() error
	Close() error
}

type tcpPeer struct{ *session.Session }

func (p tcpPeer) Open(ctx context.Context, h string, port uint16) (net.Conn, error) {
	return p.Session.Open(ctx, h, port)
}

type quicPeer struct{ *transport.QUICSession }

// prober is a peer that can prove its session alive (QUIC's acknowledged
// heartbeat on the UDP-control stream).
type prober interface{ Probe(context.Context) error }

func (p quicPeer) Open(ctx context.Context, h string, port uint16) (net.Conn, error) {
	return p.QUICSession.Open(ctx, h, port)
}

// socketIDs is channel.SocketIDs: one never-reused ID space for every physical
// session of the outbound's channel, across reconnects.
type socketIDs struct{ next atomic.Uint64 }

func (s *socketIDs) Next() (uint32, error) {
	n := s.next.Add(1)
	if n > 0xffffffff {
		return 0, errors.New("orbit: socket ID space exhausted")
	}
	return uint32(n), nil
}

// generation is one authenticated session (VPN-Core's engine.Client).
type generation struct {
	peer      peer
	udp       *datagram.Hub
	ctx       context.Context
	cancel    context.CancelFunc
	transport string
	once      sync.Once
	// probing, probed (UnixNano of the last acknowledged probe) and reason
	// (why the client retired it) belong to Client.suspect.
	probing atomic.Bool
	probed  atomic.Int64
	reason  atomic.Pointer[probeFailure]
}

func (g *generation) alive() bool {
	select {
	case <-g.ctx.Done():
		return false
	case <-g.peer.Done():
		return false
	default:
		return true
	}
}

func (g *generation) close() {
	g.once.Do(func() {
		g.cancel()
		_ = g.peer.Close()
		if g.udp != nil {
			_ = g.udp.Close()
		}
	})
}

// failure is the reason the generation ended, for request errors.
func (g *generation) failure() error {
	if r := g.reason.Load(); r != nil {
		return r
	}
	if e := g.peer.Err(); e != nil {
		return e
	}
	return g.ctx.Err()
}

type dialPlan struct {
	settings  Settings
	timeout   time.Duration
	user      protocol.UserInfo
	pinHex    string
	channelID [16]byte
	ids       *socketIDs
}

func newDialPlan(c *Config) (*dialPlan, error) {
	s, err := settingsOf(c).Normalize()
	if err != nil {
		return nil, err
	}
	credentials, pin, err := connectionkey.Decode(s.Key)
	if err != nil {
		return nil, fieldError("key", "is not a valid private connection key")
	}
	timeout := time.Duration(c.HandshakeTimeout) * time.Second
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	id, err := protocol.NewChannelID()
	if err != nil {
		return nil, err
	}
	return &dialPlan{settings: s, timeout: timeout, pinHex: hex.EncodeToString(pin[:]), channelID: id, ids: new(socketIDs),
		user: protocol.UserInfo{UID: credentials.UID, Token: credentials.Token, DeviceID: credentials.DeviceID}}, nil
}

func (p *dialPlan) serverAddress() string {
	return net.JoinHostPort(p.settings.Address, strconv.FormatUint(uint64(p.settings.Port), 10))
}

// innerName is the inner origin certificate identity: the numeric address for
// tcp/quic, the peer (defaulting to host) for ws/wss.
func (p *dialPlan) innerName() string {
	if p.settings.Transport == "ws" || p.settings.Transport == "wss" {
		return p.settings.Peer
	}
	return p.settings.Address
}

func requestID() (uint32, error) {
	var b [4]byte
	if _, e := rand.Read(b[:]); e != nil {
		return 0, e
	}
	id := binary.LittleEndian.Uint32(b[:])
	if id == 0 {
		id = 1
	}
	return id, nil
}

// errReachTimeout is engine.ErrReachTimeout.
var errReachTimeout = errors.New("orbit: the server did not acknowledge the reach request (516)")

// awaitReachID is engine.awaitReachID: the native state5 readiness, an initial
// type 1 then four retries at 1.5 seconds, satisfied by a type 2 with this
// request's ID (or zero, for the legacy path).
func awaitReachID(ctx context.Context, p peer, id uint32, interval time.Duration, retries int, initialSent, acceptZero bool) error {
	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 || !initialSent {
			if e := p.SendApp(ctx, protocol.AppMessage{Type: 1, RequestID: id}); e != nil {
				return e
			}
		}
		wait, stop := context.WithTimeout(ctx, interval)
		for {
			reply, e := p.ReceiveApp(wait)
			if e != nil {
				stop()
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if errors.Is(e, context.DeadlineExceeded) {
					break
				}
				return e
			}
			if reply.Type == 2 && (reply.RequestID == id || acceptZero && reply.RequestID == 0) {
				// The optional landing JSON cannot fail a valid ACK.
				stop()
				return nil
			}
		}
	}
	return errReachTimeout
}

// dial establishes one generation. base carries the request's outbound
// records for Xray's dialer but not its cancellation; the generation lives
// until it fails or the outbound closes (closing cancels base's child).
func (p *dialPlan) dial(base context.Context, dialer internet.Dialer) (g *generation, err error) {
	ctx, cancel := context.WithCancel(base)
	defer func() {
		if err != nil {
			cancel()
		}
	}()
	var reachID uint32
	if p.settings.Transport != "quic" {
		// supportsReachPipeline: a one-carrier tcp/ws/wss link profile sends
		// the reach request together with the connection request.
		if reachID, err = requestID(); err != nil {
			return nil, err
		}
	}
	var pr peer
	if p.settings.Transport == "quic" {
		pr, err = p.dialQUIC(ctx, dialer)
	} else {
		pr, err = p.dialTCP(ctx, dialer, reachID)
	}
	if err != nil {
		return nil, describe(p.settings.Transport, err)
	}
	if reachID != 0 {
		err = awaitReachID(ctx, pr, reachID, 1500*time.Millisecond, 4, true, false)
	} else {
		var id uint32
		if id, err = requestID(); err == nil {
			err = awaitReachID(ctx, pr, id, 1500*time.Millisecond, 4, false, true)
		}
	}
	if err != nil {
		_ = pr.Close()
		return nil, describe(p.settings.Transport, err)
	}
	g = &generation{peer: pr, ctx: ctx, cancel: cancel, transport: p.settings.Transport}
	// startApps: later application messages (landing updates, events) are
	// drained, as the session ends when its bounded app queue overflows.
	go func() {
		defer nativebridge.RecoverWorker(func(error) { g.close() })
		for {
			if _, e := pr.ReceiveApp(ctx); e != nil {
				return
			}
		}
	}()
	g.udp = datagram.New(ctx, pr, 128)
	go func() {
		defer nativebridge.RecoverWorker(func(error) { g.close() })
		select {
		case <-ctx.Done():
		case <-pr.Done():
		}
		g.close()
	}()
	return g, nil
}

// dialConn dials one physical socket through the outbound's Xray dialer, so
// sockopt, dialerProxy/proxySettings chaining, accounting and the Android
// socket protection apply. Its lifetime is ctx's (the generation's), not that
// of whatever handshake asked for it.
func dialConn(ctx context.Context, dialer internet.Dialer, network xnet.Network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, err
	}
	dest := xnet.Destination{Network: network, Address: xnet.ParseAddress(host), Port: xnet.Port(n)}
	return dialer.Dial(nativebridge.DialContext(ctx, dest, "orbit"), dest)
}

func (p *dialPlan) dialTCP(ctx context.Context, dialer internet.Dialer, reachID uint32) (peer, error) {
	address := p.serverAddress()
	var raw net.Conn
	var err error
	switch p.settings.Transport {
	case "ws", "wss":
		raw, err = transport.DialWebSocket(ctx, transport.WebSocketDialOptions{
			Address: address, Host: p.settings.Host, Path: p.settings.Path,
			Secure: p.settings.Transport == "wss", Timeout: p.timeout,
			DialContext: func(_ context.Context, network, a string) (net.Conn, error) {
				return dialConn(ctx, dialer, xnet.Network_TCP, a)
			},
			Fingerprint: p.settings.Fingerprint, UserAgent: p.settings.UserAgent,
			Headers: p.settings.Headers, Browser: p.settings.Browser,
		})
	default:
		raw, err = dialConn(ctx, dialer, xnet.Network_TCP, address)
	}
	if err != nil {
		return nil, err
	}
	options := transport.HTTPOptions{
		Options: transport.Options{Timeout: p.timeout},
		Type:    2, Header: transport.HTTPHeader{CheaterID: 2, Domain: p.innerName()}, Path: "/",
	}
	if p.settings.Security == "reality" {
		// VPN-Core 0.12 engine.dialOne: REALITY authenticates the outer TCP
		// stream with its own public key, and the native HTTP prefix and
		// account handshake follow inside it with no second TLS. A failed
		// proof closes raw; nothing is sent to the cover.
		hctx, done := context.WithTimeout(ctx, p.timeout)
		r := p.settings.Reality
		raw, err = transport.DialReality(hctx, raw, transport.RealityClientOptions{
			ServerName: r.ServerName, PublicKey: r.PublicKey, ShortID: r.ShortID, Fingerprint: r.Fingerprint,
		})
		done()
		if err != nil {
			return nil, err
		}
		options.Reality = true
	} else {
		tc, err := pki.ClientTLS(p.innerName(), p.pinHex)
		if err != nil {
			raw.Close()
			return nil, err
		}
		options.TLSConfig, options.NativeTLS = tc, p.settings.Transport == "tcp"
	}
	wrapped, err := transport.HTTPClient(ctx, raw, options)
	if err != nil {
		return nil, err
	}
	s, err := session.Client(ctx, wrapped, session.ClientOptions{AllocateSocketID: p.ids.Next, User: p.user,
		ChannelID: p.channelID, InitialReachID: reachID, Options: session.Options{HandshakeTimeout: p.timeout}})
	if err != nil {
		wrapped.Close()
		return nil, err
	}
	return tcpPeer{s}, nil
}

// connectedPacketConn is the net.PacketConn quic-go needs over the connected
// UDP socket Xray's dialer returns (a PacketConnWrapper, a stats wrapper or a
// chained connection). Every datagram goes to and comes from the server.
type connectedPacketConn struct {
	net.Conn
	remote net.Addr
}

func (c *connectedPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.Conn.Read(b)
	return n, c.remote, err
}

func (c *connectedPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) { return c.Conn.Write(b) }

func (p *dialPlan) dialQUIC(ctx context.Context, dialer internet.Dialer) (peer, error) {
	tc, err := pki.ClientTLS(p.innerName(), p.pinHex)
	if err != nil {
		return nil, err
	}
	address := p.serverAddress()
	ip := netip.MustParseAddr(p.settings.Address)
	remote := &net.UDPAddr{IP: ip.AsSlice(), Port: int(p.settings.Port)}
	var cid [4]byte
	if _, err = rand.Read(cid[:]); err != nil {
		return nil, err
	}
	user := p.user
	initial := transport.QUICInitialOptions{AllocateSocketID: p.ids.Next, ChannelID: p.channelID,
		ConnectionID:   binary.LittleEndian.Uint32(cid[:]),
		EncodeUserInfo: func(r io.Reader) ([128]byte, error) { return protocol.EncodeUserInfo(user, r) },
		PacketConnFactory: func(context.Context) (net.PacketConn, error) {
			c, err := dialConn(ctx, dialer, xnet.Network_UDP, address)
			if err != nil {
				return nil, err
			}
			return &connectedPacketConn{Conn: c, remote: remote}, nil
		},
		ResolveUDP: func(context.Context, string) (*net.UDPAddr, error) { return remote, nil },
	}
	hctx, done := context.WithTimeout(ctx, p.timeout)
	defer done()
	q, err := transport.DialQUIC(hctx, address, tc, initial)
	if err != nil {
		return nil, fmt.Errorf("QUIC handshake: %w", err)
	}
	return quicPeer{q}, nil
}

// describe turns a carrier failure into an error that says what happened.
// It never includes key material.
func describe(carrier string, err error) error {
	switch {
	case errors.Is(err, session.ErrAuthentication):
		return fmt.Errorf("orbit %s: the server rejected the private connection key (authentication failed): %w", carrier, err)
	case errors.Is(err, transport.ErrRealityAuthentication):
		// The server answered with something other than REALITY's proof for
		// this key: an official REALITY server hands such a client to its
		// cover, so a wrong pbk, sid or sni, or a clock outside the window
		// all look the same from here.
		return fmt.Errorf("orbit %s: REALITY authentication failed: the server did not prove the REALITY public key (check pbk, sid and sni, and that this device's clock is within the server's window, one minute by default); nothing was sent: %w", carrier, err)
	case errors.Is(err, pki.ErrPinMismatch):
		return fmt.Errorf("orbit %s: the server's TLS key does not match the pin in the private connection key: %w", carrier, err)
	case errors.Is(err, pki.ErrPinnedCertificate):
		return fmt.Errorf("orbit %s: the server's pinned TLS certificate was rejected (validity period, key usage or name): %w", carrier, err)
	case outerCertificateError(err):
		// Only the outer WSS certificate is checked against the system roots.
		return fmt.Errorf("orbit %s: the TLS certificate of the WebSocket front (host) failed verification against the system roots: %w", carrier, err)
	case carrier == "quic" && (errors.Is(err, context.DeadlineExceeded) || isTimeout(err)):
		return fmt.Errorf("orbit quic: QUIC handshake timed out (the server drops an unknown or revoked key silently, or UDP is blocked): %w", err)
	}
	return fmt.Errorf("orbit %s: %w", carrier, err)
}

// outerCertificateError is a standard certificate verification failure, from
// crypto/tls or uTLS (the outer WSS handshake); the inner pinned check never
// produces one without a pki sentinel.
func outerCertificateError(err error) bool {
	var verify *tls.CertificateVerificationError
	var uverify *utls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	return errors.As(err, &verify) || errors.As(err, &uverify) || errors.As(err, &unknown) ||
		errors.As(err, &hostname) || errors.As(err, &invalid)
}

func isTimeout(err error) bool {
	var t interface{ Timeout() bool }
	return errors.As(err, &t) && t.Timeout()
}
