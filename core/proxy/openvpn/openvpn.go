// Package openvpn is Xray's OpenVPN client outbound.
//
// The protocol lives in ./ovpn (no Xray imports); this package binds one
// ovpn/client session to a gVisor userspace stack (proxy/wireguard/gvisortun)
// and dials each Xray request through that stack, the way the WireGuard
// outbound does.
//
// The session is made on first use with the dialer Process is handed (so
// sockopt, dialerProxy and Android socket protection apply to the OpenVPN
// transport), on a context that keeps the first request's values but not its
// cancellation. Concurrent requests during the handshake wait for it. When
// the session dies, the stack goes with it, and the next request builds a
// new pair. A failed setup is not retried at once (retry.go): requests fail
// with its error until the back-off allows a new attempt, and for good once
// the server answered AUTH_FAILED (other than to a pushed auth-token) or
// HALT. Close (called when the Xray instance closes) ends the session.
//
// A UDP link sends each datagram to its own destination (b.UDP) and labels
// each reply with its source, so one link carries a whole SOCKS UDP
// association (udp.go).
//
// A TCP link keeps each direction open until its own end, as on the plain IP
// link a stock client gives: the client's end goes to the destination as a
// FIN and the reply still comes back, and the destination's FIN ends only
// the reply (tcp.go).
//
// Unlike WireGuard, a live session is kept when a later request comes with a
// different dialer. An OpenVPN session is server-side state -- a TLS
// handshake, an authenticated login, an address lease, often a
// one-session-per-user limit -- and replacing it would cut every connection
// in flight for nothing: in Xray the dialer is the outbound handler itself,
// the same object for every request, so a different one does not mean a
// different route to the server.
package openvpn

import (
	"context"
	goerrors "errors"
	gonet "net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy/openvpn/internal/icmpecho"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/client"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/clientproof"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/options"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}

// errClosed is returned to requests once Close was called.
var errClosed = goerrors.New("the OpenVPN outbound is closed")

// Handler is the OpenVPN outbound.
type Handler struct {
	proof         *clientproof.Key
	conf          *Config
	policyManager policy.Manager
	dns           dns.Client
	// Explicit transport families use system bootstrap DNS, independently of
	// application DNS routes that may themselves depend on this tunnel.
	transportResolver transportIPResolver
	now               func() time.Time // the back-off's clock; tests replace it

	mu       sync.Mutex
	tun      *tunnel // the current tunnel, possibly dead
	building *build  // the tunnel being made, nil when none
	closed   bool
	// The back-off after failed session setups (retry.go). failures counts
	// the setups that failed in a row and lastErr is the last one's error;
	// no setup starts before retryAt, and none at all once stopped (the
	// server rejected this configuration: AUTH_FAILED or HALT).
	failures int
	lastErr  error
	retryAt  time.Time
	stopped  bool
}

// build is one tunnel being made. tun and err are set before done closes.
type build struct {
	done   chan struct{}
	cancel context.CancelFunc
	tun    *tunnel
	err    error
}

// New validates conf (parsing its ovpn text) and returns the outbound. It
// does not connect.
func New(ctx context.Context, conf *Config) (*Handler, error) {
	v := core.MustFromContext(ctx)
	return newHandler(conf,
		v.GetFeature(policy.ManagerType()).(policy.Manager),
		v.GetFeature(dns.ClientType()).(dns.Client))
}

func newHandler(conf *Config, pm policy.Manager, d dns.Client) (*Handler, error) {
	if _, err := conf.ParseOptions(); err != nil {
		return nil, err
	}
	proof, err := conf.proofKey()
	if err != nil {
		return nil, err
	}
	return &Handler{conf: conf, proof: proof, policyManager: pm, dns: d, now: time.Now}, nil
}

// Process implements proxy.Outbound.
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		return errors.New("target not specified")
	}
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified")
	}
	ob.Name = "ov"
	ob.CanSpliceCopy = 3
	destination := ob.Target
	// A UDP link to port 0 carries pings (common/icmpecho): each names its
	// own address, resolved per echo for the echo's family.
	echoOnly := destination.Network == xnet.Network_UDP && icmpecho.IsMarker(destination)

	t, err := h.getTunnel(ctx, dialer)
	if err != nil {
		return errors.New("OpenVPN tunnel unavailable").Base(err)
	}
	var addrPort netip.AddrPort
	if !echoOnly {
		addrPort, err = h.resolve(t, destination)
		if err != nil {
			return err
		}
	}

	var newCtx context.Context
	var newCancel context.CancelFunc
	if session.TimeoutOnlyFromContext(ctx) {
		newCtx, newCancel = context.WithCancel(context.Background())
	}

	p := h.policyManager.ForLevel(0)
	// Newer core inbounds dispatch socket links directly and do not own a
	// separate inactivity timer. Apply their authenticated level here.
	ownsHalfCloseTimer := false
	if in := session.InboundFromContext(ctx); in != nil && in.Timer == nil && in.Name != "" {
		ownsHalfCloseTimer = true
		if in.User != nil {
			p = h.policyManager.ForLevel(in.User.Level)
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
		if newCancel != nil {
			newCancel()
		}
	}, p.Timeouts.ConnectionIdle)

	var requestFunc, responseFunc func() error
	// endDownlink, when set, runs before the link's writer is interrupted.
	var endDownlink func()
	if destination.Network == xnet.Network_UDP {
		// Each datagram goes to its own destination (b.UDP) and each reply
		// says where it came from: one link can carry many destinations.
		u, err := newUDPLink(ctx, h, t, destination, addrPort, link.Writer)
		if err != nil {
			return err
		}
		defer u.close()
		// The pings on the link go through the tunnel as real ICMP.
		echo := h.newEchoFlow(ctx, t, u.out, timer)
		defer echo.Close()
		requestFunc = func() error {
			defer timer.SetTimeout(p.Timeouts.DownlinkOnly)
			return buf.Copy(link.Reader, &icmpecho.LinkWriter{Flow: echo, Target: destination, Next: u}, buf.UpdateActivity(timer))
		}
		responseFunc = func() error {
			defer timer.SetTimeout(p.Timeouts.UplinkOnly)
			return u.copyReplies(timer)
		}
	} else {
		conn, err := t.net.DialContextTCPAddrPort(ctx, addrPort)
		if err != nil {
			return errors.New("failed to connect to ", addrPort, " inside the OpenVPN tunnel").Base(err)
		}
		defer conn.Close()
		// Each direction ends on its own (tcp.go), so the idle timer may
		// still be at the connection-idle timeout when both are over: stop
		// it with the connection.
		defer timer.SetTimeout(0)
		// Once the destination ended its side, only the client's is waited
		// for, and the end of the tunnel does not wake that wait: end the
		// connection with the tunnel.
		defer context.AfterFunc(t.ctx, func() { timer.SetTimeout(0) })()
		r := &tcpRelay{conn: conn, link: link, timer: timer, tun: t, downlinkOnly: p.Timeouts.DownlinkOnly, noHalfClose: session.MuxStreamFromContext(ctx), ownHalfCloseTimer: ownsHalfCloseTimer, uplinkOnly: p.Timeouts.UplinkOnly}
		var inDownlinkOnly time.Duration
		r.inTimer, r.inIdle, inDownlinkOnly = h.inboundTimer(ctx)
		r.inTick = feedInterval(inDownlinkOnly)
		requestFunc, responseFunc, endDownlink = r.uplink, r.downlink, r.endDownlink
	}

	if newCtx != nil {
		ctx = newCtx
	}

	responseDonePost := task.OnSuccess(responseFunc, task.Close(link.Writer))
	if err := task.Run(ctx, requestFunc, responseDonePost); err != nil {
		if endDownlink != nil {
			endDownlink()
		}
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		return errors.New("connection ends").Base(err)
	}
	return nil
}

// Close ends the session.
func (h *Handler) Close() error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	t, b := h.tun, h.building
	h.tun = nil
	h.mu.Unlock()

	if b != nil {
		// The build sees closed when it ends and releases what it made.
		b.cancel()
		timer := time.NewTimer(teardownWait)
		select {
		case <-b.done:
		case <-timer.C:
		}
		timer.Stop()
	}
	if t != nil {
		t.close()
	}
	return nil
}

// getTunnel returns the live tunnel, or makes one (one build at a time; a
// request that finds a build in flight waits for it, until its own ctx ends).
// After a failed build it makes none until the back-off allows it, and none
// at all once the server rejected the configuration: until then requests
// fail at once with the last error.
func (h *Handler) getTunnel(ctx context.Context, dialer internet.Dialer) (*tunnel, error) {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil, errClosed
	}
	if t := h.tun; t != nil {
		if t.alive() {
			h.mu.Unlock()
			return t, nil
		}
		if h.sessionEnded(t) {
			cause, err := h.lastErr, h.holdOff()
			h.mu.Unlock()
			errors.LogWarningInner(ctx, cause, "the OpenVPN server ended the session and rejected this configuration; not connecting again until it is reloaded")
			return nil, err
		}
	}
	b := h.building
	if b == nil {
		if err := h.holdOff(); err != nil {
			h.mu.Unlock()
			return nil, err
		}
		b = h.startBuild(ctx, dialer)
	}
	h.mu.Unlock()

	select {
	case <-b.done:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if b.err != nil {
		return nil, b.err
	}
	if !b.tun.alive() {
		if err := b.tun.sess.Err(); err != nil {
			return nil, errors.New("the OpenVPN session ended right after it was set up").Base(err)
		}
		return nil, errors.New("the OpenVPN session ended right after it was set up")
	}
	return b.tun, nil
}

// startBuild starts making a tunnel in the background. h.mu is held.
func (h *Handler) startBuild(ctx context.Context, dialer internet.Dialer) *build {
	sctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	b := &build{done: make(chan struct{}), cancel: cancel}
	h.building = b
	go func() {
		t, err := h.buildTunnel(sctx, cancel, dialer)
		h.mu.Lock()
		h.building = nil
		closed := h.closed
		var note string
		if err == nil && !closed {
			h.tun = t
			h.setupWorked()
		}
		if err != nil && !closed && !goerrors.Is(err, errClosed) {
			note = h.setupFailed(err)
		}
		h.mu.Unlock()
		if note != "" {
			errors.LogWarningInner(sctx, err, note)
		}
		if err == nil && closed {
			t.close()
			t, err = nil, errClosed
		}
		if err != nil {
			cancel()
		}
		b.tun, b.err = t, err
		close(b.done)
	}()
	return b
}

// buildTunnel dials a session and starts a tunnel on it. ctx lives as long
// as the session (cancel ends it).
func (h *Handler) buildTunnel(ctx context.Context, cancel context.CancelFunc, dialer internet.Dialer) (*tunnel, error) {
	// A fresh parse per session, so nothing of an earlier session's options
	// carries over (New already ran the full ParseOptions checks).
	opts, err := options.Parse(h.conf.Ovpn)
	if err != nil {
		return nil, errors.New("invalid ovpn configuration").Base(err)
	}
	sess, err := dialSession(ctx, client.Config{
		ClientProof: h.proof,
		Options:     opts,
		Username:    h.conf.Username,
		Password:    h.conf.Password,
		Dial:        h.dialFunc(ctx, dialer),
		Logger:      sessionLogger{ctx: ctx},
		Platform:    platform(),
	})
	if err != nil {
		if ctx.Err() != nil {
			return nil, errClosed // Close cancelled the handshake
		}
		return nil, errors.New("failed to set up the OpenVPN session").Base(err)
	}
	t, err := newTunnel(ctx, cancel, sess, int(h.conf.Mtu))
	if err != nil {
		_ = sess.Close()
		return nil, err
	}
	info := sess.Info()
	errors.LogInfo(ctx, "OpenVPN tunnel up: server ", info.Remote.Host, " port ", info.Remote.Port, " over ", info.Remote.Network,
		", address ", prefixString(info.IPv4), " ", prefixString(info.IPv6), ", mtu ", t.mtu,
		", ", info.TLSVersion, ", cipher ", info.Cipher, " (", info.KeyDerivation, ")")
	t.start()
	return t, nil
}

func prefixString(p netip.Prefix) string {
	if !p.IsValid() {
		return "-"
	}
	return p.String()
}

// dialFunc opens the OpenVPN transport with dialer. The connection is dialled
// with base, which lives as long as the session (a transport chained through
// another outbound ends with it); the session's own dial context only bounds
// the wait.
func (h *Handler) dialFunc(base context.Context, dialer internet.Dialer) client.DialFunc {
	return func(ctx context.Context, network, address string) (gonet.Conn, error) {
		dest, err := transportDestination(network, address)
		if err != nil {
			return nil, err
		}
		type result struct {
			conn gonet.Conn
			err  error
		}
		done := make(chan result, 1)
		go func() {
			target, err := h.transportFamily(ctx, network, dest)
			if err != nil {
				done <- result{nil, err}
				return
			}
			c, err := dialer.Dial(transportContext(base, target), target)
			if err != nil {
				done <- result{nil, err}
				return
			}
			if c != nil && dest.Network == xnet.Network_TCP {
				boundTransportBacklog(base, c)
			}
			if c != nil && dest.Network == xnet.Network_UDP {
				c = preserveTransportPackets(c)
			}
			done <- result{c, nil}
		}()
		select {
		case r := <-done:
			if r.err != nil {
				return nil, errors.New("failed to dial the OpenVPN server ", dest).Base(r.err)
			}
			if r.conn == nil {
				return nil, errors.New("failed to dial the OpenVPN server ", dest, ": no connection")
			}
			return r.conn, nil
		case <-ctx.Done():
			go func() {
				if r := <-done; r.conn != nil {
					_ = r.conn.Close()
				}
			}()
			return nil, ctx.Err()
		}
	}
}

// transportDestination turns a client.DialFunc network and address into the
// destination handed to Xray's dialer. Unsuffixed transports keep hostnames
// for the dialer's usual resolution. dialFunc resolves an explicit "4"/"6"
// family before dialing because xnet.Destination itself has no family selector.
func transportDestination(network, address string) (xnet.Destination, error) {
	var n xnet.Network
	switch network {
	case "udp", "udp4", "udp6":
		n = xnet.Network_UDP
	case "tcp", "tcp4", "tcp6":
		n = xnet.Network_TCP
	default:
		return xnet.Destination{}, errors.New("unsupported transport ", strconv.Quote(network))
	}
	host, port, err := gonet.SplitHostPort(address)
	if err != nil {
		return xnet.Destination{}, errors.New("bad server address ", strconv.Quote(address)).Base(err)
	}
	if host == "" {
		return xnet.Destination{}, errors.New("bad server address ", strconv.Quote(address), ": no host")
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return xnet.Destination{}, errors.New("bad server address ", strconv.Quote(address), ": bad port")
	}
	return xnet.Destination{Network: n, Address: xnet.ParseAddress(host), Port: xnet.Port(p)}, nil
}

// transportContext is base with its own copy of the last outbound, aimed at
// dest: Xray's dialer records the connection and gateway there, and must not
// write into the request that happened to start the session.
func transportContext(base context.Context, dest xnet.Destination) context.Context {
	outbounds := session.OutboundsFromContext(base)
	if len(outbounds) == 0 {
		return session.ContextWithOutbounds(base, []*session.Outbound{{Target: dest, Name: "ov"}})
	}
	cp := make([]*session.Outbound, len(outbounds))
	copy(cp, outbounds)
	last := *outbounds[len(outbounds)-1]
	last.Target = dest
	last.Conn = nil
	cp[len(cp)-1] = &last
	return session.ContextWithOutbounds(base, cp)
}

// resolve turns dest into an address inside the tunnel: a domain per the
// domain strategy, restricted to the families the tunnel has.
func (h *Handler) resolve(t *tunnel, dest xnet.Destination) (netip.AddrPort, error) {
	addr := dest.Address
	if addr.Family().IsDomain() {
		ips, err := lookupInTunnel(h.dns, h.conf, t.hasIPv4, t.hasIPv6, addr.Domain())
		if err != nil {
			return netip.AddrPort{}, err
		}
		addr = xnet.IPAddress(ips[dice.Roll(len(ips))])
	}
	ip, ok := netip.AddrFromSlice(addr.IP())
	if !ok {
		return netip.AddrPort{}, errors.New("bad destination address ", dest.Address)
	}
	ip = ip.Unmap()
	switch {
	case ip.Is4() && !t.hasIPv4:
		return netip.AddrPort{}, errors.New("cannot reach ", ip, ": the OpenVPN tunnel has no IPv4 address")
	case ip.Is6() && !t.hasIPv6:
		return netip.AddrPort{}, errors.New("cannot reach ", ip, ": the OpenVPN tunnel has no IPv6 address")
	}
	return netip.AddrPortFrom(ip, dest.Port.Value()), nil
}

// newEchoFlow executes the pings of one UDP link through the tunnel's
// netstack: real ICMP echoes from the tunnel's address of the echo's family,
// a name resolved per the domain strategy for that family only. Each reply
// goes into out and counts as activity on the link.
func (h *Handler) newEchoFlow(ctx context.Context, t *tunnel, out buf.Writer, timer signal.ActivityUpdater) *icmpecho.Flow {
	deliver := icmpecho.Deliverer(out)
	return icmpecho.NewFlow(ctx, icmpecho.Options{
		Open: func(v6 bool) (icmpecho.Conn, error) {
			switch {
			case v6 && !t.hasIPv6:
				return nil, errors.New("the OpenVPN tunnel has no IPv6 address to ping from")
			case !v6 && !t.hasIPv4:
				return nil, errors.New("the OpenVPN tunnel has no IPv4 address to ping from")
			}
			c, err := t.net.ListenPing(v6)
			if err != nil {
				return nil, errors.New("failed to open ICMP inside the OpenVPN tunnel").Base(err)
			}
			return c, nil
		},
		Resolve: func(_ context.Context, domain string, v6 bool) (netip.Addr, error) {
			ips, err := lookupInTunnel(h.dns, h.conf, !v6 && t.hasIPv4, v6 && t.hasIPv6, domain)
			if err != nil {
				return netip.Addr{}, err
			}
			a, _ := netip.AddrFromSlice(ips[dice.Roll(len(ips))])
			return a.Unmap(), nil
		},
		Deliver: func(from xnet.Address, msg []byte) {
			timer.Update()
			deliver(from, msg)
		},
	})
}

// lookupInTunnel resolves domain as WireGuard does for its domain strategy,
// asking only for the families the tunnel has and keeping only those.
func lookupInTunnel(d dns.Client, conf *Config, hasIPv4, hasIPv6 bool, domain string) ([]xnet.IP, error) {
	v4, v6 := hasIPv4 && conf.preferIP4(), hasIPv6 && conf.preferIP6()
	f4, f6 := hasIPv4 && conf.fallbackIP4(), hasIPv6 && conf.fallbackIP6()
	if !v4 && !v6 && !f4 && !f6 {
		return nil, errors.New("cannot resolve ", domain, ": domainStrategy ", conf.DomainStrategy, " allows no address family the OpenVPN tunnel has")
	}
	var ips []xnet.IP
	var err error
	if v4 || v6 {
		ips, _, err = d.LookupIP(domain, dns.IPOption{IPv4Enable: v4, IPv6Enable: v6})
		ips = keepFamilies(ips, v4, v6)
	}
	if (len(ips) == 0 || err != nil) && conf.hasFallback() && (f4 || f6) {
		ips, _, err = d.LookupIP(domain, dns.IPOption{IPv4Enable: f4, IPv6Enable: f6})
		ips = keepFamilies(ips, f4, f6)
	}
	if err != nil {
		return nil, errors.New("failed to lookup DNS").Base(err)
	}
	if len(ips) == 0 {
		return nil, dns.ErrEmptyResponse
	}
	return ips, nil
}

func keepFamilies(ips []xnet.IP, v4, v6 bool) []xnet.IP {
	out := ips[:0:0]
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			if v4 {
				out = append(out, ip4)
			}
		} else if len(ip) == xnet.IPv6len && v6 {
			out = append(out, ip)
		}
	}
	return out
}
