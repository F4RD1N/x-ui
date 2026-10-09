package freedom

import (
	"context"
	"encoding/binary"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/icmpecho"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

// Pings arrive as the common/icmpecho marker: a UDP datagram to port 0 whose
// payload is an ICMP echo request. Freedom sends it from this host as a real
// echo request and returns the target's reply on the same flow, as a datagram
// from the pinged address and port 0. Nothing else of the client's payload
// leaves the host: the request is checked to be an echo request, and only
// its data goes into the ICMP message.

// localSocketSettings is implemented by the outbound handler that runs
// freedom (app/proxyman/outbound).
type localSocketSettings interface {
	LocalSocketSettings() (*internet.SocketConfig, bool)
}

const (
	// maxEchoResolved bounds the domains a flow remembers the address of.
	maxEchoResolved = 16
	// echoLookupTimeout bounds a system resolver lookup for a ping.
	echoLookupTimeout = 5 * time.Second
)

type echoResolveKey struct {
	domain string
	ipv6   bool
}

// echoFlow executes the echo requests of one freedom UDP flow. Its sockets,
// one per family opened on first use, and its tracker belong to this flow
// alone, so replies cannot cross between flows.
type echoFlow struct {
	ctx      context.Context
	h        *Handler
	sockopt  *internet.SocketConfig
	gateway  net.Address
	override net.Address
	out      buf.Writer
	tracker  *icmpecho.Tracker
	// activity is called on every echo sent and every reply returned. It is
	// set before the flow is used.
	activity func()

	mu       sync.Mutex
	closed   bool
	conns    [2]*echoConn
	failed   [2]bool
	resolved map[echoResolveKey]net.IP
}

// newEchoFlow returns the executor for a UDP flow, or nil when pings cannot
// be sent from here because the outbound's traffic leaves through another
// outbound; marker datagrams then travel on like any UDP.
func (h *Handler) newEchoFlow(ctx context.Context, dialer internet.Dialer, ob *session.Outbound, out buf.Writer) *echoFlow {
	var sockopt *internet.SocketConfig
	if s, ok := dialer.(localSocketSettings); ok {
		var local bool
		if sockopt, local = s.LocalSocketSettings(); !local {
			return nil
		}
	}
	f := &echoFlow{
		ctx:      ctx,
		h:        h,
		sockopt:  sockopt,
		gateway:  ob.Gateway,
		out:      out,
		tracker:  icmpecho.NewTracker(),
		activity: func() {},
		resolved: make(map[echoResolveKey]net.IP),
	}
	if o := h.config.DestinationOverride; o != nil && o.Server != nil && isValidAddress(o.Server.Address) {
		f.override = o.Server.Address.AsAddress()
	}
	return f
}

// send executes one marker datagram addressed to target, and releases b.
// Anything that is not a well-formed echo request, or that may not or
// cannot be sent, is dropped without a word: the client sees a timeout.
func (f *echoFlow) send(b *buf.Buffer, target net.Address) {
	defer b.Release()
	req, ok := icmpecho.ParseRequest(b.Bytes())
	if !ok {
		return
	}
	dst := target
	if f.override != nil {
		dst = f.override
	}
	if !icmpecho.FamilyMatches(req, dst) {
		return
	}
	if !f.tracker.Admit(time.Now()) {
		errors.LogDebug(f.ctx, "freedom: ping to ", target, " over the flow's limits, dropped")
		return
	}
	ip := f.resolve(dst, req.IPv6)
	if ip == nil || !echoTargetAllowed(ip) {
		return
	}
	conn := f.conn(req.IPv6)
	if conn == nil {
		return
	}
	// The echo's wait starts now, after any lookup.
	seq, ok := f.tracker.Add(time.Now(), icmpecho.Pending{Target: target, Peer: ip, ID: req.ID, Seq: req.Seq}, req.Data)
	if !ok {
		return
	}
	// Rewrite the header in place; the data is the client's, untouched.
	msg := b.Bytes()
	msg[2], msg[3] = 0, 0
	binary.BigEndian.PutUint16(msg[4:6], conn.wireID)
	binary.BigEndian.PutUint16(msg[6:8], seq)
	if !req.IPv6 {
		binary.BigEndian.PutUint16(msg[2:4], icmpecho.Checksum(msg))
	}
	if err := conn.write(ip, msg); err != nil {
		f.tracker.Cancel(seq)
		errors.LogDebugInner(f.ctx, err, "freedom: failed to ping ", ip)
		return
	}
	f.activity()
}

// onReply returns an echo reply read from the flow's socket of that family,
// if it answers one of the flow's echoes.
func (f *echoFlow) onReply(ipv6 bool, peer net.IP, msg []byte) {
	rep, ok := icmpecho.ParseReply(msg, ipv6)
	if !ok {
		return
	}
	p, ok := f.tracker.Match(time.Now(), rep.Seq, peer, rep.Data)
	if !ok {
		return
	}
	n := icmpecho.HeaderLen + len(rep.Data)
	var b *buf.Buffer
	if n <= buf.Size {
		b = buf.New()
	} else {
		b = buf.NewWithSize(int32(n))
	}
	icmpecho.AppendReply(b.Extend(int32(n))[:0], icmpecho.Echo{IPv6: ipv6, ID: p.ID, Seq: p.Seq, Data: rep.Data})
	b.UDP = &net.Destination{Network: net.Network_UDP, Address: p.Target, Port: 0}
	if f.out.WriteMultiBuffer(buf.MultiBuffer{b}) == nil {
		f.activity()
	}
}

// resolve returns the IP to ping for addr, of the echo's family. A domain is
// resolved as freedom resolves UDP destinations, restricted to that family:
// by its domainStrategy through Xray's DNS, falling back to the system
// resolver unless the strategy forces Xray's. The answer is kept for the
// flow, so a run of pings goes to one address.
func (f *echoFlow) resolve(addr net.Address, ipv6 bool) net.IP {
	if addr.Family().IsIP() {
		return addr.IP()
	}
	key := echoResolveKey{domain: addr.Domain(), ipv6: ipv6}
	f.mu.Lock()
	ip, ok := f.resolved[key]
	f.mu.Unlock()
	if ok {
		return ip
	}
	if ip = f.lookup(key.domain, ipv6); ip == nil {
		return nil
	}
	f.mu.Lock()
	if len(f.resolved) < maxEchoResolved {
		f.resolved[key] = ip
	}
	f.mu.Unlock()
	return ip
}

func (f *echoFlow) lookup(domain string, ipv6 bool) net.IP {
	strategy := f.h.config.DomainStrategy
	if strategy.HasStrategy() {
		// A local address of the family limits the lookup to that family.
		local := net.AnyIP
		if ipv6 {
			local = net.AnyIPv6
		}
		ips, err := internet.LookupForIP(domain, strategy, local)
		if err == nil {
			if ip := pickEchoIP(ips, ipv6); ip != nil {
				return ip
			}
		}
		if strategy.ForceIP() {
			return nil
		}
	}
	network := "ip4"
	if ipv6 {
		network = "ip6"
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(f.ctx), echoLookupTimeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, network, domain)
	if err != nil {
		errors.LogDebugInner(f.ctx, err, "freedom: failed to resolve ", domain, " to ping it")
		return nil
	}
	return pickEchoIP(ips, ipv6)
}

// pickEchoIP picks one of the addresses of the family at random, as freedom
// does for UDP. ips may be the DNS cache's own slice and is not modified.
func pickEchoIP(ips []net.IP, ipv6 bool) net.IP {
	n := 0
	for _, ip := range ips {
		if (ip.To4() == nil) == ipv6 {
			n++
		}
	}
	if n == 0 {
		return nil
	}
	k := dice.Roll(n)
	for _, ip := range ips {
		if (ip.To4() == nil) == ipv6 {
			if k == 0 {
				return ip
			}
			k--
		}
	}
	return nil
}

// echoTargetAllowed rejects destinations that reach no host or many: the
// unspecified address, multicast and the limited broadcast. (A subnet
// broadcast needs SO_BROADCAST, which the echo socket never sets.)
func echoTargetAllowed(ip net.IP) bool {
	return !ip.IsUnspecified() && !ip.IsMulticast() && !ip.Equal(net.IP{255, 255, 255, 255})
}

// conn returns the flow's socket of the family, opening it on first use. A
// family that failed to open stays failed for the flow.
func (f *echoFlow) conn(ipv6 bool) *echoConn {
	i := 0
	if ipv6 {
		i = 1
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.failed[i] {
		return nil
	}
	if c := f.conns[i]; c != nil {
		return c
	}
	var bind net.IP
	if f.gateway != nil && f.gateway.Family().IsIP() {
		if f.gateway.Family().IsIPv6() != ipv6 {
			// sendThrough is of the other family: nothing to send from.
			f.failed[i] = true
			return nil
		}
		bind = f.gateway.IP()
	}
	c, err := openEchoConn(f.ctx, ipv6, bind, f.sockopt)
	if err != nil {
		f.failed[i] = true
		errors.LogInfoInner(f.ctx, err, "freedom: cannot send pings")
		return nil
	}
	f.conns[i] = c
	go c.readLoop(func(peer net.IP, msg []byte) {
		f.onReply(ipv6, peer, msg)
	})
	return c
}

// Close closes the flow's sockets; their readers end with them.
func (f *echoFlow) Close() {
	f.mu.Lock()
	f.closed = true
	conns := f.conns
	f.conns = [2]*echoConn{}
	f.mu.Unlock()
	for _, c := range conns {
		if c != nil {
			c.Close()
		}
	}
}

// echoSplitWriter takes the marker datagrams out of a UDP flow and hands
// the rest to the flow's packet writer.
type echoSplitWriter struct {
	buf.Writer
	echo *echoFlow
}

func (w *echoSplitWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	rest := mb[:0]
	for _, b := range mb {
		if b.UDP != nil && b.UDP.Port == 0 {
			w.echo.send(b, b.UDP.Address)
			continue
		}
		rest = append(rest, b)
	}
	if len(rest) == 0 {
		return nil
	}
	return w.Writer.WriteMultiBuffer(rest)
}

// echoOnlyWriter executes the datagrams of a flow that opened with a ping.
// Such a flow has no UDP socket, so a datagram to any other port is dropped.
type echoOnlyWriter struct {
	echo   *echoFlow
	target net.Address
}

func (w *echoOnlyWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for _, b := range mb {
		target := w.target
		if b.UDP != nil {
			if b.UDP.Port != 0 {
				b.Release()
				continue
			}
			target = b.UDP.Address
		}
		w.echo.send(b, target)
	}
	return nil
}

// processEcho serves a flow whose first datagram is a ping. Replies are
// written by the echo sockets' readers; the flow lives until it is idle for
// the policy's connection idle time, as any UDP flow does.
func (h *Handler) processEcho(ctx context.Context, link *transport.Link, target net.Address, echo *echoFlow) error {
	var newCtx context.Context
	var newCancel context.CancelFunc
	if session.TimeoutOnlyFromContext(ctx) {
		newCtx, newCancel = context.WithCancel(context.Background())
	}

	plcy := h.policy()
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
		if newCancel != nil {
			newCancel()
		}
	}, plcy.Timeouts.ConnectionIdle)
	echo.activity = timer.Update

	done := ctx.Done()
	if newCtx != nil {
		done = newCtx.Done()
	}

	requestDone := func() error {
		defer timer.SetTimeout(plcy.Timeouts.DownlinkOnly)
		if err := buf.Copy(link.Reader, &echoOnlyWriter{echo: echo, target: target}, buf.UpdateActivity(timer)); err != nil {
			return errors.New("failed to process request").Base(err)
		}
		return nil
	}

	responseDone := func() error {
		defer timer.SetTimeout(plcy.Timeouts.UplinkOnly)
		<-done
		return nil
	}

	if newCtx != nil {
		ctx = newCtx
	}

	if err := task.Run(ctx, requestDone, task.OnSuccess(responseDone, task.Close(link.Writer))); err != nil {
		return errors.New("connection ends").Base(err)
	}
	return nil
}
