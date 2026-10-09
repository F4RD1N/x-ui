package freedom

import (
	"context"
	"encoding/binary"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/icmpecho"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Pings arrive as the common/icmpecho marker: a UDP datagram to port 0 whose
// payload is an ICMP echo request. Freedom sends it from this host as a real
// echo request and returns the target's reply on the same flow, as a datagram
// from the pinged address and port 0. Nothing else of the client's payload
// leaves the host: the request is checked to be an echo request, and only
// its data goes into the ICMP message. Routing saw only the flow's first
// destination, so a flow pings that address and no other.

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

// maxEchoFlows bounds the flows of this process that hold an ICMP socket or
// identifier at once, whoever opens them: without it, clients opening flow
// after flow could use up the identifiers every ping needs (65536 per family,
// for this process and, with datagram sockets, for the kernel). Pings of a
// flow over the cap are dropped, which its client sees as a timeout, until
// other flows end. A handset's hev-socks5-tunnel keeps at most 128 ping
// sessions.
var maxEchoFlows int32 = 1024

// echoFlowCount is the number of flows holding one of maxEchoFlows.
var echoFlowCount atomic.Int32

type echoResolveKey struct {
	domain string
	ipv6   bool
}

// echoFlow executes the echo requests of one freedom UDP flow. Its ICMP
// endpoints, one per family opened on first use, and its tracker belong to
// this flow alone, so replies cannot cross between flows.
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
	counted  bool // holds one of maxEchoFlows
	conns    [2]*echoConn
	failed   [2]bool
	resolved map[echoResolveKey]net.IP
	// replies carries the replies matched to the flow's echoes to the
	// goroutine writing them to out, so that a socket's reader, which may
	// serve many flows, never waits for a flow's client. Both channels are
	// made with the flow's first endpoint; done is closed by Close.
	replies chan *buf.Buffer
	done    chan struct{}
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
	select {
	case f.replies <- b:
	default:
		// The client is MaxOutstanding replies behind: the reply is lost.
		b.Release()
	}
}

// writeReplies writes the flow's replies to its client until the flow is
// closed.
func (f *echoFlow) writeReplies(replies <-chan *buf.Buffer, done <-chan struct{}) {
	for {
		select {
		case b := <-replies:
			if f.out.WriteMultiBuffer(buf.MultiBuffer{b}) == nil {
				f.activity()
			}
		case <-done:
			for {
				select {
				case b := <-replies:
					b.Release()
				default:
					return
				}
			}
		}
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

// conn returns the flow's endpoint of the family, opening it on first use.
// A family that failed to open stays failed for the flow. A flow that would
// exceed maxEchoFlows gets none, and may try again with its next ping.
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
	if !f.counted {
		if echoFlowCount.Add(1) > maxEchoFlows {
			echoFlowCount.Add(-1)
			errors.LogDebug(f.ctx, "freedom: too many flows are pinging, ping dropped")
			return nil
		}
		f.counted = true
	}
	if f.replies == nil {
		f.replies = make(chan *buf.Buffer, icmpecho.MaxOutstanding)
		f.done = make(chan struct{})
		go f.writeReplies(f.replies, f.done)
	}
	c, err := openEchoConn(f.ctx, ipv6, bind, f.sockopt, func(peer net.IP, msg []byte) {
		f.onReply(ipv6, peer, msg)
	})
	if err != nil {
		f.failed[i] = true
		if f.conns[1-i] == nil {
			echoFlowCount.Add(-1)
			f.counted = false
		}
		errors.LogInfoInner(f.ctx, err, "freedom: cannot send pings")
		return nil
	}
	f.conns[i] = c
	return c
}

// Close closes the flow's endpoints and ends its reply writer.
func (f *echoFlow) Close() {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	f.closed = true
	conns := f.conns
	f.conns = [2]*echoConn{}
	counted := f.counted
	f.counted = false
	if f.done != nil {
		close(f.done)
	}
	f.mu.Unlock()
	for _, c := range conns {
		if c != nil {
			c.Close()
		}
	}
	if counted {
		echoFlowCount.Add(-1)
	}
}

// sameAddress reports whether a and b are one address: equal IPs (an
// IPv4-mapped IPv6 address is its IPv4 one), or domains equal but for case.
func sameAddress(a, b net.Address) bool {
	if a == nil || b == nil {
		return false
	}
	if a.Family().IsDomain() || b.Family().IsDomain() {
		return a.Family().IsDomain() && b.Family().IsDomain() && strings.EqualFold(a.Domain(), b.Domain())
	}
	return a.IP().Equal(b.IP())
}

// echoSplitWriter takes the pings out of a UDP flow and executes them, and
// hands the rest to the flow's UDP writer.
//
// Routing saw only the flow's first destination, so only pings to that
// address are executed. A ping to any other address is dropped; in a flow
// that has only pinged so far it ends the flow instead, so that the client's
// next datagram is dispatched, and routed, afresh.
type echoSplitWriter struct {
	buf.Writer
	echo *echoFlow
	// target is where the flow was routed to, before destinationOverride. A
	// datagram without an address goes there.
	target net.Destination
	// udp is the UDP socket of a flow that opened with a ping, nil for one
	// that opened with UDP.
	udp *udpOnDemand
}

func (w *echoSplitWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	start := 0 // mb[start:i] is UDP not written yet
	for i, b := range mb {
		dest := w.target
		if b.UDP != nil {
			dest = *b.UDP
		}
		if dest.Port != 0 {
			continue
		}
		if err := w.writeUDP(mb[start:i:i]); err != nil {
			buf.ReleaseMulti(mb[i:])
			return err
		}
		start = i + 1
		if !sameAddress(dest.Address, w.target.Address) {
			b.Release()
			if w.udp != nil && !w.udp.opened() {
				buf.ReleaseMulti(mb[i+1:])
				return errors.New("freedom: ping to ", dest.Address, " in a flow routed to ", w.target.Address)
			}
			continue
		}
		w.echo.send(b, dest.Address)
	}
	return w.writeUDP(mb[start:])
}

func (w *echoSplitWriter) writeUDP(mb buf.MultiBuffer) error {
	if len(mb) == 0 {
		return nil
	}
	return w.Writer.WriteMultiBuffer(mb)
}

// udpOnDemand is the UDP socket of a flow that opened with a ping. It is
// dialed for the flow's first ordinary datagram, as Process dials one for a
// flow that opens with UDP, and then carries the flow's UDP both ways. A
// flow that only pings holds no UDP socket, and a flow that goes on to carry
// UDP -- a new association of the client reusing the source port, an XUDP
// session resumed -- works as any UDP flow does.
type udpOnDemand struct {
	ctx         context.Context
	h           *Handler
	dialer      internet.Dialer
	inbound     *session.Inbound
	gateway     net.Address
	udpOverride net.Destination
	// activity is called on every datagram sent.
	activity func()

	// writer and reader are set, by the flow's writer, before ready is
	// closed.
	writer buf.Writer
	reader buf.Reader
	ready  chan struct{}

	mu     sync.Mutex
	closed bool
	conn   stat.Connection
}

func (h *Handler) newUDPOnDemand(ctx context.Context, dialer internet.Dialer, inbound *session.Inbound, gateway net.Address, udpOverride net.Destination) *udpOnDemand {
	return &udpOnDemand{
		// The flow may outlive the request's context (XUDP), and the socket
		// is dialed later than a flow's would be.
		ctx:         context.WithoutCancel(ctx),
		h:           h,
		dialer:      dialer,
		inbound:     inbound,
		gateway:     gateway,
		udpOverride: udpOverride,
		activity:    func() {},
		ready:       make(chan struct{}),
	}
}

// opened reports whether the socket was dialed. Only the flow's writer may
// call it.
func (u *udpOnDemand) opened() bool {
	return u.writer != nil
}

func (u *udpOnDemand) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if u.writer == nil {
		var first *net.Destination
		for _, b := range mb {
			if b.UDP != nil {
				first = b.UDP
				break
			}
		}
		if first == nil {
			// Never so: a datagram without an address goes to the flow's
			// target, which is a ping.
			buf.ReleaseMulti(mb)
			return nil
		}
		if err := u.open(*first); err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
	}
	u.activity()
	return u.writer.WriteMultiBuffer(mb)
}

// open dials the socket as if the flow had opened with a datagram to first.
func (u *udpOnDemand) open(first net.Destination) error {
	destination := first
	if u.udpOverride.Address != nil {
		destination.Address = u.udpOverride.Address
	}
	if u.udpOverride.Port != 0 {
		destination.Port = u.udpOverride.Port
	}
	conn, err := u.h.dial(u.ctx, u.dialer, u.inbound, destination, first.Address, u.gateway)
	if err != nil {
		return errors.New("failed to open connection to ", destination).Base(err)
	}
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		conn.Close()
		return errors.New("flow closed")
	}
	u.conn = conn
	u.mu.Unlock()
	errors.LogInfo(u.ctx, "connection opened to ", destination, ", local endpoint ", conn.LocalAddr(), ", remote endpoint ", conn.RemoteAddr())
	u.writer = u.h.newUDPWriter(u.ctx, conn, u.udpOverride, destination)
	u.reader = NewPacketReader(conn, u.udpOverride, destination)
	close(u.ready)
	return nil
}

// Close closes the socket, if one was dialed; its reader ends with it.
func (u *udpOnDemand) Close() {
	u.mu.Lock()
	u.closed = true
	conn := u.conn
	u.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
}
