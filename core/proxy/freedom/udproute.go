package freedom

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	routing_session "github.com/xtls/xray-core/features/routing/session"
	"github.com/xtls/xray-core/features/stats"
)

// udpRouteEachDestination (config udp_route_each_destination).
//
// Xray routes a UDP flow once, by its first datagram. A full-cone flow
// (mux.cool/XUDP, socks, shadowsocks, trojan, ... UDP) carries the
// destination of every later datagram in buf.Buffer.UDP, and freedom would
// send each one there without routing it: with an allow-list routing, a flow
// opened to an allowed destination could reach any other. With the setting
// on, every datagram's destination is checked before it is written:
//
//   - the flow's own destinations (ob.Target, ob.OriginalTarget and the
//     dialed address) were routed here already and pass;
//   - any other destination is routed by the core's router, with the flow's
//     own routing context (inbound tag, user, source, sniffed protocol,
//     attributes) and the new destination as its target, without DNS; it
//     passes only when the route is this outbound. Blocked, another
//     outbound, a balancer that picks another, no route or an error: the
//     datagram is dropped, and the flow goes on.
//
// The decisions are kept for the flow, so the router runs once per new
// destination of a flow, not once per datagram. What a client can make the
// server do is bounded: a flow routes at most udpRouteBurst new destinations
// at once and udpRouteRate a second after that (a datagram to a new
// destination over that budget is dropped unrouted: denying is the safe
// side), a flow remembers at most maxUDPRouteDecisions decisions, and a
// handler's flows together maxUDPRouteCached.

const (
	// maxUDPRouteDecisions bounds the destinations a flow remembers the
	// decision of, far above what a real flow uses. Over it the decisions
	// are forgotten (the flow's own destinations are kept apart and stay)
	// and are made again as datagrams come.
	maxUDPRouteDecisions = 1024
	// maxUDPRouteCached bounds the decisions all flows of a handler
	// remember (~80 B each). Over it a flow remembers no new denials, and
	// allowed decisions only while it has fewer than udpRouteSmallFlow.
	maxUDPRouteCached = 1 << 18
	udpRouteSmallFlow = 64

	// The router budget of a flow: udpRouteBurst calls at once, then
	// udpRouteRate a second.
	udpRouteBurst      = 128
	udpRouteRate       = 64
	udpRouteTokenEvery = int64(time.Second) / udpRouteRate
)

// udpRouteLogInterval is the least time between two log lines of a handler
// about the datagrams it dropped.
var udpRouteLogInterval = 60 * time.Second

// udpRouteNow is the clock of the router budget (UnixNano); tests set it.
var udpRouteNow = func() int64 { return time.Now().UnixNano() }

// udpRouteKey is a UDP destination as a map key: no allocation to build or
// look up. Addresses made by net.IPAddress are canonical: an IPv4-mapped
// IPv6 address is the IPv4 one. Domains are looked up as they come and, on
// a miss, in lower case too.
type udpRouteKey struct {
	addr net.Address // ipv4Address, ipv6Address or domainAddress: comparable
	port net.Port
}

// canonical returns the key with a domain in lower case. An IP address is
// canonical already: net.IPAddress, which makes every one, turns an
// IPv4-mapped IPv6 address into the IPv4 one. It allocates only for a
// domain with upper case.
func (k udpRouteKey) canonical() udpRouteKey {
	if k.addr != nil && k.addr.Family().IsDomain() {
		if d := k.addr.Domain(); strings.ToLower(d) != d {
			k.addr = net.DomainAddress(strings.ToLower(d))
		}
	}
	return k
}

// udpRouteContext is the flow's routing context with the target replaced by
// one datagram's destination, as UDP and without DNS. Everything else
// (inbound tag, user, source, local address, sniffed protocol, attributes,
// VLESS route) is the flow's.
type udpRouteContext struct {
	routing.Context
	ips    []net.IP
	domain string
	port   net.Port
}

func newUDPRouteContext(base routing.Context, dest net.Destination) *udpRouteContext {
	c := &udpRouteContext{Context: base, port: dest.Port}
	if dest.Address.Family().IsDomain() {
		c.domain = dest.Address.Domain()
	} else {
		c.ips = []net.IP{dest.Address.IP()}
	}
	return c
}

// GetTargetIPs implements routing.Context.
func (c *udpRouteContext) GetTargetIPs() []net.IP { return c.ips }

// GetTargetPort implements routing.Context.
func (c *udpRouteContext) GetTargetPort() net.Port { return c.port }

// GetTargetDomain implements routing.Context.
func (c *udpRouteContext) GetTargetDomain() string { return c.domain }

// GetNetwork implements routing.Context.
func (c *udpRouteContext) GetNetwork() net.Network { return net.Network_UDP }

// GetSkipDNSResolve implements routing.Context: no lookups on the data path.
func (c *udpRouteContext) GetSkipDNSResolve() bool { return true }

// udpRouteGuard decides, for one UDP flow, which datagram destinations may
// be written. allow and approve are called by the flow's writer only, which
// runs in the one goroutine copying the flow's request (Process's
// requestDone). That goroutine may outlive Process, which calls release:
// mu orders the two, off the hit path.
//
// Most flows have one destination: the guard of such a flow allocates
// only itself and the boxed dialed address. The map and the routing context are made on the
// first destination that is not the flow's own.
type udpRouteGuard struct {
	ctx    context.Context
	h      *Handler
	tag    string // this outbound's tag: the only route a datagram may take
	router routing.Router
	base   routing.Context // made on the first route

	// The flow's own destinations, always allowed: ob.Target,
	// ob.OriginalTarget and the dialed address, each also in canonical form.
	approved  [6]udpRouteKey
	nApproved int

	decided map[udpRouteKey]bool // made on the first decision

	// The last destination looked up and its decision: most datagrams of a
	// flow go where the one before went.
	last    udpRouteKey
	lastOK  bool
	hasLast bool

	// The router budget: tokens left, and when the last one was added.
	tokens   int64
	refilled int64

	mu       sync.Mutex
	counted  int // decisions of this flow in h.udpRouteCached
	released bool
}

// newUDPRouteGuard returns the guard of a UDP flow, or nil when the flow is
// not checked: the setting is off, or a destinationOverride address sends
// every datagram to one address anyway. The caller releases it.
func (h *Handler) newUDPRouteGuard(ctx context.Context, ob *session.Outbound, udpOverride net.Destination) *udpRouteGuard {
	if !h.config.UdpRouteEachDestination || udpOverride.Address != nil {
		return nil
	}
	g := &udpRouteGuard{
		ctx:    ctx,
		h:      h,
		tag:    ob.Tag,
		router: h.router,
		tokens: udpRouteBurst,
	}
	g.approve(ob.Target.Address, ob.Target.Port)
	g.approve(ob.OriginalTarget.Address, ob.OriginalTarget.Port)
	return g
}

// approve allows a destination for the rest of the flow.
func (g *udpRouteGuard) approve(addr net.Address, port net.Port) {
	if addr == nil {
		return
	}
	k := udpRouteKey{addr: addr, port: port}
	for _, key := range [2]udpRouteKey{k, k.canonical()} {
		if !g.isApproved(key) && g.nApproved < len(g.approved) {
			g.approved[g.nApproved] = key
			g.nApproved++
		}
	}
	g.hasLast = false
}

// approveAddr approves the address a flow's socket was dialed to (one
// 4- or 16-byte allocation, to box it).
func (g *udpRouteGuard) approveAddr(addr net.Addr) {
	if ua, ok := addr.(*net.UDPAddr); ok {
		if ip := net.IPAddress(ua.IP); ip != nil {
			g.approve(ip, net.Port(ua.Port))
		}
	}
}

func (g *udpRouteGuard) isApproved(k udpRouteKey) bool {
	for _, a := range g.approved[:g.nApproved] {
		if a == k {
			return true
		}
	}
	return false
}

// allow reports whether a datagram to dest may be written. A datagram that
// may not is counted as dropped; the caller releases it.
func (g *udpRouteGuard) allow(dest *net.Destination) bool {
	k := udpRouteKey{addr: dest.Address, port: dest.Port}
	if g.hasLast && k == g.last {
		if !g.lastOK {
			g.h.udpRouteDrops.packet(g.ctx, g.tag)
		}
		return g.lastOK
	}
	ok, found := g.isApproved(k), true
	if !ok {
		ok, found = g.decided[k]
	}
	if !found {
		var decided bool
		ok, decided = g.decide(k)
		if !decided {
			// Over the router budget: dropped unrouted, decided later.
			g.h.udpRouteDrops.overBudget(g.ctx, g.tag)
			return false
		}
	}
	g.last, g.lastOK, g.hasLast = k, ok, true
	if !ok {
		g.h.udpRouteDrops.packet(g.ctx, g.tag)
	}
	return ok
}

// decide routes a destination the flow has no decision for, and keeps the
// decision when there is room. decided is false when the flow's router
// budget is spent: the destination was not routed.
func (g *udpRouteGuard) decide(k udpRouteKey) (ok, decided bool) {
	if k.addr == nil {
		return false, true
	}
	ck := k.canonical()
	if ck != k {
		if g.isApproved(ck) {
			return true, true
		}
		if ok, found := g.decided[ck]; found {
			g.remember(k, ok)
			return ok, true
		}
	}
	if !g.takeToken() {
		return false, false
	}
	ok, tag := g.route(net.UDPDestination(ck.addr, ck.port))
	if !ok {
		g.h.udpRouteDrops.destination(g.ctx, g.tag, ck, tag)
	}
	g.remember(ck, ok)
	if ck != k {
		g.remember(k, ok)
	}
	return ok, true
}

// takeToken spends one router call of the flow's budget, if one is left.
func (g *udpRouteGuard) takeToken() bool {
	now := udpRouteNow()
	if g.tokens < udpRouteBurst {
		if n := (now - g.refilled) / udpRouteTokenEvery; n > 0 {
			g.tokens = min(udpRouteBurst, g.tokens+n)
			g.refilled += n * udpRouteTokenEvery
		}
	}
	if g.tokens <= 0 {
		return false
	}
	if g.tokens == udpRouteBurst {
		g.refilled = now // the budget refills from its first use
	}
	g.tokens--
	return true
}

// remember keeps a decision for the flow, within the flow's and the
// handler's bounds.
func (g *udpRouteGuard) remember(k udpRouteKey, ok bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.released {
		return
	}
	if _, found := g.decided[k]; !found {
		if g.h.udpRouteCached.Load() >= maxUDPRouteCached && (!ok || len(g.decided) >= udpRouteSmallFlow) {
			return
		}
		if len(g.decided) >= maxUDPRouteDecisions {
			// A new map, not clear(): the old one's memory is let go.
			g.decided = nil
		}
		if g.decided == nil {
			g.decided = make(map[udpRouteKey]bool, 4)
		}
	}
	g.decided[k] = ok
	g.account()
}

// account brings h.udpRouteCached up to date with the flow's decisions.
// Called with mu held.
func (g *udpRouteGuard) account() {
	if n := len(g.decided); n != g.counted {
		g.h.udpRouteCached.Add(int64(n - g.counted))
		g.counted = n
	}
}

// release takes the flow's decisions off the handler's count, when the
// flow ends. The guard keeps working, without remembering new decisions.
func (g *udpRouteGuard) release() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.released {
		g.released = true
		g.h.udpRouteCached.Add(int64(-g.counted))
		g.counted = 0
	}
}

// route asks the router where dest goes in this flow, and reports whether
// that is this outbound, and the outbound it is otherwise ("" for no route).
func (g *udpRouteGuard) route(dest net.Destination) (bool, string) {
	if g.router == nil {
		return false, ""
	}
	if g.base == nil {
		g.base = routing_session.AsRoutingContext(g.ctx)
	}
	r, err := g.router.PickRoute(newUDPRouteContext(g.base, dest))
	if err != nil || r == nil {
		return false, ""
	}
	tag := r.GetOutboundTag()
	return tag != "" && tag == g.tag, tag
}

// udpRouteDrops counts the datagrams and destinations a handler dropped,
// in stats counters when the core has a stats manager, and logs them at most
// once per udpRouteLogInterval.
type udpRouteDrops struct {
	sm   stats.Manager
	once sync.Once
	// The counters; nil without a stats manager. Set by once.
	packets      stats.Counter
	destinations stats.Counter

	// Since the last log line.
	pendingPackets      atomic.Int64
	pendingDestinations atomic.Int64
	pendingOverBudget   atomic.Int64
	example             atomic.Pointer[string]
	lastLog             atomic.Int64 // UnixNano of the last log line
}

// counters registers the handler's counters on first use. tag is the
// outbound's tag; an outbound without one has no counters.
func (d *udpRouteDrops) counters(tag string) {
	d.once.Do(func() {
		if d.sm == nil || tag == "" {
			return
		}
		prefix := "outbound>>>" + tag + ">>>udp>>>"
		if c, err := stats.GetOrRegisterCounter(d.sm, prefix+"dropped_packets"); err == nil {
			d.packets = c
		}
		if c, err := stats.GetOrRegisterCounter(d.sm, prefix+"dropped_destinations"); err == nil {
			d.destinations = c
		}
	})
}

// destination counts a destination denied for a flow: routed to outbound
// ("" for no route) instead of this one.
func (d *udpRouteDrops) destination(ctx context.Context, tag string, k udpRouteKey, outbound string) {
	d.counters(tag)
	if d.destinations != nil {
		d.destinations.Add(1)
	}
	d.pendingDestinations.Add(1)
	if outbound == "" {
		outbound = "(no route)"
	}
	example := net.UDPDestination(k.addr, k.port).NetAddr() + " -> " + outbound
	d.example.Store(&example)
}

// overBudget counts a datagram dropped unrouted: its flow had spent its
// router budget.
func (d *udpRouteDrops) overBudget(ctx context.Context, tag string) {
	d.pendingOverBudget.Add(1)
	d.packet(ctx, tag)
}

// packet counts a dropped datagram, and logs the drops when the last log
// line is old enough.
func (d *udpRouteDrops) packet(ctx context.Context, tag string) {
	d.counters(tag)
	if d.packets != nil {
		d.packets.Add(1)
	}
	d.pendingPackets.Add(1)
	now := time.Now().UnixNano()
	last := d.lastLog.Load()
	if last != 0 && now-last < int64(udpRouteLogInterval) {
		return
	}
	if !d.lastLog.CompareAndSwap(last, now) {
		return
	}
	packets := d.pendingPackets.Swap(0)
	destinations := d.pendingDestinations.Swap(0)
	overBudget := d.pendingOverBudget.Swap(0)
	example := ""
	if e := d.example.Load(); e != nil {
		example = *e
	}
	budget := ""
	if overBudget > 0 {
		budget = "; " + strconv.FormatInt(overBudget, 10) + " of the packets were to new destinations over their flow's routing budget, not routed"
	}
	errors.LogInfo(ctx, "freedom [", tag, "]: udpRouteEachDestination dropped ", packets, " UDP packets; ",
		destinations, " new destinations not routed to this outbound, e.g. ", example, budget)
}
