package freedom

import (
	"context"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/router"
	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

// The routing of these tests is an allow-list like the production template:
// the first outbound is "blocked", nothing is a catch-all, and only these
// rules send traffic to "direct" (this freedom outbound).
//
//	9.9.9.0/24                         -> direct (an IP rule, as DNS resolvers)
//	udp port 3478 from inbound "in-a"  -> direct (a port rule, as STUN)
//	full:localhost, domain:instagram.com -> direct (domain rules)
//	10.66.0.0/16                       -> blocked
//	10.77.0.0/16                       -> proxy (another outbound)
//	10.88.0.0/16                       -> balancer "bal-proxy": proxy-a/proxy-b
//	10.99.0.0/16                       -> balancer "bal-direct": direct
//	anything else                      -> no route
const testTag = "direct"

func cidr(a, b, c, d byte, prefix uint32) *router.GeoIP {
	return &router.GeoIP{Cidr: []*router.CIDR{{Ip: []byte{a, b, c, d}, Prefix: prefix}}}
}

func testRoutingConfig() *router.Config {
	tag := func(t string) *router.RoutingRule_Tag { return &router.RoutingRule_Tag{Tag: t} }
	return &router.Config{
		DomainStrategy: router.Config_IpOnDemand, // no DNS may happen anyway
		Rule: []*router.RoutingRule{
			{TargetTag: tag("direct"), Geoip: []*router.GeoIP{cidr(9, 9, 9, 0, 24)}},
			{TargetTag: tag("direct"), InboundTag: []string{"in-a"}, Networks: []net.Network{net.Network_UDP},
				PortList: &net.PortList{Range: []*net.PortRange{{From: 3478, To: 3478}}}},
			{TargetTag: tag("direct"), Domain: []*router.Domain{
				{Type: router.Domain_Full, Value: "localhost"},
				{Type: router.Domain_Domain, Value: "instagram.com"},
			}},
			{TargetTag: tag("blocked"), Geoip: []*router.GeoIP{cidr(10, 66, 0, 0, 16)}},
			{TargetTag: tag("proxy"), Geoip: []*router.GeoIP{cidr(10, 77, 0, 0, 16)}},
			{TargetTag: &router.RoutingRule_BalancingTag{BalancingTag: "bal-proxy"}, Geoip: []*router.GeoIP{cidr(10, 88, 0, 0, 16)}},
			{TargetTag: &router.RoutingRule_BalancingTag{BalancingTag: "bal-direct"}, Geoip: []*router.GeoIP{cidr(10, 99, 0, 0, 16)}},
		},
		BalancingRule: []*router.BalancingRule{
			{Tag: "bal-proxy", OutboundSelector: []string{"proxy-"}},
			{Tag: "bal-direct", OutboundSelector: []string{"direct"}},
		},
	}
}

// testOutbounds is the outbound manager the balancers select from.
type testOutbounds struct {
	outbound.Manager
	tags []string
}

func (o testOutbounds) Select(selectors []string) []string {
	var out []string
	for _, t := range o.tags {
		for _, s := range selectors {
			if strings.HasPrefix(t, s) {
				out = append(out, t)
				break
			}
		}
	}
	return out
}

// noDNS fails the test on any lookup: routing a datagram must not resolve.
type noDNS struct {
	t testing.TB
}

func (noDNS) Type() interface{} { return dns.ClientType() }
func (noDNS) Start() error      { return nil }
func (noDNS) Close() error      { return nil }
func (d noDNS) LookupIP(domain string, _ dns.IPOption) ([]net.IP, uint32, error) {
	d.t.Errorf("DNS lookup of %s while routing a datagram", domain)
	return nil, 0, io.EOF
}

// countingRouter is the real router, counting its calls.
type countingRouter struct {
	routing.Router
	calls atomic.Int64
}

func (r *countingRouter) PickRoute(ctx routing.Context) (routing.Route, error) {
	r.calls.Add(1)
	return r.Router.PickRoute(ctx)
}

func newTestRouter(t testing.TB) *countingRouter {
	r := new(router.Router)
	common.Must(r.Init(context.Background(), testRoutingConfig(), noDNS{t: t},
		testOutbounds{tags: []string{"blocked", "direct", "proxy", "proxy-a", "proxy-b"}}, nil))
	return &countingRouter{Router: r}
}

type routeTest struct {
	h      *Handler
	router *countingRouter
	stats  *appstats.Manager
}

func newRouteTest(t testing.TB, config *Config) *routeTest {
	sm, err := appstats.NewManager(context.Background(), &appstats.Config{})
	common.Must(err)
	rt := &routeTest{h: new(Handler), router: newTestRouter(t), stats: sm}
	rt.h.router = rt.router
	rt.h.udpRouteDrops.sm = sm
	common.Must(rt.h.Init(config, policy.DefaultManager{}))
	return rt
}

func (rt *routeTest) counter(name string) int64 {
	c := rt.stats.GetCounter("outbound>>>" + testTag + ">>>udp>>>" + name)
	if c == nil {
		return -1
	}
	return c.Value()
}

// recordConn is a UDP socket that records what is written to it.
type recordConn struct {
	mu     sync.Mutex
	writes []string // "addr payload"
	done   chan struct{}
	once   sync.Once
}

func newRecordConn() *recordConn { return &recordConn{done: make(chan struct{})} }

func (c *recordConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, addr.String()+" "+string(p))
	c.mu.Unlock()
	return len(p), nil
}

func (c *recordConn) ReadFrom([]byte) (int, net.Addr, error) {
	<-c.done
	return 0, nil, io.EOF
}

func (c *recordConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return nil
}

func (c *recordConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IP{192, 0, 2, 1}, Port: 40000}
}
func (c *recordConn) SetDeadline(time.Time) error      { return nil }
func (c *recordConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordConn) SetWriteDeadline(time.Time) error { return nil }

func (c *recordConn) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.writes...)
}

// recordDialer dials recordConns; a domain is "resolved" by resolve.
type recordDialer struct {
	mu      sync.Mutex
	dials   []string
	conns   []*recordConn
	resolve map[string]net.IP
}

func (d *recordDialer) Dial(_ context.Context, dest net.Destination) (stat.Connection, error) {
	ip := net.IP(nil)
	if dest.Address.Family().IsDomain() {
		ip = d.resolve[dest.Address.Domain()]
		if ip == nil {
			return nil, io.ErrUnexpectedEOF
		}
	} else {
		ip = dest.Address.IP()
	}
	c := newRecordConn()
	d.mu.Lock()
	d.dials = append(d.dials, dest.String())
	d.conns = append(d.conns, c)
	d.mu.Unlock()
	return &internet.PacketConnWrapper{PacketConn: c, Dest: &net.UDPAddr{IP: ip, Port: int(dest.Port)}}, nil
}

func (d *recordDialer) DestIpAddress() net.IP                                 { return nil }
func (d *recordDialer) SetOutboundGateway(context.Context, *session.Outbound) {}

func (d *recordDialer) conn(t *testing.T) *recordConn {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.conns) != 1 {
		t.Fatalf("%d sockets dialed (%v), want 1", len(d.conns), d.dials)
	}
	return d.conns[0]
}

// routeFlow is one UDP flow through Handler.Process.
type routeFlow struct {
	t      *testing.T
	up     *pipe.Writer
	cancel context.CancelFunc
	done   chan struct{}
	d      *recordDialer
	sent   int
}

type flowOpts struct {
	inboundTag string
	ob         session.Outbound // Target etc.; Tag defaults to testTag
	protocol   string
}

func startRouteFlow(t *testing.T, h *Handler, d *recordDialer, o flowOpts) *routeFlow {
	t.Helper()
	upR, upW := pipe.New(pipe.WithoutSizeLimit())
	_, downW := pipe.New(pipe.WithoutSizeLimit())
	ctx, cancel := context.WithCancel(context.Background())
	ob := o.ob
	if ob.Tag == "" {
		ob.Tag = testTag
	}
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{&ob})
	in := o.inboundTag
	if in == "" {
		in = "in-a"
	}
	ctx = session.ContextWithInbound(ctx, &session.Inbound{
		Tag:    in,
		Source: net.UDPDestination(net.ParseAddress("198.51.100.7"), 51000),
		User:   &protocol.MemoryUser{Email: "user@test"},
	})
	ctx = session.ContextWithContent(ctx, &session.Content{Protocol: o.protocol})
	f := &routeFlow{t: t, up: upW, cancel: cancel, done: make(chan struct{}), d: d}
	go func() {
		h.Process(ctx, &transport.Link{Reader: upR, Writer: downW}, d)
		close(f.done)
	}()
	t.Cleanup(f.close)
	return f
}

// send writes one datagram to to (nil: the flow's own target).
func (f *routeFlow) send(to *net.Destination, payload string) {
	b := buf.New()
	b.WriteString(payload)
	if to != nil {
		d := *to
		b.UDP = &d
	}
	if err := f.up.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		f.t.Fatal(err)
	}
	f.sent++
}

// sync sends a datagram to the flow's own destination and waits until it
// is written: everything sent before it has been handled.
func (f *routeFlow) sync() []string {
	f.t.Helper()
	marker := fmt.Sprintf("sync-%d", f.sent)
	f.send(nil, marker)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		f.d.mu.Lock()
		var c *recordConn
		if len(f.d.conns) > 0 {
			c = f.d.conns[0]
		}
		f.d.mu.Unlock()
		if c != nil {
			w := c.snapshot()
			if len(w) > 0 && strings.HasSuffix(w[len(w)-1], " "+marker) {
				return w[:len(w)-1]
			}
			for _, s := range w {
				if strings.HasSuffix(s, " "+marker) {
					f.t.Fatalf("sync datagram not last: %v", w)
				}
			}
		}
		time.Sleep(time.Millisecond)
	}
	f.t.Fatal("sync datagram never written")
	return nil
}

func (f *routeFlow) close() {
	f.up.Close()
	f.cancel()
	select {
	case <-f.done:
	case <-time.After(5 * time.Second):
		f.t.Error("flow did not end")
	}
}

func dst(addr string, port net.Port) *net.Destination {
	d := net.UDPDestination(net.ParseAddress(addr), port)
	return &d
}

func expectWrites(t *testing.T, got []string, want ...string) {
	t.Helper()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("written:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

// captureLog records the log lines about dropped datagrams.
type captureLog struct {
	mu    sync.Mutex
	lines []string
}

func (c *captureLog) Handle(msg log.Message) {
	s := msg.String()
	if strings.Contains(s, "udpRouteEachDestination") {
		c.mu.Lock()
		c.lines = append(c.lines, s)
		c.mu.Unlock()
	}
}

func (c *captureLog) get() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.lines...)
}

func withCaptureLog(t *testing.T) *captureLog {
	c := new(captureLog)
	log.RegisterHandler(c)
	t.Cleanup(func() { log.RegisterHandler(discardLog{}) })
	return c
}

type discardLog struct{}

func (discardLog) Handle(log.Message) {}

// newGuard returns the guard of a flow routed to ob, as Process makes it.
func newGuard(h *Handler, ob *session.Outbound) *udpRouteGuard {
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{ob})
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Tag: "in-a"})
	return h.newUDPRouteGuard(ctx, ob, net.Destination{})
}

var on = &Config{UdpRouteEachDestination: true}

func TestUDPRouteFirstDestinationPasses(t *testing.T) {
	rt := newRouteTest(t, on)
	d := &recordDialer{}
	f := startRouteFlow(t, rt.h, d, flowOpts{ob: session.Outbound{Target: *dst("9.9.9.9", 53)}})
	f.send(dst("9.9.9.9", 53), "q1") // XUDP: the first datagram carries the target
	f.send(nil, "q2")
	f.send(dst("9.9.9.9", 53), "q3")
	expectWrites(t, f.sync(), "9.9.9.9:53 q1", "9.9.9.9:53 q2", "9.9.9.9:53 q3")
	if n := rt.router.calls.Load(); n != 0 {
		t.Fatalf("router called %d times for the flow's own destination", n)
	}
}

func TestUDPRouteLaterDestinations(t *testing.T) {
	logs := withCaptureLog(t)
	rt := newRouteTest(t, on)
	d := &recordDialer{}
	f := startRouteFlow(t, rt.h, d, flowOpts{ob: session.Outbound{Target: *dst("9.9.9.9", 53)}})
	f.send(dst("9.9.9.9", 53), "first")
	f.send(dst("9.9.9.10", 53), "ip-rule")      // allowed by the IP rule
	f.send(dst("5.75.198.163", 3478), "port")   // allowed by the port rule (inbound in-a)
	f.send(dst("5.75.198.163", 554), "nolist")  // not listed: no route
	f.send(dst("10.66.1.1", 53), "blocked")     // routed to blocked
	f.send(dst("10.77.1.1", 53), "proxy")       // routed to another outbound
	f.send(dst("10.88.1.1", 53), "bal-proxy")   // balancer picks proxy-a/b
	f.send(dst("10.99.1.1", 53), "bal-direct")  // balancer picks direct
	f.send(dst("5.75.198.163", 554), "nolist2") // cached denial
	expectWrites(t, f.sync(),
		"9.9.9.9:53 first", "9.9.9.10:53 ip-rule", "5.75.198.163:3478 port", "10.99.1.1:53 bal-direct")
	if n := rt.router.calls.Load(); n != 7 {
		t.Fatalf("router called %d times, want 7 (one per new destination)", n)
	}
	if p, ds := rt.counter("dropped_packets"), rt.counter("dropped_destinations"); p != 5 || ds != 4 {
		t.Fatalf("dropped_packets %d, dropped_destinations %d; want 5, 4", p, ds)
	}
	lines := logs.get()
	if len(lines) != 1 || !strings.Contains(lines[0], "[Info]") || !strings.Contains(lines[0], "5.75.198.163:554 -> (no route)") {
		t.Fatalf("log lines: %q, want one Info line with the example", lines)
	}
}

func TestUDPRouteUsesFlowContext(t *testing.T) {
	// The port rule is for inbound in-a only: the same datagram of a flow
	// from in-b is dropped.
	rt := newRouteTest(t, on)
	d := &recordDialer{}
	f := startRouteFlow(t, rt.h, d, flowOpts{inboundTag: "in-b", ob: session.Outbound{Target: *dst("9.9.9.9", 53)}})
	f.send(dst("5.75.198.163", 3478), "stun")
	expectWrites(t, f.sync())
}

func TestUDPRouteRouterOncePerDestination(t *testing.T) {
	rt := newRouteTest(t, on)
	d := &recordDialer{}
	f := startRouteFlow(t, rt.h, d, flowOpts{ob: session.Outbound{Target: *dst("9.9.9.9", 53)}})
	var want []string
	for i := 0; i < 10; i++ {
		for _, a := range []string{"9.9.9.20", "9.9.9.21", "10.66.0.1"} {
			f.send(dst(a, 53), fmt.Sprint(i))
			if a != "10.66.0.1" {
				want = append(want, fmt.Sprintf("%s:53 %d", a, i))
			}
		}
	}
	expectWrites(t, f.sync(), want...)
	if n := rt.router.calls.Load(); n != 3 {
		t.Fatalf("router called %d times for 30 datagrams to 3 new destinations, want 3", n)
	}
	if p := rt.counter("dropped_packets"); p != 10 {
		t.Fatalf("dropped_packets %d, want 10", p)
	}
}

// The setting off: every destination is written, as before.
func TestUDPRouteOffKeepsBehaviour(t *testing.T) {
	run := func(config *Config, router bool) ([]string, int64) {
		rt := newRouteTest(t, config)
		if !router {
			rt.h.router = nil
		}
		d := &recordDialer{}
		f := startRouteFlow(t, rt.h, d, flowOpts{ob: session.Outbound{Target: *dst("9.9.9.9", 53)}})
		for i, a := range []string{"9.9.9.9", "5.75.198.163", "10.66.0.1", "10.77.0.1", "10.88.0.1", "2001:db8::1"} {
			f.send(dst(a, net.Port(554+i)), fmt.Sprintf("payload-%d-\x00\xff", i))
		}
		w := f.sync()
		f.close()
		return w, rt.router.calls.Load()
	}
	want := []string{
		"9.9.9.9:554 payload-0-\x00\xff", "5.75.198.163:555 payload-1-\x00\xff", "10.66.0.1:556 payload-2-\x00\xff",
		"10.77.0.1:557 payload-3-\x00\xff", "10.88.0.1:558 payload-4-\x00\xff", "[2001:db8::1]:559 payload-5-\x00\xff",
	}
	for _, c := range []struct {
		name   string
		config *Config
		router bool
	}{{"default", &Config{}, true}, {"default-no-router", &Config{}, false}, {"explicit-false", &Config{UdpRouteEachDestination: false}, true}} {
		got, calls := run(c.config, c.router)
		expectWrites(t, got, want...)
		if calls != 0 {
			t.Fatalf("%s: router called %d times with the setting off", c.name, calls)
		}
	}
}

// A QUIC flow allowed by its sniffed domain keeps working for later datagrams
// to the same IP; another IP is routed without the domain.
func TestUDPRouteSniffedDomain(t *testing.T) {
	t.Run("routeOnly", func(t *testing.T) {
		rt := newRouteTest(t, on)
		d := &recordDialer{}
		ip := *dst("203.0.113.10", 443)
		f := startRouteFlow(t, rt.h, d, flowOpts{protocol: "quic", ob: session.Outbound{
			Target:      ip,
			RouteTarget: net.UDPDestination(net.DomainAddress("www.instagram.com"), 443),
		}})
		f.send(&ip, "initial")
		f.send(&ip, "later")
		f.send(dst("203.0.113.11", 443), "other-ip")
		expectWrites(t, f.sync(), "203.0.113.10:443 initial", "203.0.113.10:443 later")
	})
	t.Run("destOverride", func(t *testing.T) {
		rt := newRouteTest(t, on)
		d := &recordDialer{resolve: map[string]net.IP{"www.instagram.com": {203, 0, 113, 99}}}
		ip := *dst("203.0.113.10", 443)
		f := startRouteFlow(t, rt.h, d, flowOpts{protocol: "quic", ob: session.Outbound{
			Target:         net.UDPDestination(net.DomainAddress("www.instagram.com"), 443),
			OriginalTarget: ip,
		}})
		f.send(&ip, "to-original")                        // ob.OriginalTarget
		f.send(dst("203.0.113.99", 443), "to-dialed")     // conn.RemoteAddr()
		f.send(dst("203.0.113.11", 443), "other-ip")      // routed: no domain, no route
		f.send(dst("::ffff:203.0.113.10", 443), "mapped") // the original, IPv4-mapped
		expectWrites(t, f.sync(), "203.0.113.10:443 to-original", "203.0.113.99:443 to-dialed", "203.0.113.10:443 mapped")
		if n := rt.router.calls.Load(); n != 1 {
			t.Fatalf("router called %d times, want 1", n)
		}
	})
}

func TestUDPRouteDomainDestination(t *testing.T) {
	rt := newRouteTest(t, on)
	d := &recordDialer{}
	f := startRouteFlow(t, rt.h, d, flowOpts{ob: session.Outbound{Target: *dst("9.9.9.9", 53)}})
	local := net.UDPDestination(net.DomainAddress("localhost"), 5000)
	f.send(&local, "domain-allowed") // full:localhost; resolved after the check
	f.send(&local, "again")
	denied := net.UDPDestination(net.DomainAddress("denied.invalid"), 5000)
	f.send(&denied, "domain-denied") // never resolved: dropped before any lookup
	got := f.sync()
	if len(got) != 2 || !strings.HasSuffix(got[0], ":5000 domain-allowed") || !strings.HasSuffix(got[1], ":5000 again") {
		t.Fatalf("written %q", got)
	}
	if n := rt.router.calls.Load(); n != 2 {
		t.Fatalf("router called %d times, want 2", n)
	}
	if ds := rt.counter("dropped_destinations"); ds != 1 {
		t.Fatalf("dropped_destinations %d, want 1", ds)
	}
}

func TestUDPRouteKeyCanonical(t *testing.T) {
	v4 := udpRouteKey{addr: net.ParseAddress("9.9.9.9"), port: 53}
	mapped := udpRouteKey{addr: net.IPAddress(net.ParseIP("::ffff:9.9.9.9")), port: 53}
	if v4 != mapped || v4.canonical() != mapped.canonical() {
		t.Fatalf("IPv4-mapped IPv6 key %v differs from IPv4 key %v", mapped, v4)
	}
	if k := (udpRouteKey{addr: net.DomainAddress("WWW.Example.COM"), port: 1}).canonical(); k.addr.Domain() != "www.example.com" {
		t.Fatalf("domain key %v not lower case", k.addr)
	}
	rt := newRouteTest(t, on)
	g := newGuard(rt.h, &session.Outbound{Tag: testTag, Target: *dst("::ffff:9.9.9.9", 53)})
	if !g.allow(dst("9.9.9.9", 53)) || rt.router.calls.Load() != 0 {
		t.Fatal("the IPv4 form of the flow's IPv4-mapped target was not approved")
	}
}

// unlimited lifts the guard's router budget, for tests of other bounds.
func unlimited(g *udpRouteGuard) *udpRouteGuard {
	g.tokens = 1 << 40
	return g
}

func TestUDPRouteCacheBound(t *testing.T) {
	rt := newRouteTest(t, on)
	g := unlimited(newGuard(rt.h, &session.Outbound{Tag: testTag, Target: *dst("9.9.9.9", 53)}))
	g.approveAddr(&net.UDPAddr{IP: net.IP{9, 9, 9, 8}, Port: 53})
	dest := func(i int) *net.Destination { return dst(fmt.Sprintf("10.66.%d.%d", i/256, i%256), 53) }
	for i := 0; i < maxUDPRouteDecisions; i++ {
		if g.allow(dest(i)) {
			t.Fatal("blocked destination allowed")
		}
	}
	if len(g.decided) != maxUDPRouteDecisions || rt.h.udpRouteCached.Load() != maxUDPRouteDecisions {
		t.Fatalf("%d decisions kept (%d counted), want %d", len(g.decided), rt.h.udpRouteCached.Load(), maxUDPRouteDecisions)
	}
	calls := rt.router.calls.Load()
	g.allow(dest(0)) // still cached
	if rt.router.calls.Load() != calls {
		t.Fatal("a cached decision was routed again")
	}
	old := reflect.ValueOf(g.decided).UnsafePointer()
	g.allow(dest(maxUDPRouteDecisions)) // one too many: the decisions are forgotten
	if len(g.decided) != 1 || rt.h.udpRouteCached.Load() != 1 {
		t.Fatalf("%d decisions (%d counted) after the overflow, want the 1 new", len(g.decided), rt.h.udpRouteCached.Load())
	}
	if reflect.ValueOf(g.decided).UnsafePointer() == old {
		t.Fatal("the full map was kept: its memory is not let go")
	}
	for _, ok := range []bool{g.allow(dst("9.9.9.9", 53)), g.allow(dst("9.9.9.8", 53))} {
		if !ok {
			t.Fatal("an approved destination was lost in the overflow")
		}
	}
	if rt.router.calls.Load() != calls+1 {
		t.Fatal("approved destinations were routed after the overflow")
	}
	g.allow(dest(0))
	if rt.router.calls.Load() != calls+2 {
		t.Fatal("a forgotten decision was not made again")
	}
	g.release()
	if n := rt.h.udpRouteCached.Load(); n != 0 {
		t.Fatalf("%d decisions counted after release, want 0", n)
	}
}

// fakeClock sets the router budget's clock for a test.
func fakeClock(t *testing.T) *atomic.Int64 {
	var now atomic.Int64
	now.Store(time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC).UnixNano())
	saved := udpRouteNow
	udpRouteNow = now.Load
	t.Cleanup(func() { udpRouteNow = saved })
	return &now
}

// A flow routes udpRouteBurst new destinations at once, then udpRouteRate a
// second: a datagram over that is dropped unrouted and remembered nowhere.
func TestUDPRouteBudget(t *testing.T) {
	now := fakeClock(t)
	logs := withCaptureLog(t)
	rt := newRouteTest(t, on)
	g := newGuard(rt.h, &session.Outbound{Tag: testTag, Target: *dst("9.9.9.9", 53)})
	dest := func(i int) *net.Destination { return dst(fmt.Sprintf("45.33.%d.%d", i/256, i%256), 554) }
	const spray = udpRouteBurst + 72
	for i := 0; i < spray; i++ {
		if g.allow(dest(i)) {
			t.Fatal("an unlisted destination was allowed")
		}
	}
	if n := rt.router.calls.Load(); n != udpRouteBurst {
		t.Fatalf("router called %d times for %d new destinations at once, want the burst %d", n, spray, udpRouteBurst)
	}
	if p, ds := rt.counter("dropped_packets"), rt.counter("dropped_destinations"); p != spray || ds != udpRouteBurst {
		t.Fatalf("dropped_packets %d, dropped_destinations %d; want %d, %d", p, ds, spray, udpRouteBurst)
	}
	if len(g.decided) != udpRouteBurst {
		t.Fatalf("%d decisions kept, want %d: over the budget nothing is remembered", len(g.decided), udpRouteBurst)
	}
	// The flow's own destination and the decided ones need no budget.
	if !g.allow(dst("9.9.9.9", 53)) || g.allow(dest(0)) || rt.router.calls.Load() != udpRouteBurst {
		t.Fatal("decided destinations were routed again over the budget")
	}
	// An allowed destination over the budget is dropped too, until the
	// budget refills: denying is the safe side.
	if g.allow(dst("9.9.9.10", 53)) {
		t.Fatal("a new destination was allowed over the budget")
	}
	now.Add(udpRouteTokenEvery)
	if !g.allow(dst("9.9.9.10", 53)) {
		t.Fatal("the allowed destination was dropped after the budget refilled")
	}
	if g.allow(dst("9.9.9.11", 53)) {
		t.Fatal("one token refilled, two spent")
	}
	// One second refills udpRouteRate calls.
	now.Add(int64(time.Second))
	calls := rt.router.calls.Load()
	for i := spray; i < spray+2*udpRouteRate; i++ {
		g.allow(dest(i))
	}
	if n := rt.router.calls.Load() - calls; n != udpRouteRate {
		t.Fatalf("router called %d times in the second after, want %d", n, udpRouteRate)
	}
	// Idle long enough, the budget is a full burst again, not more.
	now.Add(int64(time.Hour))
	calls = rt.router.calls.Load()
	for i := 0; i < 2*udpRouteBurst; i++ {
		g.allow(dst(fmt.Sprintf("45.34.%d.%d", i/256, i%256), 554))
	}
	if n := rt.router.calls.Load() - calls; n != udpRouteBurst {
		t.Fatalf("router called %d times after an idle hour, want %d", n, udpRouteBurst)
	}
	lines := logs.get()
	if len(lines) != 1 || !strings.Contains(lines[0], "[Info]") {
		t.Fatalf("log lines %q", lines)
	}
	rt.h.udpRouteDrops.lastLog.Store(time.Now().Add(-udpRouteLogInterval).UnixNano())
	g.allow(dst("45.35.0.1", 554))
	if lines = logs.get(); len(lines) != 2 || !strings.Contains(lines[1], "over their flow's routing budget") {
		t.Fatalf("log lines %q, want the budget drops in the second", lines)
	}
}

// Over the handler's bound a flow remembers no new denials, and allowed
// decisions only while it is small. The flows' decisions are counted off
// when they end.
func TestUDPRouteHandlerCacheBound(t *testing.T) {
	rt := newRouteTest(t, on)
	rt.h.udpRouteCached.Store(maxUDPRouteCached)
	g := unlimited(newGuard(rt.h, &session.Outbound{Tag: testTag, Target: *dst("9.9.9.9", 53)}))
	g.allow(dst("10.66.0.1", 53))
	g.allow(dst("10.66.0.2", 53))
	g.allow(dst("10.66.0.1", 53))
	if n := rt.router.calls.Load(); n != 3 || len(g.decided) != 0 {
		t.Fatalf("router called %d times, %d decisions kept; want 3, 0: no denials remembered", n, len(g.decided))
	}
	for i := 0; i < 2*udpRouteSmallFlow; i++ {
		if !g.allow(dst(fmt.Sprintf("9.9.9.%d", 10+i), 53)) {
			t.Fatal("allowed destination dropped")
		}
	}
	if len(g.decided) != udpRouteSmallFlow {
		t.Fatalf("%d allowed decisions kept, want %d", len(g.decided), udpRouteSmallFlow)
	}
	g.release()
	if n := rt.h.udpRouteCached.Load(); n != maxUDPRouteCached {
		t.Fatalf("count %d after release, want %d", n, maxUDPRouteCached)
	}

	// Flows through Process count their decisions off when they end.
	rt.h.udpRouteCached.Store(0)
	d := &recordDialer{}
	f := startRouteFlow(t, rt.h, d, flowOpts{ob: session.Outbound{Target: *dst("9.9.9.9", 53)}})
	f.send(dst("9.9.9.10", 53), "a")
	f.send(dst("10.66.0.1", 53), "b")
	f.sync()
	if n := rt.h.udpRouteCached.Load(); n != 2 {
		t.Fatalf("count %d during the flow, want 2", n)
	}
	f.close()
	if n := rt.h.udpRouteCached.Load(); n != 0 {
		t.Fatalf("count %d after the flow, want 0", n)
	}
}

// release may come from Process while the flow's copy goroutine still
// writes (task.Run returns on the first error): run with -race.
func TestUDPRouteReleaseRace(t *testing.T) {
	rt := newRouteTest(t, on)
	g := unlimited(newGuard(rt.h, &session.Outbound{Tag: testTag, Target: *dst("9.9.9.9", 53)}))
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 2000; i++ {
			g.allow(dst(fmt.Sprintf("10.66.%d.%d", i/256, i%256), 53))
		}
	}()
	time.Sleep(time.Millisecond)
	g.release()
	<-done
	if n := rt.h.udpRouteCached.Load(); n != 0 {
		t.Fatalf("count %d after release, want 0", n)
	}
}

// A flow with one destination allocates only its guard and the boxed dialed
// address: no map, no routing context.
func TestUDPRouteGuardLazy(t *testing.T) {
	rt := newRouteTest(t, on)
	ob := &session.Outbound{Tag: testTag, Target: *dst("9.9.9.9", 53)}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{ob})
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Tag: "in-a"})
	dialed := &net.UDPAddr{IP: net.IP{9, 9, 9, 9}, Port: 53}
	var g *udpRouteGuard
	if n := testing.AllocsPerRun(1000, func() {
		g = rt.h.newUDPRouteGuard(ctx, ob, net.Destination{})
		g.approveAddr(dialed)
	}); n > 2 {
		t.Fatalf("%v allocations per flow, want at most 2", n)
	}
	for i := 0; i < 10; i++ {
		if !g.allow(dst("9.9.9.9", 53)) {
			t.Fatal("own destination dropped")
		}
	}
	if g.decided != nil || g.base != nil || rt.router.calls.Load() != 0 {
		t.Fatal("a single-destination flow made its map or routing context")
	}
	g.allow(dst("10.66.0.1", 53))
	if g.decided == nil || g.base == nil {
		t.Fatal("no map or routing context after a new destination")
	}
}

// destinationOverride's address sends every datagram there: nothing to check.
func TestUDPRouteOverrideBypasses(t *testing.T) {
	config := &Config{UdpRouteEachDestination: true, DestinationOverride: &DestinationOverride{Server: &protocol.ServerEndpoint{
		Address: net.NewIPOrDomain(net.ParseAddress("127.0.0.1")), Port: 9999,
	}}}
	rt := newRouteTest(t, config)
	d := &recordDialer{}
	f := startRouteFlow(t, rt.h, d, flowOpts{ob: session.Outbound{Target: *dst("9.9.9.9", 53)}})
	f.send(dst("10.66.0.1", 53), "a")
	f.send(dst("5.75.198.163", 554), "b")
	expectWrites(t, f.sync(), "127.0.0.1:9999 a", "127.0.0.1:9999 b")
	if n := rt.router.calls.Load(); n != 0 {
		t.Fatalf("router called %d times with an override address", n)
	}
}

// A port-only override still lets datagrams reach any address: they are
// checked by the destination the client asked for.
func TestUDPRoutePortOverrideChecked(t *testing.T) {
	config := &Config{UdpRouteEachDestination: true, DestinationOverride: &DestinationOverride{Server: &protocol.ServerEndpoint{Port: 5353}}}
	rt := newRouteTest(t, config)
	d := &recordDialer{}
	f := startRouteFlow(t, rt.h, d, flowOpts{ob: session.Outbound{Target: *dst("9.9.9.9", 53)}})
	f.send(dst("9.9.9.9", 53), "own")
	f.send(dst("9.9.9.10", 53), "listed")
	f.send(dst("5.75.198.163", 53), "unlisted")
	expectWrites(t, f.sync(), "9.9.9.9:5353 own", "9.9.9.10:5353 listed")
}

// Noise is sent to the dialed address; the datagrams are still checked.
func TestUDPRouteNoiseWriter(t *testing.T) {
	config := &Config{UdpRouteEachDestination: true, Noises: []*Noise{{Packet: []byte("noise"), ApplyTo: "ip"}}}
	rt := newRouteTest(t, config)
	d := &recordDialer{}
	f := startRouteFlow(t, rt.h, d, flowOpts{ob: session.Outbound{Target: *dst("9.9.9.9", 443)}})
	f.send(dst("10.66.0.1", 443), "denied")
	f.send(dst("9.9.9.9", 443), "own")
	expectWrites(t, f.sync(), "9.9.9.9:443 noise", "9.9.9.9:443 own")
}

// A flow that opens with a ping (icmpecho marker) dials its UDP socket for
// its first datagram: only for one routed here.
func TestUDPRouteEchoFlowThenUDP(t *testing.T) {
	rt := newRouteTest(t, on)
	d := &recordDialer{}
	f := startRouteFlow(t, rt.h, d, flowOpts{ob: session.Outbound{Target: *dst("9.9.9.9", 0)}})
	f.send(dst("5.75.198.163", 554), "denied-first")
	f.send(dst("10.66.0.1", 53), "blocked-first")
	time.Sleep(20 * time.Millisecond)
	d.mu.Lock()
	dials := len(d.dials)
	d.mu.Unlock()
	if dials != 0 {
		t.Fatalf("a socket was dialed for a denied datagram: %v", d.dials)
	}
	f.send(dst("9.9.9.9", 53), "allowed")
	f.send(dst("5.75.198.163", 554), "denied-later")
	f.send(dst("9.9.9.10", 53), "allowed-later")
	// The flow's own target is the ping target 9.9.9.9:0, so f.sync cannot
	// be used: the last datagram written means the ones before were handled.
	deadline := time.Now().Add(5 * time.Second)
	var got []string
	for time.Now().Before(deadline) && len(got) < 2 {
		d.mu.Lock()
		if len(d.conns) > 0 {
			got = d.conns[0].snapshot()
		}
		d.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	got = d.conn(t).snapshot()
	expectWrites(t, got, "9.9.9.9:53 allowed", "9.9.9.10:53 allowed-later")
	if p := rt.counter("dropped_packets"); p != 3 {
		t.Fatalf("dropped_packets %d, want 3", p)
	}
}

// The log line is rate-limited per handler.
func TestUDPRouteLogRateLimit(t *testing.T) {
	logs := withCaptureLog(t)
	rt := newRouteTest(t, on)
	g := newGuard(rt.h, &session.Outbound{Tag: testTag, Target: *dst("9.9.9.9", 53)})
	for i := 0; i < 1000; i++ {
		g.allow(dst("10.66.0.1", net.Port(1000+i%10)))
	}
	if n := len(logs.get()); n != 1 {
		t.Fatalf("%d log lines for 1000 drops in one interval, want 1", n)
	}
	rt.h.udpRouteDrops.lastLog.Store(time.Now().Add(-udpRouteLogInterval).UnixNano())
	g.allow(dst("10.77.0.1", 53))
	lines := logs.get()
	if len(lines) != 2 || !strings.Contains(lines[1], "dropped 1000 UDP packets; 10 new destinations") ||
		!strings.Contains(lines[1], "10.77.0.1:53 -> proxy") {
		t.Fatalf("log lines %q", lines)
	}
	if p := rt.counter("dropped_packets"); p != 1001 {
		t.Fatalf("dropped_packets %d, want 1001", p)
	}
}

// Without a router (a handler built without the core) nothing new passes.
func TestUDPRouteNoRouterFailsClosed(t *testing.T) {
	h := new(Handler)
	common.Must(h.Init(on, policy.DefaultManager{}))
	g := newGuard(h, &session.Outbound{Tag: testTag, Target: *dst("9.9.9.9", 53)})
	if !g.allow(dst("9.9.9.9", 53)) || g.allow(dst("9.9.9.10", 53)) {
		t.Fatal("want the flow's own destination only")
	}
}

// The hit path does not allocate.
func TestUDPRouteHitPathAllocs(t *testing.T) {
	rt := newRouteTest(t, on)
	g := newGuard(rt.h, &session.Outbound{Tag: testTag, Target: *dst("9.9.9.9", 53)})
	dests := []*net.Destination{dst("9.9.9.9", 53), dst("9.9.9.10", 53), dst("10.66.0.1", 53), dst("2001:db8::1", 53)}
	for _, d := range dests {
		g.allow(d)
	}
	i := 0
	if n := testing.AllocsPerRun(1000, func() { g.allow(dests[i%len(dests)]); i++ }); n != 0 {
		t.Fatalf("%v allocations per check", n)
	}
}

// discardConn is a UDP socket that drops what is written.
type discardConn struct{ recordConn }

func (*discardConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }

func benchmarkPacketWriter(b *testing.B, n int, enabled bool) {
	rt := newRouteTest(b, &Config{UdpRouteEachDestination: enabled})
	dests := make([]net.Destination, n)
	for i := range dests {
		dests[i] = net.UDPDestination(net.IPAddress([]byte{9, 9, byte(i / 256), byte(i % 256)}), 443)
	}
	// 9.9.0.0/16 is "direct" too, for the benchmark: add the rule.
	cfg := testRoutingConfig()
	cfg.Rule = append([]*router.RoutingRule{{TargetTag: &router.RoutingRule_Tag{Tag: "direct"}, Geoip: []*router.GeoIP{cidr(9, 9, 0, 0, 16)}}}, cfg.Rule...)
	r := new(router.Router)
	common.Must(r.Init(context.Background(), cfg, noDNS{t: b}, testOutbounds{tags: []string{"direct"}}, nil))
	rt.h.router = r
	ob := &session.Outbound{Tag: testTag, Target: dests[0]}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{ob})
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Tag: "in-a"})
	var guard *udpRouteGuard
	if enabled {
		guard = rt.h.newUDPRouteGuard(ctx, ob, net.Destination{})
	}
	sink := new(discardConn)
	sink.done = make(chan struct{})
	conn := &internet.PacketConnWrapper{PacketConn: sink, Dest: dests[0].RawNetAddr()}
	if guard != nil {
		unlimited(guard).approveAddr(conn.RemoteAddr())
	}
	w := rt.h.newUDPWriter(ctx, conn, net.Destination{}, dests[0], guard)
	payload := make([]byte, 1200)
	write := func(i int) {
		p := buf.New()
		p.Write(payload)
		p.UDP = &dests[i%n]
		if err := w.WriteMultiBuffer(buf.MultiBuffer{p}); err != nil {
			b.Fatal(err)
		}
	}
	for i := 0; i < n; i++ { // every destination decided before timing
		write(i)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		write(i)
	}
	b.StopTimer()
	if enabled && len(guard.decided) != n-1 { // dests[0] is the flow's own
		b.Fatalf("%d decisions for %d destinations", len(guard.decided), n)
	}
}

func BenchmarkPacketWriter(b *testing.B) {
	for _, n := range []int{1, 64, maxUDPRouteDecisions} {
		for _, enabled := range []bool{false, true} {
			name := fmt.Sprintf("dests=%d/route=off", n)
			if enabled {
				name = fmt.Sprintf("dests=%d/route=on", n)
			}
			b.Run(name, func(b *testing.B) { benchmarkPacketWriter(b, n, enabled) })
		}
	}
}

// The check alone, on its hit path and on a miss (one router call).
func BenchmarkUDPRouteGuard(b *testing.B) {
	for _, n := range []int{1, 64, maxUDPRouteDecisions} {
		b.Run(fmt.Sprintf("hit/dests=%d", n), func(b *testing.B) {
			rt := newRouteTest(b, on)
			// dests[0] is the flow's own destination: n destinations in all.
			dests := make([]net.Destination, n)
			for i := range dests {
				dests[i] = net.UDPDestination(net.IPAddress([]byte{9, 9, 9, byte(i)}), net.Port(1000+i))
			}
			g := unlimited(newGuard(rt.h, &session.Outbound{Tag: testTag, Target: dests[0]}))
			for i := range dests {
				g.allow(&dests[i])
			}
			if len(g.decided) != n-1 {
				b.Fatalf("%d decisions for %d destinations", len(g.decided), n)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if !g.allow(&dests[i%n]) {
					b.Fatal("denied")
				}
			}
		})
	}
	b.Run("miss", func(b *testing.B) {
		rt := newRouteTest(b, on)
		// Unlimited budget: every datagram is a router call; the decisions
		// overflow and are forgotten as they would be.
		g := unlimited(newGuard(rt.h, &session.Outbound{Tag: testTag, Target: *dst("9.9.9.9", 53)}))
		dests := make([]net.Destination, 1<<16)
		for i := range dests {
			dests[i] = net.UDPDestination(net.IPAddress([]byte{10, 66, byte(i >> 8), byte(i)}), 53)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			g.allow(&dests[i%len(dests)])
		}
	})
}
