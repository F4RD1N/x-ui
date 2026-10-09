//go:build linux

package freedom

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/icmpecho"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

// These tests send real pings. Run as root they use a raw socket; the
// datagram socket is used where net.ipv4.ping_group_range admits the group
// (it is per network namespace, so a namespace can enable it). A mode the
// host cannot open is skipped. ICMPECHO_TEST_PEER4 and ICMPECHO_TEST_PEER6
// name a host on another namespace to ping as well, and
// ICMPECHO_TEST_SILENT4 an address that is routed but never answers.

type testDialer struct {
	sockopt *internet.SocketConfig
	chained bool
	gateway net.Address // sendThrough
}

func (d *testDialer) Dial(ctx context.Context, dest net.Destination) (stat.Connection, error) {
	return internet.DialSystem(ctx, dest, nil)
}

func (d *testDialer) DestIpAddress() net.IP { return nil }

func (d *testDialer) SetOutboundGateway(_ context.Context, ob *session.Outbound) {
	if d.gateway != nil {
		ob.Gateway = d.gateway
	}
}

func (d *testDialer) LocalSocketSettings() (*internet.SocketConfig, bool) {
	return d.sockopt, !d.chained
}

func newTestHandler(config *Config) *Handler {
	h := new(Handler)
	h.Init(config, policy.DefaultManager{})
	return h
}

// idlePolicy is the default policy with a short connection idle timeout.
type idlePolicy struct {
	policy.DefaultManager
	idle time.Duration
}

func (p idlePolicy) ForLevel(uint32) policy.Session {
	s := policy.SessionDefault()
	s.Timeouts.ConnectionIdle = p.idle
	return s
}

type testFlow struct {
	t        *testing.T
	up       *pipe.Writer
	down     *pipe.Reader
	pending  buf.MultiBuffer
	cancel   context.CancelFunc
	finished chan struct{}
	result   error // set before finished is closed
}

func startFlow(t *testing.T, h *Handler, d internet.Dialer, target net.Destination) *testFlow {
	t.Helper()
	upR, upW := pipe.New(pipe.WithoutSizeLimit())
	downR, downW := pipe.New(pipe.WithoutSizeLimit())
	ctx, cancel := context.WithCancel(context.Background())
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: target}})
	f := &testFlow{t: t, up: upW, down: downR, cancel: cancel, finished: make(chan struct{})}
	go func() {
		f.result = h.Process(ctx, &transport.Link{Reader: upR, Writer: downW}, d)
		close(f.finished)
	}()
	t.Cleanup(f.close)
	return f
}

// ended reports whether the flow's Process returned within d, and its error.
func (f *testFlow) ended(d time.Duration) (bool, error) {
	select {
	case <-f.finished:
		return true, f.result
	case <-time.After(d):
		return false, nil
	}
}

// send writes one datagram; to is nil for the flow's own target.
func (f *testFlow) send(to *net.Destination, payload []byte) {
	b := buf.New()
	b.Write(payload)
	b.UDP = to
	if err := f.up.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		f.t.Fatal(err)
	}
}

// recv returns the next datagram, or nil when none comes within d.
func (f *testFlow) recv(d time.Duration) *buf.Buffer {
	deadline := time.Now().Add(d)
	for len(f.pending) == 0 {
		left := time.Until(deadline)
		if left <= 0 {
			return nil
		}
		mb, err := f.down.ReadMultiBufferTimeout(left)
		if err != nil {
			return nil
		}
		f.pending = append(f.pending, mb...)
	}
	b := f.pending[0]
	f.pending = f.pending[1:]
	return b
}

func (f *testFlow) close() {
	f.up.Close()
	f.cancel()
	f.down.Interrupt()
	select {
	case <-f.finished:
	case <-time.After(5 * time.Second):
		f.t.Error("flow did not end")
	}
}

// startUDPEcho runs a UDP server on 127.0.0.1 that answers each datagram
// with "echo:" and the datagram, and returns its address.
func startUDPEcho(t *testing.T) net.Destination {
	t.Helper()
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP{127, 0, 0, 1}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	go func() {
		b := make([]byte, 2048)
		for {
			n, from, err := srv.ReadFromUDP(b)
			if err != nil {
				return
			}
			srv.WriteToUDP(append([]byte("echo:"), b[:n]...), from)
		}
	}()
	return net.UDPDestination(net.LocalHostIP, net.Port(srv.LocalAddr().(*net.UDPAddr).Port))
}

// expectUDP checks b is the datagram want from from.
func expectUDP(t *testing.T, b *buf.Buffer, from net.Destination, want string) {
	t.Helper()
	if b == nil {
		t.Fatalf("no answer %q from %v", want, from)
	}
	defer b.Release()
	if string(b.Bytes()) != want {
		t.Fatalf("got %q from %v, want %q", b.Bytes(), b.UDP, want)
	}
	if b.UDP == nil || *b.UDP != from {
		t.Fatalf("answer from %v, want %v", b.UDP, from)
	}
}

// openFDs counts the process's open file descriptors.
func openFDs(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip("cannot count open files: ", err)
	}
	return len(ents)
}

func udpTo(s string, port net.Port) *net.Destination {
	d := net.UDPDestination(net.ParseAddress(s), port)
	return &d
}

// echoModes are the socket types the host can open for the family.
func echoModes(t *testing.T, ipv6 bool) map[string]int {
	family, proto := unix.AF_INET, unix.IPPROTO_ICMP
	if ipv6 {
		family, proto = unix.AF_INET6, unix.IPPROTO_ICMPV6
	}
	modes := map[string]int{}
	for name, typ := range map[string]int{"dgram": unix.SOCK_DGRAM, "raw": unix.SOCK_RAW} {
		fd, err := unix.Socket(family, typ|unix.SOCK_CLOEXEC, proto)
		if err != nil {
			t.Logf("%s ICMP socket (ipv6=%v) not available here: %v", name, ipv6, err)
			continue
		}
		unix.Close(fd)
		modes[name] = typ
	}
	return modes
}

// withMode runs fn once per socket type available, forcing freedom to use it.
func withMode(t *testing.T, ipv6 bool, fn func(t *testing.T)) {
	modes := echoModes(t, ipv6)
	if len(modes) == 0 {
		t.Skip("no ICMP socket can be opened")
	}
	for name, typ := range modes {
		t.Run(name, func(t *testing.T) {
			saved := echoSocketTypes
			echoSocketTypes = []int{typ}
			// Registered before the flows' cleanups, so it runs after them,
			// once no flow can still be opening a socket.
			t.Cleanup(func() { echoSocketTypes = saved })
			fn(t)
		})
	}
}

func hasIPv6Loopback() bool {
	c, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.LocalHostIPv6.IP()})
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func request(ipv6 bool, id, seq uint16, data []byte) []byte {
	return icmpecho.AppendRequest(nil, icmpecho.Echo{IPv6: ipv6, ID: id, Seq: seq, Data: data})
}

// expectReply checks b is the echo reply to (id, seq, data) from from:0.
func expectReply(t *testing.T, b *buf.Buffer, from net.Address, ipv6 bool, id, seq uint16, data []byte) {
	t.Helper()
	if b == nil {
		t.Fatalf("no reply to seq %d from %v", seq, from)
	}
	defer b.Release()
	if b.UDP == nil || b.UDP.Network != net.Network_UDP || b.UDP.Port != 0 || b.UDP.Address != from {
		t.Fatalf("reply from %v, want udp:%v:0", b.UDP, from)
	}
	e, ok := icmpecho.ParseReply(b.Bytes(), ipv6)
	if !ok {
		t.Fatalf("not an echo reply: %x", b.Bytes())
	}
	if e.ID != id || e.Seq != seq || !bytes.Equal(e.Data, data) {
		t.Fatalf("reply id %#x seq %d data %q, want id %#x seq %d data %q", e.ID, e.Seq, e.Data, id, seq, data)
	}
	if !ipv6 && icmpecho.Checksum(b.Bytes()) != 0 {
		t.Fatal("bad checksum in the reply")
	}
}

func pingAddress(t *testing.T, target net.Address, ipv6 bool) {
	withMode(t, ipv6, func(t *testing.T) {
		f := startFlow(t, newTestHandler(&Config{}), &testDialer{}, net.UDPDestination(target, 0))
		const id = 0x1234
		for seq := uint16(1); seq <= 3; seq++ {
			data := []byte(fmt.Sprintf("ping %d to %v, abcdefghijklmnopqrstuvwxyz", seq, target))
			f.send(nil, request(ipv6, id, seq, data))
			expectReply(t, f.recv(3*time.Second), target, ipv6, id, seq, data)
		}
		if b := f.recv(200 * time.Millisecond); b != nil {
			t.Fatalf("unexpected extra datagram: %x", b.Bytes())
		}
	})
}

func TestEchoLoopbackIPv4(t *testing.T) {
	pingAddress(t, net.LocalHostIP, false)
}

func TestEchoLoopbackIPv6(t *testing.T) {
	if !hasIPv6Loopback() {
		t.Skip("no IPv6 loopback")
	}
	pingAddress(t, net.LocalHostIPv6, true)
}

func TestEchoNamespacePeer(t *testing.T) {
	for _, c := range []struct {
		env  string
		ipv6 bool
	}{{"ICMPECHO_TEST_PEER4", false}, {"ICMPECHO_TEST_PEER6", true}} {
		t.Run(c.env, func(t *testing.T) {
			peer := os.Getenv(c.env)
			if peer == "" {
				t.Skip(c.env + " not set")
			}
			pingAddress(t, net.ParseAddress(peer), c.ipv6)
		})
	}
}

// A domain is resolved to the echo's family and the reply comes from the
// domain, as the client sent it.
func TestEchoDomain(t *testing.T) {
	withMode(t, false, func(t *testing.T) {
		host := net.DomainAddress("localhost")
		f := startFlow(t, newTestHandler(&Config{}), &testDialer{}, net.UDPDestination(host, 0))
		f.send(nil, request(false, 7, 1, []byte("by name")))
		expectReply(t, f.recv(3*time.Second), host, false, 7, 1, []byte("by name"))
	})
}

// Everything that is not a well-formed echo request of the target's family
// to a single host is dropped, and the flow carries on.
func TestEchoDrops(t *testing.T) {
	withMode(t, false, func(t *testing.T) {
		f := startFlow(t, newTestHandler(&Config{}), &testDialer{}, net.UDPDestination(net.LocalHostIP, 0))
		f.send(nil, request(true, 1, 1, nil))                    // IPv6 echo to an IPv4 address
		f.send(nil, []byte{13, 0, 0, 0, 0, 1, 0, 1})             // timestamp request
		f.send(nil, []byte{0, 0, 0, 0, 0, 1, 0, 1})              // echo reply
		f.send(nil, []byte{8, 1, 0, 0, 0, 1, 0, 1})              // code 1
		f.send(nil, []byte{8, 0, 0, 0, 0, 1, 0})                 // short
		f.send(nil, make([]byte, 0))                             // empty
		f.send(nil, request(false, 2, 2, []byte("still alive"))) // the one to answer
		expectReply(t, f.recv(3*time.Second), net.LocalHostIP, false, 2, 2, []byte("still alive"))
		if b := f.recv(500 * time.Millisecond); b != nil {
			t.Fatalf("a dropped datagram was answered: %v %x", b.UDP, b.Bytes())
		}
	})
}

// Targets that reach no host or many are never pinged.
func TestEchoDropsTargets(t *testing.T) {
	withMode(t, false, func(t *testing.T) {
		for _, target := range []string{
			"224.0.0.1",       // multicast
			"255.255.255.255", // broadcast
			"0.0.0.0",         // unspecified
			"::1",             // an IPv4 echo to an IPv6 address
		} {
			f := startFlow(t, newTestHandler(&Config{}), &testDialer{}, *udpTo(target, 0))
			f.send(nil, request(false, 1, 1, []byte("nobody")))
			if b := f.recv(300 * time.Millisecond); b != nil {
				t.Fatalf("ping to %s answered: %v %x", target, b.UDP, b.Bytes())
			}
		}
	})
}

// A flow that opens with ordinary UDP still has its pings to the flow's own
// address executed, and its UDP keeps working around them.
func TestEchoInsideUDPFlow(t *testing.T) {
	udpTarget := startUDPEcho(t)
	ping := net.UDPDestination(net.LocalHostIP, 0)

	withMode(t, false, func(t *testing.T) {
		f := startFlow(t, newTestHandler(&Config{}), &testDialer{}, udpTarget)
		f.send(nil, []byte("one"))
		f.send(&ping, request(false, 9, 1, []byte("mid-flow ping")))
		f.send(nil, []byte("two"))
		got := map[string]bool{}
		for i := 0; i < 3; i++ {
			b := f.recv(3 * time.Second)
			if b == nil {
				t.Fatalf("only %d of 3 replies: %v", i, got)
			}
			if b.UDP != nil && b.UDP.Port == 0 {
				expectReply(t, b, net.LocalHostIP, false, 9, 1, []byte("mid-flow ping"))
				got["ping"] = true
				continue
			}
			got[string(b.Bytes())] = true
			b.Release()
		}
		if !got["ping"] || !got["echo:one"] || !got["echo:two"] {
			t.Fatalf("replies: %v", got)
		}
	})
}

// Routing saw only the flow's first destination, so a flow pings that
// address alone. In a flow that opened with UDP a ping to any other address
// is dropped and the UDP carries on; a flow that opened with a ping ends, so
// that the client's next datagram is dispatched and routed afresh.
func TestEchoStaysOnRoutedTarget(t *testing.T) {
	udpTarget := startUDPEcho(t)
	withMode(t, false, func(t *testing.T) {
		t.Run("udp flow", func(t *testing.T) {
			f := startFlow(t, newTestHandler(&Config{}), &testDialer{}, udpTarget)
			f.send(udpTo("127.0.0.2", 0), request(false, 5, 1, []byte("elsewhere")))
			f.send(udpTo("localhost", 0), request(false, 5, 2, []byte("by name")))
			f.send(nil, []byte("after"))
			expectUDP(t, f.recv(3*time.Second), udpTarget, "echo:after")
			f.send(udpTo("127.0.0.1", 0), request(false, 5, 3, []byte("own address")))
			expectReply(t, f.recv(3*time.Second), net.LocalHostIP, false, 5, 3, []byte("own address"))
			if b := f.recv(500 * time.Millisecond); b != nil {
				t.Fatalf("a ping to another address was answered: %v %x", b.UDP, b.Bytes())
			}
		})
		t.Run("ping flow", func(t *testing.T) {
			f := startFlow(t, newTestHandler(&Config{}), &testDialer{}, net.UDPDestination(net.LocalHostIP, 0))
			f.send(nil, request(false, 6, 1, []byte("routed")))
			expectReply(t, f.recv(3*time.Second), net.LocalHostIP, false, 6, 1, []byte("routed"))
			// The same address spelt as an IPv4-mapped IPv6 one is the target.
			f.send(udpTo("::ffff:127.0.0.1", 0), request(false, 6, 2, []byte("mapped")))
			expectReply(t, f.recv(3*time.Second), net.LocalHostIP, false, 6, 2, []byte("mapped"))
			f.send(udpTo("127.0.0.2", 0), request(false, 6, 3, []byte("elsewhere")))
			if b := f.recv(500 * time.Millisecond); b != nil {
				t.Fatalf("a ping to another address was answered: %v %x", b.UDP, b.Bytes())
			}
			if ended, err := f.ended(2 * time.Second); !ended || err == nil {
				t.Fatalf("flow did not end on a ping to another address (ended %v, err %v)", ended, err)
			}
		})
		t.Run("domain flow", func(t *testing.T) {
			host := net.DomainAddress("localhost")
			f := startFlow(t, newTestHandler(&Config{}), &testDialer{}, net.UDPDestination(host, 0))
			f.send(udpTo("LocalHost", 0), request(false, 7, 1, []byte("same name")))
			expectReply(t, f.recv(3*time.Second), net.DomainAddress("LocalHost"), false, 7, 1, []byte("same name"))
			f.send(udpTo("127.0.0.1", 0), request(false, 7, 2, []byte("its address")))
			if b := f.recv(500 * time.Millisecond); b != nil {
				t.Fatalf("a ping to another address was answered: %v %x", b.UDP, b.Bytes())
			}
			if ended, _ := f.ended(2 * time.Second); !ended {
				t.Fatal("flow did not end on a ping to another address")
			}
		})
	})
}

// A flow that opened with a ping carries ordinary UDP that follows it, as a
// flow that opened with UDP carries pings: a new association that inherits
// the flow (a reused source port, an XUDP session resumed) is not blackholed.
func TestEchoFlowThenUDP(t *testing.T) {
	udpTarget := startUDPEcho(t)
	withMode(t, false, func(t *testing.T) {
		f := startFlow(t, newTestHandler(&Config{}), &testDialer{}, net.UDPDestination(net.LocalHostIP, 0))
		f.send(nil, request(false, 8, 1, []byte("first")))
		expectReply(t, f.recv(3*time.Second), net.LocalHostIP, false, 8, 1, []byte("first"))
		for i, payload := range []string{"one", "two"} {
			f.send(&udpTarget, []byte(payload))
			expectUDP(t, f.recv(3*time.Second), udpTarget, "echo:"+payload)
			f.send(nil, request(false, 8, uint16(2+i), []byte(payload)))
			expectReply(t, f.recv(3*time.Second), net.LocalHostIP, false, 8, uint16(2+i), []byte(payload))
		}
	})
}

// Datagrams that are dropped do not keep a flow that opened with a ping
// alive: it ends once no echo has been sent or answered for the idle time.
func TestEchoDroppedDatagramsDoNotKeepFlowAlive(t *testing.T) {
	withMode(t, false, func(t *testing.T) {
		h := new(Handler)
		h.Init(&Config{}, idlePolicy{idle: time.Second})
		f := startFlow(t, h, &testDialer{}, net.UDPDestination(net.LocalHostIP, 0))
		f.send(nil, request(false, 1, 1, []byte("hello")))
		expectReply(t, f.recv(3*time.Second), net.LocalHostIP, false, 1, 1, []byte("hello"))
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			f.send(nil, []byte{13, 0, 0, 0, 0, 1, 0, 1}) // dropped: not an echo request
			if ended, _ := f.ended(200 * time.Millisecond); ended {
				return
			}
		}
		t.Fatal("dropped datagrams kept the flow alive")
	})
}

// withRaw runs fn with freedom forced to raw ICMP sockets, as root gets
// them where net.ipv4.ping_group_range does not admit it.
func withRaw(t *testing.T, ipv6 bool, fn func(t *testing.T)) {
	typ, ok := echoModes(t, ipv6)["raw"]
	if !ok {
		t.Skip("no raw ICMP socket can be opened: run as root")
	}
	saved := echoSocketTypes
	echoSocketTypes = []int{typ}
	t.Cleanup(func() { echoSocketTypes = saved })
	fn(t)
}

// Every ICMP packet the host receives is copied to each raw ICMP socket, so
// flows share one raw socket per family instead of opening one each: what a
// packet costs the kernel must not grow with the flows clients open.
func TestEchoRawFlowsShareOneSocket(t *testing.T) {
	withRaw(t, false, func(t *testing.T) {
		h := newTestHandler(&Config{})
		before := openFDs(t)
		const flows = 200
		fs := make([]*testFlow, flows)
		for i := range fs {
			fs[i] = startFlow(t, h, &testDialer{}, net.UDPDestination(net.LocalHostIP, 0))
			fs[i].send(nil, request(false, uint16(i), 1, []byte(fmt.Sprintf("flow %d", i))))
		}
		for i, f := range fs {
			expectReply(t, f.recv(5*time.Second), net.LocalHostIP, false, uint16(i), 1, []byte(fmt.Sprintf("flow %d", i)))
		}
		if opened := openFDs(t) - before; opened > 2 {
			t.Fatalf("%d flows opened %d files, want one shared raw socket", flows, opened)
		}
		rawEchoSockets.mu.RLock()
		socks := len(rawEchoSockets.socks)
		rawEchoSockets.mu.RUnlock()
		if socks != 1 {
			t.Fatalf("%d shared raw sockets, want 1", socks)
		}
		for _, f := range fs {
			f.close()
		}
		// The socket is closed with its last flow.
		rawEchoSockets.mu.RLock()
		socks = len(rawEchoSockets.socks)
		rawEchoSockets.mu.RUnlock()
		if socks != 0 {
			t.Fatalf("%d shared raw sockets left after every flow ended", socks)
		}
		// The descriptor is released once the socket's reader lets go of it.
		for deadline := time.Now().Add(time.Second); openFDs(t) > before; {
			if time.Now().After(deadline) {
				t.Fatalf("%d files left open after every flow ended", openFDs(t)-before)
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
}

// The kernel hands a shared raw socket echo replies only: every other ICMP
// type is rejected before it is copied for the socket.
func TestEchoRawSocketFilter(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("ipv6=%v", ipv6), func(t *testing.T) {
			if ipv6 && !hasIPv6Loopback() {
				t.Skip("no IPv6 loopback")
			}
			withRaw(t, ipv6, func(t *testing.T) {
				target := net.LocalHostIP
				if ipv6 {
					target = net.LocalHostIPv6
				}
				f := startFlow(t, newTestHandler(&Config{}), &testDialer{}, net.UDPDestination(target, 0))
				f.send(nil, request(ipv6, 1, 1, []byte("filter")))
				expectReply(t, f.recv(3*time.Second), target, ipv6, 1, 1, []byte("filter"))

				rawEchoSockets.mu.RLock()
				s := rawEchoSockets.socks[rawEchoKey{ipv6: ipv6}]
				rawEchoSockets.mu.RUnlock()
				if s == nil {
					t.Fatal("no shared raw socket")
				}
				var ferr error
				s.rc.Control(func(fd uintptr) {
					if ipv6 {
						var filter *unix.ICMPv6Filter
						if filter, ferr = unix.GetsockoptICMPv6Filter(int(fd), unix.IPPROTO_ICMPV6, unix.ICMPV6_FILTER); ferr != nil {
							return
						}
						for typ := 0; typ < 256; typ++ {
							blocked := filter.Data[typ>>5]&(1<<(typ&31)) != 0
							if blocked == (typ == icmpecho.TypeEchoReply6) {
								ferr = fmt.Errorf("ICMPv6 type %d blocked: %v", typ, blocked)
								return
							}
						}
						return
					}
					var mask int
					if mask, ferr = unix.GetsockoptInt(int(fd), unix.SOL_RAW, unix.ICMP_FILTER); ferr != nil {
						return
					}
					if want := ^uint32(1 << icmpecho.TypeEchoReply4); uint32(mask) != want {
						ferr = fmt.Errorf("ICMP_FILTER %#x, want %#x", uint32(mask), want)
					}
				})
				if ferr != nil {
					t.Fatal(ferr)
				}
			})
		})
	}
}

// At most maxEchoFlows flows ping at once; a flow over the cap has its pings
// dropped until another flow ends.
func TestEchoFlowCap(t *testing.T) {
	withMode(t, false, func(t *testing.T) {
		saved := maxEchoFlows
		maxEchoFlows = echoFlowCount.Load() + 2
		t.Cleanup(func() { maxEchoFlows = saved })

		h := newTestHandler(&Config{})
		ping := func(f *testFlow, seq uint16) *buf.Buffer {
			f.send(nil, request(false, 1, seq, []byte("cap")))
			return f.recv(time.Second)
		}
		a := startFlow(t, h, &testDialer{}, net.UDPDestination(net.LocalHostIP, 0))
		b := startFlow(t, h, &testDialer{}, net.UDPDestination(net.LocalHostIP, 0))
		c := startFlow(t, h, &testDialer{}, net.UDPDestination(net.LocalHostIP, 0))
		expectReply(t, ping(a, 1), net.LocalHostIP, false, 1, 1, []byte("cap"))
		expectReply(t, ping(b, 1), net.LocalHostIP, false, 1, 1, []byte("cap"))
		if r := ping(c, 1); r != nil {
			t.Fatalf("a flow over the cap was answered: %x", r.Bytes())
		}
		a.close()
		expectReply(t, ping(c, 2), net.LocalHostIP, false, 1, 2, []byte("cap"))
		expectReply(t, ping(b, 2), net.LocalHostIP, false, 1, 2, []byte("cap"))
	})
}

// sendThrough is the source of every echo; an address that is not this
// host's sends nothing.
func TestEchoSendThrough(t *testing.T) {
	withMode(t, false, func(t *testing.T) {
		h := newTestHandler(&Config{})
		f := startFlow(t, h, &testDialer{gateway: net.ParseAddress("127.0.0.3")}, net.UDPDestination(net.LocalHostIP, 0))
		f.send(nil, request(false, 2, 1, []byte("from .3")))
		expectReply(t, f.recv(3*time.Second), net.LocalHostIP, false, 2, 1, []byte("from .3"))

		g := startFlow(t, h, &testDialer{gateway: net.ParseAddress("192.0.2.55")}, net.UDPDestination(net.LocalHostIP, 0))
		g.send(nil, request(false, 2, 2, []byte("not ours")))
		if r := g.recv(time.Second); r != nil {
			t.Fatalf("a ping from an address not of this host was answered: %x", r.Bytes())
		}
	})
}

// A flow may start at most MaxRequestsPerSecond echoes in a second.
func TestEchoRateLimit(t *testing.T) {
	withMode(t, false, func(t *testing.T) {
		f := startFlow(t, newTestHandler(&Config{}), &testDialer{}, net.UDPDestination(net.LocalHostIP, 0))
		const sent = 3 * icmpecho.MaxRequestsPerSecond
		for i := 0; i < sent; i++ {
			f.send(nil, request(false, 1, uint16(i), []byte("burst")))
		}
		n := 0
		for f.recv(time.Second) != nil {
			n++
		}
		// The burst arrives within a fraction of a second, so the bucket
		// refills by a few tokens at most; outstanding echoes are capped too.
		if n == 0 || n > icmpecho.MaxRequestsPerSecond+10 {
			t.Fatalf("%d of %d answered, want at most about %d", n, sent, icmpecho.MaxRequestsPerSecond)
		}
		t.Logf("%d of %d answered", n, sent)
	})
}

// Flows pinging the same host with the same identifier and sequence numbers
// each get their own replies, exactly once. With raw sockets every socket
// sees every reply the host gets; only its own may pass.
func TestEchoFlowsDoNotMix(t *testing.T) {
	withMode(t, false, func(t *testing.T) {
		const flows, pings = 4, 20
		h := newTestHandler(&Config{})
		var wg sync.WaitGroup
		errs := make(chan error, flows)
		for i := 0; i < flows; i++ {
			f := startFlow(t, h, &testDialer{}, net.UDPDestination(net.LocalHostIP, 0))
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				for seq := uint16(0); seq < pings; seq++ {
					f.send(nil, request(false, 0x4242, seq, []byte(fmt.Sprintf("flow %d", i))))
				}
				for seq := uint16(0); seq < pings; seq++ {
					b := f.recv(3 * time.Second)
					if b == nil {
						errs <- fmt.Errorf("flow %d: reply %d missing", i, seq)
						return
					}
					e, ok := icmpecho.ParseReply(b.Bytes(), false)
					if !ok || string(e.Data) != fmt.Sprintf("flow %d", i) {
						errs <- fmt.Errorf("flow %d got %q", i, e.Data)
						return
					}
					b.Release()
				}
				if b := f.recv(300 * time.Millisecond); b != nil {
					errs <- fmt.Errorf("flow %d: extra reply %x", i, b.Bytes())
				}
			}(i)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
	})
}

// A silent host is a timeout: nothing comes back, and nothing is made up.
func TestEchoSilentHost(t *testing.T) {
	silent := os.Getenv("ICMPECHO_TEST_SILENT4")
	if silent == "" {
		t.Skip("ICMPECHO_TEST_SILENT4 not set")
	}
	withMode(t, false, func(t *testing.T) {
		f := startFlow(t, newTestHandler(&Config{}), &testDialer{}, net.UDPDestination(net.ParseAddress(silent), 0))
		f.send(nil, request(false, 1, 1, []byte("anyone?")))
		if b := f.recv(2 * time.Second); b != nil {
			t.Fatalf("got %v %x from a silent host", b.UDP, b.Bytes())
		}
	})
}

// The redirect address of freedom's settings is pinged in place of the
// target; the reply still comes from the address the client pinged.
func TestEchoDestinationOverride(t *testing.T) {
	withMode(t, false, func(t *testing.T) {
		h := newTestHandler(&Config{DestinationOverride: &DestinationOverride{
			Server: &protocol.ServerEndpoint{Address: net.NewIPOrDomain(net.LocalHostIP), Port: 53},
		}})
		target := net.ParseAddress("192.0.2.77")
		f := startFlow(t, h, &testDialer{}, net.UDPDestination(target, 0))
		f.send(nil, request(false, 3, 4, []byte("redirected")))
		expectReply(t, f.recv(3*time.Second), target, false, 3, 4, []byte("redirected"))
	})
}

// When the outbound sends through another outbound, a local socket would
// bypass it: the marker is left to travel on as UDP.
func TestEchoNotLocalWhenChained(t *testing.T) {
	h := newTestHandler(&Config{})
	ob := &session.Outbound{Target: net.UDPDestination(net.LocalHostIP, 0)}
	if f := h.newEchoFlow(context.Background(), &testDialer{chained: true}, ob, nil); f != nil {
		t.Fatal("echo flow made for a chained outbound")
	}
	if f := h.newEchoFlow(context.Background(), &testDialer{}, ob, nil); f == nil {
		t.Fatal("no echo flow for a direct outbound")
	}
}

// sendThrough of the other family leaves nothing to send from.
func TestEchoGatewayFamily(t *testing.T) {
	withMode(t, false, func(t *testing.T) {
		h := newTestHandler(&Config{})
		ob := &session.Outbound{Target: net.UDPDestination(net.LocalHostIP, 0), Gateway: net.LocalHostIPv6}
		f := h.newEchoFlow(context.Background(), &testDialer{}, ob, nil)
		defer f.Close()
		if f.conn(false) != nil {
			t.Fatal("IPv4 socket opened with an IPv6 sendThrough")
		}
		ob.Gateway = net.LocalHostIP
		g := h.newEchoFlow(context.Background(), &testDialer{}, ob, nil)
		defer g.Close()
		if g.conn(false) == nil {
			t.Fatal("IPv4 socket not opened with an IPv4 sendThrough")
		}
	})
}
