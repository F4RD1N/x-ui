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
}

func (d *testDialer) Dial(ctx context.Context, dest net.Destination) (stat.Connection, error) {
	return internet.DialSystem(ctx, dest, nil)
}

func (d *testDialer) DestIpAddress() net.IP { return nil }

func (d *testDialer) SetOutboundGateway(context.Context, *session.Outbound) {}

func (d *testDialer) LocalSocketSettings() (*internet.SocketConfig, bool) {
	return d.sockopt, !d.chained
}

func newTestHandler(config *Config) *Handler {
	h := new(Handler)
	h.Init(config, policy.DefaultManager{})
	return h
}

type testFlow struct {
	t       *testing.T
	up      *pipe.Writer
	down    *pipe.Reader
	pending buf.MultiBuffer
	cancel  context.CancelFunc
	done    chan error
}

func startFlow(t *testing.T, h *Handler, d internet.Dialer, target net.Destination) *testFlow {
	t.Helper()
	upR, upW := pipe.New(pipe.WithoutSizeLimit())
	downR, downW := pipe.New(pipe.WithoutSizeLimit())
	ctx, cancel := context.WithCancel(context.Background())
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: target}})
	f := &testFlow{t: t, up: upW, down: downR, cancel: cancel, done: make(chan error, 1)}
	go func() {
		f.done <- h.Process(ctx, &transport.Link{Reader: upR, Writer: downW}, d)
	}()
	t.Cleanup(f.close)
	return f
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
	case <-f.done:
	case <-time.After(5 * time.Second):
		f.t.Error("flow did not end")
	}
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
		to := func(s string) *net.Destination {
			d := net.UDPDestination(net.ParseAddress(s), 0)
			return &d
		}
		f.send(nil, request(true, 1, 1, nil))                    // IPv6 echo to an IPv4 address
		f.send(nil, []byte{13, 0, 0, 0, 0, 1, 0, 1})             // timestamp request
		f.send(nil, []byte{0, 0, 0, 0, 0, 1, 0, 1})              // echo reply
		f.send(nil, []byte{8, 1, 0, 0, 0, 1, 0, 1})              // code 1
		f.send(nil, []byte{8, 0, 0, 0, 0, 1, 0})                 // short
		f.send(nil, make([]byte, 0))                             // empty
		f.send(to("224.0.0.1"), request(false, 1, 1, nil))       // multicast
		f.send(to("255.255.255.255"), request(false, 1, 1, nil)) // broadcast
		f.send(to("0.0.0.0"), request(false, 1, 1, nil))         // unspecified
		f.send(to("::1"), request(false, 1, 1, nil))             // IPv4 echo to an IPv6 address
		f.send(nil, request(false, 2, 2, []byte("still alive"))) // the one to answer
		expectReply(t, f.recv(3*time.Second), net.LocalHostIP, false, 2, 2, []byte("still alive"))
		if b := f.recv(500 * time.Millisecond); b != nil {
			t.Fatalf("a dropped datagram was answered: %v %x", b.UDP, b.Bytes())
		}
	})
}

// A flow that opens with ordinary UDP still has its pings executed, and its
// UDP keeps working around them.
func TestEchoInsideUDPFlow(t *testing.T) {
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP{127, 0, 0, 1}})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
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
	udpTarget := net.UDPDestination(net.LocalHostIP, net.Port(srv.LocalAddr().(*net.UDPAddr).Port))
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
