package openvpn

import (
	"bytes"
	"context"
	goerrors "errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/client"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// Ports of the half-close servers on the fake server's stack.
const (
	hcSinkPort    = 18082 // reads to EOF, waits, answers, closes
	hcGreeterPort = 18083 // greets, sends FIN, reads to EOF, reports, closes
	hcSilentPort  = 18084 // reads to EOF, then says nothing until the test ends
)

// testPolicy is the default policy with other timeouts.
type testPolicy struct {
	policy.DefaultManager
	idle, uplinkOnly, downlinkOnly time.Duration
	// levels holds the connection-idle timeout of other levels.
	levels map[uint32]time.Duration
}

func (p testPolicy) ForLevel(level uint32) policy.Session {
	s := policy.SessionDefault()
	if p.idle > 0 {
		s.Timeouts.ConnectionIdle = p.idle
	}
	if d, ok := p.levels[level]; ok {
		s.Timeouts.ConnectionIdle = d
	}
	if p.uplinkOnly > 0 {
		s.Timeouts.UplinkOnly = p.uplinkOnly
	}
	if p.downlinkOnly > 0 {
		s.Timeouts.DownlinkOnly = p.downlinkOnly
	}
	return s
}

// hcServers runs the half-close servers on the fake server of session i and
// returns what the greeter and the sink received (one count per connection).
type hcServers struct {
	sinkGot    chan int
	greeterGot chan int
	silentGot  chan int
	release    chan struct{} // ends the silent server's connections
}

func (f *fixture) serveHalfClose(t *testing.T, i int, a netip.Addr, delay time.Duration) *hcServers {
	t.Helper()
	s := &hcServers{sinkGot: make(chan int, 16), greeterGot: make(chan int, 16), silentGot: make(chan int, 16), release: make(chan struct{})}
	t.Cleanup(func() { close(s.release) })
	st := f.session(i).srv.stack
	listen := func(port uint16, serve func(c *gonet.TCPConn)) {
		pn := tcpip.NetworkProtocolNumber(ipv4.ProtocolNumber)
		if a.Is6() {
			pn = ipv6.ProtocolNumber
		}
		l, err := gonet.ListenTCP(st, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(a.AsSlice()), Port: port}, pn)
		if err != nil {
			t.Fatalf("listen %v port %d: %v", a, port, err)
		}
		t.Cleanup(func() { _ = l.Close() })
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go serve(c.(*gonet.TCPConn))
			}
		}()
	}
	listen(hcSinkPort, func(c *gonet.TCPConn) {
		defer c.Close()
		n, err := io.Copy(io.Discard, c)
		if err != nil {
			return
		}
		s.sinkGot <- int(n)
		time.Sleep(delay)
		_, _ = fmt.Fprintf(c, "got %d bytes then your FIN", n)
	})
	listen(hcGreeterPort, func(c *gonet.TCPConn) {
		defer c.Close()
		if _, err := c.Write([]byte("hello, I am done talking")); err != nil {
			return
		}
		if err := c.CloseWrite(); err != nil {
			return
		}
		n, err := io.Copy(io.Discard, c)
		if err != nil {
			s.greeterGot <- -1
			return
		}
		s.greeterGot <- int(n)
	})
	listen(hcSilentPort, func(c *gonet.TCPConn) {
		defer c.Close()
		n, _ := io.Copy(io.Discard, c)
		s.silentGot <- int(n)
		<-s.release
	})
	return s
}

// closeUp ends the client's side of the request (EOF on the link's reader).
func (r *request) closeUp(t *testing.T) {
	t.Helper()
	if err := r.up.Close(); err != nil {
		t.Fatalf("close uplink: %v", err)
	}
}

// recvToEOF reads the downlink until it is closed, failing after d.
func (r *request) recvToEOF(t *testing.T, d time.Duration) []byte {
	t.Helper()
	deadline := time.Now().Add(d)
	var out []byte
	for {
		left := time.Until(deadline)
		if left <= 0 {
			t.Fatalf("downlink not closed within %v (got %q)", d, out)
		}
		mb, err := r.down.ReadMultiBufferTimeout(left)
		for _, b := range mb {
			out = append(out, b.Bytes()...)
		}
		buf.ReleaseMulti(mb)
		if goerrors.Is(err, io.EOF) {
			return out
		}
		if err != nil && !goerrors.Is(err, buf.ErrReadTimeout) {
			select {
			case perr := <-r.errc:
				t.Fatalf("downlink: %v after %q (Process: %v)", err, out, perr)
			default:
			}
			t.Fatalf("downlink: %v after %q", err, out)
		}
	}
}

// running fails t when Process has returned.
func (r *request) running(t *testing.T) {
	t.Helper()
	select {
	case err := <-r.errc:
		t.Fatalf("Process returned early: %v", err)
	default:
	}
}

func recvCount(t *testing.T, c chan int, what string) int {
	t.Helper()
	select {
	case n := <-c:
		return n
	case <-time.After(waitLong):
		t.Fatalf("%s: nothing received", what)
		return 0
	}
}

// relayGoroutines counts the goroutines in a TCP relay or Process.
func relayGoroutines() (int, string) {
	b := make([]byte, 1<<22)
	b = b[:runtime.Stack(b, true)]
	n := 0
	var found []string
	for _, g := range strings.Split(string(b), "\n\n") {
		if strings.Contains(g, "proxy/openvpn.(*tcpRelay)") || strings.Contains(g, "proxy/openvpn.(*Handler).Process") {
			n++
			found = append(found, g)
		}
	}
	return n, strings.Join(found, "\n\n")
}

// expectReleased waits until no relay goroutine is left and the client
// stack has no TCP endpoint and no connection beyond base.
func expectReleased(t *testing.T, st *stack.Stack, base int) {
	t.Helper()
	deadline := time.Now().Add(waitLong)
	for {
		g, stacks := relayGoroutines()
		eps := len(st.RegisteredEndpoints())
		conns := st.Stats().TCP.CurrentConnected.Value()
		if g == 0 && eps <= base && conns == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("not released: %d relay goroutines, %d endpoints (base %d), %d connected\n%s", g, eps, base, conns, stacks)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// hcFixture is a fixture with a live session, the half-close servers on
// srvV4, short TIME-WAIT and FIN-WAIT-2 timeouts on the client stack (so
// that closed endpoints go away within the test) and the client stack's
// endpoint count at rest.
func hcFixture(t *testing.T, pm policy.Manager, delay time.Duration) (*fixture, *hcServers, *stack.Stack, int) {
	t.Helper()
	f := newFixture(t, nil)
	if pm != nil {
		f.h.policyManager = pm
	}
	// A UDP request brings the session up and leaves no endpoint behind.
	warm := f.start(context.Background(), udpDest(srvV4, echoUDPPort))
	warm.echo(t, []byte("warm up"))
	_ = warm.end(t)
	f.h.mu.Lock()
	tun := f.h.tun
	f.h.mu.Unlock()
	tw := tcpip.TCPTimeWaitTimeoutOption(50 * time.Millisecond)
	if err := tun.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &tw); err != nil {
		t.Fatal(err)
	}
	// A connection closed while the destination's side is still open
	// waits in FIN-WAIT-2 for the linger timeout (60 s by default, as
	// Linux's tcp_fin_timeout), then goes.
	lt := tcpip.TCPLingerTimeoutOption(50 * time.Millisecond)
	if err := tun.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &lt); err != nil {
		t.Fatal(err)
	}
	s := f.serveHalfClose(t, 0, srvV4, delay)
	expectReleased(t, tun.stack, 0)
	return f, s, tun.stack, len(tun.stack.RegisteredEndpoints())
}

// The client half-closes: the destination sees the FIN, and its answer,
// sent after the FIN (at once, or 3 s later: beyond DownlinkOnly), reaches
// the client before the downlink closes.
func TestTCPHalfCloseClientFirst(t *testing.T) {
	for _, delay := range []time.Duration{0, 300 * time.Millisecond, 3 * time.Second} {
		t.Run(fmt.Sprint("reply after ", delay), func(t *testing.T) {
			f, s, st, base := hcFixture(t, nil, delay)
			r := f.start(context.Background(), tcpDest(srvV4, hcSinkPort))
			r.send(t, bytes.Repeat([]byte("x"), 1000))
			r.closeUp(t)
			if n := recvCount(t, s.sinkGot, "sink"); n != 1000 {
				t.Fatalf("the destination got %d bytes before the FIN, want 1000", n)
			}
			start := time.Now()
			got := r.recvToEOF(t, delay+waitLong)
			if want := "got 1000 bytes then your FIN"; string(got) != want {
				t.Fatalf("reply %q, want %q", got, want)
			}
			if el := time.Since(start); el < delay-100*time.Millisecond {
				t.Fatalf("reply after %v, the sink waits %v", el, delay)
			}
			if err := r.wait(t, waitLong); err != nil {
				t.Fatalf("Process: %v", err)
			}
			expectReleased(t, st, base)
		})
	}
}

// The destination half-closes: the client gets everything and the end of
// the downlink, and can go on sending -- also after a pause longer than
// UplinkOnly -- until it ends its side.
func TestTCPHalfCloseServerFirst(t *testing.T) {
	f, s, st, base := hcFixture(t, nil, 0)
	r := f.start(context.Background(), tcpDest(srvV4, hcGreeterPort))
	if got := r.recvToEOF(t, waitLong); string(got) != "hello, I am done talking" {
		t.Fatalf("greeting %q", got)
	}
	r.send(t, []byte("still talking"))
	time.Sleep(2500 * time.Millisecond)
	r.running(t)
	payload := pattern(200 << 10)
	r.send(t, payload)
	r.closeUp(t)
	if n := recvCount(t, s.greeterGot, "greeter"); n != len("still talking")+len(payload) {
		t.Fatalf("the destination got %d bytes after its FIN, want %d", n, len("still talking")+len(payload))
	}
	if err := r.wait(t, waitLong); err != nil {
		t.Fatalf("Process: %v", err)
	}
	expectReleased(t, st, base)
}

// A half-closed connection is held to the connection-idle timeout: it
// outlives DownlinkOnly and UplinkOnly, and ends, with everything released,
// once it has been idle for the connection-idle timeout.
func TestTCPHalfCloseIdle(t *testing.T) {
	pm := testPolicy{idle: 1500 * time.Millisecond, uplinkOnly: 100 * time.Millisecond, downlinkOnly: 100 * time.Millisecond}
	for _, tc := range []struct {
		name string
		port uint16
	}{{"client first", hcSilentPort}, {"server first", hcGreeterPort}} {
		t.Run(tc.name, func(t *testing.T) {
			f, _, st, base := hcFixture(t, pm, 0)
			r := f.start(context.Background(), tcpDest(srvV4, tc.port))
			start := time.Now()
			if tc.port == hcSilentPort {
				r.send(t, []byte("request"))
				r.closeUp(t)
			} else {
				r.recvToEOF(t, waitLong)
			}
			time.Sleep(800 * time.Millisecond)
			r.running(t)
			err := r.wait(t, waitLong)
			el := time.Since(start)
			if err == nil {
				t.Fatal("an idle half-closed connection ended without an error")
			}
			if el < pm.idle || el > 2*pm.idle+time.Second {
				t.Fatalf("ended after %v, the connection-idle timeout is %v", el, pm.idle)
			}
			expectReleased(t, st, base)
		})
	}
}

// Cancellation, the end of the session and Close end a half-closed
// connection at once, with everything released.
func TestTCPHalfCloseTeardown(t *testing.T) {
	for _, tc := range []string{"cancel", "session ends", "close"} {
		for _, port := range []uint16{hcSilentPort, hcGreeterPort} {
			t.Run(fmt.Sprintf("%s/%d", tc, port), func(t *testing.T) {
				f, _, st, base := hcFixture(t, nil, 0)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				r := f.start(ctx, tcpDest(srvV4, port))
				if port == hcSilentPort {
					r.send(t, []byte("request"))
					r.closeUp(t)
				} else {
					r.recvToEOF(t, waitLong)
				}
				time.Sleep(200 * time.Millisecond)
				r.running(t)
				start := time.Now()
				switch tc {
				case "cancel":
					cancel()
				case "session ends":
					f.session(0).fail(client.ErrPingTimeout)
				case "close":
					_ = f.h.Close()
				}
				if err := r.wait(t, waitLong); err == nil {
					t.Fatal("Process ended without an error")
				}
				if el := time.Since(start); el > 900*time.Millisecond {
					t.Fatalf("Process took %v to end", el)
				}
				if tc == "cancel" {
					expectReleased(t, st, base)
				} else {
					expectReleased(t, st, 1<<30) // the stack is gone; only the goroutines count
				}
			})
		}
	}
}

// A connection that cannot be half-closed keeps today's behaviour: once the
// client's side ended, DownlinkOnly applies.
func TestTCPRelayWithoutCloseWrite(t *testing.T) {
	f := newFixture(t, nil)
	warm := f.start(context.Background(), tcpDest(srvV4, echoTCPPort))
	warm.echo(t, []byte("warm up"))
	_ = warm.end(t)
	f.h.mu.Lock()
	tun := f.h.tun
	f.h.mu.Unlock()

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var fired atomic.Bool
	timer := signal.CancelAfterInactivity(ctx, func() { fired.Store(true); cancel() }, time.Hour)
	defer timer.SetTimeout(0)
	upR, upW := pipe.New(pipe.WithoutSizeLimit())
	r := &tcpRelay{conn: a, link: &transport.Link{Reader: upR}, timer: timer, tun: tun, downlinkOnly: 100 * time.Millisecond}
	go func() { _, _ = io.Copy(io.Discard, b) }()
	_ = upW.Close()
	if err := r.uplink(); err != nil {
		t.Fatalf("uplink: %v", err)
	}
	deadline := time.Now().Add(waitLong)
	for !fired.Load() {
		if time.Now().After(deadline) {
			t.Fatal("DownlinkOnly did not apply to a connection without CloseWrite")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The inbound's timer, which the inbound set to DownlinkOnly when its client
// ended its side, is raised to the inbound's connection-idle timeout when
// the FIN goes out: a reply 3 s later still reaches the client. It is left
// alone for a mux stream (an XUDP one is also TimeoutOnly) and a chained
// request. TestMuxStreamHasNoHalfClose runs a mux stream through the real
// mux server.
func TestTCPHalfCloseInboundTimer(t *testing.T) {
	const level = 8
	pm := testPolicy{levels: map[uint32]time.Duration{level: 200 * time.Second}}
	for _, tc := range []struct {
		name  string
		raise bool
		ctx   func(context.Context) context.Context
	}{
		{"own link", true, func(ctx context.Context) context.Context { return ctx }},
		{"mux stream", false, func(ctx context.Context) context.Context { return session.ContextWithMuxStream(ctx) }},
		{"XUDP stream", false, func(ctx context.Context) context.Context {
			return session.ContextWithTimeoutOnly(session.ContextWithMuxStream(ctx), true)
		}},
		{"chained", false, func(ctx context.Context) context.Context {
			return session.ContextWithOutbounds(ctx, []*session.Outbound{{Tag: "front"}})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, s, st, base := hcFixture(t, pm, 3*time.Second)
			inCtx, inCancel := context.WithCancel(context.Background())
			defer inCancel()
			var inFired atomic.Bool
			inTimer := signal.CancelAfterInactivity(inCtx, func() { inFired.Store(true); inCancel() }, 300*time.Second)
			defer inTimer.SetTimeout(0)
			in := &session.Inbound{Timer: inTimer, User: &protocol.MemoryUser{Level: level}}
			ctx := tc.ctx(session.ContextWithInbound(context.Background(), in))

			if got, idle, dlo := f.h.inboundTimer(withTarget(ctx, srvV4)); (got != nil) != tc.raise || (tc.raise && (idle != 200*time.Second || dlo != policy.SessionDefault().Timeouts.DownlinkOnly)) {
				t.Fatalf("inboundTimer: %v %v %v", got != nil, idle, dlo)
			}
			if !tc.raise {
				return
			}

			r := f.start(ctx, tcpDest(srvV4, hcSinkPort))
			r.send(t, []byte("request"))
			// As an inbound does when its client ends its side: DownlinkOnly
			// on its timer, then the end of the link.
			inTimer.SetTimeout(time.Second)
			r.closeUp(t)
			recvCount(t, s.sinkGot, "sink")
			if got := r.recvToEOF(t, waitLong); string(got) != "got 7 bytes then your FIN" {
				t.Fatalf("reply %q", got)
			}
			if inFired.Load() {
				t.Fatal("the inbound's timer fired before the reply arrived")
			}
			if err := r.wait(t, waitLong); err != nil {
				t.Fatalf("Process: %v", err)
			}
			// As an inbound does when the response ended: its own final
			// timeout, which then runs out.
			inTimer.SetTimeout(100 * time.Millisecond)
			deadline := time.Now().Add(waitLong)
			for !inFired.Load() {
				if time.Now().After(deadline) {
					t.Fatal("the inbound's final timeout did not apply")
				}
				time.Sleep(10 * time.Millisecond)
			}
			expectReleased(t, st, base)
		})
	}
}

// withTarget is ctx with one outbound aimed at a, unless ctx has one.
func withTarget(ctx context.Context, a netip.Addr) context.Context {
	if len(session.OutboundsFromContext(ctx)) > 0 {
		obs := append(session.OutboundsFromContext(ctx), &session.Outbound{Target: tcpDest(a, hcSinkPort)})
		return session.ContextWithOutbounds(ctx, obs)
	}
	return session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: tcpDest(a, hcSinkPort)}})
}

// slowWriter takes each write after a delay.
type slowWriter struct{ delay time.Duration }

func (w slowWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	time.Sleep(w.delay)
	return nil
}

// While the request moves into the stack, the inbound's timer -- set to
// DownlinkOnly once the inbound put the last of the request into the link --
// is fed: by every write (many writes, each shorter than the tick) and every
// tick while one write is blocked. It is not fed while nothing is written,
// nor once the link's writer is ending.
func TestTCPRelayFeedsInboundTimer(t *testing.T) {
	const downlinkOnly = 400 * time.Millisecond
	for _, tc := range []struct {
		name   string
		writes int
		delay  time.Duration
		ended  bool // the downlink ended first
		fire   bool
	}{
		{"short writes", 10, 100 * time.Millisecond, false, false},
		{"one blocked write", 1, 1500 * time.Millisecond, false, false},
		{"no writes", 0, 0, false, true},
		{"downlink ended", 1, 1500 * time.Millisecond, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var fired atomic.Bool
			inTimer := signal.CancelAfterInactivity(ctx, func() { fired.Store(true); cancel() }, time.Hour)
			defer inTimer.SetTimeout(0)
			r := &tcpRelay{inTimer: inTimer, inTick: feedInterval(downlinkOnly)}
			if tc.ended {
				r.endDownlink()
			}
			f := &inboundFeeder{w: slowWriter{tc.delay}, r: r}
			inTimer.SetTimeout(downlinkOnly)
			start := time.Now()
			for i := 0; i < tc.writes; i++ {
				if err := f.WriteMultiBuffer(buf.MultiBuffer{buf.New()}); err != nil {
					t.Fatal(err)
				}
			}
			if tc.writes == 0 {
				time.Sleep(3 * downlinkOnly)
			}
			if fired.Load() != tc.fire {
				t.Fatalf("after %v of writes: the inbound's timer fired %v, want %v", time.Since(start).Round(time.Millisecond), fired.Load(), tc.fire)
			}
			// The tick is stopped with the write: the timer runs out now.
			time.Sleep(3 * downlinkOnly)
			if !fired.Load() {
				t.Fatal("the inbound's timer is still fed after the writes")
			}
		})
	}
}
