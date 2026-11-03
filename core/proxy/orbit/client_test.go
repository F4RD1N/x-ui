package orbit

import (
	"context"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type netDialer struct{ dials atomic.Int64 }

func (d *netDialer) Dial(ctx context.Context, dest xnet.Destination) (stat.Connection, error) {
	d.dials.Add(1)
	var nd net.Dialer
	return nd.DialContext(ctx, dest.Network.SystemString(), dest.NetAddr())
}
func (*netDialer) SetOutboundGateway(context.Context, *session.Outbound) {}
func (*netDialer) Address() xnet.Address                                 { return nil }
func (*netDialer) DestIpAddress() net.IP                                 { return nil }

// silentServer accepts TCP connections and never answers.
func silentServer(t *testing.T) (port uint32, accepted *atomic.Int64) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted = new(atomic.Int64)
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		l.Close()
		mu.Lock()
		for _, c := range conns {
			c.Close()
		}
		mu.Unlock()
	})
	return uint32(l.Addr().(*net.TCPAddr).Port), accepted
}

func testClient(t *testing.T, port uint32, timeout uint32) *Client {
	t.Helper()
	c, err := Settings{Address: "127.0.0.1", Port: port, Key: testKey(t), Transport: "tcp"}.Config(timeout, "")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := newDialPlan(c)
	if err != nil {
		t.Fatal(err)
	}
	base, cancel := context.WithCancel(context.Background())
	return &Client{plan: plan, resolver: defaultResolver, ctx: base, cancel: cancel}
}

func orbitWorkers() int {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	n := 0
	for _, g := range strings.Split(string(buf), "\n\n") {
		if strings.Contains(g, "xray-core/proxy/orbit") && !strings.Contains(g, "_test.go") {
			n++
		}
	}
	return n
}

func TestConcurrentRequestsShareOneDial(t *testing.T) {
	port, accepted := silentServer(t)
	c := testClient(t, port, 1)
	defer c.Close()
	d := new(netDialer)
	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := c.session(context.Background(), d)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err == nil {
			t.Fatal("a silent server produced a session")
		}
	}
	if n := d.dials.Load(); n != 1 || accepted.Load() != 1 {
		t.Fatalf("%d dials (%d accepted) for 10 concurrent requests, want 1", n, accepted.Load())
	}
	// The next request after a failure dials again (lazily, not before).
	if _, err := c.session(context.Background(), d); err == nil || d.dials.Load() != 2 {
		t.Fatal("no new dial after a failed one", d.dials.Load())
	}
}

func TestCloseCancelsDialInProgress(t *testing.T) {
	port, accepted := silentServer(t)
	c := testClient(t, port, 60)
	result := make(chan error, 1)
	go func() {
		_, err := c.session(context.Background(), new(netDialer))
		result <- err
	}()
	for accepted.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	start := time.Now()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("dial succeeded against a silent server")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close left the dial running")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("Close waited for the handshake timeout")
	}
	if _, err := c.session(context.Background(), new(netDialer)); err == nil {
		t.Fatal("a closed outbound dialed")
	}
	deadline := time.Now().Add(2 * time.Second)
	for orbitWorkers() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("orbit goroutines outlived Close")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestRequestCancellationDoesNotAbortSharedDial(t *testing.T) {
	port, accepted := silentServer(t)
	c := testClient(t, port, 60)
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := c.session(ctx, new(netDialer)); done <- err }()
	for accepted.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != context.Canceled {
		t.Fatal("the canceled request did not return its own cancellation:", err)
	}
	c.mu.Lock()
	pending := c.pending != nil
	c.mu.Unlock()
	if !pending {
		t.Fatal("the shared dial ended with the first request")
	}
}

func TestNetworkChangeCancelsPendingDial(t *testing.T) {
	port, accepted := silentServer(t)
	c := testClient(t, port, 60)
	defer c.Close()
	result := make(chan error, 1)
	go func() {
		_, err := c.session(context.Background(), new(netDialer))
		result <- err
	}()
	for accepted.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	ResetConnections()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("dial succeeded against a silent server")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a network change left the dial on the old network running")
	}
	// The outbound stays usable: the next request dials again.
	d := new(netDialer)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for d.dials.Load() == 0 {
			time.Sleep(10 * time.Millisecond)
		}
		cancel()
	}()
	_, _ = c.session(ctx, d)
	if d.dials.Load() != 1 {
		t.Fatal("no dial after the network change")
	}
}
