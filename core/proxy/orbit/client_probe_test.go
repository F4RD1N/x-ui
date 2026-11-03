package orbit

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy/orbit/internal/protocol"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// stuckPeer is a live session whose flow opens never get an answer (a slow
// destination, or a server that stopped granting streams).
type stuckPeer struct {
	done   chan struct{}
	once   sync.Once
	opens  atomic.Int64
	closes atomic.Int64
}

func newStuckPeer() *stuckPeer { return &stuckPeer{done: make(chan struct{})} }

func (p *stuckPeer) Open(ctx context.Context, _ string, _ uint16) (net.Conn, error) {
	p.opens.Add(1)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.done:
		return nil, net.ErrClosed
	}
}
func (p *stuckPeer) SendUDP(context.Context, protocol.UDPEnvelope) error { return errors.New("no UDP") }
func (p *stuckPeer) ReceiveUDP(ctx context.Context) (protocol.UDPEnvelope, error) {
	<-ctx.Done()
	return protocol.UDPEnvelope{}, ctx.Err()
}
func (p *stuckPeer) SendApp(context.Context, protocol.AppMessage) error { return nil }
func (p *stuckPeer) ReceiveApp(ctx context.Context) (protocol.AppMessage, error) {
	<-ctx.Done()
	return protocol.AppMessage{}, ctx.Err()
}
func (p *stuckPeer) Done() <-chan struct{} { return p.done }
func (p *stuckPeer) Err() error {
	select {
	case <-p.done:
		return net.ErrClosed
	default:
		return nil
	}
}
func (p *stuckPeer) Close() error {
	p.closes.Add(1)
	p.once.Do(func() { close(p.done) })
	return nil
}

// probingStuckPeer is a stuckPeer over QUIC: it answers probes with probe().
type probingStuckPeer struct {
	*stuckPeer
	probes atomic.Int64
	probe  func(context.Context) error
}

func (p *probingStuckPeer) Probe(ctx context.Context) error {
	p.probes.Add(1)
	return p.probe(ctx)
}

func shortTimers(t *testing.T, open, after, probe time.Duration) {
	o, a, p := openTimeout, probeAfter, probeTimeout
	openTimeout, probeAfter, probeTimeout = open, after, probe
	t.Cleanup(func() { openTimeout, probeAfter, probeTimeout = o, a, p })
}

// withGeneration installs pr as the client's live session.
func withGeneration(c *Client, pr peer, carrier string) *generation {
	ctx, cancel := context.WithCancel(context.Background())
	g := &generation{peer: pr, ctx: ctx, cancel: cancel, transport: carrier}
	c.mu.Lock()
	c.current = g
	c.mu.Unlock()
	return g
}

func processTCP(c *Client, timeout time.Duration) error {
	dest := xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(80))
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: dest}})
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ur, uw := pipe.New()
	dr, dw := pipe.New()
	defer uw.Close()
	defer dr.Interrupt()
	return c.Process(ctx, &transport.Link{Reader: ur, Writer: dw}, new(netDialer))
}

// TestOpenTimeoutFailsOnlyThatFlow: a flow open that times out on a live
// session fails alone. The session, and so every other flow on it, stays,
// as in VPN-Core's channel.Pool.Open (a TCP carrier has no probe).
func TestOpenTimeoutFailsOnlyThatFlow(t *testing.T) {
	shortTimers(t, 200*time.Millisecond, 50*time.Millisecond, 200*time.Millisecond)
	port, _ := silentServer(t)
	c := testClient(t, port, 1)
	defer c.Close()
	p := newStuckPeer()
	g := withGeneration(c, p, "tcp")
	err := processTCP(c, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "opening the flow failed") {
		t.Fatal("open on a stuck session:", err)
	}
	if p.closes.Load() != 0 || !g.alive() {
		t.Fatal("one slow flow open closed the whole session")
	}
	c.mu.Lock()
	current := c.current
	c.mu.Unlock()
	if current != g || p.opens.Load() != 1 {
		t.Fatalf("the session was replaced (%d opens)", p.opens.Load())
	}
}

// TestAnsweredProbeKeepsTheSession: over QUIC a slow open makes the session
// prove it is alive; an acknowledged probe keeps it, and only the slow flow
// fails.
func TestAnsweredProbeKeepsTheSession(t *testing.T) {
	shortTimers(t, 300*time.Millisecond, 50*time.Millisecond, 200*time.Millisecond)
	port, _ := silentServer(t)
	c := testClient(t, port, 1)
	defer c.Close()
	p := &probingStuckPeer{stuckPeer: newStuckPeer(), probe: func(context.Context) error { return nil }}
	g := withGeneration(c, p, "quic")
	if err := processTCP(c, 5*time.Second); err == nil {
		t.Fatal("a stuck open succeeded")
	}
	if p.probes.Load() != 1 {
		t.Fatalf("%d probes, want 1", p.probes.Load())
	}
	if p.closes.Load() != 0 || !g.alive() {
		t.Fatal("an acknowledged probe still closed the session")
	}
}

// TestUnansweredProbeRetiresTheSession: a QUIC session that does not
// acknowledge the probe is retired, the waiting open fails over to a new
// session within the same request, and the error says why.
func TestUnansweredProbeRetiresTheSession(t *testing.T) {
	shortTimers(t, 5*time.Second, 50*time.Millisecond, 200*time.Millisecond)
	port, accepted := silentServer(t)
	c := testClient(t, port, 1)
	defer c.Close()
	p := &probingStuckPeer{stuckPeer: newStuckPeer(), probe: func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }}
	g := withGeneration(c, p, "quic")
	start := time.Now()
	err := processTCP(c, 10*time.Second)
	if err == nil {
		t.Fatal("a request over a dead session succeeded")
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("the request waited %v: it did not fail over after the probe", took)
	}
	if p.closes.Load() == 0 || g.alive() {
		t.Fatal("a session that did not acknowledge the probe was kept")
	}
	if accepted.Load() != 1 {
		t.Fatalf("%d new dials after the retirement, want 1 (within the same request)", accepted.Load())
	}
	if r := g.reason.Load(); r == nil || !strings.Contains(r.Error(), "did not acknowledge a heartbeat") {
		t.Fatal("no retirement reason:", r)
	}
}

// TestFlowLimitErrorKeepsTheSession: an open refused for the flow limit
// (TCP's ErrFlowLimit, and QUIC's since the client caps its streams) fails
// alone and probes nothing.
func TestFlowLimitErrorKeepsTheSession(t *testing.T) {
	shortTimers(t, time.Second, 50*time.Millisecond, 200*time.Millisecond)
	port, _ := silentServer(t)
	c := testClient(t, port, 1)
	defer c.Close()
	p := &probingStuckPeer{stuckPeer: newStuckPeer(), probe: func(context.Context) error { return errors.New("unexpected probe") }}
	limited := &limitPeer{p}
	g := withGeneration(c, limited, "quic")
	if err := processTCP(c, 5*time.Second); err == nil || !strings.Contains(err.Error(), "flow limit") {
		t.Fatal("open over the limit:", err)
	}
	if p.probes.Load() != 0 || p.closes.Load() != 0 || !g.alive() {
		t.Fatal("a flow-limit refusal touched the session")
	}
}

type limitPeer struct{ *probingStuckPeer }

func (limitPeer) Open(context.Context, string, uint16) (net.Conn, error) {
	return nil, errors.New("transport: flow limit reached")
}
