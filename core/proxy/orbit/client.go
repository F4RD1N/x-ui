// Package orbit is an Xray outbound for the VPN-Core protocol (the recovered
// SpeedTop v1.2.0 transport and channel protocol) of the user's own server:
// "protocol": "orbit". It is a client only. The wire code under internal/ is
// copied from the user's VPN-Core client (/root/VPN-Core) and adapted to the
// dependencies already in this module.
package orbit

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy/nativebridge"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

var (
	// openTimeout bounds one flow's open (VPN-Core's SOCKS adapter uses 30 s).
	// When it expires only that flow fails, as in VPN-Core's channel.Pool.Open:
	// a slow destination or a full flow table says nothing about the session.
	openTimeout = 30 * time.Second
	// probeAfter is how long a flow open over QUIC may go unanswered before
	// the session has to prove it is alive (see Client.suspect).
	probeAfter = 3 * time.Second
	// probeTimeout is the native heartbeat budget: the request goes out at
	// tick 30 and the session expires at tick 38 without an acknowledgement.
	probeTimeout = 8 * time.Second
)

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, c interface{}) (result interface{}, err error) {
		defer nativebridge.Recover(&err, nil)
		return New(ctx, c.(*Config))
	}))
}

// Client is the outbound handler. All flows share one authenticated session
// (one "generation"), as VPN-Core's client does. A session that dies is
// replaced lazily, by the next request that needs one; nothing reconnects in
// the background. Close ends the session and any dial in progress.
type Client struct {
	plan     *dialPlan
	policy   policy.Manager
	resolver string

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu      sync.Mutex
	current *generation
	pending *dialCall
	closed  bool
}

type dialCall struct {
	done   chan struct{}
	gen    *generation
	err    error
	cancel context.CancelFunc
}

func New(ctx context.Context, c *Config) (*Client, error) {
	if c == nil {
		return nil, errNoConfig
	}
	plan, err := newDialPlan(c)
	if err != nil {
		return nil, err
	}
	resolver := c.Resolver
	if resolver == "" {
		resolver = defaultResolver
	}
	if _, err = parseResolver(resolver); err != nil {
		return nil, err
	}
	// Building the handler starts nothing: no socket or worker exists until a
	// request arrives, also when a later step of core.New fails.
	base, cancel := context.WithCancel(context.Background())
	return &Client{plan: plan, policy: core.MustFromContext(ctx).GetFeature(policy.ManagerType()).(policy.Manager),
		resolver: resolver, ctx: base, cancel: cancel}, nil
}

// session returns the live generation, dialing one if there is none. Requests
// arriving during a dial wait for that dial instead of starting their own.
func (c *Client) session(ctx context.Context, dialer internet.Dialer) (*generation, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, net.ErrClosed
	}
	if g := c.current; g != nil {
		if g.alive() {
			c.mu.Unlock()
			return g, nil
		}
		c.current = nil
	}
	call := c.pending
	if call == nil {
		call = &dialCall{done: make(chan struct{})}
		c.pending = call
		// The session outlives this request: it is dialed on a context that
		// carries the request's outbound records for Xray's dialer but not
		// its cancellation, and that ends when the outbound closes.
		base, cancel := context.WithCancel(context.WithoutCancel(privateInbound(ctx)))
		call.cancel = cancel
		track(c)
		c.wg.Add(1)
		go c.dial(call, base, dialer)
	}
	c.mu.Unlock()
	select {
	case <-call.done:
		return call.gen, call.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// privateInbound gives the session's dials their own inbound record. The
// session outlives the request that dialed it, and a chained dial
// (sockopt.dialerProxy) reads the inbound record while the request's
// inbound handler keeps writing to its own (SOCKS sets CanSpliceCopy), a data
// race; the request's record also holds the client's socket and timer, which
// the session must neither keep nor offer for splicing. Only the fields that
// are fixed before dispatch are copied.
func privateInbound(ctx context.Context) context.Context {
	in := session.InboundFromContext(ctx)
	if in == nil {
		return ctx
	}
	return session.ContextWithInbound(ctx, &session.Inbound{Source: in.Source, Gateway: in.Gateway, Tag: in.Tag,
		Name: in.Name, User: in.User, CanSpliceCopy: 3})
}

func (c *Client) dial(call *dialCall, base context.Context, dialer internet.Dialer) {
	defer c.wg.Done()
	defer func() {
		if recover() != nil {
			call.err = errors.New("orbit: internal failure while connecting")
			call.gen = nil
		}
		c.mu.Lock()
		if c.pending == call {
			c.pending = nil
		}
		if call.gen != nil {
			if c.closed {
				call.gen.close()
				call.gen, call.err = nil, net.ErrClosed
			} else {
				c.current = call.gen
			}
		}
		c.mu.Unlock()
		close(call.done)
	}()
	ctx, cancel := base, call.cancel
	stop := context.AfterFunc(c.ctx, cancel)
	g, err := c.plan.dial(ctx, dialer)
	if err != nil {
		stop()
		cancel()
		call.err = err
		return
	}
	// The generation's own context is a child of ctx: closing the outbound
	// (c.ctx) cancels it through the AfterFunc above, and it releases ctx
	// when it ends by itself.
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		defer nativebridge.RecoverWorker(nil)
		<-g.ctx.Done()
		g.close()
		stop()
		cancel()
		c.mu.Lock()
		if c.current == g {
			c.current = nil
		}
		c.mu.Unlock()
	}()
	call.gen = g
}

// suspect runs when a flow open on g has gone unanswered for probeAfter.
// Over QUIC nothing tells the client that the server restarted or the path
// died until quic-go's idle timeout, so the session is asked for a heartbeat
// acknowledgement on its UDP-control stream (one probe at a time, and none
// right after one succeeded). No acknowledgement within the native budget
// retires the session, and the waiting opens fail over to a new one. The TCP
// carriers have no acknowledged heartbeat; a reset ends their session at
// once and a silent path ends it on the peer idle timeout, as in VPN-Core.
func (c *Client) suspect(g *generation) {
	// suspect runs on a timer goroutine of its own: a panic in the probe ends
	// this session only, not the process.
	defer nativebridge.RecoverWorker(func(error) { c.retire(g) })
	p, ok := g.peer.(prober)
	if !ok || !g.alive() || !g.probing.CompareAndSwap(false, true) {
		return
	}
	defer g.probing.Store(false)
	if last := g.probed.Load(); last != 0 && time.Since(time.Unix(0, last)) < probeTimeout {
		return
	}
	ctx, cancel := context.WithTimeout(g.ctx, probeTimeout)
	err := p.Probe(ctx)
	cancel()
	if err == nil {
		g.probed.Store(time.Now().UnixNano())
		return
	}
	if g.alive() {
		g.reason.CompareAndSwap(nil, &probeFailure{err})
		c.retire(g)
	}
}

type probeFailure struct{ err error }

func (p *probeFailure) Error() string {
	return fmt.Sprintf("the server did not acknowledge a heartbeat within %v, so the session's path is gone: %v", probeTimeout, p.err)
}
func (p *probeFailure) Unwrap() error { return p.err }

// retire ends a generation that proved unusable so the next request dials.
func (c *Client) retire(g *generation) {
	g.close()
	c.mu.Lock()
	if c.current == g {
		c.current = nil
	}
	c.mu.Unlock()
}

func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) (err error) {
	var g *generation
	defer nativebridge.Recover(&err, func() {
		if g != nil {
			c.retire(g)
		}
	})
	target, err := nativebridge.Target(ctx, "orbit")
	if err != nil {
		return err
	}
	if target.Network == xnet.Network_UDP {
		return c.processUDP(ctx, link, dialer, target)
	}
	var conn net.Conn
	// A session found dead (including one retired because it stopped
	// answering heartbeats) is replaced once, within the same request. A flow
	// that fails on a live session fails alone.
	for attempt := 0; ; attempt++ {
		if g, err = c.session(ctx, dialer); err != nil {
			return err
		}
		gen := g
		octx, cancel := context.WithTimeout(ctx, openTimeout)
		watch := time.AfterFunc(probeAfter, func() { c.suspect(gen) })
		conn, err = g.peer.Open(octx, targetHost(target.Address), target.Port.Value())
		watch.Stop()
		cancel()
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if g.alive() {
			return fmt.Errorf("orbit: opening the flow failed: %w", err)
		}
		if attempt > 0 {
			return fmt.Errorf("orbit: opening the flow failed: %w (session: %v)", err, g.failure())
		}
	}
	defer conn.Close()
	return nativebridge.Relay(ctx, link, conn, nil, target, c.policy.ForLevel(0))
}

// targetHost is the destination as the native address carries it: a numeric
// IP without brackets, or the domain (resolved by the server).
func targetHost(a xnet.Address) string {
	if a.Family().IsIP() {
		return a.IP().String()
	}
	return a.Domain()
}

// Close ends the session and any dial in progress, and waits for the
// outbound's own workers. Flows still running end with their session.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	g := c.current
	c.current = nil
	c.mu.Unlock()
	untrack(c)
	c.cancel()
	if g != nil {
		g.close()
	}
	c.wg.Wait()
	return nil
}

// Network changes. VPN-Core's client drops its session and any pending dial
// when the device's network changes (NETWORK-RECOVERY.md): the old socket is
// bound to the old network. ResetConnections is an Orbit-only lifecycle hook;
// it requires no mobile transport API in the server core. Only outbounds that
// have dialed are tracked, and Close
// removes them.
var (
	liveMu sync.Mutex
	live   = make(map[*Client]struct{})
)

func track(c *Client) {

	liveMu.Lock()
	live[c] = struct{}{}
	liveMu.Unlock()
}

func untrack(c *Client) {
	liveMu.Lock()
	delete(live, c)
	liveMu.Unlock()
}

// ResetConnections drops only Orbit sessions; future requests dial afresh.
func ResetConnections() {
	defer func() { _ = recover() }()
	liveMu.Lock()
	clients := make([]*Client, 0, len(live))
	for c := range live {
		clients = append(clients, c)
	}
	liveMu.Unlock()
	for _, c := range clients {
		c.networkChanged()
	}
}

func (c *Client) networkChanged() {
	c.mu.Lock()
	g, call := c.current, c.pending
	c.current = nil
	c.mu.Unlock()
	if g != nil {
		g.close()
	}
	if call != nil && call.cancel != nil {
		call.cancel()
	}
}
