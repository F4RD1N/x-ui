// Package dnstt implements an authenticated DNS tunnel outbound. DNS, KCP,
// pinned Noise NK and smux v2 carry a separately authenticated inner proxy.
package dnstt

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy/nativebridge"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"www.bamsoftware.com/git/dnstt.git/noise"
)

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, value interface{}) (out interface{}, err error) {
		defer nativebridge.Recover(&err, nil)
		return New(ctx, value.(*Config))
	}))
}

// Client owns all of its generations. Construction is passive: sockets and
// workers are created lazily by the first flow, never by config registration.
type Client struct {
	cfg    *Config
	policy policy.Manager
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu      sync.Mutex
	closed  bool
	epoch   uint64
	current *generation
	pending *dialCall
	// An instance-local factory also lets lifecycle tests model a delayed
	// network dial without changing process-wide network implementations.
	dial func(context.Context, *Config, internet.Dialer) (*generation, error)
}

type dialCall struct {
	done   chan struct{}
	cancel context.CancelFunc
	epoch  uint64
	gen    *generation
	err    error
}

func New(ctx context.Context, config *Config) (*Client, error) {
	cfg, err := NormalizeConfig(config)
	if err != nil {
		return nil, err
	}
	c := newClient(cfg)
	c.policy = core.MustFromContext(ctx).GetFeature(policy.ManagerType()).(policy.Manager)
	return c, nil
}

func newClient(cfg *Config) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{cfg: cfg, ctx: ctx, cancel: cancel, dial: newGeneration}
}

func privateInbound(ctx context.Context) context.Context {
	in := session.InboundFromContext(ctx)
	if in == nil {
		return ctx
	}
	copy := *in
	copy.Conn = nil
	copy.Timer = nil
	copy.CanSpliceCopy = 3
	return session.ContextWithInbound(ctx, &copy)
}

func (c *Client) generation(ctx context.Context, dialer internet.Dialer) (*generation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	if g := c.current; g != nil && g.alive() {
		c.mu.Unlock()
		return g, nil
	}
	call := c.pending
	if call == nil {
		// A generation outlives the flow that first requested it. Preserve
		// dialer context values, while isolating mutable inbound/outbound
		// records and making cancellation belong to the client generation.
		base, cancel := context.WithCancel(context.WithoutCancel(privateInbound(ctx)))
		call = &dialCall{done: make(chan struct{}), cancel: cancel, epoch: c.epoch}
		c.pending = call
		track(c)
		c.wg.Add(1)
		go c.connect(call, base, dialer)
	}
	c.mu.Unlock()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-call.done:
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return call.gen, call.err
	}
}

func (c *Client) connect(call *dialCall, base context.Context, dialer internet.Dialer) {
	defer c.wg.Done()
	stop := context.AfterFunc(c.ctx, call.cancel)
	var g *generation
	var err error
	defer func() {
		if recover() != nil {
			err = errors.New("dnstt: internal failure while connecting")
		}
		c.mu.Lock()
		if c.pending == call {
			c.pending = nil
		}
		if err == nil && (c.closed || c.epoch != call.epoch || g != nil && !g.alive()) {
			err = net.ErrClosed
		}
		if err == nil && g != nil {
			c.current = g
			call.gen = g
			c.wg.Add(1)
			go c.watch(g, func() { stop(); call.cancel() })
		}
		call.err = err
		c.mu.Unlock()
		if call.gen == nil {
			if g != nil {
				g.close()
			}
			stop()
			call.cancel()
		}
		close(call.done)
	}()
	g, err = c.dial(base, c.cfg, dialer)
	if g == nil && err == nil {
		err = errors.New("dnstt: connection returned no generation")
	}
}

func (c *Client) watch(g *generation, release func()) {
	defer c.wg.Done()
	defer release()
	defer nativebridge.RecoverWorker(func(error) { g.close() })
	select {
	case <-g.ctx.Done():
	case <-g.mux.CloseChan():
	}
	g.close()
	c.mu.Lock()
	if c.current == g {
		c.current = nil
	}
	c.mu.Unlock()
}

func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) (err error) {
	var g *generation
	var conn net.Conn
	defer nativebridge.Recover(&err, func() {
		if conn != nil {
			_ = conn.Close()
		}
		if g != nil {
			g.close()
		}
	})
	target, err := nativebridge.Target(ctx, "dnstt")
	if err != nil {
		return err
	}
	if target.Network != xnet.Network_TCP && target.Network != xnet.Network_UDP {
		return errors.New("dnstt: destination must use TCP or UDP")
	}
	if target.Network == xnet.Network_UDP && c.cfg.Inner.Protocol == "socks" {
		return errors.New("dnstt: SOCKS5 inner protocol supports TCP only")
	}
	g, err = c.generation(ctx, dialer)
	if err != nil {
		return err
	}
	openCtx, cancel := context.WithTimeout(ctx, time.Duration(c.cfg.HandshakeTimeout)*time.Second)
	defer cancel()
	conn, err = g.open(openCtx)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn, packets, err := innerConnection(ctx, conn, target, c.cfg)
	if err != nil {
		return err
	}
	return nativebridge.Relay(ctx, link, conn, packets, target, c.policy.ForLevel(0))
}

func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.epoch++
	g, call := c.current, c.pending
	c.current, c.pending = nil, nil
	c.mu.Unlock()
	untrack(c)
	c.cancel()
	if call != nil {
		call.cancel()
	}
	if g != nil {
		g.close()
	}
	c.wg.Wait()
	return nil
}

func (c *Client) networkChanged() {
	c.mu.Lock()
	c.epoch++
	g, call := c.current, c.pending
	c.current, c.pending = nil, nil
	c.mu.Unlock()
	if call != nil {
		call.cancel()
	}
	if g != nil {
		g.close()
	}
}

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

func resetAll() {
	defer nativebridge.RecoverWorker(nil)
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

type generation struct {
	ctx    context.Context
	cancel context.CancelFunc
	packet net.PacketConn
	kcp    *kcp.UDPSession
	noise  io.ReadWriteCloser
	mux    *smux.Session
	once   sync.Once
	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
}

func newGeneration(base context.Context, cfg *Config, dialer internet.Dialer) (g *generation, err error) {
	ctx, cancel := context.WithCancel(base)
	g = &generation{ctx: ctx, cancel: cancel}
	setupTimer := time.AfterFunc(time.Duration(cfg.HandshakeTimeout)*time.Second, cancel)
	defer setupTimer.Stop()
	defer func() {
		if recover() != nil {
			err = errors.New("dnstt: internal failure while establishing a generation")
		}
		if err != nil {
			g.close()
			g = nil
		}
	}()
	g.packet, err = newPacketConn(ctx, cfg, dialer)
	if err != nil {
		return g, err
	}
	// Closing the carrier interrupts KCP's reads even during the eager Noise
	// handshake. The returned carrier joins all of its own workers in Close.
	packet := g.packet
	stop := context.AfterFunc(ctx, func() { _ = packet.Close() })
	defer stop()
	g.kcp, err = kcp.NewConn2(carrierRemoteAddr, nil, 0, 0, g.packet)
	if err != nil {
		return g, errors.New("dnstt: could not create KCP session")
	}
	// Official dnstt v1.20260501.0 settings. Reuse the core's existing KCP
	// dependency, without changing its package-wide defaults or other users.
	g.kcp.SetStreamMode(true)
	g.kcp.SetNoDelay(0, 0, 0, 1)
	g.kcp.SetWindowSize(64, 64)
	mtu, err := packetMTU(cfg)
	if err != nil {
		return g, err
	}
	if !g.kcp.SetMtu(mtu) {
		return g, errors.New("dnstt: KCP rejected the DNS packet MTU")
	}
	_ = g.kcp.SetDeadline(time.Now().Add(time.Duration(cfg.HandshakeTimeout) * time.Second))
	key, _ := hex.DecodeString(cfg.PublicKey)
	g.noise, err = noise.NewClient(g.kcp, key)
	if err != nil {
		if ctx.Err() != nil {
			return g, ctx.Err()
		}
		return g, errors.New("dnstt: pinned Noise handshake failed or timed out")
	}
	_ = g.kcp.SetDeadline(time.Time{})
	muxCfg := smux.DefaultConfig()
	muxCfg.Version = 2
	muxCfg.KeepAliveTimeout = 2 * time.Minute
	muxCfg.MaxStreamBuffer = 1 << 20
	g.mux, err = smux.Client(&generationIO{ReadWriteCloser: g.noise, failed: cancel}, muxCfg)
	if err != nil {
		return g, errors.New("dnstt: could not create smux session")
	}
	// Only the client opens streams in the dnstt forwarding protocol. Waiting
	// for a peer-initiated stream also exposes smux's read/protocol errors,
	// which do not themselves close smux.CloseChan until its idle timeout.
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		defer nativebridge.RecoverWorker(func(error) { cancel() })
		stream, _ := g.mux.AcceptStream()
		cancel()
		if stream != nil {
			_ = stream.Close()
		}
	}()
	return g, nil
}

type generationIO struct {
	io.ReadWriteCloser
	failed context.CancelFunc
}

func (rw *generationIO) Read(p []byte) (int, error) {
	n, err := rw.ReadWriteCloser.Read(p)
	if err != nil {
		rw.failed()
	}
	return n, err
}

func (rw *generationIO) Write(p []byte) (int, error) {
	n, err := rw.ReadWriteCloser.Write(p)
	if err != nil {
		rw.failed()
	}
	return n, err
}

func (g *generation) alive() bool {
	return g.ctx.Err() == nil && g.mux != nil && !g.mux.IsClosed()
}

func (g *generation) open(ctx context.Context) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	type result struct {
		conn *smux.Stream
		err  error
	}
	ready := make(chan result)
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil, net.ErrClosed
	}
	g.wg.Add(1)
	g.mu.Unlock()
	go func() {
		defer g.wg.Done()
		defer nativebridge.RecoverWorker(func(error) { g.cancel() })
		conn, err := g.mux.OpenStream()
		select {
		case ready <- result{conn, err}:
		case <-ctx.Done():
			if conn != nil {
				_ = conn.Close()
			}
		case <-g.ctx.Done():
			if conn != nil {
				_ = conn.Close()
			}
		}
	}()
	select {
	case r := <-ready:
		if err := ctx.Err(); err != nil {
			if r.conn != nil {
				_ = r.conn.Close()
			}
			return nil, err
		}
		return r.conn, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-g.ctx.Done():
		return nil, net.ErrClosed
	}
}

func (g *generation) close() {
	g.once.Do(func() {
		g.mu.Lock()
		g.closed = true
		g.mu.Unlock()
		g.cancel()
		if g.kcp != nil {
			_ = g.kcp.Close()
		}
		if g.mux != nil {
			_ = g.mux.Close()
		}
		if g.packet != nil {
			_ = g.packet.Close()
		}
		if g.noise != nil {
			_ = g.noise.Close()
			// Upstream Noise's receiver writes plaintext to an io.Pipe, but
			// its Close only closes KCP. Drain after shutdown so a receiver
			// blocked on an unread last frame can finish and release its pipe.
			_, _ = io.Copy(io.Discard, g.noise)
		}
		g.wg.Wait()
	})
}
