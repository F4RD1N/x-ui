package anytls

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy/nativebridge"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

type Client struct {
	config   *Config
	policy   policy.Manager
	mu       sync.Mutex
	padding  *padding
	sessions []*muxSession
	sequence uint64
	closed   bool
	reaping  bool
	done     chan struct{}
	// dials holds the cancel of every carrier still being set up, so Close
	// can stop it; a pooled session keeps its own.
	dials map[*context.CancelFunc]struct{}
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, c interface{}) (result interface{}, err error) {
		defer nativebridge.Recover(&err, nil)
		return New(ctx, c.(*Config))
	}))
}

func New(ctx context.Context, c *Config) (*Client, error) {
	if c.Address == "" || c.Port == 0 || c.Port > 65535 || c.Password == "" {
		return nil, errors.New("AnyTLS requires address, port and password")
	}
	pad, _ := parsePadding(defaultPadding)
	// The idle reaper starts with the first session (take), so building the
	// handler starts nothing, also when a later step of core.New fails.
	h := &Client{config: c, policy: core.MustFromContext(ctx).GetFeature(policy.ManagerType()).(policy.Manager), padding: pad, done: make(chan struct{})}
	return h, nil
}

func (h *Client) reap() {
	// A failure in the reaper restarts it; it never closes the client.
	defer nativebridge.RecoverWorker(func(error) {
		select {
		case <-h.done:
		default:
			go h.reap()
		}
	})
	i := h.config.IdleSessionCheckInterval
	if i == 0 {
		i = 30
	}
	t := time.NewTicker(time.Duration(i) * time.Second)
	defer t.Stop()
	for {
		select {
		case <-h.done:
			return
		case now := <-t.C:
			h.reapOnce(now)
		}
	}
}

// reapOnce walks the pool newest first, so MinIdleSession keeps the newest
// idle sessions, and leaves h.sessions in ascending sequence order.
func (h *Client) reapOnce(now time.Time) {
	timeout := h.config.IdleSessionTimeout
	if timeout == 0 {
		timeout = 60
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	kept := make([]*muxSession, 0, len(h.sessions))
	idle := 0
	for i := len(h.sessions) - 1; i >= 0; i-- {
		s := h.sessions[i]
		s.mu.Lock()
		dead := s.closed
		expire := !s.busy && now.Sub(s.idleAt) > time.Duration(timeout)*time.Second && idle >= int(h.config.MinIdleSession)
		if !s.busy {
			idle++
		}
		s.mu.Unlock()
		if expire && !dead {
			s.fail(errors.New("AnyTLS idle session expired"))
		}
		if !dead && !expire {
			kept = append(kept, s)
		}
	}
	slices.Reverse(kept)
	h.sessions = kept
}

// pickIdle reserves the newest idle session. Its lock is released by defer,
// so a failure here cannot leave the pool locked.
func (h *Client) pickIdle() (*muxSession, *padding, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil, nil, net.ErrClosed
	}
	var picked *muxSession
	for _, s := range h.sessions {
		s.mu.Lock()
		if !s.closed && !s.busy && (picked == nil || s.sequence > picked.sequence) {
			picked = s
		}
		s.mu.Unlock()
	}
	if picked != nil {
		picked.mu.Lock()
		picked.busy = true
		picked.mu.Unlock()
	}
	return picked, h.padding, nil
}

func (h *Client) addSession(s *muxSession) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return net.ErrClosed
	}
	h.sequence++
	s.sequence = h.sequence
	s.busy = true
	h.sessions = append(h.sessions, s)
	if !h.reaping {
		h.reaping = true
		go h.reap()
	}
	return nil
}

// trackDial registers a carrier being set up, so Close cancels it; the
// returned func unregisters it.
func (h *Client) trackDial(cancel *context.CancelFunc) (func(), error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil, net.ErrClosed
	}
	if h.dials == nil {
		h.dials = make(map[*context.CancelFunc]struct{})
	}
	h.dials[cancel] = struct{}{}
	return func() {
		h.mu.Lock()
		delete(h.dials, cancel)
		h.mu.Unlock()
	}, nil
}

func (h *Client) take(ctx context.Context, dialer internet.Dialer) (*muxSession, error) {
	picked, pad, e := h.pickIdle()
	if e != nil {
		return nil, e
	}
	if picked != nil {
		if e := picked.checkHealth(ctx); e == nil {
			return picked, nil
		} else {
			picked.fail(e)
		}
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	dest := xnet.TCPDestination(xnet.ParseAddress(h.config.Address), xnet.Port(h.config.Port))
	timeout := h.config.HandshakeTimeout
	if timeout == 0 {
		timeout = 10
	}
	// The carrier outlives this request in the pool, so it is dialed on a ctx
	// of its own (as Xray's mux pool does), which only the session's end or
	// Close cancels. Until the dial returns, this request's cancellation and
	// the setup timeout cancel it too; the handshake below stays bound to the
	// request by SetupDeadline.
	lifetime, cancel := context.WithCancel(context.WithoutCancel(nativebridge.DialContext(ctx, dest, "anytls")))
	untrack, e := h.trackDial(&cancel)
	if e != nil {
		cancel()
		return nil, e
	}
	stopRequest := context.AfterFunc(ctx, cancel)
	timer := time.AfterFunc(time.Duration(timeout)*time.Second, cancel)
	raw, e := dialer.Dial(lifetime, dest)
	timedOut := !timer.Stop()
	if e == nil && lifetime.Err() != nil {
		// canceled while the dial was finishing: nobody owns this carrier
		raw.Close()
		e = lifetime.Err()
	}
	if e != nil {
		stopRequest()
		untrack()
		cancel()
		if ce := ctx.Err(); ce != nil {
			e = ce
		} else if timedOut {
			e = errors.New("AnyTLS carrier dial timed out")
		}
		return nil, e
	}
	// Ending the carrier's ctx (a failed setup, the session's end, Close)
	// closes it; from here SetupDeadline ties the setup to the request.
	context.AfterFunc(lifetime, func() { _ = raw.Close() })
	clear := nativebridge.SetupDeadline(ctx, raw, time.Duration(timeout)*time.Second)
	stopRequest()
	defer untrack()
	tlsConfig := h.config.Tls
	if tlsConfig == nil {
		tlsConfig = &xtls.Config{ServerName: h.config.Address}
	}
	var conn net.Conn
	if tlsConfig.Fingerprint != "" {
		fp := xtls.GetFingerprint(tlsConfig.Fingerprint)
		if fp == nil {
			clear()
			raw.Close()
			cancel()
			return nil, errors.New("unsupported AnyTLS TLS fingerprint")
		}
		conn = xtls.UClient(raw, tlsConfig.GetTLSConfig(xtls.WithDestination(dest)), fp)
	} else {
		conn = xtls.Client(raw, tlsConfig.GetTLSConfig(xtls.WithDestination(dest)))
	}
	if e = conn.(xtls.Interface).HandshakeContext(ctx); e != nil {
		clear()
		raw.Close()
		cancel()
		return nil, e
	}
	s, e := newSession(conn, h, pad, cancel)
	clear()
	if e != nil {
		conn.Close()
		cancel()
		return nil, e
	}
	if e = h.addSession(s); e != nil {
		s.fail(e)
		return nil, e
	}
	return s, nil
}

func (h *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) (err error) {
	// A failure is confined to the session this request used; the client and
	// its other pooled sessions keep working.
	var s *muxSession
	defer nativebridge.Recover(&err, func() {
		if s != nil {
			s.fail(errors.New("AnyTLS request internal failure"))
		}
	})
	target, e := nativebridge.Target(ctx, "anytls")
	if e != nil {
		return e
	}
	s, e = h.take(ctx, dialer)
	if e != nil {
		return e
	}
	addressTarget := target
	if target.Network == xnet.Network_UDP {
		addressTarget = xnet.TCPDestination(xnet.DomainAddress("sp.v2.udp-over-tcp.arpa"), 0)
	}
	addr, e := nativebridge.Address(addressTarget)
	if e != nil {
		s.mu.Lock()
		s.busy = false
		s.mu.Unlock()
		return e
	}
	st, e := s.open(ctx, addr)
	if e != nil {
		return withSessionFailure(e, s)
	}
	defer st.Close()
	var packets nativebridge.PacketCodec
	if target.Network == xnet.Network_UDP {
		u, e := newUOT(st, target)
		if e != nil {
			return e
		}
		packets = u
	}
	return withSessionFailure(nativebridge.Relay(ctx, link, st, packets, target, h.policy.ForLevel(0)), s)
}

// withSessionFailure adds the reason the session closed (a server alert, for
// example) to a request error, so the outbound log shows it.
func withSessionFailure(e error, s *muxSession) error {
	if e == nil {
		return nil
	}
	if se := s.failure(); se != nil && !errors.Is(se, net.ErrClosed) {
		return fmt.Errorf("%w (session: %v)", e, se)
	}
	return e
}

func (h *Client) Close() error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	close(h.done)
	sessions := append([]*muxSession(nil), h.sessions...)
	h.sessions = nil
	dials := h.dials
	h.dials = nil
	h.mu.Unlock()
	for cancel := range dials {
		(*cancel)()
	}
	for _, s := range sessions {
		s.fail(net.ErrClosed)
	}
	return nil
}
