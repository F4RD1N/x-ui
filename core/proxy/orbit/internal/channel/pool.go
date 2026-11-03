// Package channel groups physical sessions under one runtime channel identity
// (VPN-Core 0.12 channel/pool.go). The provider (custom) outbound pools its
// TCP and QUIC sessions here; orbit links use one session and do not import
// it. The only change: every worker runs under guard.Go, so a panic closes
// the pool instead of the process.
package channel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/proxy/orbit/internal/guard"
	"github.com/xtls/xray-core/proxy/orbit/internal/protocol"
)

var (
	ErrClosed      = errors.New("channel: closed")
	ErrNoPeers     = errors.New("channel: no physical sessions available")
	ErrIdentity    = errors.New("channel: peer identity does not match")
	ErrSocketIDs   = errors.New("channel: socket ID space exhausted")
	ErrUnsupported = errors.New("channel: operation unavailable")
)

// SocketIDs must be shared by all physical TCP and QUIC sessions in a channel.
// IDs are never reused during this allocator's lifetime, including after close.
type SocketIDs struct{ next atomic.Uint64 }

func (s *SocketIDs) Next() (uint32, error) {
	n := s.next.Add(1)
	if n > 0xffffffff {
		return 0, ErrSocketIDs
	}
	return uint32(n), nil
}

type Peer interface {
	Open(context.Context, string, uint16) (net.Conn, error)
	SendUDP(context.Context, protocol.UDPEnvelope) error
	ReceiveUDP(context.Context) (protocol.UDPEnvelope, error)
	User() protocol.UserInfo
	ChannelID() [16]byte
	Done() <-chan struct{}
	Err() error
	Close() error
}
type AppPeer interface {
	SendApp(context.Context, protocol.AppMessage) error
	ReceiveApp(context.Context) (protocol.AppMessage, error)
}
type member struct {
	peer       Peer
	quic, dead bool
	active     int
}

// Pool chooses a ready QUIC peer when present, otherwise the TCP peer with the
// fewest attached sockets, retaining the first peer on ties. A flow remains on
// the chosen physical session for its lifetime; failed flows are not replayed.
type Pool struct {
	ctx            context.Context
	cancel         context.CancelFunc
	user           protocol.UserInfo
	id             [16]byte
	mu             sync.Mutex
	members        []*member
	sealed, closed bool
	tcpFirst       bool
	pending        int
	refill         func(context.Context, bool) (Peer, error)
	err            error
	changed        chan struct{}
	done           chan struct{}
	udp            chan protocol.UDPEnvelope
	app            chan protocol.AppMessage
	dropped        atomic.Uint64
}

func New(ctx context.Context, user protocol.UserInfo, id [16]byte) *Pool {
	ctx, cancel := context.WithCancel(ctx)
	p := &Pool{ctx: ctx, cancel: cancel, user: protocol.NormalizeIdentity(user), id: id, changed: make(chan struct{}), done: make(chan struct{}), udp: make(chan protocol.UDPEnvelope, 128), app: make(chan protocol.AppMessage, 64)}
	guard.Go(func() {
		select {
		case <-ctx.Done():
			p.shutdown(ctx.Err())
		case <-p.done:
		}
	}, p.fail)
	return p
}

// SetTCPFirst applies the route preference to TCP flows and UDP envelopes.
// Application control messages still prefer a ready QUIC control stream.
func (p *Pool) SetTCPFirst(enabled bool) { p.mu.Lock(); p.tcpFirst = enabled; p.mu.Unlock() }

func (p *Pool) User() protocol.UserInfo { return p.user }
func (p *Pool) ChannelID() [16]byte     { return p.id }
func (p *Pool) Done() <-chan struct{}   { return p.done }
func (p *Pool) Err() error              { p.mu.Lock(); defer p.mu.Unlock(); return p.err }
func (p *Pool) DroppedUDP() uint64      { return p.dropped.Load() }
func (p *Pool) Close() error            { p.shutdown(ErrClosed); return nil }
func (p *Pool) fail()                   { p.shutdown(guard.ErrInternal) }
func (p *Pool) signal()                 { close(p.changed); p.changed = make(chan struct{}) }
func (p *Pool) AddTCP(peer Peer) error  { return p.add(peer, false, false) }
func (p *Pool) AddQUIC(peer Peer) error { return p.add(peer, true, false) }
func (p *Pool) add(peer Peer, quic, replacement bool) error {
	if peer == nil {
		return ErrIdentity
	}
	if peer.ChannelID() != p.id || protocol.NormalizeIdentity(peer.User()) != p.user {
		return ErrIdentity
	}
	p.mu.Lock()
	if p.closed || (p.sealed && !replacement) {
		p.mu.Unlock()
		return ErrClosed
	}
	for _, m := range p.members {
		if quic && m.quic && !m.dead {
			p.mu.Unlock()
			return errors.New("channel: native channel has one QUIC session")
		}
	}
	m := &member{peer: peer, quic: quic}
	p.members = append(p.members, m)
	p.signal()
	p.mu.Unlock()
	guard.Go(func() { p.readUDP(m) }, p.fail)
	if a, ok := peer.(AppPeer); ok {
		guard.Go(func() { p.readApp(m, a) }, p.fail)
	}
	guard.Go(func() {
		select {
		case <-peer.Done():
			p.depart(m)
		case <-p.done:
		}
	}, p.fail)
	return nil
}

// Seal marks all initial dial attempts finished. It does not prevent existing
// streams from running. Public Add calls stop; reserved refills may still join.
func (p *Pool) Seal() {
	p.mu.Lock()
	p.sealed = true
	empty := p.liveLocked() == 0 && p.pending == 0
	p.signal()
	p.mu.Unlock()
	if empty {
		p.shutdownEmpty(ErrNoPeers)
	}
}

// SetRefill installs a replacement dialer. Its callback owns bounded retry
// timing and must honor ctx. Registration must precede adding initial peers.
func (p *Pool) SetRefill(fn func(context.Context, bool) (Peer, error)) {
	p.mu.Lock()
	p.refill = fn
	p.mu.Unlock()
}
func (p *Pool) Pending() int      { p.mu.Lock(); defer p.mu.Unlock(); return p.pending }
func (p *Pool) RefillTCP() error  { return p.startRefill(false) }
func (p *Pool) RefillQUIC() error { return p.startRefill(true) }
func (p *Pool) startRefill(quic bool) error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return ErrClosed
	}
	fn := p.refill
	if fn == nil {
		p.mu.Unlock()
		return ErrUnsupported
	}
	p.pending++
	p.signal()
	p.mu.Unlock()
	guard.Go(func() { p.replenish(fn, quic) }, p.fail)
	return nil
}
func (p *Pool) liveLocked() int {
	// A just-closed peer remains present until depart reserves its replacement.
	// This prevents Seal racing a peer's Done notification.
	return len(p.members)
}
func (p *Pool) depart(m *member) {
	p.mu.Lock()
	if m.dead || p.closed {
		p.mu.Unlock()
		return
	}
	m.dead = true
	for i, candidate := range p.members {
		if candidate == m {
			copy(p.members[i:], p.members[i+1:])
			p.members[len(p.members)-1] = nil
			p.members = p.members[:len(p.members)-1]
			break
		}
	}
	fn := p.refill
	if fn != nil {
		p.pending++
	}
	empty := p.sealed && p.liveLocked() == 0 && p.pending == 0
	p.signal()
	p.mu.Unlock()
	if fn != nil {
		guard.Go(func() { p.replenish(fn, m.quic) }, p.fail)
	}
	if empty {
		err := m.peer.Err()
		if err == nil {
			err = ErrNoPeers
		}
		p.shutdownEmpty(err)
	}
}
func (p *Pool) replenish(fn func(context.Context, bool) (Peer, error), quic bool) {
	peer, err := fn(p.ctx, quic)
	if err == nil {
		err = p.add(peer, quic, true)
	}
	if err != nil && peer != nil {
		_ = peer.Close()
	}
	p.mu.Lock()
	p.pending--
	empty := !p.closed && p.sealed && p.liveLocked() == 0 && p.pending == 0
	p.signal()
	p.mu.Unlock()
	if empty {
		if err == nil {
			err = ErrNoPeers
		}
		p.shutdownEmpty(err)
	}
}
func (p *Pool) shutdown(err error)      { p.shutdownWhen(err, false) }
func (p *Pool) shutdownEmpty(err error) { p.shutdownWhen(err, true) }
func (p *Pool) shutdownWhen(err error, onlyEmpty bool) {
	p.mu.Lock()
	if p.closed || (onlyEmpty && (!p.sealed || p.liveLocked() != 0 || p.pending != 0)) {
		p.mu.Unlock()
		return
	}
	p.closed = true
	p.err = err
	p.signal()
	close(p.done)
	peers := append([]*member(nil), p.members...)
	p.mu.Unlock()
	p.cancel()
	for _, m := range peers {
		_ = m.peer.Close()
	}
}
func (p *Pool) choose(ctx context.Context, flow bool) (*member, error) {
	if ctx == nil {
		return nil, errors.New("channel: nil context")
	}
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, ErrClosed
		}
		var selected, quic *member
		for _, m := range p.members {
			if m.dead {
				continue
			}
			select {
			case <-m.peer.Done():
				continue
			default:
			}
			if m.quic {
				quic = m
				continue
			}
			if selected == nil || m.active < selected.active {
				selected = m
			}
		}
		if quic != nil && (!p.tcpFirst || selected == nil) {
			selected = quic
		}
		if selected != nil {
			if flow {
				selected.active++
			}
			p.mu.Unlock()
			return selected, nil
		}
		changed, sealed := p.changed, p.sealed && p.pending == 0 && p.liveLocked() == 0
		p.mu.Unlock()
		if sealed {
			return nil, ErrNoPeers
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-p.done:
			return nil, ErrClosed
		case <-changed:
		}
	}
}
func (p *Pool) Open(ctx context.Context, host string, port uint16) (net.Conn, error) {
	m, err := p.choose(ctx, true)
	if err != nil {
		return nil, err
	}
	release := func() { p.mu.Lock(); m.active--; p.mu.Unlock() }
	c, err := m.peer.Open(ctx, host, port)
	if err != nil {
		release()
		return nil, err
	}
	return &flowConn{Conn: c, release: release}, nil
}
func (p *Pool) SendUDP(ctx context.Context, u protocol.UDPEnvelope) error {
	if _, err := p.choose(ctx, false); err != nil {
		return err
	}
	p.mu.Lock()
	var selected, quic *member
	index := -1
	for i, m := range p.members {
		if m.dead {
			continue
		}
		select {
		case <-m.peer.Done():
			continue
		default:
		}
		if m.quic {
			quic = m
			continue
		}
		if selected == nil {
			selected = m
			index = i
		}
	}
	if quic != nil && (!p.tcpFirst || selected == nil) {
		selected = quic
		index = -1
	}
	if index >= 0 {
		// The native UDP fallback rotates the working TCP list. This also
		// affects later least-loaded TCP ties, which use the current list order.
		copy(p.members[index:], p.members[index+1:])
		p.members[len(p.members)-1] = selected
	}
	p.mu.Unlock()
	if selected == nil {
		return ErrNoPeers
	}
	return selected.peer.SendUDP(ctx, u)
}
func (p *Pool) ReceiveUDP(ctx context.Context) (protocol.UDPEnvelope, error) {
	if ctx == nil {
		return protocol.UDPEnvelope{}, errors.New("channel: nil context")
	}
	select {
	case u := <-p.udp:
		return u, nil
	case <-ctx.Done():
		return protocol.UDPEnvelope{}, ctx.Err()
	case <-p.done:
		return protocol.UDPEnvelope{}, ErrClosed
	}
}
func (p *Pool) readUDP(m *member) {
	for {
		u, err := m.peer.ReceiveUDP(p.ctx)
		if err != nil {
			return
		}
		select {
		case p.udp <- u:
		case <-p.done:
			return
		default:
			p.dropped.Add(1)
		}
	}
}

// SendApp follows the recovered choice: ready QUIC first, otherwise one random
// available TCP peer. Responses are merged while preserving the request ID.
func (p *Pool) SendApp(ctx context.Context, a protocol.AppMessage) error {
	if _, err := p.choose(ctx, false); err != nil {
		return err
	}
	p.mu.Lock()
	var candidates []AppPeer
	for _, m := range p.members {
		if m.dead {
			continue
		}
		select {
		case <-m.peer.Done():
			continue
		default:
		}
		if peer, ok := m.peer.(AppPeer); ok {
			if m.quic {
				candidates = []AppPeer{peer}
				break
			}
			candidates = append(candidates, peer)
		}
	}
	p.mu.Unlock()
	if len(candidates) == 0 {
		return ErrUnsupported
	}
	var random [4]byte
	if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
		return err
	}
	return candidates[int(binary.LittleEndian.Uint32(random[:]))%len(candidates)].SendApp(ctx, a)
}
func (p *Pool) ReceiveApp(ctx context.Context) (protocol.AppMessage, error) {
	if ctx == nil {
		return protocol.AppMessage{}, errors.New("channel: nil context")
	}
	select {
	case a := <-p.app:
		return a, nil
	case <-ctx.Done():
		return protocol.AppMessage{}, ctx.Err()
	case <-p.done:
		return protocol.AppMessage{}, ErrClosed
	}
}
func (p *Pool) readApp(m *member, a AppPeer) {
	for {
		message, err := a.ReceiveApp(p.ctx)
		if err != nil {
			return
		}
		select {
		case p.app <- message:
		case <-p.done:
			return
		default:
			p.shutdown(errors.New("channel: application receive queue full"))
			return
		}
	}
}
func (p *Pool) RouteMetadata() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, m := range p.members {
		if !m.dead {
			if v, ok := m.peer.(interface{ RouteMetadata() []byte }); ok {
				return v.RouteMetadata()
			}
		}
	}
	return nil
}

// Counts reports live physical peers and attached flow counts in insertion order.
func (p *Pool) Counts() (tcp, quic int, active []int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, m := range p.members {
		if m.dead {
			continue
		}
		select {
		case <-m.peer.Done():
			continue
		default:
		}
		if m.quic {
			quic++
		} else {
			tcp++
		}
		active = append(active, m.active)
	}
	return
}

type flowConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *flowConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
func (c *flowConn) CloseWrite() error {
	if v, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return v.CloseWrite()
	}
	return c.Close()
}
func (c *flowConn) CloseRead() error {
	if v, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return v.CloseRead()
	}
	return ErrUnsupported
}
