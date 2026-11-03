// Package datagram dispatches reference UDP envelopes without changing their
// source/destination tuple or introducing an extra wire association identifier.
package datagram

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/proxy/orbit/internal/guard"
	"github.com/xtls/xray-core/proxy/orbit/internal/protocol"
)

type Channel interface {
	SendUDP(context.Context, protocol.UDPEnvelope) error
	ReceiveUDP(context.Context) (protocol.UDPEnvelope, error)
}
type tuple struct{ local, remote netip.AddrPort }
type Hub struct {
	channel      Channel
	ctx          context.Context
	cancel       context.CancelFunc
	mu           sync.Mutex
	routes       map[tuple]*Association
	associations map[*Association]bool
	next         uint16
	limit        int
	done         chan struct{}
	err          error
	drops        atomic.Uint64
}
type Association struct {
	hub     *Hub
	source  netip.AddrPort
	kind    byte
	packets chan protocol.UDPEnvelope
	done    chan struct{}
	once    sync.Once
}

func New(ctx context.Context, ch Channel, limit int) *Hub {
	if limit <= 0 {
		limit = 128
	}
	ctx, cancel := context.WithCancel(ctx)
	h := &Hub{channel: ch, ctx: ctx, cancel: cancel, routes: make(map[tuple]*Association), associations: make(map[*Association]bool), next: 32768, limit: limit, done: make(chan struct{})}
	guard.Go(h.run, func() { h.cancel() })
	return h
}

func (h *Hub) run() {
	defer close(h.done)
	for {
		u, err := h.channel.ReceiveUDP(h.ctx)
		if err != nil {
			h.mu.Lock()
			h.err = err
			h.mu.Unlock()
			h.cancel()
			return
		}
		h.mu.Lock()
		a := h.routes[tuple{u.Destination, u.Source}]
		h.mu.Unlock()
		if a == nil {
			h.drops.Add(1)
			continue
		}
		select {
		case <-a.done:
			h.drops.Add(1)
		case a.packets <- u:
		default:
			h.drops.Add(1)
		}
	}
}

func (h *Hub) Open(source netip.AddrPort, kind byte) (*Association, error) {
	if kind != protocol.UDPKindDNS && kind != protocol.UDPKindData {
		return nil, protocol.ErrUnsupported
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.ctx.Err() != nil {
		return nil, io.ErrClosedPipe
	}
	if len(h.associations) >= h.limit {
		return nil, errors.New("UDP association limit reached")
	}
	if !source.IsValid() {
		source = netip.AddrPortFrom(netip.MustParseAddr("26.26.26.2"), 0)
	}
	if !source.Addr().Is4() {
		return nil, protocol.ErrUnsupported
	}
	if source.Port() == 0 {
		found := false
		for i := 0; i < 32768; i++ {
			candidate := netip.AddrPortFrom(source.Addr(), h.next)
			h.next++
			if h.next < 32768 {
				h.next = 32768
			}
			used := false
			for a := range h.associations {
				if a.source == candidate {
					used = true
					break
				}
			}
			if !used {
				source = candidate
				found = true
				break
			}
		}
		if !found {
			return nil, errors.New("UDP source ports exhausted")
		}
	}
	a := &Association{hub: h, source: source, kind: kind, packets: make(chan protocol.UDPEnvelope, 32), done: make(chan struct{})}
	h.associations[a] = true
	return a, nil
}

func (a *Association) Source() netip.AddrPort { return a.source }
func (a *Association) Send(ctx context.Context, to netip.AddrPort, data []byte) error {
	if !to.IsValid() || !to.Addr().Is4() || to.Port() == 0 {
		return protocol.ErrUnsupported
	}
	if len(data) > protocol.MaxUDPDataSize {
		return protocol.ErrMalformed
	}
	select {
	case <-a.done:
		return io.ErrClosedPipe
	default:
	}
	h := a.hub
	h.mu.Lock()
	if !h.associations[a] || h.ctx.Err() != nil {
		h.mu.Unlock()
		return io.ErrClosedPipe
	}
	k := tuple{a.source, to}
	if old := h.routes[k]; old != nil && old != a {
		h.mu.Unlock()
		return errors.New("UDP source/destination tuple is already in use")
	}
	count := 0
	for _, owner := range h.routes {
		if owner == a {
			count++
		}
	}
	if count >= 128 && h.routes[k] == nil {
		h.mu.Unlock()
		return errors.New("UDP destinations per association exceeded")
	}
	h.routes[k] = a
	h.mu.Unlock()
	return h.channel.SendUDP(ctx, protocol.UDPEnvelope{Kind: a.kind, Source: a.source, Destination: to, Data: append([]byte(nil), data...)})
}

func (a *Association) Receive(ctx context.Context) (protocol.UDPEnvelope, error) {
	select {
	case <-a.done:
		return protocol.UDPEnvelope{}, io.ErrClosedPipe
	case <-a.hub.ctx.Done():
		return protocol.UDPEnvelope{}, io.ErrClosedPipe
	case <-ctx.Done():
		return protocol.UDPEnvelope{}, ctx.Err()
	case u := <-a.packets:
		return u, nil
	}
}
func (a *Association) Close() error {
	a.once.Do(func() {
		h := a.hub
		h.mu.Lock()
		delete(h.associations, a)
		for k, owner := range h.routes {
			if owner == a {
				delete(h.routes, k)
			}
		}
		h.mu.Unlock()
		close(a.done)
	})
	return nil
}
func (h *Hub) Close() error          { h.cancel(); <-h.done; return nil }
func (h *Hub) Drops() uint64         { return h.drops.Load() }
func (h *Hub) Done() <-chan struct{} { return h.done }
