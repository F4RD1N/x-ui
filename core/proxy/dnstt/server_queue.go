package dnstt

import (
	"context"
	"net"
	"sync"
	"time"

	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

const serverIdleTimeout = 2 * time.Minute

type serverPeer struct {
	id                turbotunnel.ClientID
	ctx               context.Context
	local, remote     net.Addr
	created, lastSeen time.Time
	authenticated     bool
	outgoing          chan []byte
	stash             chan []byte
}

type serverPacket struct {
	data []byte
	id   turbotunnel.ClientID
}

// authorityQueue is deliberately instance-owned and bounded. The upstream
// RemoteMap starts a perpetual expiration goroutine, unsuitable for core reloads.
// Pending IDs have their own small evictable budget. Only successful inner
// authentication promotes a peer into the protected active-session budget.
// Polls cannot extend pending lifetime or pin the authenticated capacity.
type authorityQueue struct {
	ctx                 context.Context
	cancel              context.CancelFunc
	mu                  sync.Mutex
	peers               map[turbotunnel.ClientID]*serverPeer
	incoming            chan serverPacket
	limit, pendingLimit int
	pendingLifetime     time.Duration
}

func newAuthorityQueue(ctx context.Context, limit int) *authorityQueue {
	ctx, cancel := context.WithCancel(ctx)
	return &authorityQueue{ctx: ctx, cancel: cancel, peers: make(map[turbotunnel.ClientID]*serverPeer), incoming: make(chan serverPacket, turbotunnel.QueueSize), limit: limit, pendingLimit: min(64, max(16, limit)), pendingLifetime: 30 * time.Second}
}

// admit returns a new/existing pending peer and any evicted old peer. The
// caller closes only sessions associated with that exact old peer pointer.
func (q *authorityQueue) admit(id turbotunnel.ClientID, ctx context.Context, local, remote net.Addr) (*serverPeer, *serverPeer) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.ctx.Err() != nil {
		return nil, nil
	}
	now := time.Now()
	var evicted *serverPeer
	if p := q.peers[id]; p != nil {
		if p.authenticated || now.Sub(p.created) < q.pendingLifetime {
			p.lastSeen = now
			return p, nil
		}
		evicted = p
		delete(q.peers, id)
	}
	pending := 0
	var oldest *serverPeer
	for _, p := range q.peers {
		if !p.authenticated {
			pending++
			if oldest == nil || p.created.Before(oldest.created) {
				oldest = p
			}
		}
	}
	if pending >= q.pendingLimit {
		// This can only happen for a previously unseen ID, so evicted is nil.
		evicted = oldest
		delete(q.peers, oldest.id)
	}
	p := &serverPeer{id: id, ctx: ctx, local: local, remote: remote, created: now, lastSeen: now, outgoing: make(chan []byte, turbotunnel.QueueSize), stash: make(chan []byte, 1)}
	q.peers[id] = p
	return p, evicted
}

func (q *authorityQueue) promote(peer *serverPeer) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.ctx.Err() != nil || peer == nil || q.peers[peer.id] != peer {
		return false
	}
	if peer.authenticated {
		return true
	}
	active := 0
	for _, p := range q.peers {
		if p.authenticated {
			active++
		}
	}
	if active >= q.limit {
		return false
	}
	peer.authenticated = true
	return true
}

func (q *authorityQueue) remove(peer *serverPeer) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if peer != nil && q.peers[peer.id] == peer {
		delete(q.peers, peer.id)
	}
}

func (q *authorityQueue) peer(id turbotunnel.ClientID) *serverPeer {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.peers[id]
}

func (q *authorityQueue) expire(now time.Time) []*serverPeer {
	q.mu.Lock()
	defer q.mu.Unlock()
	var expired []*serverPeer
	for id, p := range q.peers {
		if (p.authenticated && now.Sub(p.lastSeen) >= serverIdleTimeout) || (!p.authenticated && now.Sub(p.created) >= q.pendingLifetime) {
			delete(q.peers, id)
			expired = append(expired, p)
		}
	}
	return expired
}

func (q *authorityQueue) queue(data []byte, id turbotunnel.ClientID) {
	if q.ctx.Err() != nil {
		return
	}
	p := serverPacket{data: append([]byte(nil), data...), id: id}
	select {
	case q.incoming <- p:
	default:
	}
}
func (q *authorityQueue) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case <-q.ctx.Done():
		return 0, nil, net.ErrClosed
	case p := <-q.incoming:
		return copy(b, p.data), p.id, nil
	}
}
func (q *authorityQueue) WriteTo(b []byte, addr net.Addr) (int, error) {
	if q.ctx.Err() != nil {
		return 0, net.ErrClosed
	}
	id, ok := addr.(turbotunnel.ClientID)
	if !ok {
		return 0, net.InvalidAddrError("invalid DNS tunnel client")
	}
	p := q.peer(id)
	if p == nil {
		return len(b), nil
	}
	if len(b) > 4096 {
		return 0, net.InvalidAddrError("oversized DNS tunnel packet")
	}
	data := append([]byte(nil), b...)
	select {
	case p.outgoing <- data:
	default:
	}
	return len(b), nil
}
func (q *authorityQueue) Close() error                     { q.cancel(); return nil }
func (q *authorityQueue) LocalAddr() net.Addr              { return tunnelAddr("authority") }
func (q *authorityQueue) SetDeadline(time.Time) error      { return nil }
func (q *authorityQueue) SetReadDeadline(time.Time) error  { return nil }
func (q *authorityQueue) SetWriteDeadline(time.Time) error { return nil }

func (q *authorityQueue) isAuthenticated(peer *serverPeer) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return peer != nil && q.peers[peer.id] == peer && peer.authenticated
}
