package dnstt

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// Resolver health belongs to one tunnel generation. It adds no background
// workers, global state, alternative endpoints, or same-query retries.
type resolverScheduler struct {
	ctx      context.Context
	mu       sync.Mutex
	members  []resolverHealth
	next     int
	cooldown time.Duration
	changed  chan struct{}
}

type resolverHealth struct {
	generation uint64
	unhealthy  bool
	until      time.Time
	probing    bool
}

type resolverTicket struct {
	index      int
	generation uint64
	probe      bool
}

func newResolverScheduler(ctx context.Context, count int, timeout time.Duration) *resolverScheduler {
	return &resolverScheduler{ctx: ctx, members: make([]resolverHealth, count),
		cooldown: min(30*time.Second, max(time.Second, 2*timeout)), changed: make(chan struct{})}
}

// tryAcquire accepts an explicit clock value so cooldown and generation
// transitions can be tested without sleeping or opening a network socket.
// A zero wakeup means every unavailable member already has a recovery probe.
func (s *resolverScheduler) tryAcquire(now time.Time) (resolverTicket, bool, time.Time, <-chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var wakeup time.Time
	for offset := 0; offset < len(s.members); offset++ {
		index := (s.next + offset) % len(s.members)
		member := &s.members[index]
		if member.unhealthy {
			if member.probing {
				continue
			}
			if member.until.After(now) {
				if wakeup.IsZero() || member.until.Before(wakeup) {
					wakeup = member.until
				}
				continue
			}
			member.probing = true
		}
		s.next = (index + 1) % len(s.members)
		return resolverTicket{index: index, generation: member.generation, probe: member.probing}, true, time.Time{}, s.changed
	}
	return resolverTicket{}, false, wakeup, s.changed
}

func (s *resolverScheduler) acquire(ctx context.Context) (resolverTicket, error) {
	for {
		if err := ctx.Err(); err != nil {
			return resolverTicket{}, err
		}
		if s.ctx.Err() != nil {
			return resolverTicket{}, net.ErrClosed
		}
		ticket, available, wakeup, changed := s.tryAcquire(time.Now())
		if available {
			return ticket, nil
		}
		var timer *time.Timer
		var ready <-chan time.Time
		if !wakeup.IsZero() {
			timer = time.NewTimer(time.Until(wakeup))
			ready = timer.C
		}
		select {
		case <-ctx.Done():
		case <-s.ctx.Done():
		case <-changed:
		case <-ready:
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

func (s *resolverScheduler) complete(ticket resolverTicket, err error, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	member := &s.members[ticket.index]
	// Concurrent queries issued before a failure must neither extend its
	// cooldown nor clear it with a late success. Only its one recovery probe
	// may declare the member healthy again.
	if member.generation != ticket.generation {
		return
	}
	if errors.Is(err, context.Canceled) {
		if !ticket.probe {
			return
		}
		member.generation++
		member.probing = false
	} else if err != nil {
		member.generation++
		member.unhealthy = true
		member.probing = false
		member.until = now.Add(s.cooldown)
	} else {
		if !ticket.probe {
			return
		}
		member.generation++
		member.unhealthy = false
		member.probing = false
		member.until = time.Time{}
	}
	close(s.changed)
	s.changed = make(chan struct{})
}

func (s *resolverScheduler) exchange(ctx context.Context, call func(int) ([]byte, error)) (response []byte, err error) {
	ticket, err := s.acquire(ctx)
	if err != nil {
		return nil, err
	}
	// Account for cancellation races and release a reserved probe even if a
	// transport panics; the enclosing packet worker retains panic containment.
	completed := false
	defer func() {
		result := err
		switch {
		case !completed:
			// No transport result exists when cancellation won before the call
			// or the outer containment boundary is handling a panic.
			result = context.Canceled
		case errors.Is(ctx.Err(), context.Canceled) || s.ctx.Err() != nil:
			result = context.Canceled
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			// TLS setup uses a derived lifetime context; its cancellation can
			// obscure the original query's deadline error.
			result = context.DeadlineExceeded
		case errors.Is(result, context.Canceled):
			// A completed child transport can also cancel its own setup while
			// both caller and generation are active. This is a transport failure,
			// not user cancellation. Preserve the original outward error.
			result = errors.New("dnstt: resolver transport canceled internally")
		}
		s.complete(ticket, result, time.Now())
	}()
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if s.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	response, err = call(ticket.index)
	completed = true
	if err == nil {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		if s.ctx.Err() != nil {
			return nil, net.ErrClosed
		}
	}
	return response, err
}
