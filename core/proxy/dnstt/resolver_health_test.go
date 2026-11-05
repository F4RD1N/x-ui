package dnstt

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func schedulerTicket(t *testing.T, s *resolverScheduler, now time.Time) resolverTicket {
	t.Helper()
	ticket, ok, _, _ := s.tryAcquire(now)
	if !ok {
		t.Fatal("expected available resolver")
	}
	return ticket
}

func TestResolverHealthHealthyRoundRobin(t *testing.T) {
	s := newResolverScheduler(context.Background(), 3, 5*time.Second)
	for i := 0; i < 30; i++ {
		response, err := s.exchange(context.Background(), func(index int) ([]byte, error) {
			if index != i%3 {
				t.Fatalf("rotation=%d, want%d", index, i%3)
			}
			return []byte{byte(index)}, nil
		})
		if err != nil || len(response) != 1 {
			t.Fatalf("exchange: %v", err)
		}
	}
}

func TestResolverHealthAvoidsSilentMemberAfterFirstFailure(t *testing.T) {
	s := newResolverScheduler(context.Background(), 2, 5*time.Second)
	now := time.Unix(1000, 0)
	// Model a full 32-query window issued before the first timeout. Its late
	// failures/successes cannot keep moving the failed member's cooldown.
	tickets := make([]resolverTicket, 32)
	for i := range tickets {
		tickets[i] = schedulerTicket(t, s, now)
	}
	s.complete(tickets[0], context.DeadlineExceeded, now)
	deadline := s.members[0].until
	for _, ticket := range tickets[1:] {
		err := error(nil)
		if ticket.index == 0 {
			err = context.DeadlineExceeded
		}
		s.complete(ticket, err, now.Add(time.Second))
	}
	s.complete(tickets[0], nil, now.Add(2*time.Second))
	if !s.members[0].unhealthy || !s.members[0].until.Equal(deadline) {
		t.Fatal("stale completions changed failure epoch")
	}
	for i := 0; i < 128; i++ {
		ticket := schedulerTicket(t, s, now.Add(time.Second))
		if ticket.index != 1 || ticket.probe {
			t.Fatal("silent member continued consuming query slots")
		}
		s.complete(ticket, nil, now.Add(time.Second))
	}
}

func TestResolverHealthOneConcurrentRecoveryProbe(t *testing.T) {
	s := newResolverScheduler(context.Background(), 2, time.Second)
	now := time.Unix(1000, 0)
	failed := schedulerTicket(t, s, now)
	s.complete(failed, context.DeadlineExceeded, now)
	now = now.Add(2 * time.Second)
	var probes atomic.Int32
	var probe resolverTicket
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticket, ok, _, _ := s.tryAcquire(now)
			if !ok {
				t.Error("healthy member unavailable")
				return
			}
			if ticket.index == 0 {
				if !ticket.probe {
					t.Error("recovery was not a probe")
				}
				probes.Add(1)
				probe = ticket
			}
		}()
	}
	wg.Wait()
	if probes.Load() != 1 {
		t.Fatalf("concurrent recovery probes=%d", probes.Load())
	}
	s.complete(probe, nil, now)
	if s.members[0].unhealthy || s.members[0].probing {
		t.Fatal("matching probe did not restore health")
	}
	seen := map[int]bool{}
	for i := 0; i < 4; i++ {
		seen[schedulerTicket(t, s, now).index] = true
	}
	if len(seen) != 2 {
		t.Fatal("recovered resolver did not rejoin round robin")
	}
}

func TestResolverHealthLateEpochCannotClearNewFailure(t *testing.T) {
	s := newResolverScheduler(context.Background(), 2, time.Second)
	now := time.Unix(1000, 0)
	old := schedulerTicket(t, s, now)
	s.complete(old, context.DeadlineExceeded, now)
	_ = schedulerTicket(t, s, now) // healthy member; next selection starts at0
	probe := schedulerTicket(t, s, now.Add(2*time.Second))
	if probe.index != 0 || !probe.probe {
		t.Fatal("missing recovery probe")
	}
	s.complete(old, nil, now.Add(2*time.Second))
	if !s.members[0].probing || !s.members[0].unhealthy {
		t.Fatal("old success cleared newer probe")
	}
	s.complete(probe, context.DeadlineExceeded, now.Add(2*time.Second))
	want := s.members[0]
	s.complete(old, context.DeadlineExceeded, now.Add(time.Hour))
	s.complete(probe, nil, now.Add(time.Hour))
	if s.members[0] != want {
		t.Fatal("stale completion reset or prolonged newer failure")
	}
}

func TestResolverHealthCanceledProbeDoesNotPoisonMember(t *testing.T) {
	s := newResolverScheduler(context.Background(), 2, time.Second)
	now := time.Unix(1000, 0)
	s.complete(schedulerTicket(t, s, now), context.DeadlineExceeded, now)
	_ = schedulerTicket(t, s, now)
	probe := schedulerTicket(t, s, now.Add(2*time.Second))
	until := s.members[0].until
	s.complete(probe, context.Canceled, now.Add(time.Hour))
	if !s.members[0].unhealthy || s.members[0].probing || !s.members[0].until.Equal(until) {
		t.Fatal("canceled probe altered cooldown or retained ownership")
	}
	_ = schedulerTicket(t, s, now.Add(2*time.Second))
	next := schedulerTicket(t, s, now.Add(2*time.Second))
	if next.index != 0 || !next.probe || next.generation == probe.generation {
		t.Fatal("canceled probe was not safely replaceable")
	}
	s.complete(probe, nil, now.Add(time.Hour))
	if !s.members[0].probing {
		t.Fatal("canceled ticket cleared new probe")
	}
}

type resolverObservedContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *resolverObservedContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func TestResolverHealthAllUnavailableWaitsAndCancels(t *testing.T) {
	for _, mode := range []string{"caller-cancel", "caller-deadline", "generation-close"} {
		t.Run(mode, func(t *testing.T) {
			base, closeSet := context.WithCancel(context.Background())
			defer closeSet()
			s := newResolverScheduler(base, 2, time.Second)
			future := time.Now().Add(time.Hour)
			for i := 0; i < 2; i++ {
				s.complete(schedulerTicket(t, s, future), context.DeadlineExceeded, future)
			}
			_, ok, wakeup, _ := s.tryAcquire(time.Now())
			if ok || wakeup.IsZero() {
				t.Fatal("all-down selection did not return a bounded cooldown wait")
			}
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "caller-deadline" {
				parent, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				defer cancel()
			}
			ctx := &resolverObservedContext{Context: parent, waiting: make(chan struct{})}
			result := make(chan error, 1)
			var calls atomic.Int32
			go func() {
				_, err := s.exchange(ctx, func(int) ([]byte, error) { calls.Add(1); return nil, nil })
				result <- err
			}()
			if mode != "caller-deadline" {
				select {
				case <-ctx.waiting:
				case <-time.After(time.Second):
					t.Fatal("all-down exchange never entered wait")
				}
				select {
				case err := <-result:
					t.Fatalf("all-down exchange failed immediately: %v", err)
				default:
				}
				if mode == "generation-close" {
					closeSet()
				} else {
					cancel()
				}
			}
			select {
			case err := <-result:
				want := error(context.Canceled)
				if mode == "caller-deadline" {
					want = context.DeadlineExceeded
				}
				if mode == "generation-close" {
					want = net.ErrClosed
				}
				if !errors.Is(err, want) {
					t.Fatalf("cancellation=%v, want%v", err, want)
				}
			case <-time.After(time.Second):
				t.Fatal("cancellation did not release wait")
			}
			if calls.Load() != 0 {
				t.Fatal("all-down wait dialed a resolver")
			}
		})
	}
}

func TestResolverHealthAllProbingWaitsForStateChange(t *testing.T) {
	s := newResolverScheduler(context.Background(), 2, time.Second)
	now := time.Unix(1000, 0)
	for i := 0; i < 2; i++ {
		s.complete(schedulerTicket(t, s, now), context.DeadlineExceeded, now)
	}
	first := schedulerTicket(t, s, now.Add(2*time.Second))
	_ = schedulerTicket(t, s, now.Add(2*time.Second))
	_, ok, wakeup, _ := s.tryAcquire(now.Add(3 * time.Second))
	if ok || !wakeup.IsZero() {
		t.Fatal("in-flight probes produced immediate retry timer")
	}
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &resolverObservedContext{Context: parent, waiting: make(chan struct{})}
	result := make(chan error, 1)
	go func() {
		_, err := s.exchange(ctx, func(index int) ([]byte, error) {
			if index != first.index {
				return nil, errors.New("wrong recovered member")
			}
			return []byte("ok"), nil
		})
		result <- err
	}()
	select {
	case <-ctx.waiting:
	case <-time.After(time.Second):
		t.Fatal("probe waiter did not wait")
	}
	s.complete(first, nil, time.Now())
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("successful probe did not wake waiters")
	}
}

func TestResolverHealthExchangeCancellationAndFailure(t *testing.T) {
	for _, kind := range []string{"cancel", "child-cancel", "deadline", "network", "late-cancel", "panic"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s := newResolverScheduler(context.Background(), 2, time.Second)
			func() {
				defer func() {
					if r := recover(); r != nil && kind != "panic" {
						panic(r)
					}
				}()
				_, _ = s.exchange(ctx, func(int) ([]byte, error) {
					switch kind {
					case "cancel":
						cancel()
						return nil, context.Canceled
					case "child-cancel":
						return nil, context.Canceled
					case "deadline":
						return nil, context.DeadlineExceeded
					case "network":
						return nil, net.ErrClosed
					case "late-cancel":
						cancel()
						return []byte("late"), nil
					case "panic":
						panic("test failure")
					}
					return nil, nil
				})
			}()
			want := kind != "cancel" && kind != "late-cancel" && kind != "panic"
			if s.members[0].unhealthy != want {
				t.Fatalf("unhealthy=%v, want%v", s.members[0].unhealthy, want)
			}
		})
	}
}

type resolverCompletedDeadlineContext struct {
	context.Context
	err error
}

func (c *resolverCompletedDeadlineContext) Err() error { return c.err }

func TestResolverHealthCompletedDerivedCancellationKeepsDeadlineFailure(t *testing.T) {
	ctx := &resolverCompletedDeadlineContext{Context: context.Background()}
	s := newResolverScheduler(context.Background(), 2, time.Second)
	_, err := s.exchange(ctx, func(int) ([]byte, error) {
		ctx.err = context.DeadlineExceeded
		return nil, context.Canceled // TLS observes its derived context, not ctx.
	})
	if !errors.Is(err, context.Canceled) || !s.members[0].unhealthy {
		t.Fatalf("completed deadline lost health failure or outward error: error=%v unhealthy=%v", err, s.members[0].unhealthy)
	}
}

func TestResolverHealthCooldownBounds(t *testing.T) {
	for _, tc := range []struct{ timeout, want time.Duration }{{0, time.Second}, {5 * time.Second, 10 * time.Second}, {60 * time.Second, 30 * time.Second}} {
		if got := newResolverScheduler(context.Background(), 2, tc.timeout).cooldown; got != tc.want {
			t.Fatalf("cooldown=%s,want%s", got, tc.want)
		}
	}
}

type resolverPreCallContext struct {
	context.Context
	calls      int
	beforeCall func() error
}

func (c *resolverPreCallContext) Err() error {
	c.calls++
	if c.calls >= 2 {
		return c.beforeCall()
	}
	return nil
}

func TestResolverHealthCancellationBeforeTransportDoesNotPoison(t *testing.T) {
	for _, generationClosed := range []bool{false, true} {
		base, closeSet := context.WithCancel(context.Background())
		s := newResolverScheduler(base, 2, time.Second)
		ctx := &resolverPreCallContext{Context: context.Background(), beforeCall: func() error {
			if generationClosed {
				closeSet()
				return nil
			}
			return context.DeadlineExceeded
		}}
		called := false
		_, err := s.exchange(ctx, func(int) ([]byte, error) { called = true; return nil, nil })
		want := error(context.DeadlineExceeded)
		if generationClosed {
			want = net.ErrClosed
		}
		if !errors.Is(err, want) || called || s.members[0].unhealthy {
			t.Fatalf("pre-call cancellation: error=%v called=%v unhealthy=%v", err, called, s.members[0].unhealthy)
		}
		closeSet()
	}
}

func TestResolverHealthSingleResolverKeepsExistingPath(t *testing.T) {
	for _, count := range []int{1, 2} {
		resolvers := []*Resolver{{Transport: "udp", Address: "127.0.0.1:53"}}
		if count == 2 {
			resolvers = append(resolvers, &Resolver{Transport: "udp", Address: "127.0.0.2:53"})
		}
		set, err := newResolverSet(context.Background(), &Config{Resolvers: resolvers, QueryTimeout: 5, MaxConcurrentQueries: 32}, &wireTestDialer{})
		if err != nil {
			t.Fatal(err)
		}
		if (set.scheduler != nil) != (count > 1) {
			t.Fatal("single-resolver transport path changed")
		}
		set.Close() // Construction is passive; no fake dialer socket is opened.
	}
}
