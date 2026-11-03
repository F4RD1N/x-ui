package transport

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

// TestQUICFlowLimitFailsOnlyTheExtraOpen: the server grants MaxFlows streams
// per session (plus the UDP-control stream). An open beyond that fails at
// once with ErrFlowLimit, as the TCP session's does, instead of blocking in
// OpenStreamSync; the open flows keep working, and a closed flow frees its
// place.
func TestQUICFlowLimitFailsOnlyTheExtraOpen(t *testing.T) {
	serverTLS, clientTLS := testTLS(t)
	const maxFlows = 8
	srv := listenTestQUIC(t, serverTLS, QUICServerOptions{MaxFlows: maxFlows}, nil)
	q := dialTestQUIC(t, srv, clientTLS)
	q.serverOptions = QUICServerOptions{MaxFlows: maxFlows}
	var flows []*QUICStream
	for i := 0; i < maxFlows; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		st, err := q.Open(ctx, "127.0.0.1", 80)
		cancel()
		if err != nil {
			t.Fatalf("flow %d: %v", i, err)
		}
		if err = echoOnce(st, fmt.Sprint("hello-", i)); err != nil {
			t.Fatalf("flow %d echo: %v", i, err)
		}
		flows = append(flows, st)
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	_, err := q.Open(ctx, "127.0.0.1", 80)
	cancel()
	if !errors.Is(err, ErrFlowLimit) || time.Since(start) > time.Second {
		t.Fatalf("open over the limit: %v after %v, want ErrFlowLimit at once", err, time.Since(start))
	}
	for i, st := range flows {
		if err := echoOnce(st, fmt.Sprint("again-", i)); err != nil {
			t.Fatalf("flow %d died after the extra open: %v", i, err)
		}
	}
	select {
	case <-q.Done():
		t.Fatal("the session ended")
	default:
	}
	// Closing one flow frees its place (the server returns the stream credit
	// once both sides are done with the stream).
	flows[0].Close()
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	st, err := q.Open(ctx, "127.0.0.1", 80)
	cancel()
	if err != nil {
		t.Fatal("open after a flow closed:", err)
	}
	if err = echoOnce(st, "freed"); err != nil {
		t.Fatal(err)
	}
	if n := q.logical.flows.Load(); n != maxFlows {
		t.Fatalf("%d flows counted, want %d", n, maxFlows)
	}
	// A failed open gives its place back.
	st.Close()
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	if _, err = q.Open(ctx, "127.0.0.1", 80); err == nil {
		t.Fatal("a canceled open succeeded")
	}
	if n := q.logical.flows.Load(); n != maxFlows-1 {
		t.Fatalf("%d flows counted after a failed open, want %d", n, maxFlows-1)
	}
}

// TestQUICProbe: a live session acknowledges the probe; a session whose
// path went silent does not, within the probe's deadline.
func TestQUICProbe(t *testing.T) {
	serverTLS, clientTLS := testTLS(t)
	var silent atomic.Bool
	srv := listenTestQUIC(t, serverTLS, QUICServerOptions{}, silent.Load)
	q := dialTestQUIC(t, srv, clientTLS)
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := q.Probe(ctx)
		cancel()
		if err != nil {
			t.Fatalf("probe %d on a live session: %v", i, err)
		}
	}
	silent.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	err := q.Probe(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("probe over a silent path: %v, want a timeout", err)
	}
	select {
	case <-q.Done():
		t.Fatal("a probe timeout closed the session by itself")
	default:
	}
}
