package dnstt

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtaci/smux"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	"www.bamsoftware.com/git/dnstt.git/noise"
)

func localGeneration(t *testing.T) *generation {
	t.Helper()
	a, b := net.Pipe()
	cfg := smux.DefaultConfig()
	cfg.Version, cfg.KeepAliveDisabled = 2, true
	client, err := smux.Client(a, cfg)
	if err != nil {
		t.Fatal(err)
	}
	server, err := smux.Server(b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	g := &generation{ctx: ctx, cancel: cancel, mux: client}
	t.Cleanup(func() { g.close(); server.Close() })
	return g
}

func TestOneGenerationForConcurrentWaitersAndPrivateContext(t *testing.T) {
	c := newClient(normalizedTestConfig(t))
	defer c.Close()
	g := localGeneration(t)
	ready, release := make(chan struct{}), make(chan struct{})
	var dials atomic.Int32
	in := &session.Inbound{Tag: "request", CanSpliceCopy: 1}
	c.dial = func(ctx context.Context, _ *Config, _ internet.Dialer) (*generation, error) {
		dials.Add(1)
		if got := session.InboundFromContext(ctx); got == in || got == nil || got.Tag != "request" || got.CanSpliceCopy != 3 {
			return nil, errors.New("shared mutable inbound context")
		}
		close(ready)
		<-release
		return g, nil
	}
	ctx := session.ContextWithInbound(context.Background(), in)
	var wait sync.WaitGroup
	errCh := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			got, err := c.generation(ctx, nil)
			if err != nil {
				errCh <- err
			} else if got != g {
				errCh <- errors.New("different generation")
			}
		}()
	}
	<-ready
	close(release)
	wait.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("%d physical generation dials, want 1", got)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.generation(ctx, nil); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("dial after Close: %v", err)
	}
}

func TestCancelledWaiterDoesNotCancelSharedGeneration(t *testing.T) {
	c := newClient(normalizedTestConfig(t))
	defer c.Close()
	g := localGeneration(t)
	ready, release := make(chan struct{}), make(chan struct{})
	c.dial = func(ctx context.Context, _ *Config, _ internet.Dialer) (*generation, error) {
		close(ready)
		select {
		case <-release:
			return g, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { _, err := c.generation(ctx, nil); first <- err }()
	<-ready
	cancel()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled request: %v", err)
	}
	second := make(chan error, 1)
	go func() {
		got, err := c.generation(context.Background(), nil)
		if got != g && err == nil {
			err = errors.New("wrong generation")
		}
		second <- err
	}()
	close(release)
	if err := <-second; err != nil {
		t.Fatal(err)
	}
}

func TestResetRejectsLateGenerationFromPreviousNetwork(t *testing.T) {
	c := newClient(normalizedTestConfig(t))
	defer c.Close()
	old, fresh := localGeneration(t), localGeneration(t)
	ready, release := make(chan struct{}), make(chan struct{})
	var dials atomic.Int32
	c.dial = func(context.Context, *Config, internet.Dialer) (*generation, error) {
		if dials.Add(1) == 1 {
			close(ready)
			<-release // Deliberately ignore cancellation, like a delayed dial completion.
			return old, nil
		}
		return fresh, nil
	}
	first := make(chan error, 1)
	go func() { _, err := c.generation(context.Background(), nil); first <- err }()
	<-ready
	c.networkChanged()
	got, err := c.generation(context.Background(), nil)
	if err != nil || got != fresh {
		t.Fatalf("fresh network generation: %v", err)
	}
	close(release)
	if err := <-first; err == nil {
		t.Fatal("stale dial was published after reset")
	}
	if old.alive() {
		t.Fatal("stale generation was not closed")
	}
	if got, err = c.generation(context.Background(), nil); err != nil || got != fresh {
		t.Fatalf("late old dial displaced the new generation: %v", err)
	}
}

func TestCloseCancelsAndJoinsPendingDial(t *testing.T) {
	c := newClient(normalizedTestConfig(t))
	ready := make(chan struct{})
	c.dial = func(ctx context.Context, _ *Config, _ internet.Dialer) (*generation, error) {
		close(ready)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	waiter := make(chan error, 1)
	go func() { _, err := c.generation(context.Background(), nil); waiter <- err }()
	<-ready
	done := make(chan struct{})
	go func() { c.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not join pending dial")
	}
	if err := <-waiter; err == nil {
		t.Fatal("closed client's pending dial succeeded")
	}
}

func TestGenerationCloseReleasesUnreadUpstreamNoisePipe(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_ = a.SetDeadline(time.Now().Add(3 * time.Second))
	_ = b.SetDeadline(time.Now().Add(3 * time.Second))
	priv, err := noise.GeneratePrivkey()
	if err != nil {
		t.Fatal(err)
	}
	written := make(chan error, 1)
	go func() {
		rw, err := noise.NewServer(b, priv)
		if err == nil {
			_, err = rw.Write(make([]byte, 4096))
		}
		written <- err
	}()
	rw, err := noise.NewClient(a, noise.PubkeyFromPrivkey(priv))
	if err != nil {
		t.Fatal(err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	// No plaintext has been read: upstream's decrypt worker is blocked on
	// io.Pipe.Write. Close must drain it after closing its underlying socket.
	ctx, cancel := context.WithCancel(context.Background())
	g := &generation{ctx: ctx, cancel: cancel, noise: rw}
	done := make(chan struct{})
	go func() { g.close(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Noise decrypt worker stayed blocked on its plaintext pipe")
	}
	if _, err := rw.Read(make([]byte, 1)); err == nil {
		t.Fatal("Noise receiver did not finish")
	}
}

func TestSOCKSUDPRejectedBeforeDial(t *testing.T) {
	cfg := normalizedTestConfig(t)
	cfg.Inner = &Inner{Protocol: "socks", Username: "test-user", Password: "test-password"}
	c := newClient(cfg)
	defer c.Close()
	c.dial = func(context.Context, *Config, internet.Dialer) (*generation, error) {
		t.Error("UDP request dialed SOCKS tunnel")
		return nil, io.EOF
	}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: xnet.UDPDestination(xnet.LocalHostIP, 53)}})
	if err := c.Process(ctx, nil, nil); err == nil {
		t.Fatal("SOCKS UDP request accepted")
	}
}

func TestAlreadyCancelledFlowStartsNoGenerationOrStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := newClient(normalizedTestConfig(t))
	defer c.Close()
	c.dial = func(context.Context, *Config, internet.Dialer) (*generation, error) {
		t.Error("cancelled flow started a physical generation")
		return nil, io.EOF
	}
	if got, err := c.generation(ctx, nil); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled generation request: %v", err)
	}
	g := localGeneration(t)
	if conn, err := g.open(ctx); conn != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled stream open: %v", err)
	}
	if g.mux.NumStreams() != 0 {
		t.Fatal("cancelled flow opened a stream")
	}
}
