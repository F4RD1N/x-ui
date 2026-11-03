package anytls

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// blockedDialer stands in for a chained or custom dialer: Dial returns only
// when its ctx ends, or with conn once release is closed.
type blockedDialer struct {
	entered chan context.Context
	release chan struct{}
	conn    net.Conn
	dials   atomic.Int32
	once    sync.Once
}

func (d *blockedDialer) unblock() { d.once.Do(func() { close(d.release) }) }

func newBlockedDialer(conn net.Conn) *blockedDialer {
	return &blockedDialer{entered: make(chan context.Context, 1), release: make(chan struct{}), conn: conn}
}

func (*blockedDialer) Address() xnet.Address  { return xnet.LocalHostIP }
func (*blockedDialer) DestIpAddress() xnet.IP { return nil }
func (d *blockedDialer) Dial(ctx context.Context, _ xnet.Destination) (stat.Connection, error) {
	d.dials.Add(1)
	d.entered <- ctx
	if d.conn != nil {
		<-d.release // ignores ctx, as a dialer might
		return d.conn, nil
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-d.release:
		return nil, errors.New("test cleanup")
	}
}

func cancelTestClient(timeout uint32) *Client {
	pad, _ := parsePadding(defaultPadding)
	return &Client{config: &Config{Address: "127.0.0.1", Port: 1, Password: "p", HandshakeTimeout: timeout}, padding: pad, done: make(chan struct{})}
}

func takeAsync(c *Client, ctx context.Context, d *blockedDialer) chan error {
	result := make(chan error, 1)
	go func() {
		s, e := c.take(ctx, d)
		if s != nil {
			s.fail(net.ErrClosed)
		}
		result <- e
	}()
	return result
}

func waitTake(t *testing.T, result chan error, d *blockedDialer, within time.Duration) error {
	t.Helper()
	select {
	case e := <-result:
		return e
	case <-time.After(within):
		d.unblock()
		<-result
		t.Fatal("carrier setup still pending")
		return nil
	}
}

// A pending carrier dial ends with the request, with Client.Close and with
// the setup timeout; it never outlives all three (A05-01).
func TestPendingDialEnds(t *testing.T) {
	t.Run("request canceled", func(t *testing.T) {
		c := cancelTestClient(10)
		defer c.Close()
		d := newBlockedDialer(nil)
		ctx, cancel := context.WithCancel(context.Background())
		result := takeAsync(c, ctx, d)
		dialCtx := <-d.entered
		cancel()
		if e := waitTake(t, result, d, 2*time.Second); !errors.Is(e, context.Canceled) {
			t.Fatalf("take: %v, want context.Canceled", e)
		}
		if dialCtx.Err() == nil {
			t.Fatal("dial ctx still live after the request ended")
		}
	})
	t.Run("client closed", func(t *testing.T) {
		c := cancelTestClient(10)
		d := newBlockedDialer(nil)
		result := takeAsync(c, context.Background(), d)
		<-d.entered
		c.Close()
		if e := waitTake(t, result, d, 2*time.Second); e == nil {
			t.Fatal("take succeeded on a closed client")
		}
	})
	t.Run("setup timeout", func(t *testing.T) {
		c := cancelTestClient(1)
		defer c.Close()
		d := newBlockedDialer(nil)
		result := takeAsync(c, context.Background(), d)
		<-d.entered
		if e := waitTake(t, result, d, 3*time.Second); e == nil || !strings.Contains(e.Error(), "timed out") {
			t.Fatalf("take: %v, want a dial timeout", e)
		}
	})
	t.Run("already canceled", func(t *testing.T) {
		c := cancelTestClient(10)
		defer c.Close()
		d := newBlockedDialer(nil)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if e := waitTake(t, takeAsync(c, ctx, d), d, 2*time.Second); !errors.Is(e, context.Canceled) {
			t.Fatalf("take: %v, want context.Canceled", e)
		}
		if n := d.dials.Load(); n != 0 {
			t.Fatalf("%d dials for a canceled request", n)
		}
	})
	t.Run("late dial result closed", func(t *testing.T) {
		local, remote := net.Pipe()
		defer remote.Close()
		c := cancelTestClient(10)
		defer c.Close()
		d := newBlockedDialer(local)
		ctx, cancel := context.WithCancel(context.Background())
		result := takeAsync(c, ctx, d)
		<-d.entered
		cancel()
		d.unblock()
		if e := <-result; e == nil {
			t.Fatal("take succeeded after the request ended")
		}
		_ = remote.SetReadDeadline(time.Now().Add(time.Second))
		if _, e := remote.Read(make([]byte, 1)); !errors.Is(e, io.EOF) {
			t.Fatalf("carrier dialed for a canceled request left open: %v", e)
		}
	})
	t.Run("client closed during handshake", func(t *testing.T) {
		local, remote := net.Pipe() // the peer never answers the ClientHello
		defer remote.Close()
		go io.Copy(io.Discard, remote)
		c := cancelTestClient(10)
		d := newBlockedDialer(local)
		d.unblock()
		result := takeAsync(c, context.Background(), d)
		<-d.entered
		time.Sleep(50 * time.Millisecond)
		c.Close()
		if e := waitTake(t, result, d, 2*time.Second); e == nil {
			t.Fatal("take succeeded on a closed client")
		}
	})
}

func pipeSession(conn net.Conn) *muxSession {
	pad, _ := parsePadding("stop=0")
	return &muxSession{conn: conn, pad: pad, streams: make(map[uint32]*stream), done: make(chan struct{}), heartbeat: make(chan struct{}, 1)}
}

func openAsync(s *muxSession, ctx context.Context) chan error {
	result := make(chan error, 1)
	go func() {
		_, e := s.open(ctx, []byte{1, 127, 0, 0, 1, 0, 80})
		result <- e
	}()
	return result
}

// Opening a stream on a carrier that stopped reading ends with the request:
// on the first stream and on a reused session, by cancellation or deadline,
// and the half-open stream is dropped with the failed session (A05-02).
func TestOpenEndsWithRequest(t *testing.T) {
	for _, reuse := range []bool{false, true} {
		for _, byDeadline := range []bool{false, true} {
			name := "first"
			if reuse {
				name = "reused"
			}
			if byDeadline {
				name += "/deadline"
			} else {
				name += "/cancel"
			}
			t.Run(name, func(t *testing.T) {
				local, remote := net.Pipe()
				defer remote.Close()
				defer local.Close()
				s := pipeSession(local)
				if reuse {
					reading := make(chan struct{})
					go func() {
						defer close(reading)
						buf := make([]byte, 4096)
						for {
							if _, e := remote.Read(buf); e != nil {
								return
							}
						}
					}()
					st, e := s.open(context.Background(), []byte{1, 127, 0, 0, 1, 0, 80})
					if e != nil {
						t.Fatal(e)
					}
					s.drop(st.id)
					remote.SetReadDeadline(time.Now()) // the peer stops reading
					<-reading
					remote.SetReadDeadline(time.Time{})
				}
				ctx, cancel := context.WithCancel(context.Background())
				if byDeadline {
					ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
				}
				defer cancel()
				result := openAsync(s, ctx)
				if !byDeadline {
					time.Sleep(30 * time.Millisecond)
					cancel()
				}
				select {
				case e := <-result:
					if e == nil {
						t.Fatal("open succeeded on a stalled carrier")
					}
				case <-time.After(2 * time.Second):
					local.Close()
					<-result
					t.Fatal("open still blocked after the request ended")
				}
				if s.failure() == nil {
					t.Fatal("session with a half-written open left in use")
				}
				s.mu.Lock()
				n := len(s.streams)
				s.mu.Unlock()
				if n != 0 {
					t.Fatalf("%d streams left on the failed session", n)
				}
			})
		}
	}
}

// A stream that opened keeps no setup deadline and outlives its request ctx.
func TestOpenedStreamKeepsNoSetupDeadline(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	defer local.Close()
	go io.Copy(io.Discard, remote)
	s := pipeSession(local)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	st, e := s.open(ctx, []byte{1, 127, 0, 0, 1, 0, 80})
	if e != nil {
		t.Fatal(e)
	}
	<-ctx.Done()
	cancel()
	time.Sleep(20 * time.Millisecond)
	if _, e := st.Write([]byte("after the request deadline")); e != nil {
		t.Fatalf("write after the open's deadline: %v", e)
	}
	if e := s.failure(); e != nil {
		t.Fatalf("session failed after a successful open: %v", e)
	}
}
