package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/options"
)

// freezeRelay is a TCP relay that can stop moving bytes in both directions
// while keeping both connections open: a server that stopped reading (zero
// window) or a black-holed path.
type freezeRelay struct {
	ln     net.Listener
	frozen atomic.Bool
	quit   chan struct{}
	wg     sync.WaitGroup
	mu     sync.Mutex
	conns  []net.Conn
}

func startFreezeRelay(t testing.TB, port int) *freezeRelay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &freezeRelay{ln: ln, quit: make(chan struct{})}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			b, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
			if err != nil {
				c.Close()
				continue
			}
			r.mu.Lock()
			r.conns = append(r.conns, c, b)
			r.mu.Unlock()
			r.wg.Add(2)
			go r.pipe(c, b)
			go r.pipe(b, c)
		}
	}()
	t.Cleanup(func() {
		close(r.quit)
		ln.Close()
		r.mu.Lock()
		for _, c := range r.conns {
			c.Close()
		}
		r.mu.Unlock()
		r.wg.Wait()
	})
	return r
}

func (r *freezeRelay) pipe(src, dst net.Conn) {
	defer r.wg.Done()
	buf := make([]byte, 4096)
	for {
		n, err := src.Read(buf)
		if err != nil {
			return
		}
		if r.frozen.Load() {
			<-r.quit
			return
		}
		if _, err := dst.Write(buf[:n]); err != nil {
			return
		}
	}
}

func (r *freezeRelay) port() int { return r.ln.Addr().(*net.TCPAddr).Port }

// stallConn is a transport whose writes block, once stalled, until it is
// closed: a TCP peer whose receive window stays shut.
type stallConn struct {
	net.Conn
	stalled atomic.Bool
	closed  chan struct{}
	once    sync.Once
	blocked atomic.Int32
}

func newStallConn(c net.Conn) *stallConn { return &stallConn{Conn: c, closed: make(chan struct{})} }

func (s *stallConn) Write(b []byte) (int, error) {
	if s.stalled.Load() {
		s.blocked.Add(1)
		defer s.blocked.Add(-1)
		<-s.closed
		return 0, net.ErrClosed
	}
	return s.Conn.Write(b)
}

func (s *stallConn) Close() error {
	s.once.Do(func() { close(s.closed) })
	return s.Conn.Close()
}

func goroutinesWith(sub string) string {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	var out []string
	for _, g := range strings.Split(string(buf[:n]), "\n\n") {
		if strings.Contains(g, sub) {
			out = append(out, g)
		}
	}
	return strings.Join(out, "\n\n")
}

// TestTCPStalledPeerPingRestart: once a TCP server stops taking bytes, a
// transport write blocks; ping-restart must still end the session (and
// release the blocked writers), with and without upload traffic.
func TestTCPStalledPeerPingRestart(t *testing.T) {
	const ping, pingRestart = 200 * time.Millisecond, time.Second
	for _, kind := range []string{"relay", "stall-conn"} {
		for _, uplink := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/uplink=%v", kind, uplink), func(t *testing.T) {
				srv := startServer(t, srvConfig{tcp: true, cipher: "AES-256-GCM"})
				port := srv.port
				var relay *freezeRelay
				if kind == "relay" {
					relay = startFreezeRelay(t, srv.port)
					port = relay.port()
				}
				var sc atomic.Pointer[stallConn]
				o := parseOpts(t, ovpnText(t, fmt.Sprintf("remote 127.0.0.1 %d tcp\npull-filter ignore \"ping\"\n", port)))
				o.Ping, o.PingRestart = ping, pingRestart
				cfg := Config{Options: o, Logger: newTestLogger(t), HandshakeTimeout: 10 * time.Second,
					Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
						c, err := netDial(ctx, network, address)
						if err != nil {
							return nil, err
						}
						s := newStallConn(c)
						sc.Store(s)
						return s, nil
					}}
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				c, err := Dial(ctx, cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				echo(t, c, packetReader(c), 3, 200)

				if relay != nil {
					relay.frozen.Store(true)
				} else {
					sc.Load().stalled.Store(true)
				}
				start := time.Now()
				var writes atomic.Int64
				var lastReturn atomic.Int64 // ns since start
				upDone := make(chan struct{})
				if uplink {
					go func() {
						defer close(upDone)
						p := testPacket(1, 1400)
						for {
							err := c.WritePacket(p)
							lastReturn.Store(int64(time.Since(start)))
							if err != nil && c.Err() != nil {
								return
							}
							writes.Add(1)
						}
					}()
				} else {
					close(upDone)
				}
				select {
				case <-c.Done():
				case <-time.After(pingRestart + 3*time.Second):
					t.Logf("session goroutines:\n%s", goroutinesWith("ovpn/client.(*Client)"))
					t.Fatalf("ping-restart %v did not end the session within %v of the stall (%d packets written)", pingRestart, time.Since(start).Round(time.Millisecond), writes.Load())
				}
				ended := time.Since(start)
				t.Logf("session ended %v after the stall: %v (%d packets written)", ended.Round(time.Millisecond), c.Err(), writes.Load())
				if !errors.Is(c.Err(), ErrPingTimeout) {
					t.Errorf("Err = %v, want ErrPingTimeout", c.Err())
				}
				if ended > pingRestart+time.Second {
					t.Errorf("session ended %v after the stall, want within ping-restart %v + 1s", ended, pingRestart)
				}
				select {
				case <-upDone:
					if d := time.Duration(lastReturn.Load()) - ended; uplink && d > time.Second {
						t.Errorf("the uploader's WritePacket returned %v after the session ended", d)
					}
				case <-time.After(2 * time.Second):
					t.Fatalf("the uploader is still blocked 2s after the session ended:\n%s", goroutinesWith("WritePacket"))
				}
				closeStart := time.Now()
				c.Close()
				if d := time.Since(closeStart); d > time.Second {
					t.Errorf("Close took %v", d)
				}
			})
		}
	}
}

// TestDefaultPingRestart: when neither the profile nor the server sets
// ping-restart, the client-mode default ends a session whose server went
// away; an explicit "ping-restart 0" disables it; a pushed one wins; and
// OCC probes keep an idle tunnel to a live server up.
func TestDefaultPingRestart(t *testing.T) {
	const def = time.Second
	hooks := func(c *Config) { c.hooks = &testHooks{defaultPingRestart: def} }
	t.Run("silent-server", func(t *testing.T) {
		srv := startServer(t, srvConfig{cipher: "AES-256-GCM"})
		c := mustDial(t, srv, sessionOpts{ovpn: "pull-filter ignore \"ping\"\n", cfg: hooks})
		srv.silent.Store(true)
		start := time.Now()
		select {
		case <-c.Done():
		case <-time.After(def + 3*time.Second):
			t.Fatalf("no ping-restart %v after the server went silent (none configured or pushed)", time.Since(start).Round(time.Millisecond))
		}
		if !errors.Is(c.Err(), ErrPingTimeout) {
			t.Fatalf("Err = %v, want ErrPingTimeout", c.Err())
		}
		if d := time.Since(start); d > def+time.Second {
			t.Errorf("ended %v after the server went silent, want about %v", d, def)
		}
	})
	t.Run("idle-live-server-probed", func(t *testing.T) {
		srv := startServer(t, srvConfig{cipher: "AES-256-GCM"})
		c := mustDial(t, srv, sessionOpts{ovpn: "pull-filter ignore \"ping\"\n", cfg: hooks})
		time.Sleep(3 * def)
		if err := c.Err(); err != nil {
			t.Fatalf("an idle session to a live server ended: %v", err)
		}
		if st := srv.snapshot(); st.occRequests == 0 {
			t.Errorf("no OCC request probed the idle server")
		}
		echo(t, c, packetReader(c), 2, 100)
	})
	t.Run("explicit-zero", func(t *testing.T) {
		srv := startServer(t, srvConfig{cipher: "AES-256-GCM"})
		c := mustDial(t, srv, sessionOpts{ovpn: "pull-filter ignore \"ping\"\nping-restart 0\n", cfg: hooks})
		srv.silent.Store(true)
		time.Sleep(2 * def)
		if err := c.Err(); err != nil {
			t.Fatalf("ping-restart 0 in the profile, but the session ended: %v", err)
		}
		if st := srv.snapshot(); st.occRequests != 0 {
			t.Errorf("%d OCC probes with ping-restart 0", st.occRequests)
		}
	})
	t.Run("pushed-wins", func(t *testing.T) {
		srv := startServer(t, srvConfig{cipher: "AES-256-GCM"}) // pushes ping 10, ping-restart 60
		c := mustDial(t, srv, sessionOpts{cfg: hooks})
		srv.silent.Store(true)
		time.Sleep(2 * def)
		if err := c.Err(); err != nil {
			t.Fatalf("the pushed ping-restart 60 should apply, but the session ended: %v", err)
		}
	})
	t.Run("configured-wins", func(t *testing.T) {
		srv := startServer(t, srvConfig{cipher: "AES-256-GCM"})
		c := mustDial(t, srv, sessionOpts{ovpn: "pull-filter ignore \"ping\"\nping-restart 30\n", cfg: hooks})
		srv.silent.Store(true)
		time.Sleep(2 * def)
		if err := c.Err(); err != nil {
			t.Fatalf("the configured ping-restart 30 should apply, but the session ended: %v", err)
		}
	})
}

// errConn fails the next fail writes with err.
type errConn struct {
	net.Conn
	fail atomic.Int32
	err  error
}

func (e *errConn) Write(b []byte) (int, error) {
	if e.fail.Load() > 0 {
		e.fail.Add(-1)
		return 0, &net.OpError{Op: "write", Net: "udp", Err: os.NewSyscallError("sendto", e.err)}
	}
	return e.Conn.Write(b)
}

// TestUDPWriteErrorsNotFatal: a UDP send that fails (EPERM from a firewall
// rule during a network change) loses that datagram only; over TCP a write
// error still ends the session.
func TestUDPWriteErrorsNotFatal(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		t.Run(fmt.Sprintf("tcp=%v", tcp), func(t *testing.T) {
			srv := startServer(t, srvConfig{tcp: tcp, cipher: "AES-256-GCM"})
			var ec atomic.Pointer[errConn]
			c := mustDial(t, srv, sessionOpts{cfg: func(cfg *Config) {
				cfg.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
					conn, err := netDial(ctx, network, address)
					if err != nil {
						return nil, err
					}
					e := &errConn{Conn: conn, err: syscall.EPERM}
					ec.Store(e)
					return e, nil
				}
			}})
			in := packetReader(c)
			echo(t, c, in, 2, 100)
			ec.Load().fail.Store(5)
			for i := 0; i < 5; i++ {
				err := c.WritePacket(testPacket(uint32(i), 100))
				if !errors.Is(err, syscall.EPERM) {
					t.Fatalf("write %d: err = %v, want EPERM", i, err)
				}
				if tcp {
					break
				}
			}
			if tcp {
				select {
				case <-c.Done():
				case <-time.After(2 * time.Second):
					t.Fatal("a TCP write error did not end the session")
				}
				return
			}
			time.Sleep(50 * time.Millisecond)
			if err := c.Err(); err != nil {
				t.Fatalf("UDP send errors ended the session: %v", err)
			}
			echo(t, c, in, 3, 100)
		})
	}
}

// TestSuspendedClock: monotonic time stops while an Android device sleeps;
// the liveness timers must count that time (here: a wall clock pushed ten
// minutes ahead without monotonic time moving).
func TestSuspendedClock(t *testing.T) {
	setup := func(t *testing.T) (*fakeServer, *Client, *atomic.Int64) {
		var skew atomic.Int64
		srv := startServer(t, srvConfig{cipher: "AES-256-GCM"})
		c := mustDial(t, srv, sessionOpts{
			ovpn: "pull-filter ignore \"ping\"\n",
			opts: func(o *options.Options) { o.Ping, o.PingRestart = 10*time.Second, 60*time.Second },
			cfg: func(c *Config) {
				c.hooks = &testHooks{maxSleep: 200 * time.Millisecond, wallSkew: func() time.Duration { return time.Duration(skew.Load()) }}
			},
		})
		return srv, c, &skew
	}
	t.Run("ping-after-wakeup", func(t *testing.T) {
		srv, c, skew := setup(t)
		time.Sleep(100 * time.Millisecond)
		before := srv.snapshot().pings
		skew.Store(int64(10 * time.Minute))
		srv.sendDataPing() // the server's packet wakes the device
		start := time.Now()
		waitFor(t, "a ping after the wake-up", 2*time.Second, func() bool { return srv.snapshot().pings > before })
		if d := time.Since(start); d > 150*time.Millisecond {
			t.Errorf("the overdue ping went out %v after the first packet", d)
		}
		if err := c.Err(); err != nil {
			t.Fatalf("session ended: %v", err)
		}
	})
	t.Run("ping-restart-after-wakeup", func(t *testing.T) {
		srv, c, skew := setup(t)
		srv.silent.Store(true)
		skew.Store(int64(10 * time.Minute))
		start := time.Now()
		select {
		case <-c.Done():
		case <-time.After(3 * time.Second):
			t.Fatal("ping-restart 60s did not fire after ten minutes asleep")
		}
		if !errors.Is(c.Err(), ErrPingTimeout) {
			t.Fatalf("Err = %v, want ErrPingTimeout", c.Err())
		}
		if d := time.Since(start); d > time.Second {
			t.Errorf("ping-restart fired %v after the wake-up", d)
		}
	})
}
