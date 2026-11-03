package openvpn

import (
	"context"
	"io"
	"net"
	"sync"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// socketDialer dials real loopback sockets and hands them out through wrap,
// as Xray's dialer wraps them (stats counters, the rate limiter). It keeps
// the bare socket of each dial and how often anything asked for its file
// descriptor.
type socketDialer struct {
	wrap func(net.Conn) stat.Connection

	mu      sync.Mutex
	sockets []syscall.Conn
	fdAsked int
}

func (d *socketDialer) Dial(_ context.Context, dest xnet.Destination) (stat.Connection, error) {
	c, err := net.Dial(dest.Network.SystemString(), dest.NetAddr())
	if err != nil {
		return nil, err
	}
	s := &countingSocket{Conn: c, d: d}
	d.mu.Lock()
	d.sockets = append(d.sockets, c.(syscall.Conn))
	d.mu.Unlock()
	return d.wrap(s), nil
}

func (*socketDialer) Address() xnet.Address { return nil }
func (*socketDialer) DestIpAddress() net.IP { return nil }

var _ internet.Dialer = (*socketDialer)(nil)

// countingSocket is a socket that counts the requests for its descriptor.
type countingSocket struct {
	net.Conn
	d *socketDialer
}

func (c *countingSocket) SyscallConn() (syscall.RawConn, error) {
	c.d.mu.Lock()
	c.d.fdAsked++
	c.d.mu.Unlock()
	return c.Conn.(syscall.Conn).SyscallConn()
}

func sockoptInt(t *testing.T, s syscall.Conn, level, opt int) int {
	t.Helper()
	rc, err := s.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v int
	var serr error
	if err := rc.Control(func(fd uintptr) { v, serr = unix.GetsockoptInt(int(fd), level, opt) }); err != nil {
		t.Fatal(err)
	}
	if serr != nil {
		t.Fatalf("getsockopt: %v", serr)
	}
	return v
}

// The OpenVPN transport's TCP socket gets TCP_NOTSENT_LOWAT, also through
// the wrappers Xray's dialer puts around it, so that its unsent backlog --
// one queue for every connection in the tunnel -- stays short. A UDP
// transport is left alone, and a transport that is no socket (a chain
// through another outbound) is dialled as before.
func TestTransportNotSentLowat(t *testing.T) {
	h, err := newHandler(&Config{Ovpn: testOVPN}, policy.DefaultManager{}, &fakeDNS{})
	if err != nil {
		t.Fatal(err)
	}
	tl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tl.Close()
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, c); _ = c.Close() }()
		}
	}()
	ul, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ul.Close()

	for _, tc := range []struct {
		name string
		wrap func(net.Conn) stat.Connection
	}{
		{"socket", func(c net.Conn) stat.Connection { return c }},
		{"stats", func(c net.Conn) stat.Connection { return &stat.CounterConnection{Connection: c} }},
		{"nested stats wrappers", func(c net.Conn) stat.Connection {
			return &stat.CounterConnection{Connection: &stat.CounterConnection{Connection: c}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &socketDialer{wrap: tc.wrap}
			dial := h.dialFunc(context.Background(), d)

			c, err := dial(context.Background(), "tcp", tl.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if got := sockoptInt(t, d.sockets[0], unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT); got != 128<<10 {
				t.Fatalf("TCP_NOTSENT_LOWAT %d, want %d", got, 128<<10)
			}
			if _, err := c.Write([]byte("still a working connection")); err != nil {
				t.Fatal(err)
			}

			d.fdAsked = 0
			u, err := dial(context.Background(), "udp", ul.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer u.Close()
			if d.fdAsked != 0 {
				t.Fatal("the UDP transport's socket was touched")
			}
		})
	}

	// A transport that is no socket.
	fd := &fakeDialer{}
	c, err := h.dialFunc(context.Background(), fd)(context.Background(), "tcp", "192.0.2.1:443")
	if err != nil {
		t.Fatalf("a transport that is no socket: %v", err)
	}
	_ = c.Close()
}
