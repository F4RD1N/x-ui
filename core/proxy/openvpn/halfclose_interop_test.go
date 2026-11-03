package openvpn

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/interop"
)

// listenInHarness listens on TCP in the harness's server namespace, where
// a client of a case reaches it at the case's server tunnel address.
func listenInHarness(t *testing.T) *net.TCPListener {
	t.Helper()
	var l net.Listener
	if err := interop.InNamespace(interop.Namespace, func() error {
		var err error
		l, err = net.Listen("tcp4", "0.0.0.0:0")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l.(*net.TCPListener)
}

func serveTCP(l *net.TCPListener, serve func(c *net.TCPConn)) {
	go func() {
		for {
			c, err := l.AcceptTCP()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(time.Minute))
				serve(c)
			}()
		}
	}()
}

// TestTCPHalfCloseInterop half-closes TCP connections through stock OpenVPN
// 2.6 servers of the interop harness, to peers in the server's namespace
// (Linux TCP): the client's FIN reaches the peer, whose answer 3 s later
// comes back; the peer's FIN reaches the client, whose data after a pause
// past UplinkOnly still reaches the peer. It needs the harness:
//
//	OVPN_INTEROP=1 ovpn-gorun go test -count=1 -run TestTCPHalfCloseInterop -v ./proxy/openvpn/
func TestTCPHalfCloseInterop(t *testing.T) {
	interop.Require(t)
	sinkGot, greeterGot := make(chan int, 8), make(chan int, 8)
	sink := listenInHarness(t)
	serveTCP(sink, func(c *net.TCPConn) {
		n, err := io.Copy(io.Discard, c)
		if err != nil {
			sinkGot <- -1
			return
		}
		sinkGot <- int(n)
		time.Sleep(3 * time.Second)
		_, _ = fmt.Fprintf(c, "got %d bytes then your FIN", n)
	})
	greeter := listenInHarness(t)
	serveTCP(greeter, func(c *net.TCPConn) {
		if _, err := c.Write([]byte("hello, I am done talking")); err != nil {
			return
		}
		if err := c.CloseWrite(); err != nil {
			return
		}
		n, err := io.Copy(io.Discard, c)
		if err != nil {
			greeterGot <- -1
			return
		}
		greeterGot <- int(n)
	})
	port := func(l *net.TCPListener) uint16 { return uint16(l.Addr().(*net.TCPAddr).Port) }

	for _, name := range []string{"udp-gcm-tlscrypt", "tcp-gcm-tlsauth"} {
		t.Run(name, func(t *testing.T) {
			c, ok := interop.Lookup(name)
			if !ok {
				t.Fatalf("no case %s", name)
			}
			text, err := c.ReadOVPN()
			if err != nil {
				t.Fatal(err)
			}
			h, err := newHandler(&Config{Ovpn: text, Username: c.Username, Password: c.Password}, policy.DefaultManager{}, &fakeDNS{})
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			f := &fixture{t: t, h: h, dialer: &fakeDialer{}}
			srv := netip.MustParseAddr(c.TunnelServerIP)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			// The session first, with short TIME-WAIT and FIN-WAIT-2
			// timeouts, so that every endpoint is gone by the end.
			tun, err := h.getTunnel(ctx, interopDialer{})
			if err != nil {
				t.Fatal(err)
			}
			st := tun.stack
			for _, o := range []tcpip.SettableTransportProtocolOption{
				ptrTo(tcpip.TCPTimeWaitTimeoutOption(50 * time.Millisecond)),
				ptrTo(tcpip.TCPLingerTimeoutOption(50 * time.Millisecond)),
			} {
				if err := st.SetTransportProtocolOption(tcp.ProtocolNumber, o); err != nil {
					t.Fatal(err)
				}
			}

			// The client ends its side; the answer comes 3 s later.
			r := f.startWith(ctx, tcpDest(srv, port(sink)), interopDialer{})
			r.send(t, bytes.Repeat([]byte("x"), 1000))
			r.closeUp(t)
			if n := recvCount(t, sinkGot, "sink"); n != 1000 {
				t.Fatalf("the peer got %d bytes before the FIN, want 1000", n)
			}
			start := time.Now()
			if got := r.recvToEOF(t, waitLong); string(got) != "got 1000 bytes then your FIN" {
				t.Fatalf("reply %q", got)
			}
			t.Logf("%s: reply %v after the peer saw the client's FIN", name, time.Since(start).Round(10*time.Millisecond))
			if err := r.wait(t, waitLong); err != nil {
				t.Fatalf("Process: %v", err)
			}

			// The peer ends its side; the client goes on after a pause.
			r = f.startWith(ctx, tcpDest(srv, port(greeter)), interopDialer{})
			if got := r.recvToEOF(t, waitLong); string(got) != "hello, I am done talking" {
				t.Fatalf("greeting %q", got)
			}
			time.Sleep(2500 * time.Millisecond)
			r.running(t)
			payload := pattern(300 << 10)
			r.send(t, payload)
			r.closeUp(t)
			if n := recvCount(t, greeterGot, "greeter"); n != len(payload) {
				t.Fatalf("the peer got %d bytes after its FIN, want %d", n, len(payload))
			}
			if err := r.wait(t, waitLong); err != nil {
				t.Fatalf("Process: %v", err)
			}
			expectReleased(t, st, 0)
		})
	}
}
