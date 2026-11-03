package openvpn

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"github.com/xtls/xray-core/app/dispatcher"
	policyapp "github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	proxyoutbound "github.com/xtls/xray-core/app/proxyman/outbound"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/proxy/socks"
)

// chain is an Xray instance as the apps run it -- a SOCKS inbound at user
// level 8 with sniffing, the apps' level-8 timeouts (connIdle 300,
// uplinkOnly 1, downlinkOnly 1), the OpenVPN outbound -- on the fixture's
// fake sessions.
type chain struct {
	v    *core.Instance
	port int
	vpn  *Handler
}

func newChain(t *testing.T, f *fixture) *chain {
	t.Helper()
	return newChainBuffer(t, f, nil)
}

// newChainBuffer is newChain with the level's buffer policy (the size of
// each connection's pipe; nil for the system's default: 512 KiB on 386 and
// amd64, 4 KiB on arm64, none on armv7).
func newChainBuffer(t *testing.T, f *fixture, buffer *policyapp.Policy_Buffer) *chain {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	sec := func(v uint32) *policyapp.Second { return &policyapp.Second{Value: v} }
	v, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&policyapp.Config{Level: map[uint32]*policyapp.Policy{
				8: {Timeout: &policyapp.Policy_Timeout{Handshake: sec(4), ConnectionIdle: sec(300), UplinkOnly: sec(1), DownlinkOnly: sec(1)}, Buffer: buffer},
			}}),
		},
		Inbound: []*core.InboundHandlerConfig{{
			Tag: "socks",
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortList:         &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(xnet.Port(port))}},
				Listen:           xnet.NewIPOrDomain(xnet.LocalHostIP),
				SniffingSettings: &proxyman.SniffingConfig{Enabled: true, DestinationOverride: []string{"http", "tls"}},
			}),
			ProxySettings: serial.ToTypedMessage(&socks.ServerConfig{AuthType: socks.AuthType_NO_AUTH, UdpEnabled: true, UserLevel: 8}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{
			Tag:           "proxy",
			ProxySettings: serial.ToTypedMessage(&Config{Ovpn: testOVPN}),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Close() })
	oh := v.GetFeature(outbound.ManagerType()).(outbound.Manager).GetHandler("proxy").(*proxyoutbound.Handler)
	return &chain{v: v, port: port, vpn: oh.GetOutbound().(*Handler)}
}

// connect opens a SOCKS5 CONNECT to a:port through the chain.
func (c *chain) connect(t *testing.T, a netip.Addr, port uint16) *net.TCPConn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", c.port), waitLong)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(waitLong))
	req := []byte{5, 1, 0, 5, 1, 0, 1}
	req = append(req, a.AsSlice()...)
	req = binary.BigEndian.AppendUint16(req, port)
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 12)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("SOCKS handshake: %v", err)
	}
	if resp[0] != 5 || resp[1] != 0 || resp[3] != 0 {
		t.Fatalf("SOCKS handshake: % x", resp)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn.(*net.TCPConn)
}

// readToEOF reads conn until EOF, failing after d.
func readToEOF(t *testing.T, conn net.Conn, d time.Duration) []byte {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(d))
	b, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read: %v after %q", err, b)
	}
	return b
}

// chainFixture brings a chain's session up and serves the half-close
// servers on it. It returns the client stack's endpoint count at rest.
func chainFixture(t *testing.T, delay time.Duration) (*chain, *hcServers, int) {
	t.Helper()
	f := newFixture(t, nil)
	c := newChain(t, f)
	// The session comes up without a connection, so that none is left in
	// TIME-WAIT before the short timeouts below apply.
	tun, err := c.vpn.getTunnel(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range []tcpip.SettableTransportProtocolOption{
		ptrTo(tcpip.TCPTimeWaitTimeoutOption(50 * time.Millisecond)),
		ptrTo(tcpip.TCPLingerTimeoutOption(50 * time.Millisecond)),
	} {
		if err := tun.stack.SetTransportProtocolOption(tcp.ProtocolNumber, o); err != nil {
			t.Fatal(err)
		}
	}
	s := f.serveHalfClose(t, 0, srvV4, delay)
	warm := c.connect(t, srvV4, echoTCPPort)
	if _, err := warm.Write([]byte("warm up")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 7)
	_ = warm.SetReadDeadline(time.Now().Add(waitLong))
	if _, err := io.ReadFull(warm, b); err != nil || string(b) != "warm up" {
		t.Fatalf("warm up: %q %v", b, err)
	}
	_ = warm.Close()
	expectReleased(t, tun.stack, 0)
	return c, s, 0
}

func ptrTo[T any](v T) *T { return &v }

// Through the SOCKS inbound as the apps configure it: the client
// half-closes, and the reply the destination sends 3 s after the FIN -- past
// the inbound's DownlinkOnly of 1 s -- still reaches the client, followed by
// EOF.
func TestChainHalfCloseClientFirst(t *testing.T) {
	for _, delay := range []time.Duration{300 * time.Millisecond, 3 * time.Second} {
		t.Run(fmt.Sprint("reply after ", delay), func(t *testing.T) {
			c, s, base := chainFixture(t, delay)
			conn := c.connect(t, srvV4, hcSinkPort)
			if _, err := conn.Write(bytes.Repeat([]byte("x"), 1000)); err != nil {
				t.Fatal(err)
			}
			if err := conn.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if n := recvCount(t, s.sinkGot, "sink"); n != 1000 {
				t.Fatalf("the destination got %d bytes, want 1000", n)
			}
			if got := readToEOF(t, conn, delay+waitLong); string(got) != "got 1000 bytes then your FIN" {
				t.Fatalf("reply %q", got)
			}
			expectReleased(t, c.tunStack(), base)
		})
	}
}

// Through the SOCKS inbound: after the destination's FIN the client still
// gets everything and its later data still reaches the destination. The
// SOCKS inbound does not pass the FIN on (it has no half-close towards its
// client): the client sees the end only when the inbound closes, after
// UplinkOnly without data from the client, or once the client ends its side.
func TestChainHalfCloseServerFirst(t *testing.T) {
	c, s, base := chainFixture(t, 0)
	conn := c.connect(t, srvV4, hcGreeterPort)
	greeting := make([]byte, len("hello, I am done talking"))
	_ = conn.SetReadDeadline(time.Now().Add(waitLong))
	if _, err := io.ReadFull(conn, greeting); err != nil || string(greeting) != "hello, I am done talking" {
		t.Fatalf("greeting %q %v", greeting, err)
	}
	sent := 0
	for i := 0; i < 12; i++ { // 2.4 s of data, past UplinkOnly
		n, err := conn.Write(pattern(10 << 10))
		if err != nil {
			t.Fatalf("write %d after the destination's FIN: %v", i, err)
		}
		sent += n
		time.Sleep(200 * time.Millisecond)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if n := recvCount(t, s.greeterGot, "greeter"); n != sent {
		t.Fatalf("the destination got %d bytes after its FIN, want %d", n, sent)
	}
	if rest := readToEOF(t, conn, waitLong); len(rest) != 0 {
		t.Fatalf("extra data %q", rest)
	}
	expectReleased(t, c.tunStack(), base)

	// An idle client: the end comes with the inbound's UplinkOnly.
	conn = c.connect(t, srvV4, hcGreeterPort)
	start := time.Now()
	got := readToEOF(t, conn, waitLong)
	t.Logf("idle client: %q, then EOF %v after the destination's FIN", got, time.Since(start).Round(10*time.Millisecond))
	recvCount(t, s.greeterGot, "greeter")
	expectReleased(t, c.tunStack(), base)
}

func (c *chain) tunStack() *stack.Stack {
	c.vpn.mu.Lock()
	defer c.vpn.mu.Unlock()
	return c.vpn.tun.stack
}

// Through the SOCKS inbound: the client uploads more than the tunnel's stack
// takes at once and half-closes while the destination is slow to read.
// The inbound sets its timer to DownlinkOnly (1 s) once it has put the last
// of the upload into the pipe, but the pipe drains into the stack only as
// the destination reads: the inbound's timer must not end the connection
// while the upload is still moving. The destination gets the whole upload
// and its FIN, and the client the reply.
//
// The upload sizes lie just above what the fixture's stack and the
// destination's buffers hold (about 1.5 MiB): the rest waits in the pipe and
// in a stack write blocked until the destination reads, 3 s later. A
// destination that reads at once but slowly (256 KiB/s) keeps the drain
// moving for longer than DownlinkOnly without any write blocking that long.
func TestChainHalfCloseClientFirstBackedUp(t *testing.T) {
	type tc struct {
		name   string
		size   int
		pause  time.Duration
		rate   int // bytes per second the destination reads; 0: as fast as it can
		buffer *policyapp.Policy_Buffer
	}
	var cases []tc
	for _, b := range []struct {
		name   string
		buffer *policyapp.Policy_Buffer
	}{{"default pipe", nil}, {"4 KiB pipe", &policyapp.Policy_Buffer{Connection: 4096}}, {"no pipe", &policyapp.Policy_Buffer{Connection: 0}}} {
		for _, kib := range []int{1536, 1568, 1600} {
			cases = append(cases, tc{fmt.Sprintf("%s/%d KiB", b.name, kib), kib << 10, 3 * time.Second, 0, b.buffer})
		}
	}
	cases = append(cases, tc{"default pipe/2048 KiB read at 256 KiB per s", 2048 << 10, 0, 256 << 10, nil})

	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, nil)
			ch := newChainBuffer(t, f, c.buffer)
			if _, err := ch.vpn.getTunnel(context.Background(), nil); err != nil {
				t.Fatal(err)
			}
			port := uint16(18200 + i)
			l, err := gonet.ListenTCP(f.session(0).srv.stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(srvV4.AsSlice()), Port: port}, ipv4.ProtocolNumber)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = l.Close() })
			got := make(chan string, 1)
			go func() {
				conn, err := l.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				time.Sleep(c.pause)
				b := make([]byte, 16<<10)
				n := 0
				for {
					k, err := conn.Read(b)
					n += k
					if err == io.EOF {
						break
					}
					if err != nil {
						got <- fmt.Sprintf("read error after %d bytes: %v", n, err)
						return
					}
					if c.rate > 0 {
						time.Sleep(time.Duration(k) * time.Second / time.Duration(c.rate))
					}
				}
				got <- fmt.Sprintf("%d bytes then a FIN", n)
				_, _ = fmt.Fprintf(conn, "got %d bytes then your FIN", n)
			}()

			conn := ch.connect(t, srvV4, port)
			if _, err := conn.Write(pattern(c.size)); err != nil {
				t.Fatal(err)
			}
			if err := conn.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			fin := time.Now()
			reply := readToEOF(t, conn, 30*time.Second)
			var dest string
			select {
			case dest = <-got:
			case <-time.After(waitLong):
				dest = "no end"
			}
			if want := fmt.Sprintf("%d bytes then a FIN", c.size); dest != want {
				t.Errorf("the destination got %s, want %s", dest, want)
			}
			if want := fmt.Sprintf("got %d bytes then your FIN", c.size); string(reply) != want {
				t.Fatalf("reply %q %v after the FIN, want %q", reply, time.Since(fin).Round(time.Millisecond), want)
			}
		})
	}
}
