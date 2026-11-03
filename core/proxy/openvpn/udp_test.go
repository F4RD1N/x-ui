package openvpn

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
)

// datagram is one reply on a UDP link and the address it was labelled with.
type datagram struct {
	payload string
	from    *xnet.Destination
}

func (d datagram) String() string {
	from := "<nil>"
	if d.from != nil {
		from = d.from.String()
	}
	return fmt.Sprintf("%q from %s", d.payload, from)
}

// sendTo writes one datagram addressed to dest (b.UDP; nil leaves it unset),
// as the SOCKS inbound and the UDP dispatcher do.
func (r *request) sendTo(t *testing.T, dest *xnet.Destination, payload string) {
	t.Helper()
	b := buf.New()
	b.WriteString(payload)
	if dest != nil {
		d := *dest
		b.UDP = &d
	}
	if err := r.up.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		t.Fatalf("send: %v", err)
	}
}

// datagrams reads n replies (failing after waitLong).
func (r *request) datagrams(t *testing.T, n int) []datagram {
	t.Helper()
	deadline := time.Now().Add(waitLong)
	var out []datagram
	for len(out) < n {
		left := time.Until(deadline)
		if left <= 0 {
			t.Fatalf("received %d of %d datagrams: %v", len(out), n, out)
		}
		mb, err := r.down.ReadMultiBufferTimeout(left)
		if err != nil {
			t.Fatalf("received %d of %d datagrams: %v (%v)", len(out), n, out, err)
		}
		for _, b := range mb {
			d := datagram{payload: string(b.Bytes())}
			if b.UDP != nil {
				from := *b.UDP
				d.from = &from
			}
			out = append(out, d)
		}
		buf.ReleaseMulti(mb)
	}
	return out
}

// expectReplies reads len(want) replies and compares them, in any order,
// with want (each "payload from address").
func (r *request) expectReplies(t *testing.T, want ...string) {
	t.Helper()
	got := r.datagrams(t, len(want))
	var gs []string
	for _, d := range got {
		gs = append(gs, d.String())
	}
	ws := append([]string(nil), want...)
	sort.Strings(gs)
	sort.Strings(ws)
	if strings.Join(gs, "|") != strings.Join(ws, "|") {
		t.Fatalf("replies %v, want %v", gs, ws)
	}
}

// serverUDP opens a UDP socket on the fake server's side of session i.
func (f *fixture) serverUDP(t *testing.T, i int, a netip.Addr, port uint16) *gonet.UDPConn {
	t.Helper()
	pn := tcpip.NetworkProtocolNumber(ipv4.ProtocolNumber)
	if a.Is6() {
		pn = ipv6.ProtocolNumber
	}
	c, err := gonet.DialUDP(f.session(i).srv.stack, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(a.AsSlice()), Port: port}, nil, pn)
	if err != nil {
		t.Fatalf("server UDP %v port %d: %v", a, port, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// serveUDP answers every datagram on c with reply(payload) from c.
func serveUDP(c *gonet.UDPConn, reply func(string) string) {
	go func() {
		b := make([]byte, 2048)
		for {
			n, from, err := c.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = c.WriteTo([]byte(reply(string(b[:n]))), from)
		}
	}()
}

func ptr(d xnet.Destination) *xnet.Destination { return &d }

func udpString(a netip.Addr, port uint16) string { return udpDest(a, port).String() }

// One UDP link carries datagrams for several destinations (a SOCKS UDP
// association: one link, a destination per datagram in b.UDP): each one
// arrives where it was addressed, over either family, and each reply says
// where it came from.
func TestUDPPerDatagramDestination(t *testing.T) {
	f := newFixture(t, nil)
	r := f.start(context.Background(), udpDest(srvV4, echoUDPPort))
	r.sendTo(t, ptr(udpDest(srvV4, echoUDPPort)), "to-9")
	r.expectReplies(t, `"to-9" from `+udpString(srvV4, echoUDPPort))

	serveUDP(f.serverUDP(t, 0, srvV4, 11), func(p string) string { return "port-11 got " + p })
	serveUDP(f.serverUDP(t, 0, srvV6, echoUDPPort), func(p string) string { return "v6 got " + p })

	r.sendTo(t, ptr(udpDest(srvV4, 11)), "to-11")
	r.expectReplies(t, `"port-11 got to-11" from `+udpString(srvV4, 11))
	r.sendTo(t, ptr(udpDest(srvV6, echoUDPPort)), "to-v6")
	r.expectReplies(t, `"v6 got to-v6" from `+udpString(srvV6, echoUDPPort))
	// Unset b.UDP means the link's own destination.
	r.sendTo(t, nil, "plain")
	r.expectReplies(t, `"plain" from `+udpString(srvV4, echoUDPPort))
	r.sendTo(t, ptr(udpDest(srvV4, 11)), "again")
	r.expectReplies(t, `"port-11 got again" from `+udpString(srvV4, 11))
	// A closed port answers with an ICMP port unreachable; the datagram is
	// not delivered elsewhere and the link goes on.
	r.sendTo(t, ptr(udpDest(srvV4, 10)), "to a closed port")
	time.Sleep(50 * time.Millisecond)
	r.sendTo(t, ptr(udpDest(srvV4, echoUDPPort)), "after the closed port")
	r.expectReplies(t, `"after the closed port" from `+udpString(srvV4, echoUDPPort))
	_ = r.end(t)
	if n := f.dials(); n != 1 {
		t.Fatalf("%d sessions dialled, want 1", n)
	}
}

// A reply from another port of the server (STUN, games) reaches the link
// with its own source address.
func TestUDPReplyFromAnotherPort(t *testing.T) {
	f := newFixture(t, nil)
	warm := f.start(context.Background(), udpDest(srvV4, echoUDPPort))
	warm.echo(t, []byte("warm"))

	a := f.serverUDP(t, 0, srvV4, 12)
	b := f.serverUDP(t, 0, srvV4, 13)
	go func() {
		p := make([]byte, 2048)
		n, from, err := a.ReadFrom(p)
		if err != nil {
			return
		}
		_, _ = a.WriteTo(append([]byte("A:"), p[:n]...), from)
		_, _ = b.WriteTo(append([]byte("B:"), p[:n]...), from)
	}()
	r := f.start(context.Background(), udpDest(srvV4, 12))
	r.sendTo(t, ptr(udpDest(srvV4, 12)), "hi")
	r.expectReplies(t, `"A:hi" from `+udpString(srvV4, 12), `"B:hi" from `+udpString(srvV4, 13))
	_, _ = r.end(t), warm.end(t)
}

// A domain in b.UDP is resolved (once per link) into a family the tunnel
// has, and replies from it are labelled with the name it was sent to, so
// that Xray maps them back (a sniffed destination override, a SOCKS client
// that sent to a name). A datagram for a family the tunnel lacks is dropped
// and the link goes on.
func TestUDPDomainsAndMissingFamily(t *testing.T) {
	f := newFixture(t, nil)
	f.info.IPv6 = netip.Prefix{}
	byName := xnet.UDPDestination(xnet.DomainAddress("echo.test"), echoUDPPort)

	r := f.start(context.Background(), udpDest(srvV4, echoUDPPort))
	r.sendTo(t, nil, "first")
	r.expectReplies(t, `"first" from `+udpString(srvV4, echoUDPPort))
	f.dns.mu.Lock()
	lookups := len(f.dns.calls)
	f.dns.mu.Unlock()
	for i := 0; i < 3; i++ {
		r.sendTo(t, &byName, fmt.Sprint("by name ", i))
		r.expectReplies(t, fmt.Sprintf(`"by name %d" from %s`, i, byName))
	}
	f.dns.mu.Lock()
	lookups = len(f.dns.calls) - lookups
	f.dns.mu.Unlock()
	if lookups != 1 {
		t.Errorf("%d DNS lookups for one name on one link, want 1", lookups)
	}
	r.sendTo(t, ptr(udpDest(srvV6, echoUDPPort)), "no ipv6 in this tunnel")
	r.sendTo(t, ptr(xnet.UDPDestination(xnet.DomainAddress("none.test"), echoUDPPort)), "unresolvable")
	r.sendTo(t, ptr(udpDest(srvV4, echoUDPPort)), "still up")
	r.expectReplies(t, `"still up" from `+udpString(srvV4, echoUDPPort))
	_ = r.end(t)

	// A link whose own destination is a name (a sniffed override).
	rn := f.start(context.Background(), byName)
	rn.sendTo(t, nil, "named link")
	rn.expectReplies(t, `"named link" from `+byName.String())
	_ = rn.end(t)
}
