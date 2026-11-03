package openvpn

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/proxy/openvpn/internal/icmpecho"
	xnet "github.com/xtls/xray-core/common/net"
)

func markerTo(a netip.Addr) xnet.Destination {
	return xnet.UDPDestination(xnet.IPAddress(a.AsSlice()), 0)
}

// sendEcho writes one echo request to dest (nil: the link's own destination).
func (r *request) sendEcho(t *testing.T, dest *xnet.Destination, e icmpecho.Echo) {
	t.Helper()
	b := buf.New()
	b.Write(e.Marshal())
	if dest != nil {
		d := *dest
		b.UDP = &d
	}
	if err := r.up.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		t.Fatalf("send: %v", err)
	}
}

// expectEcho reads the next datagram and checks it is the reply to req from
// from:0.
func (r *request) expectEcho(t *testing.T, from xnet.Address, req icmpecho.Echo) {
	t.Helper()
	d := r.datagrams(t, 1)[0]
	rep, ok := icmpecho.ParseReply([]byte(d.payload))
	if !ok {
		t.Fatalf("not an echo reply: %v", d)
	}
	if d.from == nil || d.from.Port != 0 || d.from.Address.String() != from.String() {
		t.Fatalf("reply labelled %v, want %v:0", d.from, from)
	}
	if rep.V6 != req.V6 || rep.ID != req.ID || rep.Seq != req.Seq || !bytes.Equal(rep.Data, req.Data) {
		t.Fatalf("reply %+v, want the request's %+v", rep, req)
	}
}

func (r *request) expectNoDatagram(t *testing.T, d time.Duration) {
	t.Helper()
	if mb, err := r.down.ReadMultiBufferTimeout(d); err == nil && !mb.IsEmpty() {
		t.Fatalf("unexpected datagram %q from %v", mb[0].Bytes(), mb[0].UDP)
	}
}

// The far end of the session is a gVisor stack: it answers the echoes the
// tunnel's netstack sends, in both families.
func TestEchoThroughTunnel(t *testing.T) {
	f := newFixture(t, nil)
	r := f.start(context.Background(), markerTo(srvV4))
	req := icmpecho.Echo{ID: 0x4321, Seq: 1, Data: []byte("ping through OpenVPN")}
	r.sendEcho(t, nil, req)
	r.expectEcho(t, xnet.IPAddress(srvV4.AsSlice()), req)

	req6 := icmpecho.Echo{V6: true, ID: 0x4321, Seq: 2, Data: bytes.Repeat([]byte("6"), 1200)}
	r.sendEcho(t, ptr(markerTo(srvV6)), req6)
	r.expectEcho(t, xnet.IPAddress(srvV6.AsSlice()), req6)

	// Two identifiers with the same sequence on one link.
	a, b := icmpecho.Echo{ID: 1, Seq: 5, Data: []byte("a")}, icmpecho.Echo{ID: 2, Seq: 5, Data: []byte("b")}
	r.sendEcho(t, nil, a)
	r.sendEcho(t, nil, b)
	r.expectReplies(t, fmt.Sprintf("%q from udp:10.9.0.1:0", icmpecho.Echo{Reply: true, ID: 1, Seq: 5, Data: []byte("a")}.Marshal()),
		fmt.Sprintf("%q from udp:10.9.0.1:0", icmpecho.Echo{Reply: true, ID: 2, Seq: 5, Data: []byte("b")}.Marshal()))

	// A host that does not answer: nothing comes back.
	r.sendEcho(t, ptr(markerTo(netip.MustParseAddr("10.9.0.77"))), icmpecho.Echo{ID: 3, Seq: 1})
	// The wrong family, and junk to port 0.
	r.sendEcho(t, ptr(markerTo(srvV4)), icmpecho.Echo{V6: true, ID: 3, Seq: 2})
	r.sendTo(t, ptr(markerTo(srvV4)), "not icmp")
	r.expectNoDatagram(t, 300*time.Millisecond)
	_ = r.end(t)
}

func TestEchoByName(t *testing.T) {
	f := newFixture(t, nil)
	name := xnet.UDPDestination(xnet.DomainAddress("echo.test"), 0)
	r := f.start(context.Background(), name)
	req := icmpecho.Echo{ID: 7, Seq: 1, Data: []byte("v4 by name")}
	r.sendEcho(t, nil, req)
	r.expectEcho(t, xnet.DomainAddress("echo.test"), req)
	req6 := icmpecho.Echo{V6: true, ID: 7, Seq: 2, Data: []byte("v6 by name")}
	r.sendEcho(t, nil, req6)
	r.expectEcho(t, xnet.DomainAddress("echo.test"), req6)
	_ = r.end(t)
}

// A tunnel without IPv6 drops IPv6 echoes; IPv4 still works.
func TestEchoMissingFamily(t *testing.T) {
	f := newFixture(t, nil)
	f.info.IPv6 = netip.Prefix{}
	r := f.start(context.Background(), markerTo(srvV6))
	r.sendEcho(t, nil, icmpecho.Echo{V6: true, ID: 1, Seq: 1})
	r.sendEcho(t, ptr(xnet.UDPDestination(xnet.DomainAddress("echo.test"), 0)), icmpecho.Echo{V6: true, ID: 1, Seq: 2})
	r.expectNoDatagram(t, 300*time.Millisecond)
	req := icmpecho.Echo{ID: 1, Seq: 3}
	r.sendEcho(t, ptr(markerTo(srvV4)), req)
	r.expectEcho(t, xnet.IPAddress(srvV4.AsSlice()), req)
	_ = r.end(t)
}

// A ping on a UDP link to a real destination (a SOCKS association that
// carries both) is executed, and the UDP keeps working.
func TestEchoOnUDPLink(t *testing.T) {
	f := newFixture(t, nil)
	r := f.start(context.Background(), udpDest(srvV4, echoUDPPort))
	r.sendTo(t, nil, "udp first")
	r.expectReplies(t, `"udp first" from udp:10.9.0.1:9`)
	req := icmpecho.Echo{ID: 9, Seq: 9, Data: []byte("ping")}
	r.sendEcho(t, ptr(markerTo(srvV4)), req)
	r.expectEcho(t, xnet.IPAddress(srvV4.AsSlice()), req)
	r.sendTo(t, nil, "udp again")
	r.expectReplies(t, `"udp again" from udp:10.9.0.1:9`)
	_ = r.end(t)
}
