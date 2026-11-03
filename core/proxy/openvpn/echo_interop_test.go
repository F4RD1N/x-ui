package openvpn

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/openvpn/internal/icmpecho"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/interop"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

// interopDialer dials the harness from its client namespace.
type interopDialer struct{}

func (interopDialer) Dial(ctx context.Context, dest xnet.Destination) (stat.Connection, error) {
	return interop.Dial(ctx, dest.Network.SystemString(), dest.NetAddr())
}
func (interopDialer) Address() xnet.Address { return nil }
func (interopDialer) DestIpAddress() net.IP { return nil }

var _ internet.Dialer = interopDialer{}

// TestEchoInterop pings through a stock OpenVPN 2.6 server of the interop
// harness: its tunnel address in both families (the server's kernel
// answers), its LAN address (an address of the server host off the tunnel,
// still answered by the server's kernel), and a tunnel address nobody has
// (no reply). The harness does not route or NAT the tunnel anywhere else, so
// no host beyond the server can be reached. It needs the harness:
//
//	OVPN_INTEROP=1 ovpn-gorun go test -count=1 -run TestEchoInterop -v ./proxy/openvpn/
func TestEchoInterop(t *testing.T) {
	interop.Require(t)
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
			r := f.startWith(ctx, markerTo(srv), interopDialer{})

			// The first echo may be lost while the session comes up: resend
			// with a new sequence until one is answered.
			var seq uint16
			ping := func(dst netip.Addr) {
				t.Helper()
				v6 := dst.Is6()
				for try := 0; try < 10; try++ {
					seq++
					req := icmpecho.Echo{V6: v6, ID: 0x0bad, Seq: seq, Data: []byte("ping the OpenVPN server")}
					r.sendEcho(t, ptr(markerTo(dst)), req)
					mb, err := r.down.ReadMultiBufferTimeout(3 * time.Second)
					if err != nil || mb.IsEmpty() {
						continue
					}
					b := mb[0]
					rep, ok := icmpecho.ParseReply(b.Bytes())
					if !ok || b.UDP == nil || b.UDP.Port != 0 || b.UDP.Address.String() != xnet.IPAddress(dst.AsSlice()).String() {
						t.Fatalf("not the reply from %v: % x from %v", dst, b.Bytes(), b.UDP)
					}
					if rep.ID != req.ID || rep.Seq > seq || string(rep.Data) != string(req.Data) || rep.V6 != v6 {
						t.Fatalf("reply %+v to %+v", rep, req)
					}
					t.Logf("%s: %v answered sequence %d", name, dst, rep.Seq)
					return
				}
				t.Fatalf("%s: no echo reply from %v", name, dst)
			}
			ping(srv)
			if c.TunnelServerIPv6 != "" {
				ping(netip.MustParseAddr(c.TunnelServerIPv6))
			}
			ping(netip.MustParseAddr(interop.ServerIP))

			// Nobody has this tunnel address: no reply, nothing made up.
			r.sendEcho(t, ptr(markerTo(srv.Next().Next().Next().Next().Next())), icmpecho.Echo{ID: 1, Seq: 1})
			r.expectNoDatagram(t, 2*time.Second)
			_ = r.end(t)
		})
	}
}

// startWith is fixture.start with the dialer d.
func (f *fixture) startWith(ctx context.Context, dest xnet.Destination, d internet.Dialer) *request {
	ob := &session.Outbound{Target: dest, Tag: "vpn"}
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{ob})
	upR, upW := pipe.New(pipe.WithoutSizeLimit())
	downR, downW := pipe.New(pipe.WithoutSizeLimit())
	r := &request{up: upW, down: downR, ob: ob, errc: make(chan error, 1)}
	h := f.h
	go func() {
		r.errc <- h.Process(ctx, &transport.Link{Reader: upR, Writer: downW}, d)
	}()
	return r
}
