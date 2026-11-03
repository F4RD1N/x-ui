package orbit

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	xerrors "github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/nativebridge"
	"github.com/xtls/xray-core/proxy/orbit/internal/datagram"
	"github.com/xtls/xray-core/proxy/orbit/internal/protocol"
	"github.com/xtls/xray-core/proxy/orbit/internal/transport"
	"github.com/xtls/xray-core/proxy/orbit/internal/tunneldns"
	xtransport "github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

// UDP follows VPN-Core's SOCKS UDP ASSOCIATE and TUN adapters: one Xray UDP
// flow is one association of the session's UDP hub, with its own virtual
// source port; each packet keeps its own destination; a domain destination
// is resolved through the tunnel's DNS (an A query in a DNS-kind envelope);
// the server relays IPv4 only. Packets that cannot be carried (IPv6, too
// large for the current QUIC path, a name that does not resolve) are dropped
// one by one, as VPN-Core drops them, instead of ending the flow.

func parseResolver(raw string) (netip.AddrPort, error) {
	r, err := netip.ParseAddrPort(raw)
	if err != nil || !r.Addr().Is4() || r.Port() == 0 {
		return netip.AddrPort{}, fieldError("resolver", "must be a numeric IPv4 host:port")
	}
	return r, nil
}

func (c *Client) processUDP(ctx context.Context, link *xtransport.Link, dialer internet.Dialer, target xnet.Destination) error {
	kind := protocol.UDPKindData
	if target.Port == 53 {
		// The TUN adapter marks DNS to the resolver as the DNS kind.
		kind = protocol.UDPKindDNS
	}
	var g *generation
	var assoc *datagram.Association
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		if g, err = c.session(ctx, dialer); err != nil {
			return err
		}
		if assoc, err = g.udp.Open(netip.AddrPort{}, kind); err == nil {
			break
		}
		if g.alive() {
			return err
		}
	}
	if err != nil {
		return err
	}
	resolver, _ := parseResolver(c.resolver)
	flow := &udpFlow{ctx: ctx, assoc: assoc, names: make(map[string]netip.Addr),
		resolver: &tunneldns.Resolver{UDP: g.udp, OpenTCP: g.peer.Open, Server: resolver}}
	defer assoc.Close()
	return nativebridge.Relay(ctx, link, flow, flow, target, c.policy.ForLevel(0))
}

type udpFlow struct {
	ctx      context.Context
	assoc    *datagram.Association
	resolver *tunneldns.Resolver
	mu       sync.Mutex
	names    map[string]netip.Addr
}

func (f *udpFlow) destination(d xnet.Destination) (netip.Addr, bool) {
	if d.Address.Family().IsIP() {
		ip, ok := netip.AddrFromSlice(d.Address.IP())
		ip = ip.Unmap()
		return ip, ok && ip.Is4()
	}
	name := d.Address.Domain()
	f.mu.Lock()
	ip, ok := f.names[name]
	f.mu.Unlock()
	if ok {
		return ip, true
	}
	ips, err := f.resolver.LookupIP(f.ctx, name)
	if err != nil || len(ips) == 0 {
		return netip.Addr{}, false
	}
	f.mu.Lock()
	if len(f.names) < 64 {
		f.names[name] = ips[0]
	}
	f.mu.Unlock()
	return ips[0], true
}

func (f *udpFlow) WritePacket(p []byte, d xnet.Destination) error {
	ip, ok := f.destination(d)
	if !ok || d.Port == 0 {
		xerrors.LogDebug(f.ctx, "orbit: dropped a UDP packet the tunnel cannot carry (IPv6 or unresolved destination)")
		return nil
	}
	err := f.assoc.Send(f.ctx, netip.AddrPortFrom(ip, d.Port.Value()), p)
	var tooLarge *transport.UDPTooLargeError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &tooLarge), errors.Is(err, protocol.ErrMalformed), errors.Is(err, protocol.ErrUnsupported):
		xerrors.LogDebug(f.ctx, "orbit: dropped a UDP packet: ", err)
		return nil
	}
	return err
}

func (f *udpFlow) ReadPacket() ([]byte, xnet.Destination, error) {
	u, err := f.assoc.Receive(f.ctx)
	if err != nil {
		return nil, xnet.Destination{}, err
	}
	return u.Data, xnet.UDPDestination(xnet.IPAddress(u.Source.Addr().AsSlice()), xnet.Port(u.Source.Port())), nil
}

// The flow is the net.Conn Relay closes when either direction ends.
func (f *udpFlow) Read([]byte) (int, error)         { return 0, io.EOF }
func (f *udpFlow) Write(p []byte) (int, error)      { return 0, errors.New("orbit: UDP flow takes packets") }
func (f *udpFlow) Close() error                     { return f.assoc.Close() }
func (f *udpFlow) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (f *udpFlow) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (f *udpFlow) SetDeadline(time.Time) error      { return nil }
func (f *udpFlow) SetReadDeadline(time.Time) error  { return nil }
func (f *udpFlow) SetWriteDeadline(time.Time) error { return nil }
