package openvpn

import (
	"context"
	goerrors "errors"
	"io"
	"net"
	"net/netip"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal"
)

// maxLinkNames bounds the domains one UDP link remembers.
const maxLinkNames = 256

// udpLink carries one UDP link through the tunnel. Xray puts datagrams for
// several destinations on one link (a SOCKS UDP association; the UDP
// dispatcher keeps one link per association): each datagram goes where its
// b.UDP says, or to the link's own destination when that is unset, from an
// unconnected socket per address family the tunnel has, and every reply
// carries the address it came from in b.UDP -- the name it was sent to when
// it was sent to a name, so that Xray maps a sniffed destination back.
type udpLink struct {
	ctx    context.Context
	h      *Handler
	t      *tunnel
	target xnet.Destination  // the link's destination as Xray named it
	to     netip.AddrPort    // where target resolved to
	conns  [2]*gonet.UDPConn // IPv4, IPv6; nil for a family the tunnel lacks

	resolved map[string]netip.Addr // domains this link sent to (uplink only)
	named    bool                  // names was ever written (uplink only)

	// out is the link's reply side, shared by the sockets' replies and the
	// link's pings.
	out *lockedWriter

	mu    sync.Mutex
	names map[netip.AddrPort]xnet.Destination // address -> the name last used for it
}

// newUDPLink opens the link's sockets. to is target resolved (invalid when
// target is port 0: a link of pings, which never reach the sockets); the
// replies go into w.
func newUDPLink(ctx context.Context, h *Handler, t *tunnel, target xnet.Destination, to netip.AddrPort, w buf.Writer) (*udpLink, error) {
	u := &udpLink{
		ctx:      ctx,
		h:        h,
		t:        t,
		target:   target,
		to:       to,
		resolved: map[string]netip.Addr{},
		names:    map[netip.AddrPort]xnet.Destination{},
		out:      &lockedWriter{w: w, mu: &sync.Mutex{}},
	}
	for i, has := range []bool{t.hasIPv4, t.hasIPv6} {
		if !has {
			continue
		}
		pn := tcpip.NetworkProtocolNumber(ipv4.ProtocolNumber)
		if i == 1 {
			pn = ipv6.ProtocolNumber
		}
		// Bound to an ephemeral port on any address, not connected.
		c, err := gonet.DialUDP(t.stack, &tcpip.FullAddress{}, nil, pn)
		if err != nil {
			u.close()
			return nil, errors.New("failed to open UDP inside the OpenVPN tunnel").Base(err)
		}
		u.conns[i] = c
	}
	if target.Address.Family().IsDomain() && to.IsValid() {
		u.resolved[target.Address.Domain()] = to.Addr()
		u.note(to, target)
	}
	return u, nil
}

func (u *udpLink) close() {
	for _, c := range u.conns {
		if c != nil {
			_ = c.Close()
		}
	}
}

func (u *udpLink) conn(a netip.Addr) *gonet.UDPConn {
	if a.Is4() {
		return u.conns[0]
	}
	return u.conns[1]
}

// WriteMultiBuffer sends each buffer as one datagram to its own destination.
// A datagram that cannot be sent (a name that does not resolve, a family the
// tunnel lacks) is dropped and the link goes on; the link fails only when
// the tunnel is gone.
func (u *udpLink) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	for _, b := range mb {
		to, err := u.destination(b.UDP)
		if err != nil {
			errors.LogDebugInner(u.ctx, err, "dropping a UDP datagram")
			continue
		}
		c := u.conn(to.Addr())
		if c == nil {
			continue // destination checked the family
		}
		if _, err := c.WriteTo(b.Bytes(), net.UDPAddrFromAddrPort(to)); err != nil {
			if !u.t.alive() {
				return errors.New("the OpenVPN tunnel is down").Base(err)
			}
			errors.LogDebugInner(u.ctx, err, "dropping a UDP datagram to ", to)
		}
	}
	return nil
}

// destination is where a datagram addressed to d goes (nil: the link's own
// destination).
func (u *udpLink) destination(d *xnet.Destination) (netip.AddrPort, error) {
	if d == nil || (d.Address == u.target.Address && d.Port == u.target.Port) {
		u.note(u.to, u.target)
		return u.to, nil
	}
	if d.Address == nil {
		return netip.AddrPort{}, errors.New("a UDP datagram without an address")
	}
	if !d.Address.Family().IsDomain() {
		to, err := u.h.resolve(u.t, *d)
		if err == nil {
			u.note(to, *d)
		}
		return to, err
	}
	name := d.Address.Domain()
	ip, ok := u.resolved[name]
	if !ok {
		ap, err := u.h.resolve(u.t, *d)
		if err != nil {
			return netip.AddrPort{}, err
		}
		ip = ap.Addr()
		if len(u.resolved) >= maxLinkNames {
			clear(u.resolved)
		}
		u.resolved[name] = ip
	}
	to := netip.AddrPortFrom(ip, d.Port.Value())
	u.note(to, *d)
	return to, nil
}

// note records how the client addressed to: replies from to are labelled
// with the name the client last used for it, or with the address once the
// client used the address.
func (u *udpLink) note(to netip.AddrPort, d xnet.Destination) {
	byName := d.Address.Family().IsDomain()
	if !byName && !u.named {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if !byName {
		delete(u.names, to)
		return
	}
	u.named = true
	if _, ok := u.names[to]; !ok && len(u.names) >= maxLinkNames {
		clear(u.names)
	}
	u.names[to] = xnet.UDPDestination(d.Address, d.Port)
}

// source labels a reply from ap.
func (u *udpLink) source(ap netip.AddrPort) *xnet.Destination {
	ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	u.mu.Lock()
	d, ok := u.names[ap]
	u.mu.Unlock()
	if !ok {
		d = xnet.UDPDestination(xnet.IPAddress(ap.Addr().AsSlice()), xnet.Port(ap.Port()))
	}
	return &d
}

// copyReplies moves the replies of every socket into u.out until one fails
// (the sockets are closed when the link ends, or by the stack's teardown).
func (u *udpLink) copyReplies(timer signal.ActivityUpdater) error {
	locked := u.out
	errc := make(chan error, len(u.conns))
	n := 0
	for _, c := range u.conns {
		if c == nil {
			continue
		}
		n++
		go func(c *gonet.UDPConn) {
			errc <- buf.Copy(&udpReplyReader{u: u, c: c}, locked, buf.UpdateActivity(timer))
		}(c)
	}
	if n == 0 {
		return errors.New("the OpenVPN tunnel has no address family for UDP")
	}
	return <-errc
}

// udpReplyReader reads the replies of one socket.
type udpReplyReader struct {
	u *udpLink
	c *gonet.UDPConn
}

func (r *udpReplyReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b := buf.New()
	n, from, err := r.c.ReadFrom(b.Extend(buf.Size))
	if err != nil {
		b.Release()
		if goerrors.Is(err, io.EOF) {
			// The socket is closed: the tunnel went down, or the link ended.
			// Not a clean end of the replies.
			return nil, errors.New("the UDP socket inside the OpenVPN tunnel was closed")
		}
		return nil, err
	}
	b.Resize(0, int32(n))
	ua, ok := from.(*net.UDPAddr)
	if !ok {
		b.Release()
		return nil, errors.New("a UDP reply without a source address")
	}
	b.UDP = r.u.source(ua.AddrPort())
	return buf.MultiBuffer{b}, nil
}

// lockedWriter serialises the writers of several sockets into one link.
type lockedWriter struct {
	w  buf.Writer
	mu *sync.Mutex
}

func (l *lockedWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.WriteMultiBuffer(mb)
}
