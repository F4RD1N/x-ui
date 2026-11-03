package openvpn

import (
	"context"
	"errors"
	"maps"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/nativebridge"
	gvisortun "github.com/xtls/xray-core/proxy/openvpn/netstack"
	ovserver "github.com/xtls/xray-core/proxy/openvpn/ovpn/server"
	"github.com/xtls/xray-core/transport"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// validClientPacket prevents address spoofing before the per-client stack sees
// IP fragments, extensions or transport headers. Length validation is delegated
// to the IP stack after checking the base header and actual wire packet size.
func validClientPacket(p []byte, v4, v6 netip.Addr, mtu int) bool {
	if len(p) == 0 || len(p) > mtu {
		return false
	}
	switch p[0] >> 4 {
	case 4:
		if len(p) < 20 || p[0]&15 < 5 || int(p[0]&15)*4 > len(p) {
			return false
		}
		n := int(p[2])<<8 | int(p[3])
		if n != len(p) {
			return false
		}
		return netip.AddrFrom4([4]byte{p[12], p[13], p[14], p[15]}) == v4
	case 6:
		if !v6.IsValid() || len(p) < 40 || (int(p[4])<<8|int(p[5]))+40 != len(p) {
			return false
		}
		var a [16]byte
		copy(a[:], p[8:24])
		return netip.AddrFrom16(a) == v6
	}
	return false
}

type serverFlows struct {
	mu       sync.Mutex
	active   map[net.Conn]struct{}
	reserved int
	closed   bool
	max      int
	wg       sync.WaitGroup
}

func (f *serverFlows) reserve() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.reserved >= f.max {
		return false
	}
	f.reserved++
	f.wg.Add(1)
	return true
}
func (f *serverFlows) release(c net.Conn) {
	f.mu.Lock()
	delete(f.active, c)
	f.reserved--
	f.mu.Unlock()
	f.wg.Done()
}
func (f *serverFlows) track(c net.Conn) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return false
	}
	f.active[c] = struct{}{}
	return true
}
func (f *serverFlows) close() {
	f.mu.Lock()
	f.closed = true
	cs := make([]net.Conn, 0, len(f.active))
	for c := range f.active {
		cs = append(cs, c)
	}
	f.mu.Unlock()
	for _, c := range cs {
		_ = c.Close()
	}
}

func (s *Server) routeSession(ctx context.Context, p *serverPeer, sess *ovserver.Session, dispatcher routing.Dispatcher) (err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	addresses := []netip.Addr{netip.MustParsePrefix(s.settings.Tunnel.IPv4).Addr().Next()}
	if p.ipv6.IsValid() {
		addresses = append(addresses, netip.MustParsePrefix(s.settings.Tunnel.IPv6).Addr().Next())
	}
	filterClock := newServerFilterClock()
	defer filterClock.Close()
	dev, _, ipstack, e := gvisortun.CreateNetTUNWithIPTablesClock(addresses, s.settings.Tunnel.MTU, true, filterClock)
	if e != nil {
		if ipstack != nil {
			ipstack.Destroy()
		}
		return e
	}
	var gatewayV6 netip.Addr
	if len(addresses) > 1 {
		gatewayV6 = addresses[1]
	}
	restrictServerEchoReplies(ipstack, addresses[0], gatewayV6)
	flows := &serverFlows{active: map[net.Conn]struct{}{}, max: s.settings.Limits.MaxFlowsPerSession}
	stop := context.AfterFunc(ctx, func() { _ = dev.Close(); flows.close() })
	defer stop()
	defer func() { cancel(); flows.close(); _ = dev.Close(); ipstack.Destroy(); flows.wg.Wait() }()
	forward := func(d xnet.Destination, c net.Conn) {
		defer nativebridge.RecoverWorker(func(error) { _ = c.Close() })
		defer flows.release(c)
		defer c.Close()
		if !flows.track(c) {
			return
		}
		s.mu.Lock()
		user := p.user
		s.mu.Unlock()
		flowctx, flowcancel := context.WithCancel(ctx)
		defer flowcancel()
		inbound := session.Inbound{}
		if in := session.InboundFromContext(ctx); in != nil {
			inbound = *in
		}
		inbound.Name = "openvpn"
		inbound.CanSpliceCopy = 3
		inbound.Conn = nil
		inbound.Timer = nil
		inbound.User = memoryServerUser(user)
		if !inbound.Source.IsValid() {
			inbound.Source = xnet.DestinationFromAddr(c.RemoteAddr())
		}
		flowctx = session.ContextWithInbound(flowctx, &inbound)
		flowctx = session.ContextWithOutbounds(flowctx, []*session.Outbound{{}})
		content := session.Content{}
		if original := session.ContentFromContext(ctx); original != nil {
			content = *original
			content.Attributes = maps.Clone(original.Attributes)
		}
		flowctx = session.ContextWithContent(flowctx, &content)
		pol := s.policy.ForLevel(user.Level)
		// A finite read/write idle deadline releases silent UDP associations. Activity
		// extends it independently for both directions; Xray routes and counters run
		// on the authenticated per-flow context.
		idle := pol.Timeouts.ConnectionIdle
		if idle <= 0 {
			idle = 2 * time.Minute
		}
		wrapped := &serverIdleConn{Conn: c, idle: idle}
		_ = c.SetDeadline(time.Now().Add(idle))
		var reader buf.Reader = buf.NewReader(wrapped)
		if d.Network == xnet.Network_UDP {
			reader = buf.NewPacketReader(wrapped)
		}
		_ = dispatcher.DispatchLink(flowctx, d, &transport.Link{Reader: reader, Writer: buf.NewWriter(wrapped)})
	}
	tf := tcp.NewForwarder(ipstack, 0, s.settings.Limits.MaxFlowsPerSession, func(r *tcp.ForwarderRequest) {
		if !flows.reserve() {
			r.Complete(true)
			return
		}
		go func() {
			completed, transferred := false, false
			var c net.Conn
			defer nativebridge.RecoverWorker(func(error) {})
			defer func() {
				if !transferred {
					defer flows.release(nil)
					if c != nil {
						_ = c.Close()
					}
				}
				if !completed {
					completed = true
					r.Complete(true)
				}
			}()
			var q waiter.Queue
			id := r.ID()
			ep, e := r.CreateEndpoint(&q)
			if e != nil {
				return
			}
			c = gonet.NewTCPConn(&q, ep)
			completed = true
			r.Complete(false)
			destination := xnet.TCPDestination(xnet.IPAddress(id.LocalAddress.AsSlice()), xnet.Port(id.LocalPort))
			transferred = true
			forward(destination, c)
		}()
	})
	ipstack.SetTransportProtocolHandler(tcp.ProtocolNumber, tf.HandlePacket)
	// This gVisor version's UDP Forwarder.HandlePacket clones a packet without a
	// release API. Construct the synchronous request around the caller-owned
	// packet instead, then dispatch its connected endpoint in a bounded worker.
	ipstack.SetTransportProtocolHandler(udp.ProtocolNumber, func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) (handled bool) {
		reserved, transferred := false, false
		var c net.Conn
		defer nativebridge.RecoverWorker(func(error) { handled = false })
		defer func() {
			if reserved && !transferred {
				defer flows.release(nil)
				if c != nil {
					_ = c.Close()
				}
			}
		}()
		if !flows.reserve() {
			return false
		}
		reserved = true
		var q waiter.Queue
		r := udp.NewForwarderRequest(ipstack, id, pkt)
		ep, e := r.CreateEndpoint(&q)
		if e != nil {
			return false
		}
		c = gonet.NewUDPConn(&q, ep)
		destination := xnet.UDPDestination(xnet.IPAddress(id.LocalAddress.AsSlice()), xnet.Port(id.LocalPort))
		transferred = true
		go forward(destination, c)
		return true
	})

	failures := make(chan error, 2)
	var pumps sync.WaitGroup
	pumps.Add(2)
	go func() {
		defer pumps.Done()
		defer nativebridge.RecoverWorker(func(e error) { failures <- e })
		b := make([]byte, 65536)
		for {
			n, e := sess.ReadPacket(b)
			if e != nil {
				failures <- e
				return
			}
			if !validClientPacket(b[:n], p.ipv4, p.ipv6, s.settings.Tunnel.MTU) {
				continue
			}
			if _, e = dev.Write([][]byte{b[:n]}, 0); e != nil {
				failures <- e
				return
			}
		}
	}()
	go func() {
		defer pumps.Done()
		defer nativebridge.RecoverWorker(func(e error) { failures <- e })
		b := make([]byte, 65536)
		sizes := []int{0}
		for {
			_, e := dev.Read([][]byte{b}, sizes, 0)
			if e != nil {
				failures <- e
				return
			}
			if e = sess.WritePacket(b[:sizes[0]]); e != nil {
				failures <- e
				return
			}
		}
	}()
	select {
	case err = <-failures:
	case <-ctx.Done():
		err = ctx.Err()
	case <-sess.Done():
		err = sess.Err()
	}
	cancel()
	_ = dev.Close()
	_ = sess.Close()
	pumps.Wait()
	if err == nil {
		return errors.New("OpenVPN session ended")
	}
	return err
}

type serverIdleConn struct {
	net.Conn
	idle time.Duration
}

func (c *serverIdleConn) Read(p []byte) (int, error) {
	_ = c.Conn.SetDeadline(time.Now().Add(c.idle))
	return c.Conn.Read(p)
}
func (c *serverIdleConn) Write(p []byte) (int, error) {
	_ = c.Conn.SetDeadline(time.Now().Add(c.idle))
	return c.Conn.Write(p)
}
