/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2022 WireGuard LLC. All Rights Reserved.
 */

package gvisortun

import (
	"context"
	"fmt"
	"math/rand"
	stdnet "net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type netTun struct {
	ep             *channel.Endpoint
	stack          *stack.Stack
	events         chan tun.Event
	incomingPacket chan *buffer.View
	// closed is closed by Close. incomingPacket itself is never closed: the
	// stack may still be sending on it (WriteNotify runs in whatever
	// goroutine made the packet, also one injecting a packet while the
	// device closes), and a send on a closed channel panics.
	closed       chan struct{}
	closeOnce    sync.Once
	mtu          int
	hasV4, hasV6 bool
}

type Net netTun

// testHookWriteNotify, when set, runs in WriteNotify between taking a packet
// from the stack and handing it to Read (tests stall a writer there).
var testHookWriteNotify atomic.Pointer[func()]

func CreateNetTUN(localAddresses []netip.Addr, mtu int, promiscuousMode bool) (tun.Device, *Net, *stack.Stack, error) {
	return createNetTUN(localAddresses, mtu, promiscuousMode, nil)
}

// CreateNetTUNWithIPTablesClock lets the native server own the lifetime of its
// packet filter's reaper. The network stack keeps its ordinary independent
// clock, and callers that do not install packet rules use CreateNetTUN.
func CreateNetTUNWithIPTablesClock(localAddresses []netip.Addr, mtu int, promiscuousMode bool, clock tcpip.Clock) (tun.Device, *Net, *stack.Stack, error) {
	return createNetTUN(localAddresses, mtu, promiscuousMode, clock)
}

func createNetTUN(localAddresses []netip.Addr, mtu int, promiscuousMode bool, filterClock tcpip.Clock) (tun.Device, *Net, *stack.Stack, error) {
	// This private stack carries explicitly routed Xray destinations, including
	// loopback services. Destination policy is enforced by Xray routing.
	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocolWithOptions(ipv4.Options{AllowExternalLoopbackTraffic: true}), ipv6.NewProtocolWithOptions(ipv6.Options{AllowExternalLoopbackTraffic: true})},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4},
		HandleLocal:        !promiscuousMode,
	}
	if filterClock != nil {
		opts.DefaultIPTables = func(_ tcpip.Clock, rng *rand.Rand) *stack.IPTables {
			return stack.DefaultTables(filterClock, rng)
		}
	}
	dev := &netTun{
		ep:             channel.New(1024, uint32(mtu), ""),
		stack:          stack.New(opts),
		events:         make(chan tun.Event, 1),
		incomingPacket: make(chan *buffer.View),
		closed:         make(chan struct{}),
		mtu:            mtu,
	}
	dev.ep.AddNotify(dev)
	tcpipErr := dev.stack.CreateNIC(1, dev.ep)
	if tcpipErr != nil {
		return nil, nil, dev.stack, fmt.Errorf("CreateNIC: %v", tcpipErr)
	}
	for _, ip := range localAddresses {
		var protoNumber tcpip.NetworkProtocolNumber
		if ip.Is4() {
			protoNumber = ipv4.ProtocolNumber
		} else if ip.Is6() {
			protoNumber = ipv6.ProtocolNumber
		}
		protoAddr := tcpip.ProtocolAddress{
			Protocol:          protoNumber,
			AddressWithPrefix: tcpip.AddrFromSlice(ip.AsSlice()).WithPrefix(),
		}
		tcpipErr := dev.stack.AddProtocolAddress(1, protoAddr, stack.AddressProperties{})
		if tcpipErr != nil {
			return nil, nil, dev.stack, fmt.Errorf("AddProtocolAddress(%v): %v", ip, tcpipErr)
		}
		if ip.Is4() {
			dev.hasV4 = true
		} else if ip.Is6() {
			dev.hasV6 = true
		}
	}
	if dev.hasV4 {
		dev.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	}
	if dev.hasV6 {
		dev.stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1})
	}
	if promiscuousMode {
		// enable promiscuous mode to handle all packets processed by netstack
		dev.stack.SetPromiscuousMode(1, true)
		dev.stack.SetSpoofing(1, true)
	}

	opt := tcpip.CongestionControlOption("cubic")
	if err := dev.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
		return nil, nil, dev.stack, fmt.Errorf("SetTransportProtocolOption(%d, &%T(%s)): %s", tcp.ProtocolNumber, opt, opt, err)
	}

	dev.events <- tun.EventUp
	return dev, (*Net)(dev), dev.stack, nil
}

// BatchSize implements tun.Device
func (tun *netTun) BatchSize() int {
	return 1
}

// Name implements tun.Device
func (tun *netTun) Name() (string, error) {
	return "go", nil
}

// File implements tun.Device
func (tun *netTun) File() *os.File {
	return nil
}

// Events implements tun.Device
func (tun *netTun) Events() <-chan tun.Event {
	return tun.events
}

// Read implements tun.Device

func (tun *netTun) Read(buf [][]byte, sizes []int, offset int) (int, error) {
	var view *buffer.View
	select {
	case view = <-tun.incomingPacket:
	case <-tun.closed:
		return 0, os.ErrClosed
	}

	defer view.Release()
	n, err := view.Read(buf[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

// Write implements tun.Device
func (tun *netTun) Write(buf [][]byte, offset int) (int, error) {
	for _, buf := range buf {
		packet := buf[offset:]
		if len(packet) == 0 {
			continue
		}

		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
		switch packet[0] >> 4 {
		case 4:
			tun.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
		case 6:
			tun.ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
		default:
			pkb.DecRef()
			return 0, syscall.EAFNOSUPPORT
		}
		pkb.DecRef()
	}
	return len(buf), nil
}

// WriteNotify implements channel.Notification
func (tun *netTun) WriteNotify() {
	pkt := tun.ep.Read()
	if pkt == nil {
		return
	}

	view := pkt.ToView()
	pkt.DecRef()

	if hook := testHookWriteNotify.Load(); hook != nil {
		(*hook)()
	}
	select {
	case tun.incomingPacket <- view:
	case <-tun.closed:
		view.Release() // the device is closed: the packet is dropped
	}
}

// Flush  implements tun.Device
func (tun *netTun) Flush() error {
	return nil
}

// Close implements tun.Device. It may be called more than once.
func (tun *netTun) Close() error {
	tun.closeOnce.Do(func() {
		// First release Read and any writer waiting in WriteNotify.
		close(tun.closed)

		tun.stack.RemoveNIC(1)

		if tun.events != nil {
			close(tun.events)
		}

		tun.ep.Close()
	})
	return nil
}

// MTU  implements tun.Device
func (tun *netTun) MTU() (int, error) {
	return tun.mtu, nil
}

func convertToFullAddr(endpoint netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	var protoNumber tcpip.NetworkProtocolNumber
	if endpoint.Addr().Is4() {
		protoNumber = ipv4.ProtocolNumber
	} else {
		protoNumber = ipv6.ProtocolNumber
	}
	return tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(endpoint.Addr().AsSlice()),
		Port: endpoint.Port(),
	}, protoNumber
}

func (net *Net) DialContextTCPAddrPort(ctx context.Context, addr netip.AddrPort) (*gonet.TCPConn, error) {
	fa, pn := convertToFullAddr(addr)
	return gonet.DialContextTCP(ctx, net.stack, fa, pn)
}

func (net *Net) DialUDPAddrPort(laddr, raddr netip.AddrPort) (*gonet.UDPConn, error) {
	var lfa, rfa *tcpip.FullAddress
	var pn tcpip.NetworkProtocolNumber
	if laddr.IsValid() || laddr.Port() > 0 {
		var addr tcpip.FullAddress
		addr, pn = convertToFullAddr(laddr)
		lfa = &addr
	}
	if raddr.IsValid() || raddr.Port() > 0 {
		var addr tcpip.FullAddress
		addr, pn = convertToFullAddr(raddr)
		rfa = &addr
	}
	return gonet.DialUDP(net.stack, lfa, rfa, pn)
}

// PingConn is an ICMP echo ("ping") endpoint of the stack, for the pings
// Xray executes through a tunnel (common/icmpecho).
type PingConn struct {
	c *gonet.UDPConn
}

// ListenPing opens an unconnected ICMP echo endpoint of one family (v6:
// ICMPv6). Like a Linux datagram ICMP socket, it sends echo requests from the
// stack's address of that family under an identifier the stack picks (and
// computes their checksums), and receives the echo replies that carry it.
func (n *Net) ListenPing(v6 bool) (*PingConn, error) {
	proto, netProto := icmp.ProtocolNumber4, ipv4.ProtocolNumber
	if v6 {
		proto, netProto = icmp.ProtocolNumber6, ipv6.ProtocolNumber
	}
	var wq waiter.Queue
	ep, err := n.stack.NewEndpoint(proto, netProto, &wq)
	if err != nil {
		return nil, fmt.Errorf("ICMP endpoint: %v", err)
	}
	if err := ep.Bind(tcpip.FullAddress{}); err != nil {
		ep.Close()
		return nil, fmt.Errorf("ICMP endpoint: bind: %v", err)
	}
	return &PingConn{c: gonet.NewUDPConn(&wq, ep)}, nil
}

// WriteEcho sends the echo request msg (type, code, checksum, identifier,
// sequence, data) to dst; the stack puts in its identifier and checksum.
func (p *PingConn) WriteEcho(msg []byte, dst netip.Addr) error {
	_, err := p.c.WriteTo(msg, &stdnet.UDPAddr{IP: dst.AsSlice()})
	return err
}

// ReadEcho reads the next echo reply to this endpoint into b: the ICMP
// message, without the IP header. It returns io.EOF once the endpoint is
// closed.
func (p *PingConn) ReadEcho(b []byte) (int, netip.Addr, error) {
	n, from, err := p.c.ReadFrom(b)
	if err != nil {
		return 0, netip.Addr{}, err
	}
	ua, _ := from.(*stdnet.UDPAddr)
	if ua == nil {
		return 0, netip.Addr{}, fmt.Errorf("an echo reply without a source")
	}
	src, _ := netip.AddrFromSlice(ua.IP)
	return n, src.Unmap(), nil
}

// Close closes the endpoint.
func (p *PingConn) Close() error { return p.c.Close() }
