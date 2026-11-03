package openvpn

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gvisortun "github.com/xtls/xray-core/proxy/openvpn/netstack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var echoGateway4 = netip.MustParseAddr("10.23.0.1")
var echoGateway6 = netip.MustParseAddr("fd23::1")
var echoClient4 = netip.MustParseAddr("10.23.0.2")
var echoClient6 = netip.MustParseAddr("fd23::2")
var echoRemote4 = netip.MustParseAddr("198.51.100.7")
var echoRemote6 = netip.MustParseAddr("2001:db8::7")

type echoTestDevice interface {
	Write([][]byte, int) (int, error)
	Read([][]byte, []int, int) (int, error)
	Close() error
}

type echoStackFixture struct {
	dev    echoTestDevice
	stack  *stack.Stack
	output <-chan []byte
	clock  *serverFilterClock
}

func newEchoStackFixture(t *testing.T, filtered bool) echoStackFixture {
	t.Helper()
	clock := newServerFilterClock()
	dev, _, ipstack, err := gvisortun.CreateNetTUNWithIPTablesClock([]netip.Addr{echoGateway4, echoGateway6}, 1280, true, clock)
	if err != nil {
		t.Fatal(err)
	}
	if filtered {
		restrictServerEchoReplies(ipstack, echoGateway4, echoGateway6)
	}
	output := make(chan []byte, 32)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			buffers, sizes := [][]byte{make([]byte, 65536)}, []int{0}
			if _, err := dev.Read(buffers, sizes, 0); err != nil {
				return
			}
			output <- bytes.Clone(buffers[0][:sizes[0]])
		}
	}()
	t.Cleanup(func() { clock.Close(); _ = dev.Close(); ipstack.Destroy(); <-done })
	return echoStackFixture{dev: dev, stack: ipstack, output: output, clock: clock}
}

func (f echoStackFixture) inject(t *testing.T, packets ...[]byte) {
	t.Helper()
	for _, p := range packets {
		if len(p) > 1280 {
			t.Fatal("fixture sent an oversized input fragment")
		}
		if _, err := f.dev.Write([][]byte{p}, 0); err != nil {
			t.Fatal(err)
		}
	}
}

func (f echoStackFixture) reply(t *testing.T) []byte {
	t.Helper()
	select {
	case p := <-f.output:
		return p
	case <-time.After(time.Second):
		t.Fatal("private stack did not emit expected response")
		return nil
	}
}

func echoRequest4(dst netip.Addr) []byte {
	b := make([]byte, 20+8+16)
	h := header.IPv4(b)
	h.Encode(&header.IPv4Fields{TotalLength: uint16(len(b)), TTL: 64, Protocol: 1, SrcAddr: tcpip.AddrFrom4(echoClient4.As4()), DstAddr: tcpip.AddrFrom4(dst.As4())})
	h.SetChecksum(^h.CalculateChecksum())
	i := header.ICMPv4(b[20:])
	i.SetType(header.ICMPv4Echo)
	i.SetIdent(41)
	i.SetSequence(1)
	i.SetChecksum(header.ICMPv4Checksum(i, 0))
	return b
}

func echoBody6(dst netip.Addr, payload int) []byte {
	b := bytes.Repeat([]byte{0x5a}, 8+payload)
	i := header.ICMPv6(b)
	i.SetType(header.ICMPv6EchoRequest)
	i.SetCode(0)
	i.SetIdent(41)
	i.SetSequence(1)
	i.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{Header: i, Src: tcpip.AddrFrom16(echoClient6.As16()), Dst: tcpip.AddrFrom16(dst.As16())}))
	return b
}

func echoPacket6(dst netip.Addr, protocol tcpip.TransportProtocolNumber, payload []byte) []byte {
	b := make([]byte, 40+len(payload))
	h := header.IPv6(b)
	h.Encode(&header.IPv6Fields{PayloadLength: uint16(len(payload)), TransportProtocol: protocol, HopLimit: 64, SrcAddr: tcpip.AddrFrom16(echoClient6.As16()), DstAddr: tcpip.AddrFrom16(dst.As16())})
	copy(b[40:], payload)
	return b
}

func echoFragments6(dst netip.Addr, payload int) [][]byte {
	body := echoBody6(dst, payload)
	var packets [][]byte
	for off := 0; off < len(body); off += 1200 {
		end := min(off+1200, len(body))
		frag := make([]byte, 8+end-off)
		frag[0] = byte(header.ICMPv6ProtocolNumber)
		field := uint16(off/8) << 3
		if end < len(body) {
			field |= 1
		}
		binary.BigEndian.PutUint16(frag[2:4], field)
		binary.BigEndian.PutUint32(frag[4:8], 0x31415926)
		copy(frag[8:], body[off:end])
		packets = append(packets, echoPacket6(dst, header.IPv6FragmentHeader, frag))
	}
	return packets
}

func TestServerEchoFilterPreservesGatewayPings(t *testing.T) {
	f := newEchoStackFixture(t, true)
	f.inject(t, echoRequest4(echoGateway4))
	p := f.reply(t)
	if p[0]>>4 != 4 || header.IPv4(p).SourceAddress() != tcpip.AddrFrom4(echoGateway4.As4()) || header.ICMPv4(header.IPv4(p).Payload()).Type() != header.ICMPv4EchoReply {
		t.Fatal("gateway IPv4 echo response changed")
	}
	f.inject(t, echoPacket6(echoGateway6, header.ICMPv6ProtocolNumber, echoBody6(echoGateway6, 16)))
	p = f.reply(t)
	if p[0]>>4 != 6 || header.IPv6(p).SourceAddress() != tcpip.AddrFrom16(echoGateway6.As16()) || header.ICMPv6(p[40:]).Type() != header.ICMPv6EchoReply {
		t.Fatal("gateway IPv6 echo response changed")
	}
}

func TestServerEchoFilterStopsSyntheticRemoteIPv6Reply(t *testing.T) {
	// Establish that the fixture exposes the promiscuous-stack behavior, rather
	// than mistaking a malformed request or an absent route for a successful fix.
	t.Run("unfiltered-control", func(t *testing.T) {
		f := newEchoStackFixture(t, false)
		f.inject(t, echoPacket6(echoRemote6, header.ICMPv6ProtocolNumber, echoBody6(echoRemote6, 16)))
		p := f.reply(t)
		if header.IPv6(p).SourceAddress() != tcpip.AddrFrom16(echoRemote6.As16()) || header.ICMPv6(p[40:]).Type() != header.ICMPv6EchoReply {
			t.Fatal("control did not synthesize remote echo")
		}
	})
	for _, kind := range []string{"plain", "hop-by-hop", "fragmented-large"} {
		t.Run(kind, func(t *testing.T) {
			f := newEchoStackFixture(t, true)
			before := f.stack.Stats().IP.IPTablesOutputDropped.Value()
			switch kind {
			case "plain":
				f.inject(t, echoPacket6(echoRemote6, header.ICMPv6ProtocolNumber, echoBody6(echoRemote6, 16)))
			case "hop-by-hop":
				ext := make([]byte, 8)
				ext[0] = byte(header.ICMPv6ProtocolNumber)
				f.inject(t, echoPacket6(echoRemote6, 0, append(ext, echoBody6(echoRemote6, 16)...)))
			case "fragmented-large":
				f.inject(t, echoFragments6(echoRemote6, 4096)...)
			}
			if got := f.stack.Stats().IP.IPTablesOutputDropped.Value(); got != before+1 {
				t.Fatalf("request did not reach the output echo filter: dropped=%d before=%d", got, before)
			}
			select {
			case p := <-f.output:
				t.Fatalf("synthetic remote echo escaped filter: %x", p[:min(48, len(p))])
			case <-time.After(20 * time.Millisecond):
			}
			// A following legitimate gateway request also proves the stack remains usable.
			f.inject(t, echoPacket6(echoGateway6, header.ICMPv6ProtocolNumber, echoBody6(echoGateway6, 16)))
			p := f.reply(t)
			if header.IPv6(p).SourceAddress() != tcpip.AddrFrom16(echoGateway6.As16()) {
				t.Fatal("gateway echo was affected by remote suppression")
			}
		})
	}
}

func TestServerEchoFilterRunsBeforeReplyFragmentation(t *testing.T) {
	for _, filtered := range []bool{false, true} {
		name := "unfiltered-remote"
		dst := echoRemote6
		if filtered {
			name = "filtered-gateway"
			dst = echoGateway6
		}
		t.Run(name, func(t *testing.T) {
			f := newEchoStackFixture(t, filtered)
			f.inject(t, echoFragments6(dst, 4096)...)
			p := f.reply(t)
			if p[6] != header.IPv6FragmentHeader {
				t.Fatal("large control echo did not require reply fragmentation")
			}
			if header.IPv6(p).SourceAddress() != tcpip.AddrFrom16(dst.As16()) {
				t.Fatal("fragmented gateway/control source changed")
			}
		})
	}
}

func echoOutputPacket(v6 bool, protocol tcpip.TransportProtocolNumber, typ byte, source netip.Addr) *stack.PacketBuffer {
	networkSize, transportSize := 20, 8
	if v6 {
		networkSize = 40
	}
	if protocol == header.TCPProtocolNumber {
		transportSize = 20
	}
	p := stack.NewPacketBuffer(stack.PacketBufferOptions{ReserveHeaderBytes: networkSize + transportSize})
	trans := p.TransportHeader().Push(transportSize)
	trans[0] = typ
	p.TransportProtocolNumber = protocol
	if protocol == header.TCPProtocolNumber {
		trans[12] = 5 << 4
	}
	if v6 {
		p.NetworkProtocolNumber = header.IPv6ProtocolNumber
		header.IPv6(p.NetworkHeader().Push(40)).Encode(&header.IPv6Fields{PayloadLength: uint16(transportSize), TransportProtocol: protocol, HopLimit: 64, SrcAddr: tcpip.AddrFrom16(source.As16()), DstAddr: tcpip.AddrFrom16(echoClient6.As16())})
	} else {
		p.NetworkProtocolNumber = header.IPv4ProtocolNumber
		h := header.IPv4(p.NetworkHeader().Push(20))
		h.Encode(&header.IPv4Fields{TotalLength: uint16(networkSize + transportSize), TTL: 64, Protocol: uint8(protocol), SrcAddr: tcpip.AddrFrom4(source.As4()), DstAddr: tcpip.AddrFrom4(echoClient4.As4())})
		h.SetChecksum(^h.CalculateChecksum())
	}
	return p
}

func TestServerEchoFilterOnlyMatchesRemoteReplies(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		name := "IPv4"
		gateway, remote, icmp, reply := echoGateway4, echoRemote4, header.ICMPv4ProtocolNumber, byte(header.ICMPv4EchoReply)
		if v6 {
			name = "IPv6"
			gateway, remote, icmp, reply = echoGateway6, echoRemote6, header.ICMPv6ProtocolNumber, byte(header.ICMPv6EchoReply)
		}
		t.Run(name, func(t *testing.T) {
			for _, tc := range []struct {
				name     string
				protocol tcpip.TransportProtocolNumber
				typ      byte
				source   netip.Addr
				drop     bool
			}{
				{"remote-echo", icmp, reply, remote, true},
				{"gateway-echo", icmp, reply, gateway, false},
				{"tcp", header.TCPProtocolNumber, reply, remote, false},
				{"udp", header.UDPProtocolNumber, reply, remote, false},
				{"icmp-error", icmp, 3, remote, false},
				{"icmp-other", icmp, 2, remote, false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					p := echoOutputPacket(v6, tc.protocol, tc.typ, tc.source)
					defer p.DecRef()
					matcher := serverRemoteEchoMatcher{gateway: gateway}
					match, hotdrop := matcher.Match(stack.Output, p, "", "")
					if match != tc.drop || hotdrop {
						t.Fatalf("unexpected matcher result: match=%t hotdrop=%t", match, hotdrop)
					}
					if match, hotdrop = matcher.Match(stack.Input, p, "", ""); match || hotdrop {
						t.Fatal("output guard affected input handling")
					}
				})
			}
		})
	}
}

func TestServerFilterClockCloseStopsPendingAndFutureTimers(t *testing.T) {
	clock := newServerFilterClock()
	var fired atomic.Int32
	timer := clock.AfterFunc(time.Hour, func() { fired.Add(1) })
	clock.Close()
	timer.Reset(0)
	late := clock.AfterFunc(0, func() { fired.Add(1) })
	late.Reset(0)
	if timer.Stop() || late.Stop() {
		t.Fatal("closed clock left a pending timer")
	}
	time.Sleep(10 * time.Millisecond)
	if fired.Load() != 0 {
		t.Fatal("closed clock executed a pending or newly scheduled callback")
	}
	clock.mu.Lock()
	defer clock.mu.Unlock()
	if !clock.closed || len(clock.timers) != 0 {
		t.Fatal("clock teardown retained timer registrations")
	}
}

func TestServerFilterClockCloseDrainsCallbackAndBlocksRearm(t *testing.T) {
	clock := newServerFilterClock()
	entered, release, closed := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var fired atomic.Int32
	var timer tcpip.Timer
	timer = clock.AfterFunc(time.Hour, func() {
		if fired.Add(1) != 1 {
			return
		}
		close(entered)
		<-release
		// The conntrack reaper resets itself at the end of its callback.
		timer.Reset(0)
	})
	timer.Reset(0)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("callback never started")
	}
	go func() { clock.Close(); close(closed) }()
	deadline := time.Now().Add(time.Second)
	for {
		clock.mu.Lock()
		closing := clock.closed
		clock.mu.Unlock()
		if closing {
			break
		}
		if time.Now().After(deadline) {
			close(release)
			t.Fatal("Close did not mark clock closed")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-closed:
		close(release)
		t.Fatal("Close returned while a callback was still running")
	default:
	}
	close(release)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not drain running callback")
	}
	time.Sleep(10 * time.Millisecond)
	if fired.Load() != 1 {
		t.Fatal("callback rearmed after clock shutdown")
	}
	clock.Close() // Idempotent teardown must remain safe.
}

func TestServerFilterClockConcurrentResetStopAndClose(t *testing.T) {
	clock := newServerFilterClock()
	var fired atomic.Int32
	timer := clock.AfterFunc(time.Hour, func() { fired.Add(1) })
	start := make(chan struct{})
	var workers sync.WaitGroup
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			for j := 0; j < 50; j++ {
				timer.Stop()
				timer.Reset(time.Hour)
			}
		}()
	}
	workers.Add(1)
	go func() { defer workers.Done(); <-start; clock.Close() }()
	close(start)
	workers.Wait()
	timer.Reset(0)
	clock.Close()
	if fired.Load() != 0 || timer.Stop() {
		t.Fatal("concurrent reset left a live timer after Close")
	}
}

func TestServerFilterClockOwnsAndStopsActualReaper(t *testing.T) {
	f := newEchoStackFixture(t, true)
	f.clock.mu.Lock()
	var timers []*serverFilterTimer
	for timer := range f.clock.timers {
		timers = append(timers, timer)
	}
	f.clock.mu.Unlock()
	if len(timers) != 1 {
		t.Fatalf("expected one owned conntrack reaper, got %d", len(timers))
	}
	f.clock.Close()
	for _, timer := range timers {
		timer.Reset(0)
		if timer.Stop() {
			t.Fatal("actual conntrack reaper could rearm after owner shutdown")
		}
	}
	// The owner clock is separate from normal network timekeeping.
	if f.stack.Clock() == f.clock {
		t.Fatal("iptables timer ownership replaced the transport clock")
	}
}
