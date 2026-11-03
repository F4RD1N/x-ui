package openvpn

import (
	"net/netip"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// serverFilterClock owns only the private stack's iptables maintenance timers.
// This gVisor version does not stop its conntrack reaper on Stack.Destroy.
// Ordinary transport/fragmentation timers keep using the normal stack clock.
type serverFilterClock struct {
	tcpip.Clock
	mu      sync.Mutex
	closed  bool
	timers  map[*serverFilterTimer]struct{}
	running sync.WaitGroup
}

type serverFilterTimer struct {
	clock *serverFilterClock
	timer tcpip.Timer
}

func newServerFilterClock() *serverFilterClock {
	return &serverFilterClock{Clock: tcpip.NewStdClock(), timers: make(map[*serverFilterTimer]struct{})}
}

func (c *serverFilterClock) AfterFunc(delay time.Duration, f func()) tcpip.Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &serverFilterTimer{clock: c}
	if c.closed {
		return t
	}
	c.timers[t] = struct{}{}
	t.timer = c.Clock.AfterFunc(delay, func() {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return
		}
		c.running.Add(1)
		c.mu.Unlock()
		defer c.running.Done()
		f()
	})
	return t
}

func (t *serverFilterTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	return t.timer != nil && t.timer.Stop()
}

func (t *serverFilterTimer) Reset(delay time.Duration) {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	if !t.clock.closed && t.timer != nil {
		t.timer.Reset(delay)
	}
}

// Close is called by session teardown, never from a timer's own callback.
// Marking closed under the same mutex used for callback admission/Reset makes
// it impossible for the reaper to rearm after teardown starts.
func (c *serverFilterClock) Close() {
	c.mu.Lock()
	c.closed = true
	for t := range c.timers {
		t.timer.Stop()
	}
	clear(c.timers)
	c.mu.Unlock()
	c.running.Wait()
}

// restrictServerEchoReplies belongs only to a newly created server-side private
// stack. Promiscuous destination handling must not turn a ping of an arbitrary
// remote address into a local success: Xray dispatches TCP/UDP, not ICMP.
// Gateway echo remains useful for checking the tunnel itself.
//
// Filter locally generated output before IP fragmentation. Filtering raw tunnel
// input would disturb extension/fragment handling; filtering raw output could
// miss an echo reply which the stack fragmented after reassembling a request.
func restrictServerEchoReplies(ipstack *stack.Stack, gatewayV4, gatewayV6 netip.Addr) {
	for _, item := range []struct {
		v6      bool
		gateway netip.Addr
		network tcpip.NetworkProtocolNumber
		filter  stack.IPHeaderFilter
	}{
		{false, gatewayV4, header.IPv4ProtocolNumber, stack.EmptyFilter4()},
		{true, gatewayV6, header.IPv6ProtocolNumber, stack.EmptyFilter6()},
	} {
		table := ipstack.IPTables().GetTable(stack.FilterID, item.v6)
		oldOutput := table.BuiltinChains[stack.Output]
		// Preserve the other hook entrypoints and the previous output chain.
		// These private stacks start with default ACCEPT rules; copying the old
		// suffix also preserves any existing terminal output policy.
		rules := append([]stack.Rule(nil), table.Rules...)
		table.BuiltinChains[stack.Output] = len(rules)
		rules = append(rules, stack.Rule{
			Filter:   item.filter,
			Matchers: []stack.Matcher{serverRemoteEchoMatcher{gateway: item.gateway}},
			Target:   &stack.DropTarget{NetworkProtocol: item.network},
		})
		rules = append(rules, table.Rules[oldOutput:]...)
		table.Rules = rules
		ipstack.IPTables().ReplaceTable(stack.FilterID, table, item.v6)
	}
}

type serverRemoteEchoMatcher struct{ gateway netip.Addr }

func (m serverRemoteEchoMatcher) Match(hook stack.Hook, packet *stack.PacketBuffer, _, _ string) (bool, bool) {
	if hook != stack.Output {
		return false, false
	}
	transport := packet.TransportHeader().Slice()
	if len(transport) == 0 {
		return false, false
	}
	network := packet.NetworkHeader().Slice()
	var source netip.Addr
	switch packet.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber:
		if packet.TransportProtocolNumber != header.ICMPv4ProtocolNumber || transport[0] != byte(header.ICMPv4EchoReply) || len(network) < header.IPv4MinimumSize {
			return false, false
		}
		address := header.IPv4(network).SourceAddress()
		source, _ = netip.AddrFromSlice(address.AsSlice())
	case header.IPv6ProtocolNumber:
		if packet.TransportProtocolNumber != header.ICMPv6ProtocolNumber || transport[0] != byte(header.ICMPv6EchoReply) || len(network) < header.IPv6MinimumSize {
			return false, false
		}
		address := header.IPv6(network).SourceAddress()
		source, _ = netip.AddrFromSlice(address.AsSlice())
	default:
		return false, false
	}
	return source != m.gateway, false
}
