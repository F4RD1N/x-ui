package options

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// storedDNS counts the DNS addresses p keeps from both sources, which is
// what every PUSH_REPLY part walks again.
func storedDNS(p *Pushed) int {
	n := len(p.dhcpDNS)
	for _, s := range p.dnsServers {
		n += len(s.addrs)
	}
	return n
}

// TestPushReplyBounded feeds a push-continuation chain that never ends, as
// a hostile server can send it: what Pushed keeps must stay bounded however
// many parts arrive, so that memory does not grow with the parts and the
// work per part (settle walks the DNS lists) does not either.
func TestPushReplyBounded(t *testing.T) {
	p := NewPushed()
	const parts = 400
	for i := range parts {
		var b strings.Builder
		b.WriteString("PUSH_REPLY")
		for j := range 250 {
			fmt.Fprintf(&b, ",route 10.%d.%d.0 255.255.255.0", i%250, j)
		}
		for j := range 40 {
			fmt.Fprintf(&b, ",dhcp-option DNS 10.53.%d.%d", i%250, j)
		}
		fmt.Fprintf(&b, ",dns server %d address", i%200-100)
		for j := range 40 {
			fmt.Fprintf(&b, " 10.54.%d.%d", i%250, j)
		}
		for j := range 5 {
			fmt.Fprintf(&b, ",future-option-%d-%d 1", i, j)
		}
		b.WriteString(",protocol-flags")
		for j := range 5 {
			fmt.Fprintf(&b, " flag%d-%d", i, j)
		}
		b.WriteString(",push-continuation 2")
		more, err := p.ApplyPushReply(b.String(), nil)
		if err != nil || !more {
			t.Fatalf("part %d: more=%v err=%v", i, more, err)
		}
	}
	more, err := p.ApplyPushReply("PUSH_REPLY,protocol-flags tls-ekm,dhcp-option DNS 10.53.0.0,route 10.200.0.0,push-continuation 1", nil)
	if err != nil || more {
		t.Fatalf("last part: more=%v err=%v", more, err)
	}
	if n := len(p.Routes); n > 1024 {
		t.Errorf("kept %d routes from %d parts", n, parts)
	}
	if n := storedDNS(p); n > 64 {
		t.Errorf("kept %d DNS addresses from %d parts", n, parts)
	}
	if n := len(p.DNS); n == 0 || n > 64 {
		t.Errorf("DNS has %d addresses", n)
	}
	if n := len(p.dnsServers); n > 64 {
		t.Errorf("kept %d dns server priorities", n)
	}
	if n := len(p.Ignored); n > 256 {
		t.Errorf("Ignored lists %d names", n)
	}
	if n := len(p.ignored); n > 256 {
		t.Errorf("the set behind Ignored holds %d names", n)
	}
	if n := len(p.ProtocolFlags); n > 32 {
		t.Errorf("ProtocolFlags lists %d flags", n)
	}
	if n := len(p.flags); n > 32 {
		t.Errorf("the set behind ProtocolFlags holds %d flags", n)
	}
	// A flag past the cap still takes effect.
	if p.KeyDerivation != "tls-ekm" {
		t.Errorf("KeyDerivation = %q after the flag cap", p.KeyDerivation)
	}
}

// TestPushDNSDeduplicated checks that repeated addresses are not stored
// again, so that a server repeating one address cannot grow the lists.
func TestPushDNSDeduplicated(t *testing.T) {
	p := NewPushed()
	part := "PUSH_REPLY,dns server 0 address" + strings.Repeat(" 1.1.1.1", 3000) +
		strings.Repeat(",dhcp-option DNS 8.8.8.8", 3000) + ",push-continuation 2"
	for i := range 50 {
		if _, err := p.ApplyPushReply(part, nil); err != nil {
			t.Fatalf("part %d: %v", i, err)
		}
	}
	if n := storedDNS(p); n != 2 {
		t.Errorf("stored %d DNS addresses, want 2", n)
	}
	if want := []netip.Addr{addr("1.1.1.1"), addr("8.8.8.8")}; !slices.Equal(p.DNS, want) {
		t.Errorf("DNS = %v, want %v", p.DNS, want)
	}
}

// TestPushDNSOrderKeptUnderCap checks that the cap keeps the first
// addresses of each source and the priority order of the result.
func TestPushDNSOrderKeptUnderCap(t *testing.T) {
	p := NewPushed()
	msg := "PUSH_REPLY,dhcp-option DNS 10.0.0.1,dns server 5 address 10.0.0.5,dns server -1 address 10.0.0.9 10.0.0.5,dhcp-option DNS6 fd00::1"
	if _, err := p.ApplyPushReply(msg, nil); err != nil {
		t.Fatal(err)
	}
	want := []netip.Addr{addr("10.0.0.9"), addr("10.0.0.5"), addr("10.0.0.1"), addr("fd00::1")}
	if !slices.Equal(p.DNS, want) {
		t.Errorf("DNS = %v, want %v", p.DNS, want)
	}
}
