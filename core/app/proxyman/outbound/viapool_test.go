package outbound

import (
	stdnet "net"
	"testing"

	"github.com/xtls/xray-core/common/net"
)

func withLocal(t *testing.T, ips ...string) {
	old := localAddrs
	t.Cleanup(func() { localAddrs = old })
	localAddrs = func() ([]stdnet.Addr, error) {
		var out []stdnet.Addr
		for _, s := range ips {
			out = append(out, &stdnet.IPNet{IP: stdnet.ParseIP(s), Mask: stdnet.CIDRMask(32, 32)})
		}
		return out, nil
	}
}

func TestViaPoolSkipsAddressesNotOnTheMachine(t *testing.T) {
	withLocal(t, "10.0.0.1", "10.0.0.2")
	p := newViaPool([]string{"10.0.0.1", "192.0.2.9", "10.0.0.2"})
	got := p.addresses()
	if len(got) != 2 || got[0].String() != "10.0.0.1" || got[1].String() != "10.0.0.2" {
		t.Fatalf("addresses = %v", got)
	}
}

func TestViaPoolUsesAllWhenNoneIsLocal(t *testing.T) {
	withLocal(t, "10.9.9.9")
	p := newViaPool([]string{"192.0.2.1", "192.0.2.2"})
	if got := p.addresses(); len(got) != 2 {
		t.Fatalf("addresses = %v", got)
	}
}

func TestViaPoolSameClientSameAddress(t *testing.T) {
	withLocal(t, "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4")
	p := newViaPool([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"})
	used := map[string]int{}
	for i := 0; i < 2000; i++ {
		src := net.IPAddress([]byte{5, 208, byte(i >> 8), byte(i)})
		a := p.pick(src)
		if b := p.pick(src); a.String() != b.String() {
			t.Fatalf("client %v got %v then %v", src, a, b)
		}
		used[a.String()]++
	}
	if len(used) != 4 {
		t.Fatalf("only %d of 4 addresses used: %v", len(used), used)
	}
	for ip, n := range used {
		if n < 350 || n > 650 {
			t.Errorf("%s got %d of 2000 clients, want about 500", ip, n)
		}
	}
}

func TestViaPoolUnknownClientGetsAPoolAddress(t *testing.T) {
	withLocal(t, "10.0.0.1", "10.0.0.2")
	p := newViaPool([]string{"10.0.0.1", "10.0.0.2"})
	for i := 0; i < 20; i++ {
		a := p.pick(nil).String()
		if a != "10.0.0.1" && a != "10.0.0.2" {
			t.Fatalf("pick(nil) = %s", a)
		}
	}
}
