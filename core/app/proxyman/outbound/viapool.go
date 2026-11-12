package outbound

import (
	"context"
	"hash/fnv"
	stdnet "net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

// viaPool is a sendThrough of several local IPs ("ip1,ip2,..."). Every source
// IP has its own ~64k ports, so a pool multiplies the ports one outbound can
// use. A client always leaves through the same IP of the pool (picked by a hash
// of its address), so sites do not see its IP change between connections.
// Only addresses the machine actually has are used; the list is re-read every
// poolRefresh, so an address that is added or removed is picked up.
type viaPool struct {
	all []net.Address

	mu      sync.Mutex
	local   []net.Address
	checked time.Time
}

const poolRefresh = 30 * time.Second

// localAddrs is replaced in tests.
var localAddrs = func() ([]stdnet.Addr, error) { return stdnet.InterfaceAddrs() }

func newViaPool(list []string) *viaPool {
	p := &viaPool{}
	for _, s := range list {
		if a := net.ParseAddress(s); a.Family().IsIP() {
			p.all = append(p.all, a)
		}
	}
	return p
}

// addresses returns the pool's addresses this machine has. When it has none
// of them, it returns the whole pool, so the failure shows up as a dial error
// the same way a wrong single sendThrough does.
func (p *viaPool) addresses() []net.Address {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.local != nil && time.Since(p.checked) < poolRefresh {
		return p.local
	}
	have := map[string]bool{}
	if addrs, err := localAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*stdnet.IPNet); ok {
				have[ipn.IP.String()] = true
			}
		}
	}
	var local []net.Address
	for _, a := range p.all {
		if have[a.IP().String()] {
			local = append(local, a)
		}
	}
	if len(local) == 0 {
		if p.local == nil || len(p.local) != len(p.all) {
			errors.LogWarning(context.Background(), "sendThrough pool: none of ", len(p.all), " addresses is on this machine; using them anyway")
		}
		local = p.all
	} else if len(local) < len(p.all) && (p.local == nil || len(p.local) != len(local)) {
		errors.LogWarning(context.Background(), "sendThrough pool: ", len(p.all)-len(local), " of ", len(p.all), " addresses are not on this machine and are skipped")
	}
	p.local, p.checked = local, time.Now()
	return local
}

// pick returns the pool address for a client: the same one for the same
// client IP while the pool is unchanged, a random one when the client is
// unknown.
func (p *viaPool) pick(src net.Address) net.Address {
	addrs := p.addresses()
	if len(addrs) == 1 {
		return addrs[0]
	}
	if src == nil || !src.Family().IsIP() {
		return addrs[dice.Roll(len(addrs))]
	}
	h := fnv.New32a()
	h.Write(src.IP())
	return addrs[h.Sum32()%uint32(len(addrs))]
}
