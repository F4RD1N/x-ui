//go:build linux

package tune

import (
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/util/hw"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// The real probes, in throwaway network namespaces (root, XUI_TUNE_LIVE=1):
// a veth pair with its peer in a second namespace as the gateway. ICMP echo
// works; with echo ignored there, the neighbour probe does; with the peer
// down, nothing answers. The thread that made the namespaces is never
// unlocked, so Go ends it with the goroutine and the namespaces go with it.
func TestProbesLive(t *testing.T) {
	if os.Getenv("XUI_TUNE_LIVE") != "1" || os.Geteuid() != 0 {
		t.Skip("needs root and XUI_TUNE_LIVE=1")
	}
	if _, err := os.Stat("/sys/module/veth"); err != nil {
		t.Skip("the veth module is not loaded (this test loads no module)")
	}
	type result struct {
		icmp, neigh, none string
		err               error
	}
	done := make(chan result, 1)
	go func() {
		runtime.LockOSThread() // never unlocked
		var r result
		defer func() { done <- r }()
		nsFD := func() int {
			fd, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
			if err != nil {
				r.err = err
			}
			return fd
		}
		if r.err = unix.Unshare(unix.CLONE_NEWNET); r.err != nil {
			return
		}
		a := nsFD()
		veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "xuip0"}, PeerName: "xuip1"}
		if r.err = netlink.LinkAdd(veth); r.err != nil {
			return
		}
		if r.err = unix.Unshare(unix.CLONE_NEWNET); r.err != nil {
			return
		}
		b := nsFD()
		inB := func(f func() error) {
			if r.err == nil {
				if r.err = unix.Setns(b, unix.CLONE_NEWNET); r.err == nil {
					r.err = f()
					if err := unix.Setns(a, unix.CLONE_NEWNET); r.err == nil {
						r.err = err
					}
				}
			}
		}
		if r.err = unix.Setns(a, unix.CLONE_NEWNET); r.err != nil {
			return
		}
		peer, err := netlink.LinkByName("xuip1")
		if r.err = err; err != nil {
			return
		}
		if r.err = netlink.LinkSetNsFd(peer, b); r.err != nil {
			return
		}
		addr := func(name, cidr string) error {
			l, err := netlink.LinkByName(name)
			if err != nil {
				return err
			}
			ip, _ := netlink.ParseAddr(cidr)
			if err := netlink.AddrAdd(l, ip); err != nil {
				return err
			}
			return netlink.LinkSetUp(l)
		}
		inB(func() error { return addr("xuip1", "192.0.2.1/24") })
		if r.err != nil {
			return
		}
		if r.err = addr("xuip0", "192.0.2.2/24"); r.err != nil {
			return
		}
		routes := []hw.Route{{Dev: "xuip0", Gateway: net.ParseIP("192.0.2.1").To4()}}
		p := sysProber{}
		r.icmp = p.Pick(routes, time.Now().Add(5*time.Second))
		inB(func() error { return os.WriteFile("/proc/sys/net/ipv4/icmp_echo_ignore_all", []byte("1\n"), 0) })
		if r.err != nil {
			return
		}
		// Forget the neighbour, so the probe must resolve it again.
		if l, err := netlink.LinkByName("xuip0"); err == nil {
			neighs, _ := netlink.NeighList(l.Attrs().Index, netlink.FAMILY_V4)
			for _, n := range neighs {
				_ = netlink.NeighDel(&n)
			}
		}
		r.neigh = p.Pick(routes, time.Now().Add(5*time.Second))
		inB(func() error {
			l, err := netlink.LinkByName("xuip1")
			if err != nil {
				return err
			}
			return netlink.LinkSetDown(l)
		})
		if r.err != nil {
			return
		}
		if !p.Reach(r.neigh, time.Now().Add(2*time.Second)) && !p.Reach(r.icmp, time.Now().Add(time.Second)) {
			r.none = "none"
		}
	}()
	r := <-done
	if r.err != nil {
		t.Fatal(r.err)
	}
	if r.icmp != "icmp xuip0 192.0.2.1" {
		t.Errorf("icmp: %q", r.icmp)
	}
	if !strings.HasPrefix(r.neigh, "neigh xuip0 192.0.2.1") {
		t.Errorf("neighbour: %q", r.neigh)
	}
	if r.none != "none" {
		t.Error("a probe answered with the gateway down")
	}
}
