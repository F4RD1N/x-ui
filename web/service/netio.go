package service

import (
	stdnet "net"
	"os"
	"path/filepath"

	"github.com/shirou/gopsutil/v4/net"
)

// The panel's network speed and totals count the host's uplinks once.
//
// net.IOCounters(false) sums every interface, and a byte that leaves through
// a bond is counted on the bond and again on the port it went out of; so on a
// server with two bonded 10G ports the panel showed about twice the real
// speed (3.8 GB/s for 16 Gbps each way). Loopback -- the panel's calls to the
// cores, DNS through the local cache -- was added in as well.

// sysClassNet is where the interfaces are described; tests point it elsewhere.
var sysClassNet = "/sys/class/net"

// hostNetCounters returns the bytes sent and received on the interfaces
// countedInterfaces picks.
func hostNetCounters() (sent, recv uint64, err error) {
	stats, err := net.IOCounters(true)
	if err != nil {
		return 0, 0, err
	}
	names := make([]string, 0, len(stats))
	for _, s := range stats {
		names = append(names, s.Name)
	}
	counted := countedInterfaces(sysClassNet, names, loopbackNames())
	for _, s := range stats {
		if counted[s.Name] {
			sent += s.BytesSent
			recv += s.BytesRecv
		}
	}
	return sent, recv, nil
}

// countedInterfaces picks the interfaces whose traffic is the host's: each
// physical NIC, except that one in a bond (or any other master but a bridge)
// is counted as its master, once. Bridges, VLANs, veths, tunnels and loopback
// carry traffic that a physical NIC counts too, or none of the host's, and
// are left out. Where no interface is physical (a container's veth), every
// interface but loopback and ports of another interface is counted.
func countedInterfaces(root string, names []string, loopback map[string]bool) map[string]bool {
	counted := map[string]bool{}
	for _, n := range names {
		// A physical NIC has a device link (to its PCI, virtio... device).
		if _, err := os.Lstat(filepath.Join(root, n, "device")); err != nil {
			continue
		}
		if m := masterOf(root, n); m != "" {
			if _, err := os.Stat(filepath.Join(root, m, "bridge")); err != nil {
				counted[m] = true
				continue
			}
		}
		counted[n] = true
	}
	if len(counted) > 0 {
		return counted
	}
	for _, n := range names {
		if !loopback[n] && masterOf(root, n) == "" {
			counted[n] = true
		}
	}
	return counted
}

// masterOf names the interface n is a port of (a bond, a bridge...), if any.
func masterOf(root, n string) string {
	l, err := os.Readlink(filepath.Join(root, n, "master"))
	if err != nil {
		return ""
	}
	return filepath.Base(l)
}

func loopbackNames() map[string]bool {
	lo := map[string]bool{}
	ifs, err := stdnet.Interfaces()
	if err != nil {
		return lo
	}
	for _, i := range ifs {
		if i.Flags&stdnet.FlagLoopback != 0 {
			lo[i.Name] = true
		}
	}
	return lo
}
