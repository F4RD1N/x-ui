package service

// The panel's network speed and traffic count only the interfaces that carry
// a default route (the uplink). Adding up every interface counts each packet
// more than once on servers with stacked interfaces: a bond and its member
// cards, a VLAN and its parent, a GRE tunnel and the uplink it rides on.

import (
	"bufio"
	"os"
	"strings"

	"github.com/shirou/gopsutil/v4/net"
)

// Replaced in tests.
var (
	ipv4RouteFile = "/proc/net/route"
	ipv6RouteFile = "/proc/net/ipv6_route"
)

// defaultRouteInterfaces returns the interfaces of the IPv4 and IPv6 default
// routes.
func defaultRouteInterfaces() map[string]bool {
	names := map[string]bool{}
	if f, err := os.Open(ipv4RouteFile); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			// Iface Destination Gateway Flags RefCnt Use Metric Mask ...
			fields := strings.Fields(sc.Text())
			if len(fields) >= 8 && fields[1] == "00000000" && fields[7] == "00000000" && fields[0] != "lo" {
				names[fields[0]] = true
			}
		}
		f.Close()
	}
	if f, err := os.Open(ipv6RouteFile); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			// dest prefixlen src srcprefixlen nexthop metric refcnt use flags dev
			fields := strings.Fields(sc.Text())
			if len(fields) >= 10 && fields[0] == strings.Repeat("0", 32) && fields[1] == "00" && fields[9] != "lo" {
				names[fields[9]] = true
			}
		}
		f.Close()
	}
	return names
}

// uplinkTraffic sums the counters of the uplink interfaces. Without a default
// route it falls back to every interface but the loopback.
func uplinkTraffic(stats []net.IOCountersStat, uplinks map[string]bool) (sent, recv uint64) {
	found := false
	for _, s := range stats {
		if uplinks[s.Name] {
			sent += s.BytesSent
			recv += s.BytesRecv
			found = true
		}
	}
	if found {
		return sent, recv
	}
	for _, s := range stats {
		if s.Name != "lo" {
			sent += s.BytesSent
			recv += s.BytesRecv
		}
	}
	return sent, recv
}
