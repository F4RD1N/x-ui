package service

// Outgoing IP pools chosen in the outbound form: the admin picks one of the
// server's IPv4 ranges for an outbound, and every time the config is built that
// outbound's sendThrough becomes the range's usable addresses ("ip1,ip2,...",
// see the core's sendThrough pools). The choice is kept per outbound tag in its
// own setting, not in the template, so a template fetched from a URL does not
// wipe it, and the addresses are read from the machine at every build.

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/json_util"
)

// IPRange is one IPv4 network the server has addresses in, with the addresses
// an outbound may send from: the server's own, without the network, broadcast
// and gateway addresses.
type IPRange struct {
	CIDR  string   `json:"cidr"`  // the interface network: the stored value
	Label string   `json:"label"` // what the dropdown shows: the addresses themselves
	IPs   []string `json:"ips"`
}

// ipNoneValue is the dropdown's "none": the outbound keeps its own sendThrough.
const ipNoneValue = "none"

// Replaced in tests.
var (
	interfaceAddrs = defaultInterfaceAddrs
	gatewayAddrs   = defaultGateways
)

type ifaceAddr struct {
	ip  netip.Addr
	net netip.Prefix
}

func defaultInterfaceAddrs() ([]ifaceAddr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []ifaceAddr
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipn.IP.To4()
			if ip4 == nil {
				continue
			}
			ip, _ := netip.AddrFromSlice(ip4)
			ones, _ := ipn.Mask.Size()
			if !ip.IsGlobalUnicast() {
				continue
			}
			out = append(out, ifaceAddr{ip: ip, net: netip.PrefixFrom(ip, ones).Masked()})
		}
	}
	return out, nil
}

// defaultGateways reads the IPv4 gateways of the routing table.
func defaultGateways() map[netip.Addr]bool {
	gws := map[netip.Addr]bool{}
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return gws
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 || fields[0] == "Iface" {
			continue
		}
		var gw uint32
		if _, err := fmt.Sscanf(fields[2], "%X", &gw); err != nil || gw == 0 {
			continue
		}
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], gw)
		gws[netip.AddrFrom4(b)] = true
	}
	return gws
}

// LocalIPv4Ranges lists the server's IPv4 networks with their usable addresses.
func LocalIPv4Ranges() ([]IPRange, error) {
	addrs, err := interfaceAddrs()
	if err != nil {
		return nil, err
	}
	gws := gatewayAddrs()
	byNet := map[netip.Prefix]map[netip.Addr]bool{}
	for _, a := range addrs {
		if byNet[a.net] == nil {
			byNet[a.net] = map[netip.Addr]bool{}
		}
		p := a.net
		if p.Bits() <= 30 && (a.ip == p.Addr() || a.ip == lastAddr(p)) {
			continue // network or broadcast address
		}
		if gws[a.ip] {
			continue
		}
		byNet[a.net][a.ip] = true
	}
	var out []IPRange
	for p, set := range byNet {
		if len(set) == 0 {
			continue
		}
		r := IPRange{CIDR: p.String()}
		var ips []netip.Addr
		for ip := range set {
			ips = append(ips, ip)
		}
		sort.Slice(ips, func(i, j int) bool { return ips[i].Less(ips[j]) })
		for _, ip := range ips {
			r.IPs = append(r.IPs, ip.String())
		}
		r.Label = ipRunsLabel(ips)
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		a, _ := netip.ParsePrefix(out[i].CIDR)
		b, _ := netip.ParsePrefix(out[j].CIDR)
		return a.Addr().Less(b.Addr())
	})
	return out, nil
}

// ipRunsLabel names a set of addresses by what it holds, since the interface
// network (often a /24 a provider shares between customers) says nothing about
// which of its addresses are the server's: "193.16.145.140 – .143",
// "103.76.130.12, .79, .99". After the first, an address in the same /24 as
// the one before it is shortened to its last octet.
func ipRunsLabel(ips []netip.Addr) string {
	var runs [][2]netip.Addr
	for _, ip := range ips {
		if n := len(runs); n > 0 && runs[n-1][1].Next() == ip {
			runs[n-1][1] = ip
			continue
		}
		runs = append(runs, [2]netip.Addr{ip, ip})
	}
	var parts []string
	var prev netip.Addr
	short := func(ip netip.Addr) string {
		if prev.IsValid() && sameSlash24(prev, ip) {
			return "." + strings.Split(ip.String(), ".")[3]
		}
		return ip.String()
	}
	for _, r := range runs {
		s := short(r[0])
		prev = r[0]
		if r[1] != r[0] {
			s += " – " + short(r[1])
			prev = r[1]
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ", ")
}

func sameSlash24(a, b netip.Addr) bool {
	x, y := a.As4(), b.As4()
	return x[0] == y[0] && x[1] == y[1] && x[2] == y[2]
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	n := binary.BigEndian.Uint32(b[:]) | (uint32(1)<<(32-p.Bits()) - 1)
	binary.BigEndian.PutUint32(b[:], n)
	return netip.AddrFrom4(b)
}

// ParseOutboundIPPools reads the setting: outbound tag -> CIDR. "none" and
// empty values are dropped; anything else must be an IPv4 prefix.
func ParseOutboundIPPools(raw string) (map[string]string, error) {
	pools := map[string]string{}
	if strings.TrimSpace(raw) == "" {
		return pools, nil
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, fmt.Errorf("outbound IP pools: %w", err)
	}
	for tag, v := range m {
		v = strings.TrimSpace(v)
		if tag == "" || v == "" || v == ipNoneValue {
			continue
		}
		p, err := netip.ParsePrefix(v)
		if err != nil || !p.Addr().Is4() {
			return nil, fmt.Errorf("outbound IP pools: %q is not an IPv4 range", v)
		}
		pools[tag] = p.Masked().String()
	}
	return pools, nil
}

// withIPPools sets sendThrough of each outbound that has a pool to the
// usable addresses of its range. An outbound whose range is no longer on the
// server keeps its own sendThrough.
func withIPPools(raw json_util.RawMessage, pools map[string]string) json_util.RawMessage {
	if len(raw) == 0 || len(pools) == 0 {
		return raw
	}
	ranges, err := LocalIPv4Ranges()
	if err != nil {
		logger.Warning("outbound IP pools: cannot read the server's addresses:", err)
		return raw
	}
	byCIDR := map[string][]string{}
	for _, r := range ranges {
		byCIDR[r.CIDR] = r.IPs
	}
	var obs []map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if dec.Decode(&obs) != nil {
		return raw
	}
	changed := false
	for _, ob := range obs {
		if ob == nil {
			continue
		}
		tag, _ := ob["tag"].(string)
		cidr, ok := pools[tag]
		if !ok {
			continue
		}
		ips := byCIDR[cidr]
		if len(ips) == 0 {
			logger.Warning("outbound IP pools: ", cidr, " (outbound ", tag, ") is not on this server; its sendThrough is kept")
			continue
		}
		ob["sendThrough"] = strings.Join(ips, ",")
		changed = true
	}
	if !changed {
		return raw
	}
	out, err := json.Marshal(obs)
	if err != nil {
		return raw
	}
	return out
}
