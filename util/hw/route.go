package hw

import (
	"encoding/hex"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
)

// Route is a default route of the main table.
type Route struct {
	Dev     string `json:"dev"`
	Gateway net.IP `json:"gateway,omitempty"` // nil: on-link
	V6      bool   `json:"v6,omitempty"`
	Metric  int    `json:"metric"`
}

const (
	rtfUp     = 0x0001
	rtfReject = 0x0200
)

// DefaultRoutes lists the default routes, IPv4 first, in the kernel's order.
// Every line is kept, so ECMP and metric-ordered alternatives all show.
func DefaultRoutes(fs FS) []Route {
	var out []Route
	// Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
	for _, l := range strings.Split(fs.ReadTrim("/proc/net/route"), "\n") {
		f := strings.Fields(l)
		if len(f) < 8 || f[0] == "Iface" || f[0] == "*" || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil || flags&rtfUp == 0 || flags&rtfReject != 0 {
			continue
		}
		r := Route{Dev: f[0]}
		r.Metric, _ = strconv.Atoi(f[6])
		if gw, err := strconv.ParseUint(f[2], 16, 32); err == nil && gw != 0 {
			// Little-endian: "0101A8C0" is 192.168.1.1.
			r.Gateway = net.IPv4(byte(gw), byte(gw>>8), byte(gw>>16), byte(gw>>24)).To4()
		}
		out = append(out, r)
	}
	// dst dst_len src src_len next_hop metric refcnt use flags dev
	for _, l := range strings.Split(fs.ReadTrim("/proc/net/ipv6_route"), "\n") {
		f := strings.Fields(l)
		if len(f) < 10 || f[0] != strings.Repeat("0", 32) || f[1] != "00" || f[9] == "lo" {
			continue
		}
		flags, err := strconv.ParseUint(f[8], 16, 32)
		if err != nil || flags&rtfUp == 0 || flags&rtfReject != 0 {
			continue
		}
		r := Route{Dev: f[9], V6: true}
		if m, err := strconv.ParseUint(f[5], 16, 32); err == nil {
			r.Metric = int(m)
		}
		if f[4] != strings.Repeat("0", 32) {
			if b, err := hex.DecodeString(f[4]); err == nil && len(b) == 16 {
				r.Gateway = net.IP(b)
			}
		}
		out = append(out, r)
	}
	return out
}

// Uplink is a network device a default route leaves through: a physical NIC,
// a virtio NIC or an SR-IOV VF, found under the route's device.
type Uplink struct {
	Name   string   `json:"name"`
	Via    []string `json:"via,omitempty"` // the devices above it, the route's device first ("vmbr0", "bond0")
	Routes []Route  `json:"routes"`        // the default routes leaving through it
}

// tunnelKinds are uevent DEVTYPEs of devices that wrap traffic in another
// protocol: what leaves through them is sent again by some other device.
var tunnelKinds = []string{"wireguard", "tun", "tap", "gre", "gretap", "ip6gre", "ip6gretap", "ipip", "sit", "ip6tnl", "vxlan", "geneve", "erspan", "ipsec", "xfrm", "l2tp"}

// Uplinks resolves the default routes to the devices under them: a route's
// device when it has a hardware device, else the devices below it (bond,
// team, bridge, VLAN, macvlan, ipvlan), recursively. Bridge ports without a
// device (tap, veth) drop out. Notes say why a route has no uplink.
func Uplinks(fs FS) (ups []Uplink, notes []string) {
	routes := DefaultRoutes(fs)
	if len(routes) == 0 {
		return nil, []string{"no default route"}
	}
	byName := map[string]int{}
	for _, r := range routes {
		found := lowerDevices(fs, r.Dev, nil, 0)
		if len(found) == 0 {
			if n := noUplinkNote(fs, r.Dev); !slices.Contains(notes, n) {
				notes = append(notes, n)
			}
			continue
		}
		for _, f := range found {
			if i, ok := byName[f.name]; ok {
				ups[i].Routes = append(ups[i].Routes, r)
				continue
			}
			byName[f.name] = len(ups)
			ups = append(ups, Uplink{Name: f.name, Via: f.via, Routes: []Route{r}})
		}
	}
	return ups, notes
}

type lowerHit struct {
	name string
	via  []string
}

func lowerDevices(fs FS, name string, via []string, depth int) []lowerHit {
	if depth > 8 || name == "" || strings.ContainsAny(name, "/") {
		return nil
	}
	base := "/sys/class/net/" + name
	if !fs.Exists(base) {
		return nil
	}
	if fs.Exists(base + "/device") {
		return []lowerHit{{name: name, via: slices.Clone(via)}}
	}
	var out []lowerHit
	for _, e := range fs.ReadDir(base) {
		low, ok := strings.CutPrefix(e, "lower_")
		if !ok {
			continue
		}
		out = append(out, lowerDevices(fs, low, append(slices.Clone(via), name), depth+1)...)
	}
	return out
}

func noUplinkNote(fs FS, dev string) string {
	base := "/sys/class/net/" + dev
	if !fs.Exists(base) {
		return fmt.Sprintf("the default route leaves through %s, which is not visible here: no NIC under it", dev)
	}
	kind := LinkKind(fs, dev)
	switch {
	case slices.Contains(tunnelKinds, kind) || (kind == "" && fs.Exists(base+"/tun_flags")):
		return fmt.Sprintf("the default route leaves through %s (a tunnel): no NIC under it", dev)
	case kind == "" && isVeth(fs, dev):
		return fmt.Sprintf("the default route leaves through %s (a container's veth link): no NIC under it", dev)
	case kind != "":
		return fmt.Sprintf("the default route leaves through %s (%s): no NIC under it", dev, kind)
	}
	return fmt.Sprintf("the default route leaves through %s (a virtual device): no NIC under it", dev)
}

// isVeth guesses a veth device: no hardware, and its link is another
// device (the peer) rather than itself.
func isVeth(fs FS, dev string) bool {
	base := "/sys/class/net/" + dev
	idx, l := fs.ReadTrim(base+"/ifindex"), fs.ReadTrim(base+"/iflink")
	return idx != "" && l != "" && idx != l
}

// LinkKind is a network device's uevent DEVTYPE ("bond", "bridge", "vlan",
// "macvlan", "ipvlan", "team", "wireguard", ...), "" for a plain device.
func LinkKind(fs FS, name string) string {
	for _, l := range strings.Split(fs.ReadTrim("/sys/class/net/"+name+"/uevent"), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "DEVTYPE="); ok {
			return v
		}
	}
	return ""
}

// UplinkNode is the NUMA node of the first uplink whose node is known, -1
// when none is.
func UplinkNode(fs FS) int {
	ups, _ := Uplinks(fs)
	for _, u := range ups {
		if n := nicNode(fs, pciDir(fs, u.Name)); n >= 0 {
			return n
		}
	}
	return -1
}
