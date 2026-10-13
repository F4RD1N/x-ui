package hw_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/util/hw"
	"github.com/mhsanaei/3x-ui/v2/util/hw/hwtest"
)

func routesText(rs []hw.Route) string {
	var s []string
	for _, r := range rs {
		s = append(s, fmt.Sprintf("%s via %v v6=%v metric %d", r.Dev, r.Gateway, r.V6, r.Metric))
	}
	return strings.Join(s, "; ")
}

func uplinksText(ups []hw.Uplink) string {
	var s []string
	for _, u := range ups {
		s = append(s, fmt.Sprintf("%s via %v (%d routes)", u.Name, u.Via, len(u.Routes)))
	}
	return strings.Join(s, "; ")
}

func TestDefaultRoutes(t *testing.T) {
	b := hwtest.Production().Build(t)
	got := routesText(hw.DefaultRoutes(b.FS()))
	if want := "eno1 via 76.164.201.1 v6=false metric 0; eno1 via fe80::1 v6=true metric 1024"; got != want {
		t.Errorf("production routes: %s", got)
	}

	// The kernel's own format: ECMP and metric-ordered lines all kept,
	// reject routes and lo dropped, the subnet routes ignored.
	b.WriteFile("/proc/net/route", `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	01011FAC	0003	0	0	100	00000000	0	0	0
eth1	00000000	01021FAC	0003	0	0	100	00000000	0	0	0
eth0	00000000	01011FAC	0003	0	0	1002	00000000	0	0	0
*	00000000	00000000	0201	0	0	0	00000000	0	0	0
eth2	00000000	00000000	0000	0	0	0	00000000	0	0	0
eth0	01011FAC	00000000	0005	0	0	100	FFFFFFFF	0	0	0
`)
	b.WriteFile("/proc/net/ipv6_route", `00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo
2a0104f81c1b1c580000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000002 00000000 00000001     eth0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000009 00000000 00000003     eth0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000002 00000400 00000009 00000000 00000003     eth1
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000400 00000009 00000000 00000201     eth0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000400 00000009 00000000 00000001      wg0
`)
	got = routesText(hw.DefaultRoutes(b.FS()))
	want := "eth0 via 172.31.1.1 v6=false metric 100; eth1 via 172.31.2.1 v6=false metric 100; eth0 via 172.31.1.1 v6=false metric 1002; " +
		"eth0 via fe80::1 v6=true metric 1024; eth1 via fe80::2 v6=true metric 1024; wg0 via <nil> v6=true metric 1024"
	if got != want {
		t.Errorf("routes:\n got %s\nwant %s", got, want)
	}
	if rs := hw.DefaultRoutes(hw.FS{Root: t.TempDir()}); len(rs) != 0 {
		t.Errorf("no files: %v", rs)
	}
}

func TestUplinks(t *testing.T) {
	nested := hwtest.Bond()
	nested.Bridges = []hwtest.BridgeSpec{{Name: "vmbr0", Ports: []string{"bond0", "tap101i0"}}}
	nested.Routes = []hwtest.RouteSpec{{Dev: "vmbr0", Gateway: "192.0.2.1"}}
	noRoute := hwtest.Desktop()
	noRoute.Routes = nil
	for _, c := range []struct {
		name  string
		m     hwtest.Machine
		ups   string
		notes []string
	}{
		{"production", hwtest.Production(), "eno1 via [] (2 routes)", nil},
		{"bond", hwtest.Bond(), "eno1 via [bond0] (2 routes); eno2 via [bond0] (2 routes)", nil},
		{"bridge", hwtest.ProxmoxBridge(), "eno1 via [vmbr0] (1 routes)", nil},
		{"bridge over bond", nested, "eno1 via [vmbr0 bond0] (1 routes); eno2 via [vmbr0 bond0] (1 routes)", nil},
		{"vlan", hwtest.VLAN(), "eno1 via [eno1.100] (1 routes)", nil},
		{"vps", hwtest.VPS(1), "eth0 via [] (2 routes)", nil},
		{"tunnel", hwtest.Tunnel(), "", []string{"the default route leaves through wg0 (a tunnel): no NIC under it"}},
		{"container", hwtest.Container(), "", []string{"the default route leaves through eth0 (a container's veth link): no NIC under it"}},
		{"no route", noRoute, "", []string{"no default route"}},
	} {
		b := c.m.Build(t)
		ups, notes := hw.Uplinks(b.FS())
		if got := uplinksText(ups); got != c.ups || !slices.Equal(notes, c.notes) {
			t.Errorf("%s: %s %q", c.name, got, notes)
		}
	}

	// A bridge with only VM ports, and a route through a device that is
	// not here.
	m := hwtest.ProxmoxBridge()
	m.Bridges = []hwtest.BridgeSpec{{Name: "vmbr1", Ports: []string{"tap100i0"}}}
	m.Routes = []hwtest.RouteSpec{{Dev: "vmbr1", Gateway: "192.0.2.1"}, {Dev: "ghost0", V6: true}}
	b := m.Build(t)
	ups, notes := hw.Uplinks(b.FS())
	if len(ups) != 0 || !slices.Equal(notes, []string{"the default route leaves through vmbr1 (bridge): no NIC under it",
		"the default route leaves through ghost0, which is not visible here: no NIC under it"}) {
		t.Errorf("bridge without NIC: %v %q", ups, notes)
	}
}

func TestLinkKindAndUplinkNode(t *testing.T) {
	m := hwtest.Bond()
	m.Bridges = []hwtest.BridgeSpec{{Name: "vmbr0", Ports: []string{"bond0"}}}
	m.VLANs = []hwtest.VLANSpec{{Name: "vmbr0.5", Lower: "vmbr0", ID: 5}}
	m.Links = []hwtest.LinkSpec{{Name: "wg0", Kind: "wireguard"}}
	b := m.Build(t)
	for dev, want := range map[string]string{"bond0": "bond", "vmbr0": "bridge", "vmbr0.5": "vlan", "wg0": "wireguard", "eno1": "", "lo": "", "nothing": ""} {
		if got := hw.LinkKind(b.FS(), dev); got != want {
			t.Errorf("LinkKind(%s) = %q", dev, got)
		}
	}
	for name, c := range map[string]struct {
		m    hwtest.Machine
		want int
	}{
		"production": {hwtest.Production(), 1}, "epyc": {hwtest.EPYC(4), 0}, "desktop": {hwtest.Desktop(), -1},
		"vps": {hwtest.VPS(2), -1}, "tunnel": {hwtest.Tunnel(), -1}, "bond": {hwtest.Bond(), 1}, "bridge": {hwtest.ProxmoxBridge(), 0},
	} {
		if got := hw.UplinkNode(c.m.Build(t).FS()); got != c.want {
			t.Errorf("UplinkNode(%s) = %d", name, got)
		}
	}
}
