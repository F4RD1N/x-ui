package service

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/util/json_util"
	"github.com/mhsanaei/3x-ui/v2/util/sys"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

func stubHostAddresses(t *testing.T, ips ...string) {
	t.Helper()
	old := hostAddressList
	hostAddressList = func() ([]hostIP, error) {
		var out []hostIP
		for _, s := range ips {
			ip := net.ParseIP(s)
			if v4 := ip.To4(); v4 != nil {
				ip = v4
			}
			out = append(out, hostIP{IP: ip, Iface: "eth0"})
		}
		return out, nil
	}
	t.Cleanup(func() { hostAddressList = old })
}

// stubLinkDown makes every stubbed address sit on eth0, up but without its
// carrier, and eth0 the interface of the default route: the uplink drops.
func stubLinkDown(t *testing.T, ips ...string) {
	t.Helper()
	stubHostAddresses(t, ips...)
	up := hostAddressList
	hostAddressList = func() ([]hostIP, error) {
		list, err := up()
		for i := range list {
			list[i].NoCarrier = true
		}
		return list, err
	}
	stubDefaultRoute(t, "eth0")
}

func stubDefaultRoute(t *testing.T, ifaces ...string) {
	t.Helper()
	old := defaultRouteIfaces
	defaultRouteIfaces = func() map[string]bool {
		m := map[string]bool{}
		for _, n := range ifaces {
			m[n] = true
		}
		return m
	}
	t.Cleanup(func() { defaultRouteIfaces = old })
}

func TestHostAddressesOf(t *testing.T) {
	cidr := func(s string) net.Addr {
		ip, n, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		n.IP = ip
		return n
	}
	got := hostAddressesOf([]hostIface{
		{Name: "lo", Flags: net.FlagUp | net.FlagRunning | net.FlagLoopback, Addrs: []net.Addr{cidr("127.0.0.1/8")}},
		{Name: "eth0", Flags: net.FlagUp | net.FlagRunning, Addrs: []net.Addr{cidr("192.0.2.7/31"), cidr("fe80::1/64"), cidr("2001:db8::7/64")}},
		// Up, but the link is down: its addresses are listed, marked.
		{Name: "eth1", Flags: net.FlagUp, Addrs: []net.Addr{cidr("198.51.100.2/25"), cidr("198.51.100.3/25")}},
		// Down: nothing.
		{Name: "eth2", Flags: 0, Addrs: []net.Addr{cidr("203.0.113.9/24")}},
		{Name: "mc", Flags: net.FlagUp | net.FlagRunning, Addrs: []net.Addr{cidr("224.0.0.1/32"), cidr("0.0.0.0/0")}},
	})
	want := []string{"192.0.2.7 eth0 false", "2001:db8::7 eth0 false", "198.51.100.2 eth1 true", "198.51.100.3 eth1 true"}
	var have []string
	for _, a := range got {
		if a.IP.To4() != nil && len(a.IP) != net.IPv4len {
			t.Errorf("%s is not in its 4-byte form", a.IP)
		}
		have = append(have, a.IP.String()+" "+a.Iface+" "+map[bool]string{true: "true", false: "false"}[a.NoCarrier])
	}
	if strings.Join(have, "; ") != strings.Join(want, "; ") {
		t.Errorf("got %q\nwant %q", have, want)
	}
}

func TestParseDefaultRoutes(t *testing.T) {
	route := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"ens1f1np1\t00000000\t92B4292E\t0003\t0\t0\t0\t00000000\t0\t0\t0\n" +
		"ens1f1np1\t92B4292E\t00000000\t0001\t0\t0\t0\tFEFFFFFF\t0\t0\t0\n" +
		"docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n" +
		"wg0\t00000000\t00000000\t0001\t0\t0\t0\t00000080\t0\t0\t0\n"
	got := parseDefaultRoutes([]byte(route))
	if len(got) != 1 || !got["ens1f1np1"] {
		t.Errorf("default route interfaces %v", got)
	}
}

// stubClock gives EgressOutOfLine a clock the test moves, and clears what an
// earlier check left behind.
func stubClock(t *testing.T) *time.Time {
	t.Helper()
	now := time.Date(2026, 10, 14, 19, 0, 0, 0, time.UTC)
	old := egressNow
	egressNow = func() time.Time { return now }
	egressDriftMu.Lock()
	egressDriftSince = time.Time{}
	egressDriftMu.Unlock()
	t.Cleanup(func() {
		egressNow = old
		egressDriftMu.Lock()
		egressDriftSince = time.Time{}
		egressDriftMu.Unlock()
	})
	return &now
}

func stubProbe(t *testing.T, err error) {
	t.Helper()
	old := egressProbe
	egressProbe = func(net.IP) error { return err }
	t.Cleanup(func() { egressProbe = old })
}

func TestWithEgress(t *testing.T) {
	raw := json_util.RawMessage(`[
		{"tag":"direct","protocol":"freedom","settings":{"domainStrategy":"AsIs"}},
		{"tag":"own","protocol":"freedom","sendThrough":"10.0.0.9"},
		{"tag":"chained","protocol":"freedom","proxySettings":{"tag":"up"}},
		{"tag":"dialer","protocol":"freedom","streamSettings":{"sockopt":{"dialerProxy":"up"}}},
		{"tag":"iface","protocol":"freedom","streamSettings":{"sockopt":{"interface":"eth1"}}},
		{"tag":"mark","protocol":"freedom","streamSettings":{"sockopt":{"mark":4294967295}}},
		{"tag":"blocked","protocol":"blackhole","settings":{}},
		{"tag":"alias","protocol":"direct"},
		{"tag":"case","protocol":"Freedom"},
		{"tag":"v6","protocol":"freedom","settings":{"domainStrategy":"UseIPv6"}},
		{"tag":"v6first","protocol":"freedom","settings":{"targetStrategy":"forceipv6v4"}},
		{"tag":"v6sockopt","protocol":"freedom","streamSettings":{"sockopt":{"domainStrategy":"ForceIPv6"}}},
		{"tag":"v4","protocol":"freedom","settings":{"domainStrategy":"UseIPv4v6"}}
	]`)
	var obs []map[string]any
	if err := json.Unmarshal(withEgress(raw, "192.0.2.7"), &obs); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"direct": "192.0.2.7", "own": "10.0.0.9", "chained": "", "dialer": "", "iface": "", "mark": "192.0.2.7", "blocked": "",
		"alias": "192.0.2.7", "case": "192.0.2.7", "v6": "", "v6first": "", "v6sockopt": "", "v4": "192.0.2.7"}
	for _, ob := range obs {
		tag := ob["tag"].(string)
		got, _ := ob["sendThrough"].(string)
		if got != want[tag] {
			t.Errorf("%s: sendThrough %q, want %q", tag, got, want[tag])
		}
	}
	if !strings.Contains(string(withEgress(raw, "192.0.2.7")), "4294967295") {
		t.Error("a large number in another setting lost its precision")
	}
	if got := withEgress(raw, ""); string(got) != string(raw) {
		t.Error("no outgoing IP changed the outbounds")
	}
	none := json_util.RawMessage(`[{"tag":"blocked","protocol":"blackhole"}]`)
	if got := withEgress(none, "192.0.2.7"); string(got) != string(none) {
		t.Error("outbounds without freedom were rewritten")
	}
}

func TestApplyEgressSkipsAddressNotOnHost(t *testing.T) {
	stubHostAddresses(t, "192.0.2.7")
	outbounds := json_util.RawMessage(`[{"tag":"direct","protocol":"freedom"}]`)
	plan := &instancePlan{configs: map[string]*xray.Config{
		"xray-1": {OutboundConfigs: outbounds},
		"xray-2": {OutboundConfigs: outbounds},
		"xray-3": {OutboundConfigs: outbounds},
	}}
	applied := applyEgress(plan, map[string]string{"xray-1": "192.0.2.7", "xray-2": "198.51.100.1"})
	if len(applied) != 1 || applied["xray-1"] != "192.0.2.7" {
		t.Errorf("applied %v", applied)
	}
	if !strings.Contains(string(plan.configs["xray-1"].OutboundConfigs), `"sendThrough":"192.0.2.7"`) {
		t.Error("xray-1 did not get its outgoing IP")
	}
	if strings.Contains(string(plan.configs["xray-2"].OutboundConfigs), "sendThrough") {
		t.Error("xray-2 was sent from an address the host does not have")
	}
	if strings.Contains(string(plan.configs["xray-3"].OutboundConfigs), "sendThrough") {
		t.Error("xray-3 has no outgoing IP but got one")
	}
}

func TestSetInstanceEgress(t *testing.T) {
	dir := t.TempDir()
	if err := database.InitDB(filepath.Join(dir, "x-ui.db")); err != nil {
		t.Fatal(err)
	}
	defer database.CloseDB()
	in := vlessInbound(t, "xray-1", 0)
	if err := database.GetDB().Create(in).Error; err != nil {
		t.Fatal(err)
	}
	stubHostAddresses(t, "192.0.2.7", "2001:db8::7")
	stubProbe(t, nil)
	// Nothing runs: the setting is stored for the next start.
	isManuallyStopped.Store(true)
	defer isManuallyStopped.Store(false)

	var xs XrayService
	var ss SettingService
	if err := xs.SetInstanceEgress("xray-1", " 192.0.2.7 "); err != nil {
		t.Fatal(err)
	}
	if m, _ := ss.GetInstanceEgress(); m["xray-1"] != "192.0.2.7" {
		t.Fatalf("stored %v", m)
	}
	for _, c := range []struct{ name, ip, want string }{
		{"xray-9", "192.0.2.7", "no inbound runs"},
		{"xray-1", "198.51.100.1", "not an address of this server"},
		{"xray-1", "nonsense", "not an IP address"},
	} {
		err := xs.SetInstanceEgress(c.name, c.ip)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("SetInstanceEgress(%q, %q) = %v, want an error about %q", c.name, c.ip, err, c.want)
		}
	}
	// An IPv6 address would cut the instance off from IPv4.
	if err := xs.SetInstanceEgress("xray-1", "2001:db8::7"); err == nil || !strings.Contains(err.Error(), "IPv4") {
		t.Errorf("an IPv6 outgoing IP was accepted: %v", err)
	}
	stubProbe(t, errors.New("timeout"))
	if err := xs.SetInstanceEgress("xray-1", "192.0.2.7"); err == nil || !strings.Contains(err.Error(), "nothing on the internet answers") {
		t.Errorf("an address that reaches nothing was accepted: %v", err)
	}
	if m, _ := ss.GetInstanceEgress(); m["xray-1"] != "192.0.2.7" {
		t.Fatalf("a refused change was stored: %v", m)
	}
	// An instance that is gone keeps no outgoing IP: it is not listed as a
	// user, and clearing it works.
	ss.SetInstanceEgress(map[string]string{"xray-1": "192.0.2.7", "xray-3": "192.0.2.7"})
	addrs, err := xs.HostAddresses()
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 || addrs[0].IP != "192.0.2.7" || addrs[0].Iface != "eth0" || len(addrs[0].UsedBy) != 1 || addrs[0].UsedBy[0] != "xray-1" {
		t.Errorf("host addresses %+v", addrs)
	}
	if err := xs.SetInstanceEgress("xray-3", ""); err != nil {
		t.Fatalf("clearing a removed instance's outgoing IP: %v", err)
	}
	if err := xs.SetInstanceEgress("xray-1", ""); err != nil {
		t.Fatal(err)
	}
	if m, _ := ss.GetInstanceEgress(); len(m) != 0 {
		t.Fatalf("clearing left %v", m)
	}
}

// An instance's outgoing IP goes with the instance: the next instance that
// gets the name does not inherit it.
func TestEgressPrunedWithInstance(t *testing.T) {
	dir := t.TempDir()
	if err := database.InitDB(filepath.Join(dir, "x-ui.db")); err != nil {
		t.Fatal(err)
	}
	defer database.CloseDB()
	in := vlessInbound(t, "xray-1", 0)
	if err := database.GetDB().Create(in).Error; err != nil {
		t.Fatal(err)
	}
	var xs XrayService
	var ss SettingService
	ss.SetInstanceEgress(map[string]string{"xray-1": "192.0.2.7", "xray-2": "192.0.2.8"})
	m, _ := ss.GetInstanceEgress()
	xs.pruneEgress(m, []*model.Inbound{in})
	if m, _ := ss.GetInstanceEgress(); len(m) != 1 || m["xray-1"] != "192.0.2.7" {
		t.Fatalf("after pruning: %v", m)
	}
}

// runningInstance makes xray-1 a running core that was started sending from
// applied ("" for the default address), with its database in a temp folder.
func runningInstance(t *testing.T, applied string) {
	t.Helper()
	dir := t.TempDir()
	if err := database.InitDB(filepath.Join(dir, "x-ui.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.CloseDB() })
	p := xray.NewInstanceProcess("xray-1", &xray.Config{}, filepath.Join(dir, "c.json"), nil)
	// A process that runs is all it takes.
	if err := startSleeper(t, p); err != nil {
		t.Skip(err)
	}
	instMu.Lock()
	oldProcs, oldApplied := procs, egressApplied
	procs, egressApplied = map[string]*xray.Process{"xray-1": p}, map[string]string{}
	if applied != "" {
		egressApplied["xray-1"] = applied
	}
	instMu.Unlock()
	t.Cleanup(func() {
		instMu.Lock()
		procs, egressApplied = oldProcs, oldApplied
		instMu.Unlock()
	})
}

// A core started before its outgoing IP was on the host, or still sending
// from one that left it, is out of line -- once that has lasted.
func TestEgressOutOfLine(t *testing.T) {
	runningInstance(t, "")
	now := stubClock(t)
	var xs XrayService
	var ss SettingService
	// lasting reports whether the cores are applied again when the host
	// stays as it is for a minute of the panel's 30-second checks.
	lasting := func() bool {
		t.Helper()
		for i := 0; i < 3; i++ {
			if xs.EgressOutOfLine() {
				return true
			}
			*now = now.Add(30 * time.Second)
		}
		return false
	}

	if lasting() {
		t.Fatal("no outgoing IP, none applied")
	}
	ss.SetInstanceEgress(map[string]string{"xray-1": "192.0.2.7"})
	stubHostAddresses(t)
	if lasting() {
		t.Fatal("the address is not on the host yet: the default is right")
	}
	// A core goes onto its IP at the first check that finds it on the host.
	stubHostAddresses(t, "192.0.2.7")
	if !xs.EgressOutOfLine() {
		t.Fatal("the address came onto the host, and the core stays on the default address")
	}
	instMu.Lock()
	egressApplied = map[string]string{"xray-1": "192.0.2.7"}
	instMu.Unlock()
	if lasting() {
		t.Fatal("in line")
	}
	stubHostAddresses(t)
	if !lasting() {
		t.Fatal("the address left the host")
	}
}

// The panel checks every 30 seconds: a change is acted on at the third check
// that sees it, not before, and a check that finds the cores in line again
// starts the wait over.
func TestEgressOutOfLineWaits(t *testing.T) {
	runningInstance(t, "192.0.2.7")
	now := stubClock(t)
	var xs XrayService
	var ss SettingService
	ss.SetInstanceEgress(map[string]string{"xray-1": "192.0.2.7"})
	check := func(after time.Duration) bool {
		*now = now.Add(after)
		return xs.EgressOutOfLine()
	}

	// The address goes for one check and is back at the next.
	stubHostAddresses(t)
	if check(0) {
		t.Fatal("acted on the first check that saw the address gone")
	}
	stubHostAddresses(t, "192.0.2.7")
	if check(30 * time.Second) {
		t.Fatal("in line again")
	}
	stubHostAddresses(t)
	if check(30*time.Second) || check(30*time.Second) {
		t.Fatal("the wait did not start over when the address came back")
	}
	if !check(30 * time.Second) {
		t.Fatal("the address stayed gone for a minute, and the cores were left as they were")
	}
	// Acting on it starts the wait over.
	if check(30 * time.Second) {
		t.Fatal("acted twice on one change")
	}
}

// A link that drops for a few seconds -- the interface stays up, its
// addresses stay on it, only the carrier goes -- restarts no core: it keeps
// sending from its IP. The address cannot be chosen while the link is down.
func TestEgressKeptThroughLinkDrop(t *testing.T) {
	runningInstance(t, "192.0.2.7")
	now := stubClock(t)
	var xs XrayService
	var ss SettingService
	ss.SetInstanceEgress(map[string]string{"xray-1": "192.0.2.7"})
	stubLinkDown(t, "192.0.2.7")
	for i := 0; i < 6; i++ {
		if xs.EgressOutOfLine() {
			t.Fatalf("check %d during the link drop restarts the cores", i+1)
		}
		*now = now.Add(30 * time.Second)
	}

	outbounds := json_util.RawMessage(`[{"tag":"direct","protocol":"freedom"}]`)
	plan := &instancePlan{configs: map[string]*xray.Config{"xray-1": {OutboundConfigs: outbounds}}}
	if applied := applyEgress(plan, map[string]string{"xray-1": "192.0.2.7"}); applied["xray-1"] != "192.0.2.7" {
		t.Errorf("a core started during the link drop sends from the default address: %v", applied)
	}

	if isHostAddress(net.ParseIP("192.0.2.7")) {
		t.Error("an address without a link can be chosen as an outgoing IP")
	}
	if addrs, err := xs.HostAddresses(); err != nil || len(addrs) != 0 {
		t.Errorf("addresses offered without a link: %+v %v", addrs, err)
	}
}

// An address on another interface without a carrier -- a Docker bridge
// without containers -- is not kept: the default route has a link, so the
// core moves to the default address, after the wait.
func TestEgressNoCarrierOffTheUplink(t *testing.T) {
	runningInstance(t, "172.17.0.1")
	now := stubClock(t)
	var xs XrayService
	var ss SettingService
	ss.SetInstanceEgress(map[string]string{"xray-1": "172.17.0.1"})
	old := hostAddressList
	hostAddressList = func() ([]hostIP, error) {
		return []hostIP{
			{IP: net.ParseIP("192.0.2.7").To4(), Iface: "eth0"},
			{IP: net.ParseIP("172.17.0.1").To4(), Iface: "docker0", NoCarrier: true},
		}, nil
	}
	t.Cleanup(func() { hostAddressList = old })
	stubDefaultRoute(t, "eth0")

	outbounds := json_util.RawMessage(`[{"tag":"direct","protocol":"freedom"}]`)
	plan := &instancePlan{configs: map[string]*xray.Config{"xray-1": {OutboundConfigs: outbounds}}}
	if applied := applyEgress(plan, map[string]string{"xray-1": "172.17.0.1"}); len(applied) != 0 {
		t.Errorf("a core sends from a bridge without a link: %v", applied)
	}
	moved := false
	for i := 0; i < 3 && !moved; i++ {
		moved = xs.EgressOutOfLine()
		*now = now.Add(30 * time.Second)
	}
	if !moved {
		t.Error("the core stays on an address without a link off the default route")
	}
}

// Cores applied by another path -- an inbound saved, a crash restart -- start
// the wait over: an older sighting does not cut it short.
func TestEgressWaitStartsOverAfterApply(t *testing.T) {
	runningInstance(t, "192.0.2.7")
	now := stubClock(t)
	var xs XrayService
	var ss SettingService
	ss.SetInstanceEgress(map[string]string{"xray-1": "192.0.2.7"})
	stubHostAddresses(t)
	if xs.EgressOutOfLine() {
		t.Fatal("acted on the first sighting")
	}
	// Another path applied the cores to the addresses there are now.
	resetEgressDrift()
	*now = now.Add(60 * time.Second)
	if xs.EgressOutOfLine() {
		t.Fatal("a sighting from before the apply cut the wait short")
	}
	*now = now.Add(30 * time.Second)
	if xs.EgressOutOfLine() {
		t.Fatal("acted 30 s into the new wait")
	}
	*now = now.Add(30 * time.Second)
	if !xs.EgressOutOfLine() {
		t.Fatal("the address stayed gone a minute after the apply")
	}
}

// startSleeper starts p from a stand-in core that only sleeps.
func startSleeper(t *testing.T, p *xray.Process) error {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\n[ \"$1\" = -version ] && exit 0\nexec sleep 60\n"
	if err := os.WriteFile(filepath.Join(dir, xray.GetBinaryName()), []byte(script), 0o755); err != nil {
		return err
	}
	t.Setenv("XUI_BIN_FOLDER", dir)
	t.Setenv("XUI_LOG_FOLDER", dir)
	if err := p.Start(); err != nil {
		return err
	}
	t.Cleanup(func() { p.Stop() })
	return nil
}

// Nobody looking at the status: the socket dumps are not refreshed.
func TestUDPPortUseOnlyWhileWatched(t *testing.T) {
	udpMu.Lock()
	oldAt, oldUse := udpAt, udpUse
	udpAt, udpUse = time.Now().Add(-time.Hour), &sys.UDPPortUse{Pool: 1}
	udpMu.Unlock()
	t.Cleanup(func() {
		udpMu.Lock()
		udpAt, udpUse = oldAt, oldUse
		udpMu.Unlock()
		SetStatusWatched(true)
	})
	SetStatusWatched(false)
	if u := currentUDPPortUse(); u == nil || u.Pool != 1 {
		t.Fatalf("refreshed while nobody watches: %+v", u)
	}
	SetStatusWatched(true)
	if u := currentUDPPortUse(); u != nil && u.Pool == 1 {
		t.Fatal("not refreshed while watched")
	}
}
