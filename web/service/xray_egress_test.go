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

func TestReadUDPPortUse(t *testing.T) {
	dir := t.TempDir()
	rangeFile := filepath.Join(dir, "range")
	os.WriteFile(rangeFile, []byte("1000\t1009\n"), 0o644)
	reservedFile := filepath.Join(dir, "reserved")
	os.WriteFile(reservedFile, []byte("1009\n"), 0o644)
	oldRange, oldReserved := localPortRangePath, reservedPortsPath
	localPortRangePath, reservedPortsPath = rangeFile, reservedFile
	t.Cleanup(func() { localPortRangePath, reservedPortsPath = oldRange, oldReserved })

	sockets := []sys.LocalEndpoint{
		{IP: "", Port: 1000}, {IP: "", Port: 1001}, // all addresses
		{IP: "192.0.2.7", Port: 1001}, {IP: "192.0.2.7", Port: 1002}, // its own
		{IP: "192.0.2.8", Port: 1002},
		{IP: "", Port: 53},   // outside the range
		{IP: "", Port: 1009}, // reserved
	}
	u, err := readUDPPortUse(func(fn func(sys.LocalEndpoint)) error {
		for _, s := range sockets {
			fn(s)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if u.pool != 9 {
		t.Errorf("pool %d, want 9 (10 ports, 1 reserved)", u.pool)
	}
	for _, c := range []struct {
		from string
		want int
	}{
		{"", 3},          // ports 1000-1002 are taken for a socket on all addresses
		{"192.0.2.7", 3}, // 1000, 1001 (all addresses) and 1002
		{"192.0.2.8", 3}, // 1000, 1001 and 1002
		{"192.0.2.9", 2}, // only the all-address ones
	} {
		if got := u.used(c.from); got != c.want {
			t.Errorf("used(%q) = %d, want %d", c.from, got, c.want)
		}
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

// A core started before its outgoing IP was on the host, or still sending
// from one that left it, is out of line.
func TestEgressOutOfLine(t *testing.T) {
	dir := t.TempDir()
	if err := database.InitDB(filepath.Join(dir, "x-ui.db")); err != nil {
		t.Fatal(err)
	}
	defer database.CloseDB()
	var xs XrayService
	var ss SettingService
	p := xray.NewInstanceProcess("xray-1", &xray.Config{}, filepath.Join(dir, "c.json"), nil)
	// A process that runs is all it takes.
	if err := startSleeper(t, p); err != nil {
		t.Skip(err)
	}
	instMu.Lock()
	oldProcs, oldApplied := procs, egressApplied
	procs, egressApplied = map[string]*xray.Process{"xray-1": p}, map[string]string{}
	instMu.Unlock()
	t.Cleanup(func() {
		instMu.Lock()
		procs, egressApplied = oldProcs, oldApplied
		instMu.Unlock()
	})

	if xs.EgressOutOfLine() {
		t.Fatal("no outgoing IP, none applied")
	}
	ss.SetInstanceEgress(map[string]string{"xray-1": "192.0.2.7"})
	stubHostAddresses(t)
	if xs.EgressOutOfLine() {
		t.Fatal("the address is not on the host yet: the default is right")
	}
	stubHostAddresses(t, "192.0.2.7")
	if !xs.EgressOutOfLine() {
		t.Fatal("the address came onto the host")
	}
	instMu.Lock()
	egressApplied = map[string]string{"xray-1": "192.0.2.7"}
	instMu.Unlock()
	if xs.EgressOutOfLine() {
		t.Fatal("in line")
	}
	stubHostAddresses(t)
	if !xs.EgressOutOfLine() {
		t.Fatal("the address left the host")
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
	udpAt, udpUse = time.Now().Add(-time.Hour), &udpPortUse{pool: 1}
	udpMu.Unlock()
	t.Cleanup(func() {
		udpMu.Lock()
		udpAt, udpUse = oldAt, oldUse
		udpMu.Unlock()
		SetStatusWatched(true)
	})
	SetStatusWatched(false)
	if u := currentUDPPortUse(); u == nil || u.pool != 1 {
		t.Fatalf("refreshed while nobody watches: %+v", u)
	}
	SetStatusWatched(true)
	if u := currentUDPPortUse(); u != nil && u.pool == 1 {
		t.Fatal("not refreshed while watched")
	}
}
