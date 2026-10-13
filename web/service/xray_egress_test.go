package service

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/util/json_util"
	"github.com/mhsanaei/3x-ui/v2/util/sys"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

func stubHostAddresses(t *testing.T, ips ...string) {
	t.Helper()
	old := hostAddressList
	hostAddressList = func() ([]net.IP, error) {
		var out []net.IP
		for _, s := range ips {
			out = append(out, net.ParseIP(s))
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
		{"tag":"blocked","protocol":"blackhole","settings":{}}
	]`)
	var obs []map[string]any
	if err := json.Unmarshal(withEgress(raw, "192.0.2.7"), &obs); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"direct": "192.0.2.7", "own": "10.0.0.9", "chained": "", "dialer": "", "iface": "", "mark": "192.0.2.7", "blocked": ""}
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
	applyEgress(plan, map[string]string{"xray-1": "192.0.2.7", "xray-2": "198.51.100.1"})
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
	stubProbe(t, errors.New("timeout"))
	if err := xs.SetInstanceEgress("xray-1", "2001:db8::7"); err == nil || !strings.Contains(err.Error(), "nothing on the internet answers") {
		t.Errorf("an address that reaches nothing was accepted: %v", err)
	}
	if m, _ := ss.GetInstanceEgress(); m["xray-1"] != "192.0.2.7" {
		t.Fatalf("a refused change was stored: %v", m)
	}
	addrs, err := xs.HostAddresses()
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 2 || addrs[0].IP != "192.0.2.7" || len(addrs[0].UsedBy) != 1 || addrs[0].UsedBy[0] != "xray-1" || addrs[1].IP != "2001:db8::7" {
		t.Errorf("host addresses %+v", addrs)
	}
	if err := xs.SetInstanceEgress("xray-1", ""); err != nil {
		t.Fatal(err)
	}
	if m, _ := ss.GetInstanceEgress(); len(m) != 0 {
		t.Fatalf("clearing left %v", m)
	}
}
