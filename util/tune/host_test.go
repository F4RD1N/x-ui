//go:build linux

package tune

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

// cpuMachine is a 4-CPU box whose clock the OS sets: schedutil, and idle
// states POLL (0 µs), C1 (1 µs) and C2 (400 µs) on every CPU.
func cpuMachine(t *testing.T, extra map[string]string) *Env {
	files := map[string]string{}
	for p := 0; p < 4; p++ {
		d := fmt.Sprintf("%s/cpufreq/policy%d/", cpuDir, p)
		files[d+"scaling_governor"] = "schedutil\n"
		files[d+"scaling_available_governors"] = "conservative ondemand userspace powersave performance schedutil\n"
		for s, st := range []struct{ name, lat string }{{"POLL", "0"}, {"C1", "1"}, {"C2", "400"}} {
			sd := fmt.Sprintf("%s/cpu%d/cpuidle/state%d/", cpuDir, p, s)
			files[sd+"name"], files[sd+"latency"], files[sd+"disable"] = st.name+"\n", st.lat+"\n", "0\n"
		}
	}
	for k, v := range extra {
		files[k] = v
	}
	return machine{mem: 8 * GiB, cpus: 4, files: files}.build(t)
}

func cpuValues(e *Env) (gov, c1, c2 string) {
	var g, a, b []string
	for p := 0; p < 4; p++ {
		g = append(g, e.readTrim(fmt.Sprintf("%s/cpufreq/policy%d/scaling_governor", cpuDir, p)))
		a = append(a, e.readTrim(fmt.Sprintf("%s/cpu%d/cpuidle/state1/disable", cpuDir, p)))
		b = append(b, e.readTrim(fmt.Sprintf("%s/cpu%d/cpuidle/state2/disable", cpuDir, p)))
	}
	return strings.Join(g, ","), strings.Join(a, ","), strings.Join(b, ",")
}

// Performance governor and deep idle states off; again at boot; revert puts
// back exactly what was there.
func TestCPUPerformance(t *testing.T) {
	e := cpuMachine(t, nil)
	r := mustApply(t, e, ApplyOptions{Auto: true}) // an update does it too: a kernel value
	gov, c1, c2 := cpuValues(e)
	if gov != "performance,performance,performance,performance" || c1 != "0,0,0,0" || c2 != "1,1,1,1" {
		t.Fatalf("after apply: governor %s, C1 %s, C2 %s\n%v", gov, c1, c2, r.Changed)
	}
	if !strings.Contains(strings.Join(r.Changed, "\n"), "C2 (400 µs)") {
		t.Errorf("not reported: %v", r.Changed)
	}
	st, _, _ := e.loadState()
	if len(st.CPU) != 8 || st.CPU["cpufreq/policy2"].Orig != "schedutil" || st.CPU["cpu3/state2"].Orig != "0" {
		t.Fatalf("state %+v", st.CPU)
	}
	if r := mustApply(t, e, ApplyOptions{}); len(r.Changed) != 0 {
		t.Errorf("second apply changed %v", r.Changed)
	}

	// A reboot puts the kernel defaults back; the boot apply sets them again.
	for p := 0; p < 4; p++ {
		writeT(t, e.Root, fmt.Sprintf("%s/cpufreq/policy%d/scaling_governor", cpuDir, p), "schedutil\n")
		writeT(t, e.Root, fmt.Sprintf("%s/cpu%d/cpuidle/state2/disable", cpuDir, p), "0\n")
	}
	mustApply(t, e, ApplyOptions{Boot: true})
	if gov, _, c2 := cpuValues(e); gov != "performance,performance,performance,performance" || c2 != "1,1,1,1" {
		t.Fatalf("after boot: %s %s", gov, c2)
	}

	// Someone sets one policy to powersave: revert leaves that one.
	writeT(t, e.Root, cpuDir+"/cpufreq/policy1/scaling_governor", "powersave\n")
	r, err := e.Revert(false, false)
	if err != nil {
		t.Fatal(err)
	}
	gov, c1, c2 = cpuValues(e)
	if gov != "schedutil,powersave,schedutil,schedutil" || c1 != "0,0,0,0" || c2 != "0,0,0,0" {
		t.Fatalf("after revert: governor %s, C1 %s, C2 %s\n%v %v", gov, c1, c2, r.Changed, r.Problems)
	}
	if !strings.Contains(strings.Join(r.Problems, "\n"), "1 values left") {
		t.Errorf("the changed policy is not reported: %v", r.Problems)
	}
}

// A tool, the kernel command line or an admin who already turned an idle
// state off decides; a box without cpufreq and a container are left alone.
func TestCPURespectsOthers(t *testing.T) {
	cases := []struct {
		name     string
		extra    map[string]string
		answers  map[string]string
		gov, c2  string
		noteHave string
	}{
		{"tuned", map[string]string{"/etc/systemd/system/multi-user.target.wants/tuned.service": "[Unit]\n"}, nil,
			"schedutil,schedutil,schedutil,schedutil", "0,0,0,0", "kept: set by tuned"},
		{"cmdline", map[string]string{"/proc/cmdline": "BOOT_IMAGE=/vmlinuz root=/dev/sda1 intel_idle.max_cstate=1\n"}, nil,
			"schedutil,schedutil,schedutil,schedutil", "0,0,0,0", "kernel command line"},
		{"admin idle", map[string]string{cpuDir + "/cpu2/cpuidle/state2/disable": "1\n"}, nil,
			"performance,performance,performance,performance", "0,0,1,0", "turned off by someone else"},
	}
	for _, c := range cases {
		e := cpuMachine(t, c.extra)
		fakeCommands(e, c.answers)
		mustApply(t, e, ApplyOptions{})
		gov, _, c2 := cpuValues(e)
		if gov != c.gov || c2 != c.c2 {
			t.Errorf("%s: governor %s, C2 %s", c.name, gov, c2)
		}
		if info := strings.Join(e.cpuInfo(e.gatherFacts(), &State{}), "\n"); !strings.Contains(info, c.noteHave) {
			t.Errorf("%s: status %q", c.name, info)
		}
	}

	// A state the driver starts with off (default_status "disabled", as
	// intel_idle does for C3 on Broadwell-EP) is not someone else's choice:
	// the other deep states still go, and that one is left as the kernel has it.
	kernelOff := map[string]string{}
	for p := 0; p < 4; p++ {
		sd := fmt.Sprintf("%s/cpu%d/cpuidle/state3/", cpuDir, p)
		kernelOff[sd+"name"], kernelOff[sd+"latency"], kernelOff[sd+"disable"] = "C3\n", "40\n", "1\n"
		kernelOff[sd+"default_status"] = "disabled\n"
		kernelOff[fmt.Sprintf("%s/cpu%d/cpuidle/state2/default_status", cpuDir, p)] = "enabled\n"
	}
	ke := cpuMachine(t, kernelOff)
	kr := mustApply(t, ke, ApplyOptions{})
	if _, _, c2 := cpuValues(ke); c2 != "1,1,1,1" {
		t.Errorf("kernel default off: C2 %s\n%v", c2, kr.Changed)
	}
	kst, _, _ := ke.loadState()
	if kst.CPU["cpu0/state3"] != nil {
		t.Errorf("x-ui recorded the kernel's own C3: %+v", kst.CPU["cpu0/state3"])
	}
	if info := strings.Join(ke.cpuInfo(ke.gatherFacts(), kst), "\n"); strings.Contains(info, "someone else") || !strings.Contains(info, "(x-ui)") {
		t.Errorf("status: %q", info)
	}
	ke.Revert(false, false)
	for p := 0; p < 4; p++ {
		if v := ke.readTrim(fmt.Sprintf("%s/cpu%d/cpuidle/state3/disable", cpuDir, p)); v != "1" {
			t.Errorf("revert changed the kernel's C3 on cpu%d: %s", p, v)
		}
	}

	e := machine{mem: 8 * GiB, cpus: 4}.build(t)
	r := mustApply(t, e, ApplyOptions{})
	for _, c := range r.Changed {
		if strings.Contains(c, "cpu") {
			t.Errorf("no cpufreq, yet %q", c)
		}
	}
	if info := e.cpuInfo(e.gatherFacts(), &State{}); !strings.Contains(info[0], "BIOS") {
		t.Errorf("no cpufreq: %v", info)
	}

	ct := cpuMachine(t, nil)
	ct.Facts.Virt = "docker"
	mustApply(t, ct, ApplyOptions{})
	if gov, _, _ := cpuValues(ct); gov != "schedutil,schedutil,schedutil,schedutil" {
		t.Errorf("container: %s", gov)
	}
}

// linkMachine has eth0 under the default route, managed by networkd through
// netplan's file.
func linkMachine(t *testing.T, network string, managed bool) *Env {
	files := map[string]string{
		"/proc/net/route":                              "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\neth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n",
		"/sys/class/net/eth0/ifindex":                  "2\n",
		"/run/systemd/network/10-netplan-eth0.network": network,
	}
	if managed {
		files["/run/systemd/netif/links/2"] = "ADMIN_STATE=configured\nNETWORK_FILE=/run/systemd/network/10-netplan-eth0.network\n"
	}
	return machine{mem: 8 * GiB, cpus: 4, files: files}.build(t)
}

const netplanNetwork = "[Match]\nPermanentMACAddress=58:a2:e1:f0:63:51\n\n[Network]\nAddress=89.41.180.147/31\nGateway=89.41.180.146\n"

func TestKeepAddressesThroughLinkDrops(t *testing.T) {
	dropIn := "/etc/systemd/network/10-netplan-eth0.network.d/" + carrierDropIn
	e := linkMachine(t, netplanNetwork, true)
	fakeCommands(e, nil, "networkctl reload")
	mustApply(t, e, ApplyOptions{Auto: true}) // an update: not a host change
	if e.exists(dropIn) {
		t.Fatal("an update wrote the link drop-in")
	}
	r := mustApply(t, e, ApplyOptions{Auto: true, Host: true}) // a fresh install
	got := e.readTrim(dropIn)
	if !strings.Contains(got, "ConfigureWithoutCarrier=yes") || !strings.Contains(got, "IgnoreCarrierLoss=yes") || !e.isOurs(dropIn) {
		t.Fatalf("drop-in:\n%s\n%v", got, r.Problems)
	}
	if !strings.Contains(strings.Join(e.Ran, "\n"), "networkctl reload") {
		t.Errorf("networkd not reloaded: %v", e.Ran)
	}
	e.Ran = nil
	if r := mustApply(t, e, ApplyOptions{}); strings.Contains(strings.Join(e.Ran, "\n"), "networkctl") || len(r.Changed) != 0 {
		t.Errorf("second apply: %v %v", r.Changed, e.Ran)
	}
	if info := strings.Join(e.carrierInfo(e.gatherFacts()), ""); !strings.Contains(info, "(x-ui)") {
		t.Errorf("status: %s", info)
	}
	e.Ran = nil
	if _, err := e.Revert(false, false); err != nil {
		t.Fatal(err)
	}
	if e.exists(dropIn) || e.exists("/etc/systemd/network/10-netplan-eth0.network.d") || !strings.Contains(strings.Join(e.Ran, "\n"), "networkctl reload") {
		t.Fatalf("revert left the drop-in or did not reload: %v", e.Ran)
	}

	// netplan's ignore-carrier is already there; an admin's drop-in too.
	for name, e := range map[string]*Env{
		"netplan": linkMachine(t, netplanNetwork+"ConfigureWithoutCarrier=yes\n", true),
		"admin drop-in": func() *Env {
			e := linkMachine(t, netplanNetwork, true)
			writeT(t, e.Root, "/etc/systemd/network/10-netplan-eth0.network.d/50-mine.conf", "[Network]\nIgnoreCarrierLoss=5s\n")
			return e
		}(),
		"not networkd": linkMachine(t, netplanNetwork, false),
	} {
		fakeCommands(e, nil, "networkctl reload")
		mustApply(t, e, ApplyOptions{})
		if e.exists(dropIn) || strings.Contains(strings.Join(e.Ran, "\n"), "networkctl") {
			t.Errorf("%s: drop-in written", name)
		}
	}
}

// dnsMachine runs systemd-resolved (resolv.conf is its stub) with 8.8.8.8 and
// 1.1.1.1 upstream; unbound's package is not installed yet.
func dnsMachine(t *testing.T, extra map[string]string) *Env {
	files := map[string]string{
		resolvedStub:     "# This is /run/systemd/resolve/stub-resolv.conf managed by man:systemd-resolved(8).\nnameserver 127.0.0.53\noptions edns0 trust-ad\nsearch .\n",
		resolvedUpstream: "nameserver 8.8.8.8\nnameserver 1.1.1.1\nsearch .\n",
		unboundMain:      "# Debian's\ninclude-toplevel: \"/etc/unbound/unbound.conf.d/*.conf\"\n",
	}
	for k, v := range extra {
		files[k] = v
	}
	e := machine{mem: 64 * GiB, cpus: 32, files: files}.build(t)
	if _, ok := extra[ResolvConf]; !ok {
		os.MkdirAll(e.P("/etc"), 0o755)
		if err := os.Symlink("../run/systemd/resolve/stub-resolv.conf", e.P(ResolvConf)); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

var dnsOK = []string{"apt-get install", "unbound-checkconf", "systemctl enable unbound", "systemctl restart unbound", "systemctl daemon-reload", "systemctl disable", "systemctl try-restart"}

func dnsAnswers(installed bool) map[string]string {
	a := map[string]string{"command -v apt-get": "/usr/bin/apt-get"}
	if installed {
		a["command -v unbound"] = "/usr/sbin/unbound"
	}
	return a
}

func TestDNSCache(t *testing.T) {
	e := dnsMachine(t, nil)
	fakeCommands(e, dnsAnswers(false), dnsOK...)
	mustApply(t, e, ApplyOptions{Auto: true}) // an update leaves DNS alone
	if e.isOurs(ResolvConf) || strings.Contains(strings.Join(e.Ran, "\n"), "unbound") {
		t.Fatalf("an update touched DNS: %v", e.Ran)
	}
	r := mustApply(t, e, ApplyOptions{Auto: true, Host: true})
	ran := strings.Join(e.Ran, "\n")
	for _, want := range []string{"apt-get install -y -qq unbound", "unbound-checkconf", "systemctl enable unbound", "systemctl restart unbound"} {
		if !strings.Contains(ran, want) {
			t.Errorf("did not run %q:\n%s", want, ran)
		}
	}
	conf := e.readTrim("/etc/unbound/unbound.conf.d/x-ui.conf")
	for _, want := range []string{"interface: 127.0.0.1", "num-threads: 4", "msg-cache-slabs: 4", "msg-cache-size: 64m", "rrset-cache-size: 128m",
		"forward-addr: 8.8.8.8", "forward-addr: 1.1.1.1", `module-config: "iterator"`} {
		if !strings.Contains(conf, want) {
			t.Errorf("unbound config lacks %q:\n%s", want, conf)
		}
	}
	if !e.isOurs(UnboundDropIn) || !strings.Contains(e.readTrim(UnboundDropIn), "Restart=always") {
		t.Errorf("drop-in: %s", e.readTrim(UnboundDropIn))
	}
	resolv := e.readTrim(ResolvConf)
	if fi, _ := os.Lstat(e.P(ResolvConf)); fi.Mode()&os.ModeSymlink != 0 || !e.isOurs(ResolvConf) ||
		!strings.Contains(resolv, "nameserver 127.0.0.1\nnameserver 8.8.8.8\nnameserver 1.1.1.1\noptions timeout:2 attempts:2 edns0\nsearch .") {
		t.Fatalf("resolv.conf:\n%s\n%v", resolv, r.Problems)
	}
	st, _, _ := e.loadState()
	if st.DNS == nil || st.DNS.Was != "link:../run/systemd/resolve/stub-resolv.conf" || fmt.Sprint(st.DNS.Upstreams) != "[8.8.8.8 1.1.1.1]" ||
		fmt.Sprint(st.DNS.Fallbacks) != "[8.8.8.8 1.1.1.1]" || st.DNS.Fallback != "" ||
		!strings.Contains(fmt.Sprint(st.Installed), "unbound") || !strings.Contains(fmt.Sprint(st.Enabled), "unbound") {
		t.Fatalf("state %+v %+v", st.DNS, st)
	}
	if info := e.dnsInfo(e.gatherFacts(), st); !strings.Contains(info, "(x-ui)") {
		t.Errorf("status: %s", info)
	}

	// Again: nothing to do, unbound not restarted.
	e.Ran = nil
	if r := mustApply(t, e, ApplyOptions{}); strings.Contains(strings.Join(e.Ran, "\n"), "restart unbound") || len(r.Changed) != 0 {
		t.Errorf("second apply: %v %v", r.Changed, e.Ran)
	}

	// Revert: resolv.conf is the link it was, x-ui's files gone, unbound off.
	e.Ran = nil
	r, err := e.Revert(false, false)
	if err != nil {
		t.Fatal(err)
	}
	if l, err := os.Readlink(e.P(ResolvConf)); err != nil || l != "../run/systemd/resolve/stub-resolv.conf" {
		t.Fatalf("resolv.conf not restored: %q %v %v", l, err, r.Problems)
	}
	if e.exists("/etc/unbound/unbound.conf.d/x-ui.conf") || e.exists(UnboundDropIn) {
		t.Error("unbound files left")
	}
	if !strings.Contains(strings.Join(e.Ran, "\n"), "systemctl disable --now unbound") {
		t.Errorf("unbound left running: %v", e.Ran)
	}
}

// A plain resolv.conf naming public servers: they become the upstreams and the
// fallbacks, and revert puts the file back byte for byte.
func TestDNSCacheStaticResolvConf(t *testing.T) {
	old := "nameserver 1.1.1.1\nnameserver 8.8.8.8\noptions rotate\n"
	e := dnsMachine(t, map[string]string{ResolvConf: old})
	fakeCommands(e, dnsAnswers(true), dnsOK...)
	mustApply(t, e, ApplyOptions{})
	if strings.Contains(strings.Join(e.Ran, "\n"), "install -y -qq unbound") {
		t.Error("installed unbound again")
	}
	resolv := e.readTrim(ResolvConf)
	// rotate would start most lookups at a fallback instead of unbound.
	if !strings.Contains(resolv, "nameserver 127.0.0.1\nnameserver 1.1.1.1\nnameserver 8.8.8.8\noptions timeout:2 attempts:2") || strings.Contains(resolv, "rotate") {
		t.Fatalf("resolv.conf:\n%s", resolv)
	}
	st, _, _ := e.loadState()
	if strings.Contains(fmt.Sprint(st.Installed), "unbound") || st.DNS.Was != "file:"+BackupDir+ResolvConf {
		t.Fatalf("state %+v %+v", st.Installed, st.DNS)
	}
	if _, err := e.Revert(false, false); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.read(ResolvConf); got != old {
		t.Fatalf("not restored:\n%q", got)
	}
}

// A server set up by an older version names 127.0.0.53 after unbound, but
// systemd-resolved reads that file too and only hands the lookup back to
// unbound. A manual apply names the upstreams instead (an update or a boot
// leaves the file alone); a public fallback an older version chose stays.
func TestDNSCacheOldFallback(t *testing.T) {
	e := dnsMachine(t, nil)
	fakeCommands(e, dnsAnswers(false), dnsOK...)
	mustApply(t, e, ApplyOptions{Auto: true, Host: true})
	legacy := "# Written by x-ui tune (github.com/F4RD1N/x-ui).\n# old\nnameserver 127.0.0.1\nnameserver 127.0.0.53\noptions timeout:2 attempts:2 edns0 trust-ad\nsearch .\n"
	writeT(t, e.Root, ResolvConf, legacy)
	st, _, _ := e.loadState()
	st.DNS.Fallbacks, st.DNS.Fallback = nil, "127.0.0.53"
	if err := e.saveState(st, nil); err != nil {
		t.Fatal(err)
	}
	if info := e.dnsInfo(e.gatherFacts(), st); !strings.Contains(info, "then 127.0.0.53 (would be 8.8.8.8, 1.1.1.1)") {
		t.Errorf("status: %s", info)
	}
	mustApply(t, e, ApplyOptions{Auto: true})
	mustApply(t, e, ApplyOptions{Boot: true})
	if got, _ := e.read(ResolvConf); got != legacy {
		t.Fatalf("an update or boot rewrote resolv.conf:\n%s", got)
	}
	r := mustApply(t, e, ApplyOptions{})
	resolv := e.readTrim(ResolvConf)
	if !e.isOurs(ResolvConf) || !strings.Contains(resolv, "nameserver 127.0.0.1\nnameserver 8.8.8.8\nnameserver 1.1.1.1\noptions timeout:2 attempts:2 edns0\nsearch .") ||
		strings.Contains(resolv, "127.0.0.53") {
		t.Fatalf("resolv.conf:\n%s\n%v", resolv, r.Problems)
	}
	if !strings.Contains(strings.Join(r.Changed, "\n"), "falls back to 8.8.8.8, 1.1.1.1 when unbound does not answer (was 127.0.0.53)") {
		t.Errorf("not reported: %v", r.Changed)
	}
	st, _, _ = e.loadState()
	if fmt.Sprint(st.DNS.Fallbacks) != "[8.8.8.8 1.1.1.1]" || st.DNS.Fallback != "" {
		t.Errorf("state %+v", st.DNS)
	}
	if r := mustApply(t, e, ApplyOptions{}); len(r.Changed) != 0 {
		t.Errorf("second apply changed %v", r.Changed)
	}
	if _, err := e.Revert(false, false); err != nil {
		t.Fatal(err)
	}
	if l, err := os.Readlink(e.P(ResolvConf)); err != nil || l != "../run/systemd/resolve/stub-resolv.conf" {
		t.Fatalf("resolv.conf not restored: %q %v", l, err)
	}

	// What an admin wrote into x-ui's file since stays: with the new state,
	// and with the old state when the file no longer names just 127.0.0.53.
	mine := "# Written by x-ui tune (github.com/F4RD1N/x-ui).\nnameserver 127.0.0.1\nnameserver 9.9.9.9\noptions timeout:2 attempts:2\n"
	a := dnsMachine(t, nil)
	fakeCommands(a, dnsAnswers(false), dnsOK...)
	mustApply(t, a, ApplyOptions{})
	writeT(t, a.Root, ResolvConf, mine)
	if r := mustApply(t, a, ApplyOptions{}); len(r.Changed) != 0 || a.readTrim(ResolvConf)+"\n" != mine {
		t.Errorf("an admin's servers were rewritten (new state): %v\n%s", r.Changed, a.readTrim(ResolvConf))
	}
	ast, _, _ := a.loadState()
	ast.DNS.Fallbacks, ast.DNS.Fallback = nil, "127.0.0.53"
	a.saveState(ast, nil)
	if r := mustApply(t, a, ApplyOptions{}); len(r.Changed) != 0 || a.readTrim(ResolvConf)+"\n" != mine {
		t.Errorf("an admin's servers were rewritten (old state): %v\n%s", r.Changed, a.readTrim(ResolvConf))
	}

	// A link-local upstream (its zone is lost) is never a fallback.
	if got := fmt.Sprint(dnsFallbacks([]string{"fe80::1", "127.0.0.53", "2001:4860:4860::8888", "8.8.8.8", "1.1.1.1"})); got != "[2001:4860:4860::8888 8.8.8.8]" {
		t.Errorf("dnsFallbacks: %s", got)
	}

	// An older version's public fallback stays as it is.
	old := "nameserver 1.1.1.1\nnameserver 8.8.8.8\n"
	s := dnsMachine(t, map[string]string{ResolvConf: old})
	fakeCommands(s, dnsAnswers(true), dnsOK...)
	mustApply(t, s, ApplyOptions{})
	writeT(t, s.Root, ResolvConf, "# Written by x-ui tune (github.com/F4RD1N/x-ui).\nnameserver 127.0.0.1\nnameserver 1.1.1.1\noptions timeout:2 attempts:2\n")
	sst, _, _ := s.loadState()
	sst.DNS.Fallbacks, sst.DNS.Fallback = nil, "1.1.1.1"
	s.saveState(sst, nil)
	if r := mustApply(t, s, ApplyOptions{}); len(r.Changed) != 0 || !strings.Contains(s.readTrim(ResolvConf), "nameserver 1.1.1.1\noptions") {
		t.Errorf("a public fallback was rewritten: %v\n%s", r.Changed, s.readTrim(ResolvConf))
	}
}

// Left alone: a DNS server of the admin's, another manager's resolv.conf,
// port 53 taken, unbound removed by the admin, a container; and nothing
// switches when unbound's config is refused or it does not answer.
func TestDNSCacheLeftAlone(t *testing.T) {
	cases := []struct {
		name    string
		extra   map[string]string
		answers map[string]string
		virt    string
		probe   error
		fail    string // a command that fails
		note    string
	}{
		{"own cache", map[string]string{ResolvConf: "nameserver 127.0.0.1\n"}, nil, "", nil, "", "already answers at 127.0.0.1"},
		{"NetworkManager", map[string]string{ResolvConf: "# Generated by NetworkManager\nnameserver 192.168.1.1\n"}, nil, "", nil, "", "NetworkManager"},
		{"port 53", map[string]string{"/proc/net/udp": "  sl  local_address rem_address   st\n   0: 0100007F:0035 00000000:0000 07\n"}, nil, "", nil, "", "listens on port 53"},
		{"removed", nil, map[string]string{"command -v dpkg-query": "/usr/bin/dpkg-query",
			"dpkg-query -W --showformat=${Package} ${Status}\n unbound": "unbound deinstall ok config-files\n"}, "", nil, "", "unbound was removed"},
		{"container", nil, nil, "lxc", nil, "", "container"},
		{"checkconf", nil, nil, "", nil, "unbound-checkconf", ""},
		{"no answer", nil, nil, "", errors.New("timeout"), "", ""},
	}
	for _, c := range cases {
		e := dnsMachine(t, c.extra)
		e.Facts.Virt = c.virt
		answers := dnsAnswers(false)
		for k, v := range c.answers {
			answers[k] = v
		}
		ok := []string{}
		for _, o := range dnsOK {
			if o != c.fail {
				ok = append(ok, o)
			}
		}
		fakeCommands(e, answers, ok...)
		if c.probe != nil {
			e.DNSProbe = func() error { return c.probe }
		}
		r := mustApply(t, e, ApplyOptions{})
		if e.isOurs(ResolvConf) {
			t.Errorf("%s: resolv.conf switched", c.name)
		}
		if c.fail != "" && (e.exists("/etc/unbound/unbound.conf.d/x-ui.conf") || e.exists(UnboundDropIn)) {
			t.Errorf("%s: unbound files left after the refusal", c.name)
		}
		if c.note != "" {
			if info := e.dnsInfo(e.gatherFacts(), &State{}); !strings.Contains(info, c.note) {
				t.Errorf("%s: status %q", c.name, info)
			}
		} else if !strings.Contains(strings.Join(r.Problems, "\n"), "dns:") {
			t.Errorf("%s: not reported: %v", c.name, r.Problems)
		}
	}
}

func TestRenderUnboundSizes(t *testing.T) {
	for _, c := range []struct {
		mem        int64
		cpus       int
		threads    string
		msg, rrset string
	}{
		{GiB, 1, "num-threads: 1", "msg-cache-size: 4m", "rrset-cache-size: 8m"},
		{16 * GiB, 56, "num-threads: 7", "msg-cache-size: 16m", "rrset-cache-size: 32m"},
		{1024 * GiB, 256, "num-threads: 8", "msg-cache-size: 256m", "rrset-cache-size: 512m"},
	} {
		got := renderUnbound(&Facts{MemBytes: c.mem, CPUs: c.cpus}, []string{"1.1.1.1"})
		for _, want := range []string{c.threads, c.msg, c.rrset} {
			if !strings.Contains(got, want) {
				t.Errorf("%d GiB %d CPUs: no %q", c.mem/GiB, c.cpus, want)
			}
		}
	}
}
