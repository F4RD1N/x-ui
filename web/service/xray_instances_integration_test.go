package service

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

// The integration test runs real xray cores against a real (temporary)
// database: it needs a core binary, from XRAY_TEST_BINARY or the installed
// panel, and at least 4 CPUs.

func integrationCore(t *testing.T) {
	t.Helper()
	bin := os.Getenv("XRAY_TEST_BINARY")
	geoDir := filepath.Dir(bin)
	if bin == "" {
		bin = "/usr/local/x-ui/bin/" + xray.GetBinaryName()
		geoDir = "/usr/local/x-ui/bin"
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skip("no xray binary")
	}
	if len(xray.AvailableCPUs()) < 4 {
		t.Skip("needs 4 CPUs")
	}
	dir := t.TempDir()
	os.Symlink(bin, filepath.Join(dir, xray.GetBinaryName()))
	for _, geo := range []string{"geoip.dat", "geosite.dat"} {
		os.Symlink(filepath.Join(geoDir, geo), filepath.Join(dir, geo))
	}
	t.Setenv("XUI_BIN_FOLDER", dir)
	t.Setenv("XUI_LOG_FOLDER", dir)
	t.Setenv("XUI_DB_FOLDER", dir)
	// Port reservations go to a file, not the build box's sysctl.
	sysctl := filepath.Join(dir, "ip_local_reserved_ports")
	os.WriteFile(sysctl, nil, 0o644)
	oldPath := reservedPortsPath
	reservedPortsPath = sysctl
	t.Cleanup(func() { reservedPortsPath = oldPath })
	if err := database.InitDB(filepath.Join(dir, "x-ui.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		lock.Lock()
		stopAllInstances()
		instMu.Lock()
		procs = map[string]*xray.Process{}
		instMu.Unlock()
		lock.Unlock()
		database.CloseDB()
	})
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

var uuidN int

func vlessInbound(t *testing.T, instance string, cores int) *model.Inbound {
	uuidN++
	port := freeTCPPort(t)
	return &model.Inbound{
		UserId: 1, Enable: true, Remark: fmt.Sprintf("in-%d", port), Port: port,
		Protocol: model.VLESS, Tag: fmt.Sprintf("inbound-%d", port),
		XrayInstance: instance, XrayCores: cores,
		Settings:       fmt.Sprintf(`{"clients":[{"id":"6b0e9c1c-2d6f-4c6e-9b8a-%012d","email":"u%d@test","enable":true,"flow":""}],"decryption":"none","fallbacks":[]}`, uuidN, uuidN),
		StreamSettings: `{"network":"tcp","security":"none","tcpSettings":{"header":{"type":"none"}}}`,
		Sniffing:       `{"enabled":false}`,
	}
}

func procOf(name string) *xray.Process {
	instMu.RLock()
	defer instMu.RUnlock()
	return procs[name]
}

func pidOf(t *testing.T, name string) int {
	t.Helper()
	p := procOf(name)
	if p == nil || !p.IsRunning() {
		t.Fatalf("%s is not running", name)
	}
	return p.Pid()
}

// listening waits until something accepts on port.
func listening(port int) bool {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		if err == nil {
			c.Close()
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func running() []string {
	var out []string
	for _, p := range snapshotProcs() {
		if p.IsRunning() {
			out = append(out, p.Name())
		}
	}
	return out
}

func TestXrayInstancesIntegration(t *testing.T) {
	integrationCore(t)
	var xs XrayService
	var is InboundService
	cpus := xray.AvailableCPUs()
	total := len(cpus)

	add := func(in *model.Inbound) *model.Inbound {
		t.Helper()
		in, _, err := is.AddInbound(in)
		if err != nil {
			t.Fatal(err)
		}
		if err := xs.ApplyInboundChanges(); err != nil {
			t.Fatal(err)
		}
		return in
	}
	update := func(in *model.Inbound) {
		t.Helper()
		if _, _, err := is.UpdateInbound(in); err != nil {
			t.Fatal(err)
		}
		if err := xs.ApplyInboundChanges(); err != nil {
			t.Fatal(err)
		}
	}

	// Start with two inbounds, each in its own instance (names given by
	// default), both on auto: they split the CPUs.
	if err := xs.RestartXray(true); err != nil {
		t.Fatal(err)
	}
	a := add(vlessInbound(t, "", 0))
	b := add(vlessInbound(t, "", 0))
	if a.XrayInstance != "xray-1" || b.XrayInstance != "xray-2" {
		t.Fatalf("default names: %q %q", a.XrayInstance, b.XrayInstance)
	}
	if got := running(); strings.Join(got, ",") != "xray-1,xray-2" {
		t.Fatalf("running: %v", got)
	}
	if !listening(a.Port) || !listening(b.Port) {
		t.Fatal("inbounds not listening")
	}
	p1, p2 := pidOf(t, "xray-1"), pidOf(t, "xray-2")
	if p1 == p2 {
		t.Fatal("one process for two instances")
	}
	if n1, n2 := len(procOf("xray-1").CPUs()), len(procOf("xray-2").CPUs()); n1+n2 != total || n1 < total/2 || n2 < total/2 {
		t.Fatalf("auto split: %d + %d of %d", n1, n2, total)
	}
	if got := xray.ProcessCPUs(p1); len(got) != len(procOf("xray-1").CPUs()) {
		t.Fatalf("xray-1 kernel mask %v, recorded %v", got, procOf("xray-1").CPUs())
	}
	// The two cores answer on different API ports, and each runs only its
	// own inbound.
	if XrayAPIPortForTag(a.Tag) == XrayAPIPortForTag(b.Tag) || XrayAPIPortForTag(a.Tag) == 0 {
		t.Fatal("API ports")
	}
	// The inbound ports and the cores' API ports are kept out of the
	// ephemeral range.
	resv, _ := os.ReadFile(reservedPortsPath)
	got := parsePortList(string(resv))
	if !got[a.Port] || !got[b.Port] || !got[XrayAPIPortForTag(a.Tag)] || !got[XrayAPIPortForTag(b.Tag)] {
		t.Fatalf("reserved ports %q lack %d, %d or the API ports", resv, a.Port, b.Port)
	}

	t.Run("fixed cores move cores without restarting them", func(t *testing.T) {
		a.XrayCores = 2
		update(a)
		if pidOf(t, "xray-1") != p1 || pidOf(t, "xray-2") != p2 {
			t.Fatal("a core restarted")
		}
		if got := xray.ProcessCPUs(p1); len(got) != 2 {
			t.Fatalf("xray-1 on %v", got)
		}
		if got := xray.ProcessCPUs(p2); len(got) != total-2 {
			t.Fatalf("xray-2 (auto) on %v, want %d CPUs", got, total-2)
		}
		if !listening(a.Port) {
			t.Fatal("inbound lost")
		}
	})

	t.Run("cores are checked against what is available", func(t *testing.T) {
		b.XrayCores = total - 1 // xray-1 holds 2
		if _, _, err := is.UpdateInbound(b); err == nil || !strings.Contains(err.Error(), "available") {
			t.Fatalf("over-allocation accepted: %v", err)
		}
		b.XrayCores = 0
		big := vlessInbound(t, "", total)
		if _, _, err := is.AddInbound(big); err == nil {
			t.Fatal("instance with every core accepted next to others")
		}
	})

	t.Run("client changes go through the API", func(t *testing.T) {
		data := &model.Inbound{Id: a.Id, Settings: `{"clients":[{"id":"6b0e9c1c-2d6f-4c6e-9b8a-999999999999","email":"new@test","enable":true,"flow":""}]}`}
		needRestart, err := is.AddInboundClient(data)
		if err != nil || needRestart {
			t.Fatalf("add client: restart=%v err=%v", needRestart, err)
		}
		if err := xs.ApplyInboundChanges(); err != nil {
			t.Fatal(err)
		}
		if pidOf(t, "xray-1") != p1 {
			t.Fatal("client change restarted the core")
		}
	})

	t.Run("a new instance starts alone", func(t *testing.T) {
		c := add(vlessInbound(t, "big", 0))
		if !listening(c.Port) {
			t.Fatal("not listening")
		}
		if pidOf(t, "xray-1") != p1 || pidOf(t, "xray-2") != p2 {
			t.Fatal("other cores restarted")
		}
		// xray-2 and big now share the auto CPUs.
		n2, nb := len(xray.ProcessCPUs(p2)), len(procOf("big").CPUs())
		if n2+nb != total-2 {
			t.Fatalf("auto split after a new instance: %d + %d", n2, nb)
		}
		if _, err := is.DelInbound(c.Id); err != nil {
			t.Fatal(err)
		}
		if err := xs.ApplyInboundChanges(); err != nil {
			t.Fatal(err)
		}
		if procOf("big") != nil {
			t.Fatal("emptied instance still running")
		}
		if len(xray.ProcessCPUs(p2)) != total-2 {
			t.Fatal("xray-2 did not get the CPUs back")
		}
	})

	t.Run("moving an inbound to another instance", func(t *testing.T) {
		b.XrayInstance = "xray-1"
		b.XrayCores = 2 // takes the instance's cores
		update(b)
		if procOf("xray-2") != nil {
			t.Fatal("xray-2 kept running empty")
		}
		if pidOf(t, "xray-1") != p1 {
			t.Fatal("xray-1 restarted to take the inbound")
		}
		if !listening(b.Port) || !listening(a.Port) {
			t.Fatal("inbounds lost in the move")
		}
		var cores []int
		database.GetDB().Model(model.Inbound{}).Where("xray_instance = ?", "xray-1").Pluck("xray_cores", &cores)
		if len(cores) != 2 || cores[0] != 2 || cores[1] != 2 {
			t.Fatalf("instance cores in the database: %v", cores)
		}
		// Back to its own instance.
		b.XrayInstance = "xray-2"
		b.XrayCores = 0
		update(b)
		p2 = pidOf(t, "xray-2")
		if pidOf(t, "xray-1") != p1 || !listening(b.Port) {
			t.Fatal("move back")
		}
	})

	t.Run("an update without an instance keeps it", func(t *testing.T) {
		keep := *b
		keep.XrayInstance = ""
		keep.XrayCores = 0
		keep.Remark = "renamed"
		update(&keep)
		got, _ := is.GetInbound(b.Id)
		if got.XrayInstance != "xray-2" || pidOf(t, "xray-2") != p2 {
			t.Fatalf("instance changed to %q", got.XrayInstance)
		}
	})

	t.Run("disabling the last inbound stops the core", func(t *testing.T) {
		b.Enable = false
		update(b)
		if procOf("xray-2") != nil {
			t.Fatal("disabled instance still running")
		}
		statuses, sum := xs.XrayInstancesStatus()
		var idle bool
		for _, st := range statuses {
			if st.Name == "xray-2" && st.State == Idle {
				idle = true
			}
		}
		if !idle || sum.Total != total || sum.Reserved != 2 {
			t.Fatalf("status: %+v %+v", statuses, sum)
		}
		b.Enable = true
		update(b)
		p2 = pidOf(t, "xray-2")
		if !listening(b.Port) {
			t.Fatal("re-enabled inbound not listening")
		}
	})

	t.Run("a crashed core restarts alone", func(t *testing.T) {
		if proc, err := os.FindProcess(p2); err == nil {
			proc.Kill()
		}
		deadline := time.Now().Add(5 * time.Second)
		for !xs.DidXrayCrash() && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}
		if !xs.DidXrayCrash() {
			t.Fatal("crash not noticed")
		}
		if err := xs.RestartXray(false); err != nil {
			t.Fatal(err)
		}
		if pidOf(t, "xray-2") == p2 || pidOf(t, "xray-1") != p1 {
			t.Fatal("wrong core restarted")
		}
		p2 = pidOf(t, "xray-2")
		if !listening(b.Port) {
			t.Fatal("restarted core not listening")
		}
	})

	t.Run("restarting one instance", func(t *testing.T) {
		if err := xs.RestartInstance("xray-1"); err != nil {
			t.Fatal(err)
		}
		if pidOf(t, "xray-1") == p1 || pidOf(t, "xray-2") != p2 {
			t.Fatal("RestartInstance hit the wrong core")
		}
		p1 = pidOf(t, "xray-1")
		if got := xray.ProcessCPUs(p1); len(got) != 2 {
			t.Fatalf("restarted core lost its CPUs: %v", got)
		}
		if err := xs.RestartInstance("nope"); err == nil {
			t.Fatal("unknown instance")
		}
	})

	t.Run("traffic and status cover every core", func(t *testing.T) {
		if _, _, err := xs.GetXrayTraffic(); err != nil {
			t.Fatal(err)
		}
		statuses, _ := xs.XrayInstancesStatus()
		if len(statuses) != 2 {
			t.Fatalf("statuses: %+v", statuses)
		}
		for _, st := range statuses {
			if st.State != Running || st.Pid == 0 || st.Mem == 0 || st.Threads == 0 || len(st.Cpus) == 0 || st.TcpCount < 0 {
				t.Fatalf("status of %s: %+v", st.Name, st)
			}
		}
	})

	t.Run("a forced restart restarts every core", func(t *testing.T) {
		if err := xs.RestartXray(true); err != nil {
			t.Fatal(err)
		}
		if pidOf(t, "xray-1") == p1 || pidOf(t, "xray-2") == p2 {
			t.Fatal("not every core restarted")
		}
		if !listening(a.Port) || !listening(b.Port) {
			t.Fatal("inbounds lost")
		}
	})

	t.Run("stop", func(t *testing.T) {
		if err := xs.StopXray(); err != nil {
			t.Fatal(err)
		}
		if xs.IsXrayRunning() || xs.DidXrayCrash() {
			t.Fatal("still running, or a manual stop counted as a crash")
		}
		// Inbound changes while stopped do not start anything.
		if err := xs.ApplyInboundChanges(); err != nil || xs.IsXrayRunning() {
			t.Fatal("apply started cores after a manual stop")
		}
	})
}

func TestStopStartInstance(t *testing.T) {
	integrationCore(t)
	var xs XrayService
	var is InboundService
	total := len(xray.AvailableCPUs())
	if err := xs.RestartXray(true); err != nil {
		t.Fatal(err)
	}
	add := func(in *model.Inbound) *model.Inbound {
		in, _, err := is.AddInbound(in)
		if err != nil {
			t.Fatal(err)
		}
		xs.ApplyInboundChanges()
		return in
	}
	a := add(vlessInbound(t, "", 0))
	b := add(vlessInbound(t, "", 0))
	p1 := pidOf(t, "xray-1")

	if err := xs.StopInstance("xray-2"); err != nil {
		t.Fatal(err)
	}
	if procOf("xray-2") != nil || listening(b.Port) {
		t.Fatal("xray-2 still running")
	}
	if pidOf(t, "xray-1") != p1 || len(xray.ProcessCPUs(p1)) != total {
		t.Fatalf("xray-1 should keep running and take every CPU: %v", xray.ProcessCPUs(p1))
	}
	if xs.DidXrayCrash() {
		t.Fatal("a stopped instance counts as a crash")
	}
	// Neither inbound edits nor the restart check bring it back.
	b.Remark = "edited"
	if _, _, err := is.UpdateInbound(b); err != nil {
		t.Fatal(err)
	}
	xs.ApplyInboundChanges()
	xs.RestartXray(false)
	if procOf("xray-2") != nil {
		t.Fatal("stopped instance started by an edit or a restart check")
	}
	st, _ := xs.XrayInstancesStatus()
	for _, s := range st {
		if s.Name == "xray-2" && s.State != Stop {
			t.Fatalf("status of a stopped instance: %s", s.State)
		}
	}
	if err := xs.RestartInstance("xray-2"); err == nil {
		t.Fatal("restart of a stopped instance")
	}

	if err := xs.StartInstance("xray-2"); err != nil {
		t.Fatal(err)
	}
	if !listening(b.Port) || pidOf(t, "xray-1") != p1 {
		t.Fatal("start")
	}
	if n1, n2 := len(xray.ProcessCPUs(p1)), len(procOf("xray-2").CPUs()); n1+n2 != total {
		t.Fatalf("CPUs not shared again: %d + %d", n1, n2)
	}

	// After a full stop, starting one instance starts that one only.
	if err := xs.StopXray(); err != nil {
		t.Fatal(err)
	}
	if err := xs.StartInstance("xray-1"); err != nil {
		t.Fatal(err)
	}
	if !listening(a.Port) || procOf("xray-2") != nil {
		t.Fatalf("running: %v", running())
	}
	if xs.DidXrayCrash() {
		t.Fatal("the stopped one counts as a crash")
	}
	// A full restart brings everything back.
	if err := xs.RestartXray(true); err != nil {
		t.Fatal(err)
	}
	if strings.Join(running(), ",") != "xray-1,xray-2" {
		t.Fatalf("after a full restart: %v", running())
	}
	if err := xs.StartInstance("nope"); err == nil {
		t.Fatal("start of an unknown instance")
	}
}

func TestFailingInstanceBacksOff(t *testing.T) {
	integrationCore(t)
	t.Setenv("GOMEMLIMIT", "8GiB")
	var xs XrayService
	var is InboundService
	if err := xs.RestartXray(true); err != nil {
		t.Fatal(err)
	}
	good, _, err := is.AddInbound(vlessInbound(t, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	// Another program holds the port: this instance cannot start.
	blocked := vlessInbound(t, "", 0)
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", blocked.Port))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	bad, _, err := is.AddInbound(blocked)
	if err != nil {
		t.Fatal(err)
	}
	// Both cores start together.
	xs.RestartXray(true)
	pGood := pidOf(t, good.XrayInstance)

	// The memory limit is shared out by CPUs: two auto instances share every
	// CPU, and each gets its half of the limit. (A core that kept running
	// while others started keeps the limit it started with.)
	env, _ := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pGood))
	n := len(procOf(good.XrayInstance).CPUs())
	share := shareMemLimit(8<<30, n, len(xray.AvailableCPUs()))
	want := fmt.Sprintf("GOMEMLIMIT=%d", share)
	if !strings.Contains(string(env), want+"\x00") || procOf(good.XrayInstance).MemoryLimit() != share {
		t.Fatalf("core environment lacks %s", want)
	}

	waitDead := func() *xray.Process {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if p := procOf(bad.XrayInstance); p != nil && !p.IsRunning() {
				return p
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("the blocked core did not fail")
		return nil
	}
	first := waitDead()
	// Straight away: not due yet, so a restart check leaves it.
	if xs.DidXrayCrash() {
		t.Fatal("restart due immediately after a failure")
	}
	xs.RestartXray(false)
	if procOf(bad.XrayInstance) != first {
		t.Fatal("restarted before the back-off")
	}
	// After 2s it is retried; the next wait is 4s.
	time.Sleep(2100 * time.Millisecond)
	if !xs.DidXrayCrash() {
		t.Fatal("restart not due after 2s")
	}
	xs.RestartXray(false)
	second := waitDead()
	if second == first {
		t.Fatal("not retried after 2s")
	}
	time.Sleep(2100 * time.Millisecond)
	if xs.DidXrayCrash() {
		t.Fatal("second retry came after 2s instead of 4s")
	}
	st, _ := xs.XrayInstancesStatus()
	for _, s := range st {
		if s.Name == bad.XrayInstance && (s.State != Error || s.RetryIn < 1 || s.RetryIn > 2) {
			t.Fatalf("status of the failing core: %+v", s)
		}
	}
	// The other core never noticed.
	if pidOf(t, good.XrayInstance) != pGood {
		t.Fatal("a healthy core restarted")
	}
	// Fixing the inbound starts it at once, back-off or not.
	bad.Port = freeTCPPort(t)
	bad.Tag = fmt.Sprintf("inbound-%d", bad.Port)
	if _, _, err := is.UpdateInbound(bad); err != nil {
		t.Fatal(err)
	}
	if err := xs.ApplyInboundChanges(); err != nil {
		t.Fatal(err)
	}
	if !listening(bad.Port) {
		t.Fatal("fixed inbound not started at once")
	}
}

// The inbound that kept the single core down on a live server: a
// shadowsocks client saved with an empty cipher.
func TestShadowsocksClientWithoutCipherStarts(t *testing.T) {
	integrationCore(t)
	var xs XrayService
	var is InboundService
	if err := xs.RestartXray(true); err != nil {
		t.Fatal(err)
	}
	port := freeTCPPort(t)
	in := &model.Inbound{
		UserId: 1, Enable: true, Port: port, Protocol: model.Shadowsocks, Tag: fmt.Sprintf("inbound-%d", port),
		Settings:       `{"clients":[{"email":"uaj3hfu8","enable":true,"method":"","password":"MjQ5ZTQyNjktNDkzZi00ZTRmLTlhNDEtNjg0ZDlkYTA1OWQz"}],"ivCheck":true,"method":"chacha20-ietf-poly1305","network":"tcp"}`,
		StreamSettings: `{"network":"tcp","security":"none","tcpSettings":{"header":{"type":"none"}}}`,
		Sniffing:       `{"enabled":false}`,
	}
	in, _, err := is.AddInbound(in)
	if err != nil {
		t.Fatal(err)
	}
	if err := xs.ApplyInboundChanges(); err != nil {
		t.Fatal(err)
	}
	if !listening(port) {
		p := procOf(in.XrayInstance)
		t.Fatalf("shadowsocks core not up: %v", p.GetResult())
	}
}

// userOn reports whether the core of instance has email on tag: removing it
// through the core's API succeeds (and takes it off).
func userOn(t *testing.T, instance, tag, email string) bool {
	t.Helper()
	p := procOf(instance)
	if p == nil || !p.IsRunning() {
		t.Fatalf("%s is not running", instance)
	}
	if !listening(p.GetAPIPort()) {
		t.Fatalf("the API of %s does not listen", instance)
	}
	var api xray.XrayAPI
	if err := api.Init(p.GetAPIPort()); err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	err := api.RemoveUser(tag, email)
	if err != nil && !strings.Contains(err.Error(), "not found") {
		t.Fatalf("RemoveUser on %s: %v", instance, err)
	}
	return err == nil
}

// A client change that comes in while an apply restarts the core waits for
// it, and reaches the new core. Lost there, it would stay lost: later
// changes to the inbound go through the API, and the restart check does
// not look at an inbound changed that way.
func TestClientEditDuringRestartIsKept(t *testing.T) {
	integrationCore(t)
	var xs XrayService
	var is InboundService
	var ss SettingService
	if err := xs.RestartXray(true); err != nil {
		t.Fatal(err)
	}
	in := vlessInbound(t, "", 0)
	in.Settings = `{"clients":[{"id":"6b0e9c1c-2d6f-4c6e-9b8a-000000000011","email":"quota","enable":true,"flow":"","totalGB":1000}],"decryption":"none","fallbacks":[]}`
	in, _, err := is.AddInbound(in)
	if err != nil {
		t.Fatal(err)
	}
	if err := xs.ApplyInboundChanges(); err != nil {
		t.Fatal(err)
	}
	// With an outgoing IP the apply looks up the host's addresses after it
	// read the database: the edit is sent from there, as if it came in at
	// that moment.
	if err := ss.SetInstanceEgress(map[string]string{"xray-1": "127.0.0.2"}); err != nil {
		t.Fatal(err)
	}
	old := hostAddressList
	t.Cleanup(func() { hostAddressList = old })
	n := 0
	addClient := func(email string) {
		t.Helper()
		n++
		needRestart, err := is.AddInboundClient(&model.Inbound{Id: in.Id, Settings: fmt.Sprintf(`{"clients":[{"id":"6b0e9c1c-2d6f-4c6e-9b8a-%012d","email":"%s","enable":true,"flow":""}]}`, 100+n, email)})
		if err != nil {
			t.Fatal(err)
		}
		if needRestart {
			xs.SetToNeedRestart()
		}
	}
	// restartJob is what the panel's restart check does.
	restartJob := func() {
		if xs.IsNeedRestartAndSetFalse() {
			xs.RestartXray(false)
		}
	}
	duringRestart := func(edit func()) {
		t.Helper()
		var once sync.Once
		done := make(chan struct{})
		hostAddressList = func() ([]hostIP, error) {
			once.Do(func() {
				go func() { edit(); close(done) }()
				time.Sleep(500 * time.Millisecond)
			})
			return []hostIP{{IP: net.ParseIP("127.0.0.2").To4(), Iface: "lo"}}, nil
		}
		p := pidOf(t, "xray-1")
		if err := xs.RestartInstance("xray-1"); err != nil {
			t.Fatal(err)
		}
		<-done
		if pidOf(t, "xray-1") == p {
			t.Fatal("the core did not restart")
		}
		restartJob()
	}

	duringRestart(func() { addClient("late") })
	addClient("after")
	restartJob()
	if !userOn(t, "xray-1", in.Tag, "late") {
		t.Fatal("a client added during the restart is missing from the core")
	}

	// The traffic job finds a client over its quota during the restart.
	duringRestart(func() {
		err, needRestart := is.AddTraffic(nil, []*xray.ClientTraffic{{Email: "quota", Up: 5000}})
		if err != nil {
			t.Error(err)
		}
		if needRestart {
			xs.SetToNeedRestart()
		}
	})
	addClient("after2")
	restartJob()
	if userOn(t, "xray-1", in.Tag, "quota") {
		t.Fatal("a client disabled during the restart still runs on the core")
	}
}

// A core's API answers as soon as the apply that started it returns.
func TestClientRightAfterNewInstance(t *testing.T) {
	integrationCore(t)
	var xs XrayService
	var is InboundService
	if err := xs.RestartXray(true); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		in, _, err := is.AddInbound(vlessInbound(t, "", 0))
		if err != nil {
			t.Fatal(err)
		}
		if err := xs.ApplyInboundChanges(); err != nil {
			t.Fatal(err)
		}
		needRestart, err := is.AddInboundClient(&model.Inbound{Id: in.Id, Settings: fmt.Sprintf(`{"clients":[{"id":"6b0e9c1c-2d6f-4c6e-9b8a-%012d","email":"next%d","enable":true,"flow":""}]}`, 900+i, i)})
		if err != nil || needRestart {
			t.Fatalf("round %d: client added right after %s started: restart=%v err=%v", i, in.XrayInstance, needRestart, err)
		}
	}
	// The cores' configs hold every client's credentials.
	for _, f := range []string{instanceConfigPath("xray-1"), xray.GetConfigPath()} {
		if fi, err := os.Stat(f); err != nil {
			t.Error(err)
		} else if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s has mode %v", f, fi.Mode().Perm())
		}
	}
}

// After a full stop, restarting one instance starts that one only, and
// starting a running one leaves it alone.
func TestInstanceActionsAfterFullStop(t *testing.T) {
	integrationCore(t)
	var xs XrayService
	var is InboundService
	if err := xs.RestartXray(true); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, _, err := is.AddInbound(vlessInbound(t, "", 0)); err != nil {
			t.Fatal(err)
		}
		xs.ApplyInboundChanges()
	}
	if err := xs.StopXray(); err != nil {
		t.Fatal(err)
	}
	if err := xs.RestartInstance("xray-2"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(running(), ","); got != "xray-2" {
		t.Fatalf("restarting xray-2 after a full stop runs %q", got)
	}
	p2 := pidOf(t, "xray-2")
	if err := xs.StartInstance("xray-2"); err != nil {
		t.Fatal(err)
	}
	if pidOf(t, "xray-2") != p2 {
		t.Fatal("starting a running core restarted it")
	}
	if err := xs.StartInstance("xray-1"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(running(), ","); got != "xray-1,xray-2" || pidOf(t, "xray-2") != p2 {
		t.Fatalf("after starting xray-1: %q", got)
	}
}
