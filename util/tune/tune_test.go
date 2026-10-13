//go:build linux

package tune

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
)

// machine describes a fake server: a tree with /proc/sys, /etc and /sys, and
// facts that would otherwise be detected.
type machine struct {
	mem      int64
	memTotal int64 // MemTotal when it differs from mem (a cgroup limit)
	cpus     int
	kernel   string
	virt     string
	init     string
	nrOpen   int64
	pid1Hard int64
	sysctl   map[string]string // live values over the kernel defaults
	files    map[string]string // extra files (sysctl.d, units, ...)
	missing  []string          // keys the kernel does not have
	readOnly []string          // keys that cannot be written (EROFS)
	vendor   []string          // files owned by an OS package
	nics     []NIC
	bbr      string // "available" (default), "module", "missing"
	// conntrack: nf_conntrack is loaded (kernel defaults for its keys).
	conntrack bool
}

func kernelDefaults(m machine) map[string]string {
	pages := m.mem / 4096
	tcp2 := pages * 3 / 32
	ehash := pow2floor(float64(m.mem) / 4096 / 32)
	if ehash < 2048 {
		ehash = 2048
	}
	d := map[string]string{
		"fs.file-max":                               "9223372036854775807",
		"fs.nr_open":                                fmt.Sprint(m.nrOpen),
		"kernel.pid_max":                            fmt.Sprint(max(32768, 1024*m.cpus)),
		"kernel.osrelease":                          m.kernel,
		"net.ipv4.ip_local_port_range":              "32768\t60999",
		"net.ipv4.ip_local_reserved_ports":          "",
		"net.ipv4.tcp_tw_reuse":                     "2",
		"net.ipv4.tcp_fin_timeout":                  "60",
		"net.core.somaxconn":                        "4096",
		"net.ipv4.tcp_max_syn_backlog":              "512",
		"net.core.netdev_max_backlog":               "1000",
		"net.core.netdev_budget":                    "300",
		"net.core.netdev_budget_usecs":              "2000",
		"net.ipv4.tcp_max_tw_buckets":               fmt.Sprint(ehash / 2),
		"net.ipv4.tcp_max_orphans":                  fmt.Sprint(ehash / 2),
		"net.core.rmem_max":                         "212992",
		"net.core.wmem_max":                         "212992",
		"net.ipv4.tcp_rmem":                         "4096\t131072\t6291456",
		"net.ipv4.tcp_wmem":                         "4096\t16384\t4194304",
		"net.ipv4.tcp_mem":                          fmt.Sprintf("%d\t%d\t%d", tcp2/2, tcp2*2/3, tcp2),
		"net.ipv4.tcp_notsent_lowat":                "4294967295",
		"net.ipv4.tcp_slow_start_after_idle":        "1",
		"net.ipv4.tcp_mtu_probing":                  "0",
		"net.ipv4.tcp_fastopen":                     "1",
		"net.ipv4.tcp_congestion_control":           "cubic",
		"net.ipv4.tcp_available_congestion_control": "reno cubic bbr",
		"net.core.default_qdisc":                    "fq_codel",
		"net.ipv6.route.max_size":                   "4096",
		"vm.swappiness":                             "60",
		"vm.max_map_count":                          "65530",
		"vm.min_free_kbytes":                        "67584",
		"vm.overcommit_memory":                      "0",
	}
	switch m.bbr {
	case "module":
		d["net.ipv4.tcp_available_congestion_control"] = "reno cubic"
	case "missing":
		d["net.ipv4.tcp_available_congestion_control"] = "reno cubic"
	}
	return d
}

func writeT(t *testing.T, root, p, data string) {
	t.Helper()
	full := filepath.Join(root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (m machine) build(t *testing.T) *Env {
	t.Helper()
	if m.kernel == "" {
		m.kernel = "6.1.0-25-amd64"
	}
	if m.init == "" {
		m.init = "systemd"
	}
	if m.nrOpen == 0 {
		m.nrOpen = 1048576
	}
	if m.cpus == 0 {
		m.cpus = 1
	}
	root := t.TempDir()
	vals := kernelDefaults(m)
	if m.conntrack {
		vals["net.netfilter.nf_conntrack_max"] = "65536"
		vals["net.netfilter.nf_conntrack_tcp_timeout_established"] = "432000"
		writeT(t, root, hashsizePath, "65536\n")
	}
	for k, v := range m.sysctl {
		vals[k] = v
	}
	for _, k := range m.missing {
		delete(vals, k)
	}
	for k, v := range vals {
		writeT(t, root, sysctlPath(k), v+"\n")
	}
	total := m.mem
	if m.memTotal > 0 {
		total = m.memTotal
	}
	writeT(t, root, "/proc/meminfo", fmt.Sprintf("MemTotal:       %d kB\nMemAvailable:   %d kB\n", total/1024, total/2048))
	writeT(t, root, "/proc/1/status", fmt.Sprintf("Name:\tinit\nCpus_allowed_list:\t0-%d\n", m.cpus-1))
	hard := m.pid1Hard
	if hard == 0 {
		hard = m.nrOpen
	}
	writeT(t, root, "/proc/1/limits", fmt.Sprintf("Limit                     Soft Limit           Hard Limit           Units\nMax open files            %d              %d              files\n", hard, hard))
	writeT(t, root, "/proc/self/cgroup", "0::/user.slice/session-1.scope\n")
	writeT(t, root, "/proc/swaps", "Filename\tType\tSize\tUsed\tPriority\n")
	writeT(t, root, "/etc/os-release", "PRETTY_NAME=\"Test Linux\"\n")
	if m.init == "systemd" {
		os.MkdirAll(filepath.Join(root, "/run/systemd/system"), 0o755)
		writeT(t, root, "/etc/systemd/system/x-ui.service", shippedUnit(t))
	}
	if m.bbr == "module" {
		writeT(t, root, "/lib/modules/"+m.kernel+"/modules.dep", "kernel/net/ipv4/tcp_bbr.ko:\nkernel/net/sched/sch_fq.ko:\n")
	} else {
		writeT(t, root, "/lib/modules/"+m.kernel+"/modules.dep", "kernel/net/sched/sch_fq.ko:\n")
		writeT(t, root, "/lib/modules/"+m.kernel+"/modules.builtin", "kernel/net/ipv4/tcp_bbr.ko\n")
	}
	for i, n := range m.nics {
		dev := "/sys/class/net/" + n.Name
		os.MkdirAll(filepath.Join(root, dev, "device"), 0o755)
		writeT(t, root, dev+"/speed", fmt.Sprint(n.Speed))
		for q := 0; q < n.RxQueues; q++ {
			os.MkdirAll(filepath.Join(root, dev, fmt.Sprintf("queues/rx-%d", q)), 0o755)
		}
		_ = i
	}
	for p, data := range m.files {
		writeT(t, root, p, data)
	}
	vendor := map[string]bool{}
	for _, v := range m.vendor {
		vendor[v] = true
	}
	e := &Env{
		Root:      root,
		Facts:     &FactsOverride{MemBytes: m.mem, CPUs: m.cpus, Kernel: m.kernel, Virt: m.virt, Init: m.init, PageSize: 4096},
		Bin:       "/usr/local/x-ui/x-ui",
		Out:       &bytes.Buffer{},
		FailWrite: map[string]error{},
		PkgOwned:  func(p string) bool { return vendor[p] },
	}
	e.Run = e.realRun
	for _, k := range m.readOnly {
		e.FailWrite[sysctlPath(k)] = syscall.EROFS
	}
	return e
}

func shippedUnit(t *testing.T) string {
	b, err := os.ReadFile("../../x-ui.service.debian")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func live(t *testing.T, e *Env, key string) string {
	t.Helper()
	return normValue(e.readTrim(sysctlPath(key)))
}

func mustApply(t *testing.T, e *Env, o ApplyOptions) *Result {
	t.Helper()
	r, err := e.Apply(o, "test")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func targetMap(f *Facts) map[string]Target {
	m := map[string]Target{}
	for _, t := range Targets(f) {
		m[t.Key] = t
	}
	return m
}

func facts(memGiB float64, cpus int) *Facts {
	f := &Facts{MemBytes: int64(memGiB * float64(GiB)), CPUs: cpus, PageSize: 4096, NrOpen: 1048576, NrOpenRW: true, KMajor: 6, KMinor: 1, BBR: "available"}
	f.MemTotal = f.MemBytes
	f.TCPMemMax = f.MemBytes / 4096 * 3 / 32
	f.G = float64(int64(memGiB + 0.5))
	if f.G < 0.5 {
		f.G = 0.5
	}
	f.Fast = cpus >= 8
	f.PortLo, f.PortHi = 32768, 60999
	return f
}

// The worked examples of the design: every formula at every size.
func TestTargetsTable(t *testing.T) {
	type row struct {
		mem                                float64
		cpus                               int
		nofile                             int64
		gomem, gogc                        string
		somax, syn, backlog, tw, orph, buf int64
		budget                             bool
		ct                                 int64
		minFree                            int64
	}
	rows := []row{
		{1, 1, 1048576, "504MiB", "", 8192, 8192, 2048, 65536, 32768, 4 * MiB, false, 131072, 0},
		{2, 2, 1048576, "1200MiB", "", 16384, 16384, 4096, 65536, 32768, 8 * MiB, false, 131072, 0},
		{8, 4, 1048576, "5260MiB", "150", 65535, 65536, 16384, 131072, 65536, 32 * MiB, false, 524288, 32768},
		{16, 8, 1048576, "10521MiB", "150", 65535, 65536, 16384, 262144, 131072, 32 * MiB, true, 1048576, 65536},
		{128, 56, 2097152, "84172MiB", "150", 65535, 65536, 16384, 2097152, 1048576, 32 * MiB, true, 8388608, 524288},
	}
	for _, r := range rows {
		f := facts(r.mem, r.cpus)
		f.Conntrack = true
		s := ServiceTargets(f)
		tm := targetMap(f)
		got := []any{s.NoFile, s.GoMemLimit, s.GoGC, tm["net.core.somaxconn"].Num, tm["net.ipv4.tcp_max_syn_backlog"].Num,
			tm["net.core.netdev_max_backlog"].Num, tm["net.ipv4.tcp_max_tw_buckets"].Num, tm["net.ipv4.tcp_max_orphans"].Num,
			tm["net.ipv4.tcp_rmem"].Num, tm["net.core.netdev_budget"].Num == 600, tm["net.netfilter.nf_conntrack_max"].Num,
			tm["vm.min_free_kbytes"].Num}
		want := []any{r.nofile, r.gomem, r.gogc, r.somax, r.syn, r.backlog, r.tw, r.orph, r.buf, r.budget, r.ct, r.minFree}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%g GiB:\n got %v\nwant %v", r.mem, got, want)
		}
		if s.Hashsize != r.ct/2 {
			t.Errorf("%g GiB: hashsize %d", r.mem, s.Hashsize)
		}
		for k, want := range map[string]string{
			"net.ipv4.ip_local_port_range": "10000 65535", "net.ipv4.tcp_tw_reuse": "1", "net.ipv4.tcp_fin_timeout": "15",
			"net.ipv4.tcp_notsent_lowat": "131072", "net.ipv4.tcp_slow_start_after_idle": "0", "net.ipv4.tcp_mtu_probing": "1",
			"net.ipv4.tcp_fastopen": "|3", "net.ipv4.tcp_congestion_control": "bbr", "net.core.default_qdisc": "fq",
			"net.core.rmem_max": "16777216", "vm.swappiness": "10", "vm.max_map_count": "262144", "kernel.pid_max": "4194304",
			"fs.nr_open": fmt.Sprint(r.nofile), "fs.file-max": fmt.Sprint(2 * r.nofile),
			"net.netfilter.nf_conntrack_tcp_timeout_established": "7200",
		} {
			if tt := tm[k]; tt.Text() != want {
				t.Errorf("%g GiB: %s = %q, want %q", r.mem, k, tt.Text(), want)
			}
		}
	}

	// Production: 121 GiB, tcp_mem raised to 32 GiB by hand.
	f := facts(121, 56)
	f.MemBytes = 126877696 * KiB
	f.TCPMemMax = 8388608
	f.NICs = []NIC{{Name: "eno1", Driver: "ixgbe", Speed: 10000, RxQueues: 56}}
	s := ServiceTargets(f)
	tm := targetMap(f)
	if s.NoFile != 2097152 || s.GoMemLimit != "63705MiB" || tm["net.ipv4.tcp_max_tw_buckets"].Num != 1048576 ||
		tm["net.ipv4.tcp_max_orphans"].Num != 524288 || tm["vm.min_free_kbytes"].Num != 495616 {
		t.Errorf("production: %+v tw %d orph %d minfree %d", s, tm["net.ipv4.tcp_max_tw_buckets"].Num,
			tm["net.ipv4.tcp_max_orphans"].Num, tm["vm.min_free_kbytes"].Num)
	}
	// IPv6 route cache only before 6.3; netdev_budget on a 10G NIC even with few CPUs.
	f = facts(2, 2)
	f.KMajor, f.KMinor = 6, 3
	f.NICs = []NIC{{Speed: 10000}}
	f.Fast = true
	tm = targetMap(f)
	if _, ok := tm["net.ipv6.route.max_size"]; ok {
		t.Error("route.max_size on 6.3")
	}
	if tm["net.core.netdev_budget"].Num != 600 {
		t.Error("netdev_budget on a 10G NIC")
	}
	f = facts(1, 1)
	if targetMap(f)["net.ipv6.route.max_size"].Num != 65536 {
		t.Error("route.max_size on 6.1")
	}
	// Half a GiB counts as 0.5.
	f = facts(0.4, 1)
	if f.G != 0.5 || targetMap(f)["net.core.somaxconn"].Num != 8192 {
		t.Errorf("tiny: G %g", f.G)
	}
	// No BBR without the module, nor on old kernels.
	f = facts(1, 1)
	f.BBR = "missing"
	if _, ok := targetMap(f)["net.ipv4.tcp_congestion_control"]; ok {
		t.Error("bbr without the module")
	}
	f = facts(1, 1)
	f.KMajor, f.KMinor = 4, 9
	if _, ok := targetMap(f)["net.ipv4.tcp_congestion_control"]; ok {
		t.Error("bbr on 4.9")
	}
}

// A big machine whose fs.nr_open write fails gets no LimitNOFILE above it:
// systemd would refuse to start the service.
func TestNoFileCappedWhenNrOpenFails(t *testing.T) {
	e := machine{mem: 128 * GiB, cpus: 56}.build(t)
	e.FailWrite[sysctlPath("fs.nr_open")] = syscall.EINVAL
	mustApply(t, e, ApplyOptions{})
	if d := e.readTrim(DropInFile); strings.Contains(d, "LimitNOFILE") {
		t.Fatalf("drop-in above fs.nr_open:\n%s", d)
	}
	e2 := machine{mem: 128 * GiB, cpus: 56}.build(t)
	mustApply(t, e2, ApplyOptions{})
	if d := e2.readTrim(DropInFile); !strings.Contains(d, "LimitNOFILE=2097152") || live(t, e2, "fs.nr_open") != "2097152" {
		t.Fatalf("nr_open %s, drop-in:\n%s", live(t, e2, "fs.nr_open"), d)
	}
}

// LimitNOFILE is capped by fs.nr_open when that cannot be raised, and by
// PID 1's hard limit in a container.
func TestNoFileClamp(t *testing.T) {
	f := facts(128, 56)
	f.NrOpenRW = false
	if n := ServiceTargets(f).NoFile; n != 1048576 {
		t.Fatalf("read-only nr_open: %d", n)
	}
	f = facts(128, 56)
	f.Virt, f.Pid1Hard = "lxc", 524288
	if n := ServiceTargets(f).NoFile; n != 524288 {
		t.Fatalf("container: %d", n)
	}
	f = facts(1, 1)
	f.Virt, f.Pid1Hard = "docker", 524288
	if n := ServiceTargets(f).NoFile; n != 524288 {
		t.Fatalf("docker: %d", n)
	}
}

func TestPortRangeKeepsListenersOut(t *testing.T) {
	f := facts(1, 1)
	f.Listeners = []int{22, 9999, 11000, 20001, 30000, 40000}
	f.Reserved = map[int]bool{30000: true}
	tt := targetMap(f)["net.ipv4.ip_local_port_range"]
	if tt.Lo != 20002 || tt.Hi != 65535 {
		t.Fatalf("got %d-%d", tt.Lo, tt.Hi)
	}
}

func TestParseSysctl(t *testing.T) {
	got := parseSysctl(`# comment
; other comment
 net.core.somaxconn = 1024
-net/ipv4/tcp_tw_reuse=1
net.ipv4.tcp_rmem =	4096   87380 	 6291456
net.ipv4.conf.*.rp_filter = 2
bogus line
`)
	want := []kv{{"net.core.somaxconn", "1024"}, {"net.ipv4.tcp_tw_reuse", "1"}, {"net.ipv4.tcp_rmem", "4096 87380 6291456"}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v", got)
	}
}

func TestSysctlOrderAndMasking(t *testing.T) {
	e := machine{mem: GiB, files: map[string]string{
		"/usr/lib/sysctl.d/50-pid-max.conf": "kernel.pid_max = 4194304\n",
		"/usr/lib/sysctl.d/10-a.conf":       "net.core.somaxconn = 1000\n",
		"/etc/sysctl.d/10-a.conf":           "net.core.somaxconn = 2000\n", // masks /usr/lib's
		"/run/sysctl.d/20-b.conf":           "net.core.somaxconn = 3000\n",
		"/usr/local/lib/sysctl.d/30-c.conf": "vm.swappiness = 30\n",
		"/etc/sysctl.d/51-x-ui.conf":        "net.core.somaxconn = 99999\n",          // ours: ignored
		"/etc/sysctl.d/99-x-ui.conf":        Header + "net.core.somaxconn = 88888\n", // ours before: ignored
		"/etc/sysctl.d/99-bbr-x-ui.conf":    "net.ipv4.tcp_congestion_control = bbr\n",
		"/etc/sysctl.conf":                  "vm.swappiness = 5\n",
		"/etc/sysctl.d/40-masked.conf":      "vm.max_map_count = 1\n",
		"/usr/lib/sysctl.d/40-masked.conf":  "vm.max_map_count = 2\n",
	}}.build(t)
	os.Remove(e.P("/etc/sysctl.d/40-masked.conf"))
	os.Symlink("/dev/null", e.P("/etc/sysctl.d/40-masked.conf"))
	os.Symlink("../sysctl.conf", e.P("/etc/sysctl.d/99-sysctl.conf"))
	o := e.othersSettings()
	if o["net.core.somaxconn"].Value != "3000" || o["net.core.somaxconn"].File != "/run/sysctl.d/20-b.conf" {
		t.Errorf("somaxconn %+v", o["net.core.somaxconn"])
	}
	if o["vm.swappiness"].Value != "5" || o["vm.swappiness"].File != "/etc/sysctl.conf" {
		t.Errorf("swappiness %+v", o["vm.swappiness"])
	}
	if _, ok := o["vm.max_map_count"]; ok {
		t.Errorf("masked file read: %+v", o["vm.max_map_count"])
	}
	if _, ok := o["net.ipv4.tcp_congestion_control"]; ok {
		t.Error("legacy x-ui file counted as someone else's")
	}
	if !e.adminOwned("/etc/sysctl.d/99-sysctl.conf") || e.adminOwned("/usr/lib/sysctl.d/10-a.conf") {
		t.Error("owner classifier")
	}
	// A 99-x-ui.conf that x-ui did not write is somebody else's file.
	writeT(t, e.Root, OldSysctlFile, "vm.max_map_count = 77\n")
	if o := e.othersSettings(); o["vm.max_map_count"].File != OldSysctlFile {
		t.Errorf("foreign 99-x-ui.conf ignored: %+v", o["vm.max_map_count"])
	}
}

// A fresh 1 GiB VM: the expected file, live values, drop-in and state.
func TestApplyFreshSmallVM(t *testing.T) {
	e := machine{mem: GiB, cpus: 1, files: map[string]string{
		"/etc/sysctl.d/10-bufferbloat.conf": "net.core.default_qdisc = fq_codel\n",
	}, vendor: []string{"/etc/sysctl.d/10-bufferbloat.conf"}}.build(t)
	r := mustApply(t, e, ApplyOptions{})
	for k, want := range map[string]string{
		"net.core.somaxconn":              "8192",
		"net.ipv4.ip_local_port_range":    "10000 65535",
		"net.ipv4.tcp_rmem":               "4096 131072 6291456", // 4 MiB target is below the default
		"net.ipv4.tcp_wmem":               "4096 16384 4194304",
		"net.ipv4.tcp_fastopen":           "3",
		"net.ipv4.tcp_congestion_control": "bbr",
		"net.core.default_qdisc":          "fq", // a vendor file's choice is overridden
		"net.ipv4.tcp_mtu_probing":        "1",
		"kernel.pid_max":                  "4194304",
		"fs.file-max":                     "9223372036854775807", // never lowered
		"vm.min_free_kbytes":              "67584",
	} {
		if got := live(t, e, k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	conf := e.readTrim(SysctlFile)
	if !strings.HasPrefix(conf, strings.TrimSpace(Header[:60])) {
		t.Fatalf("no header:\n%s", conf)
	}
	for _, line := range []string{"net.core.somaxconn = 8192", "net.ipv4.ip_local_port_range = 10000 65535", "net.ipv4.tcp_fastopen = 3"} {
		if !strings.Contains(conf, "\n"+line+"\n") {
			t.Errorf("51-x-ui.conf lacks %q:\n%s", line, conf)
		}
	}
	if strings.Contains(conf, "fs.file-max") || strings.Contains(conf, "tcp_rmem") {
		t.Errorf("51-x-ui.conf persists a key it does not raise:\n%s", conf)
	}
	drop := e.readTrim(DropInFile)
	if strings.Contains(drop, "LimitNOFILE") || !strings.Contains(drop, "Environment=GOMEMLIMIT=504MiB") ||
		strings.Contains(drop, "GOGC") || !strings.Contains(drop, "ExecStartPre=-/usr/local/x-ui/x-ui tune apply --boot") {
		t.Errorf("drop-in:\n%s", drop)
	}
	if !r.Restart || len(r.Changed) == 0 {
		t.Errorf("result %+v", r)
	}
	if !strings.Contains(strings.Join(e.Ran, "\n"), "systemctl daemon-reload") {
		t.Errorf("no daemon-reload: %v", e.Ran)
	}
	st, had, _ := e.loadState()
	if !had || st.Keys["net.core.somaxconn"].Orig != "4096" || st.Keys["net.core.somaxconn"].Written != "8192" {
		t.Errorf("state %+v", st.Keys["net.core.somaxconn"])
	}
}

func snapshot(t *testing.T, e *Env) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, dir := range []string{"/proc", "/etc", "/sys", "/lib"} {
		filepath.WalkDir(e.P(dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			b, _ := os.ReadFile(p)
			if strings.HasPrefix(e.unP(p), "/proc/sys/") {
				b = []byte(normValue(string(b))) // the kernel prints tabs
			}
			if d.Type()&fs.ModeSymlink != 0 {
				l, _ := os.Readlink(p)
				b = []byte("link:" + l)
			}
			h := sha256.Sum256(b)
			out[e.unP(p)] = hex.EncodeToString(h[:8])
			return nil
		})
	}
	return out
}

func diffSnap(a, b map[string]string) []string {
	var d []string
	for k, v := range a {
		if b[k] != v {
			d = append(d, k)
		}
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			d = append(d, k+" (new)")
		}
	}
	sort.Strings(d)
	return d
}

// Applying twice changes nothing the second time: no writes, same bytes,
// same modification times, same state.
func TestIdempotent(t *testing.T) {
	e := machine{mem: 8 * GiB, cpus: 4, conntrack: true}.build(t)
	mustApply(t, e, ApplyOptions{})
	st1, _ := os.ReadFile(e.P(StateFile))
	var mt []time.Time
	for _, f := range []string{SysctlFile, DropInFile, StateFile} {
		s, err := os.Stat(e.P(f))
		if err != nil {
			t.Fatal(err)
		}
		mt = append(mt, s.ModTime())
	}
	snap := snapshot(t, e)
	time.Sleep(20 * time.Millisecond)
	e.Ran = nil
	r := mustApply(t, e, ApplyOptions{})
	if len(r.Changed) != 0 {
		t.Fatalf("second apply changed %v", r.Changed)
	}
	if d := diffSnap(snap, snapshot(t, e)); len(d) > 0 {
		t.Fatalf("second apply touched %v", d)
	}
	for i, f := range []string{SysctlFile, DropInFile, StateFile} {
		s, _ := os.Stat(e.P(f))
		if !s.ModTime().Equal(mt[i]) {
			t.Errorf("%s rewritten", f)
		}
	}
	st2, _ := os.ReadFile(e.P(StateFile))
	if !bytes.Equal(st1, st2) {
		t.Error("state rewritten")
	}
	if strings.Contains(strings.Join(e.Ran, "\n"), "daemon-reload") {
		t.Error("daemon-reload without a change")
	}
	// Boot mode re-applies nothing either.
	r = mustApply(t, e, ApplyOptions{Boot: true})
	if len(r.Changed) != 0 {
		t.Fatalf("boot changed %v", r.Changed)
	}
	// And status reports no drift.
	d, err := e.Status(false)
	if err != nil || len(d) != 0 {
		t.Fatalf("drift after apply: %v %v", d, err)
	}
}

// Revert puts the machine back exactly, keeps a foreign change, and turns
// automatic tuning off until a manual apply.
func TestRevertExact(t *testing.T) {
	m := machine{mem: 16 * GiB, cpus: 8, conntrack: true, files: map[string]string{
		"/etc/sysctl.d/99-bbr-x-ui.conf":                               "#fq_codel:cubic\nnet.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr\n",
		"/etc/systemd/system/x-ui.service.d/limits.conf":               "# Written by x-ui tune.sh. The shipped unit already sets these\n[Service]\nLimitNOFILE=1048576\n",
		"/etc/systemd/system/x-ui.service.d/override.conf":             "[Service]\nEnvironment=FOO=1\n",
		"/sys/module/nf_conntrack/parameters/hashsize":                 "65536\n",
		"/proc/sys/net/netfilter/nf_conntrack_max":                     "65536\n",
		"/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established": "432000\n",
	}}
	e := m.build(t)
	before := snapshot(t, e)
	r := mustApply(t, e, ApplyOptions{})
	if e.exists(LegacyBBRFile) || e.exists(DropInDir+"/limits.conf") {
		t.Fatal("legacy files not moved aside")
	}
	if live(t, e, "net.netfilter.nf_conntrack_max") != "1048576" || e.readTrim(hashsizePath) != "524288" {
		t.Fatalf("conntrack not raised: %v", r.Changed)
	}
	if !strings.Contains(e.readTrim(SysctlFile), "-net.netfilter.nf_conntrack_max = 1048576") {
		t.Fatal("conntrack line lacks the - prefix")
	}
	if !strings.Contains(e.readTrim(ModprobeFile), "options nf_conntrack hashsize=524288") {
		t.Fatal("no modprobe file")
	}
	rv, err := e.Revert(false, false)
	if err != nil {
		t.Fatal(err)
	}
	after := snapshot(t, e)
	if d := diffSnap(before, after); len(d) > 0 {
		t.Fatalf("revert left differences: %v\n%v", d, rv.Problems)
	}
	st, _, _ := e.loadState()
	if !st.Disabled {
		t.Fatal("revert did not disable")
	}
	// --auto respects the flag; a manual apply clears it.
	if r := mustApply(t, e, ApplyOptions{Auto: true}); !r.Disabled || len(r.Changed) != 0 {
		t.Fatalf("auto apply after revert: %+v", r)
	}
	if r := mustApply(t, e, ApplyOptions{Boot: true}); !r.Disabled {
		t.Fatal("boot apply after revert")
	}
	mustApply(t, e, ApplyOptions{})
	if st, _, _ := e.loadState(); st.Disabled {
		t.Fatal("manual apply did not clear the flag")
	}

	// A value someone changes after x-ui wrote it is left alone by revert.
	writeT(t, e.Root, sysctlPath("net.core.somaxconn"), "50000\n")
	rv, _ = e.Revert(false, false)
	if live(t, e, "net.core.somaxconn") != "50000" {
		t.Fatal("revert overwrote a foreign change")
	}
	if !strings.Contains(strings.Join(rv.Problems, "\n"), "net.core.somaxconn left at 50000") {
		t.Fatalf("not reported: %v", rv.Problems)
	}

	// --purge removes the state too.
	mustApply(t, e, ApplyOptions{})
	if _, err := e.Revert(true, false); err != nil {
		t.Fatal(err)
	}
	if e.exists(StateDir) {
		t.Fatal("purge left the state directory")
	}
}

// Without the state file, revert still removes x-ui's files (by header) and
// nothing else.
func TestRevertWithoutState(t *testing.T) {
	e := machine{mem: 2 * GiB, cpus: 2, files: map[string]string{
		"/etc/sysctl.d/90-mine.conf": "# Written by me\nnet.core.somaxconn = 1\n",
	}}.build(t)
	mustApply(t, e, ApplyOptions{})
	os.Remove(e.P(StateFile))
	r, err := e.Revert(false, false)
	if err != nil {
		t.Fatal(err)
	}
	if e.exists(SysctlFile) || e.exists(DropInFile) || !e.exists("/etc/sysctl.d/90-mine.conf") {
		t.Fatal("wrong files removed")
	}
	if !strings.Contains(strings.Join(r.Problems, "\n"), "no state file") {
		t.Fatalf("not reported: %v", r.Problems)
	}
}

// Production-like: hand-set values and other tools' files are all kept.
func TestProductionLike(t *testing.T) {
	m := machine{mem: 126877696 * KiB, cpus: 56, kernel: "7.0.0-1-amd64", nrOpen: 1048576, conntrack: true,
		nics: []NIC{{Name: "eno1", Speed: 10000, RxQueues: 56}},
		sysctl: map[string]string{
			"net.ipv4.ip_local_port_range": "1024\t65535", "net.ipv4.tcp_tw_reuse": "1", "net.ipv4.tcp_fin_timeout": "15",
			"net.core.somaxconn": "65535", "net.ipv4.tcp_max_syn_backlog": "65536", "net.core.netdev_max_backlog": "16384",
			"net.core.netdev_budget": "600", "net.ipv4.tcp_max_tw_buckets": "1048576", "net.ipv4.tcp_max_orphans": "262144",
			"net.ipv4.tcp_mem": "4194304\t6291456\t8388608", "net.ipv4.tcp_rmem": "4096\t131072\t33554432",
			"net.ipv4.tcp_wmem": "4096\t16384\t33554432", "net.core.default_qdisc": "fq_codel",
			"net.netfilter.nf_conntrack_max": "8388608", "net.netfilter.nf_conntrack_tcp_timeout_established": "7200",
			"fs.nr_open": "2097152",
		},
		files: map[string]string{
			"/etc/sysctl.d/90-edge-proxy.conf":                        "net.core.netdev_max_backlog = 16384\nnet.netfilter.nf_conntrack_max = 8388608\nnet.netfilter.nf_conntrack_tcp_timeout_established = 7200\nnet.ipv4.ip_local_port_range = 1024 65535\n",
			"/etc/sysctl.d/99-zet-capacity.conf":                      "net.ipv4.tcp_congestion_control = cubic\nnet.core.default_qdisc = fq_codel\nnet.ipv4.tcp_max_orphans = 262144\nnet.ipv4.tcp_mem = 4194304 6291456 8388608\nfs.nr_open = 2097152\nnet.ipv4.tcp_rmem = 4096 131072 33554432\nnet.ipv4.tcp_wmem = 4096 16384 33554432\n",
			"/etc/modprobe.d/edge-proxy.conf":                         "options nf_conntrack hashsize=4194304\n",
			"/sys/module/nf_conntrack/parameters/hashsize":            "4194304\n",
			"/etc/systemd/system/x-ui.service.d/90-zet-capacity.conf": "[Service]\nLimitNOFILE=2097152\nTimeoutStopSec=20s\nKillMode=control-group\nEnvironment=GOGC=150\nEnvironment=GOMEMLIMIT=72GiB\n",
		}}
	m.memTotal = m.mem
	e := m.build(t)
	f := e.gatherFacts()
	if f.CPUs != 56 || f.G != 121 {
		t.Fatalf("facts %+v", f)
	}
	mustApply(t, e, ApplyOptions{})
	for k, want := range map[string]string{
		"net.ipv4.ip_local_port_range":    "1024 65535",
		"net.ipv4.tcp_congestion_control": "cubic", // admin's file
		"net.core.default_qdisc":          "fq_codel",
		"net.ipv4.tcp_max_orphans":        "524288",
		"net.netfilter.nf_conntrack_max":  "8388608",
		"net.ipv4.tcp_rmem":               "4096 131072 33554432",
		"fs.nr_open":                      "2097152",
		"net.ipv4.tcp_notsent_lowat":      "131072",
		"vm.min_free_kbytes":              "495616",
	} {
		if got := live(t, e, k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if e.readTrim(hashsizePath) != "4194304" || e.exists(ModprobeFile) {
		t.Error("conntrack hashsize changed or persisted although Edge Proxy's is the same")
	}
	drop := e.readTrim(DropInFile)
	if strings.Contains(drop, "GOMEMLIMIT") || strings.Contains(drop, "GOGC") || !strings.Contains(drop, "LimitNOFILE=2097152") {
		t.Errorf("drop-in:\n%s", drop)
	}
	conf := e.readTrim(SysctlFile)
	for _, bad := range []string{"tcp_congestion_control", "default_qdisc", "ip_local_port_range", "nf_conntrack_max", "netdev_max_backlog"} {
		if strings.Contains(conf, bad) {
			t.Errorf("51-x-ui.conf sets %s, which an admin's file covers:\n%s", bad, conf)
		}
	}
	var buf bytes.Buffer
	e.Out = &buf
	e.Status(false)
	if !strings.Contains(buf.String(), "GOMEMLIMIT is set in /etc/systemd/system/x-ui.service.d/90-zet-capacity.conf") ||
		!strings.Contains(buf.String(), "overridden by: KillMode=control-group") {
		t.Errorf("status:\n%s", buf.String())
	}
}

// A Docker container: /proc/sys is read-only and memory is the cgroup's.
func TestDockerReadOnly(t *testing.T) {
	m := machine{mem: 15 * GiB, cpus: 1, virt: "docker", pid1Hard: 524288}
	e := m.build(t)
	e.Facts.MemBytes = 0 // detect it
	writeT(t, e.Root, "/proc/self/cgroup", "0::/\n")
	writeT(t, e.Root, "/sys/fs/cgroup/memory.max", fmt.Sprint(GiB)+"\n")
	writeT(t, e.Root, "/sys/fs/cgroup/cpu.max", "100000 100000\n")
	for k := range kernelDefaults(m) {
		e.FailWrite[sysctlPath(k)] = syscall.EROFS
	}
	r := mustApply(t, e, ApplyOptions{})
	f := e.gatherFacts()
	if f.MemBytes != GiB || f.CPUs != 1 {
		t.Fatalf("facts R %d C %d", f.MemBytes, f.CPUs)
	}
	if e.exists(SysctlFile) {
		t.Fatalf("sysctl file written in a read-only container:\n%s", e.readTrim(SysctlFile))
	}
	drop := e.readTrim(DropInFile)
	if strings.Contains(drop, "LimitNOFILE") || !strings.Contains(drop, "GOMEMLIMIT=504MiB") {
		t.Fatalf("drop-in:\n%s", drop)
	}
	ran := strings.Join(e.Ran, "\n")
	if strings.Contains(ran, "timedatectl") || strings.Contains(ran, "irqbalance") || strings.Contains(ran, "mkswap") || strings.Contains(ran, "modprobe") {
		t.Fatalf("host services touched in a container: %v", e.Ran)
	}
	var buf bytes.Buffer
	e.Out = &buf
	if _, err := e.Status(true); err != nil {
		t.Fatal(err)
	}
	var js struct {
		Plan struct {
			Keys []KeyPlan `json:"sysctl"`
		} `json:"plan"`
	}
	if err := json.Unmarshal(buf.Bytes(), &js); err != nil {
		t.Fatal(err)
	}
	for _, k := range js.Plan.Keys {
		if k.State != "read-only" {
			t.Errorf("%s: %s", k.Key, k.State)
		}
	}
	_ = r
	// A container with its own network namespace does not see tcp_mem at
	// all: the estimate is the host's, scaled to the cgroup, as before.
	os.Remove(e.P(sysctlPath("net.ipv4.tcp_mem")))
	if got := ServiceTargets(e.gatherFacts()).GoMemLimit; got != "504MiB" {
		t.Fatalf("without tcp_mem: GOMEMLIMIT %s", got)
	}
}

// LXC: only net.* is writable; bbr is refused by the host (EPERM).
func TestLXCNetOnly(t *testing.T) {
	m := machine{mem: 2 * GiB, cpus: 2, virt: "lxc", pid1Hard: 524288}
	e := m.build(t)
	for k := range kernelDefaults(m) {
		if !strings.HasPrefix(k, "net.") {
			e.FailWrite[sysctlPath(k)] = syscall.EACCES
		}
	}
	e.FailWrite[sysctlPath("net.core.rmem_max")] = syscall.EACCES
	r := mustApply(t, e, ApplyOptions{})
	_ = r
	if live(t, e, "net.core.somaxconn") != "16384" || live(t, e, "net.ipv4.tcp_fin_timeout") != "15" {
		t.Fatal("net keys not applied")
	}
	conf := e.readTrim(SysctlFile)
	if strings.Contains(conf, "vm.") || strings.Contains(conf, "fs.") || strings.Contains(conf, "kernel.") || strings.Contains(conf, "rmem_max") {
		t.Fatalf("read-only keys persisted:\n%s", conf)
	}
	// The host refuses BBR: reported, not persisted, apply still succeeds.
	e2 := m.build(t)
	e2.FailWrite[sysctlPath("net.ipv4.tcp_congestion_control")] = syscall.EPERM
	r2 := mustApply(t, e2, ApplyOptions{})
	if strings.Contains(e2.readTrim(SysctlFile), "tcp_congestion_control") {
		t.Fatal("refused bbr persisted")
	}
	if !strings.Contains(strings.Join(r2.Problems, "\n"), "enable it on the host") {
		t.Fatalf("problems %v", r2.Problems)
	}
}

// The kernel rejects a value (EINVAL) or lacks a key (ENOENT): skipped,
// reported, never fatal.
func TestErrors(t *testing.T) {
	e := machine{mem: GiB, missing: []string{"net.ipv6.route.max_size"}}.build(t)
	e.FailWrite[sysctlPath("net.ipv4.tcp_congestion_control")] = syscall.EINVAL
	r := mustApply(t, e, ApplyOptions{})
	if !strings.Contains(strings.Join(r.Problems, "\n"), "rejected") {
		t.Fatalf("%v", r.Problems)
	}
	if strings.Contains(e.readTrim(SysctlFile), "route.max_size") || strings.Contains(e.readTrim(SysctlFile), "tcp_congestion_control") {
		t.Fatal("missing or rejected key persisted")
	}
	// Failing to write one of x-ui's own files is reported, not a crash.
	e2 := machine{mem: GiB}.build(t)
	e2.FailWrite[SysctlFile] = syscall.ENOSPC
	r2 := mustApply(t, e2, ApplyOptions{})
	if !strings.Contains(strings.Join(r2.Problems, "\n"), "51-x-ui.conf") {
		t.Fatalf("%v", r2.Problems)
	}
}

// An admin's file decides choice keys; a vendor file does not; limits from
// any file are respected.
func TestAdminChoices(t *testing.T) {
	e := machine{mem: GiB, files: map[string]string{
		"/etc/sysctl.d/50-mine.conf":   "net.ipv4.tcp_congestion_control = cubic\nnet.ipv4.tcp_tw_reuse = 0\nnet.core.somaxconn = 30000\n",
		"/etc/sysctl.d/10-vendor.conf": "vm.swappiness = 20\n",
	}, vendor: []string{"/etc/sysctl.d/10-vendor.conf"}, sysctl: map[string]string{"net.core.somaxconn": "30000", "net.ipv4.tcp_tw_reuse": "0"}}.build(t)
	mustApply(t, e, ApplyOptions{})
	if live(t, e, "net.ipv4.tcp_congestion_control") != "cubic" || live(t, e, "net.ipv4.tcp_tw_reuse") != "0" {
		t.Error("admin choice overridden")
	}
	if live(t, e, "vm.swappiness") != "10" {
		t.Error("vendor default kept")
	}
	if live(t, e, "net.core.somaxconn") != "30000" || strings.Contains(e.readTrim(SysctlFile), "net.core.somaxconn =") {
		t.Error("higher admin limit lowered or overridden")
	}
	// With cubic chosen by the admin, no BBR modules file either.
	if e.exists(ModulesLoadFile) {
		t.Error("modules-load written for an admin's cubic")
	}
}

// A smaller machine (VPS downgrade) shrinks x-ui's own persisted value but
// never lowers anything live.
func TestDowngradeNoRatchet(t *testing.T) {
	e := machine{mem: 8 * GiB, cpus: 4}.build(t)
	mustApply(t, e, ApplyOptions{})
	if live(t, e, "net.core.somaxconn") != "65535" {
		t.Fatal("setup")
	}
	e.Facts.MemBytes = GiB
	writeT(t, e.Root, sysctlPath("net.ipv4.tcp_mem"), "12288\t16384\t24576\n")
	mustApply(t, e, ApplyOptions{})
	if live(t, e, "net.core.somaxconn") != "65535" {
		t.Error("live lowered")
	}
	if !strings.Contains(e.readTrim(SysctlFile), "net.core.somaxconn = 8192") {
		t.Errorf("persisted value did not follow the smaller machine:\n%s", e.readTrim(SysctlFile))
	}
}

// --boot never touches the unit, services, swap or legacy files.
func TestBootMode(t *testing.T) {
	e := machine{mem: GiB, files: map[string]string{
		"/etc/sysctl.d/99-bbr-x-ui.conf": "net.ipv4.tcp_congestion_control = bbr\n",
	}}.build(t)
	r := mustApply(t, e, ApplyOptions{Boot: true})
	if e.exists(DropInFile) || !e.exists(LegacyBBRFile) || !e.exists(SysctlFile) {
		t.Fatal("boot touched the unit or legacy files, or skipped sysctl")
	}
	ran := strings.Join(e.Ran, "\n")
	for _, bad := range []string{"daemon-reload", "timedatectl", "apt-get", "enable"} {
		if strings.Contains(ran, bad) {
			t.Errorf("boot ran %q", bad)
		}
	}
	if len(r.Changed) == 0 {
		t.Error("boot changed nothing")
	}
	// The CLI's boot mode always exits 0, even when the lock is held.
	t.Setenv("XUI_TUNE_ROOT", e.Root)
	unlock, err := e.lock(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	var out bytes.Buffer
	if code := run([]string{"apply", "--boot"}, "t", &out, &out); code != 0 {
		t.Fatalf("boot exit %d: %s", code, out.String())
	}
}

// fakeCommands makes e.Run answer the commands in answers, succeed for
// those starting with one of ok, and fail for the rest.
func fakeCommands(e *Env, answers map[string]string, ok ...string) {
	e.Run = func(_ time.Duration, name string, args ...string) (string, error) {
		c := strings.TrimSpace(name + " " + strings.Join(args, " "))
		e.Ran = append(e.Ran, c)
		if out, found := answers[c]; found {
			return out, nil
		}
		for _, p := range ok {
			if strings.HasPrefix(c, p) {
				return "", nil
			}
		}
		return "", errNotRun
	}
}

// hostCommands are what the host services run when they change something.
var hostCommands = []string{"timedatectl set-ntp", "apt-get install", "systemctl enable --now", "mkswap"}

// Host services on a tiny KVM VM with no time-sync client: chrony and
// irqbalance installed, a swapfile created; revert undoes them.
func TestServicesSmallVM(t *testing.T) {
	e := machine{mem: GiB, cpus: 4, nics: []NIC{{Name: "eth0", Speed: 1000, RxQueues: 4}}}.build(t)
	os.MkdirAll(e.P("/var/lib"), 0o755)
	fakeCommands(e, map[string]string{"command -v apt-get": "/usr/bin/apt-get"},
		"apt-get install", "systemctl enable", "systemctl daemon-reload")
	mustApply(t, e, ApplyOptions{})
	ran := strings.Join(e.Ran, "\n")
	for _, want := range []string{"apt-get install -y -qq chrony", "systemctl enable --now chronyd",
		"apt-get install -y -qq irqbalance", "systemctl enable --now irqbalance",
		`systemctl enable --now var-lib-x\x2dui-swapfile.swap`} {
		if !strings.Contains(ran, want) {
			t.Errorf("did not run %q:\n%s", want, ran)
		}
	}
	if strings.Contains(ran, "timedatectl set-ntp") {
		t.Errorf("timedatectl run without timesyncd:\n%s", ran)
	}
	if !e.exists(SwapFile) || !e.exists(`/etc/systemd/system/var-lib-x\x2dui-swapfile.swap`) {
		t.Fatal("no swapfile or unit")
	}
	st, _, _ := e.loadState()
	if st.NTP || st.Swap == "" || fmt.Sprint(st.Enabled) != "[chronyd irqbalance]" || fmt.Sprint(st.Installed) != "[chrony irqbalance]" {
		t.Fatalf("state %+v", st)
	}
	e.Ran = nil
	if _, err := e.Revert(false, false); err != nil {
		t.Fatal(err)
	}
	ran = strings.Join(e.Ran, "\n")
	for _, want := range []string{"systemctl disable --now chronyd", "systemctl disable --now irqbalance", "swapoff /var/lib/x-ui/swapfile"} {
		if !strings.Contains(ran, want) {
			t.Errorf("revert did not run %q:\n%s", want, ran)
		}
	}
	if e.exists(SwapFile) {
		t.Fatal("swapfile left")
	}

	// A state from an x-ui that turned timesyncd on: revert turns it off.
	e2 := machine{mem: 4 * GiB}.build(t)
	if err := e2.saveState(&State{Version: 1, Keys: map[string]*KeyState{}, NTP: true}, nil); err != nil {
		t.Fatal(err)
	}
	e2.Ran = nil
	if _, err := e2.Revert(false, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(e2.Ran, "\n"), "timedatectl set-ntp false") {
		t.Errorf("revert of an older state: %v", e2.Ran)
	}
}

// An update (--auto without --host) never touches the host services; a fresh
// install (--auto --host) and a manual apply do, and the boot apply never.
func TestHostServicesOnlyOnFreshInstall(t *testing.T) {
	for _, c := range []struct {
		name string
		o    ApplyOptions
		args []string
		host bool
	}{
		{"update", ApplyOptions{Auto: true}, []string{"apply", "--auto"}, false},
		{"fresh install", ApplyOptions{Auto: true, Host: true}, []string{"apply", "--auto", "--host"}, true},
		{"manual", ApplyOptions{}, []string{"apply"}, true},
		{"boot", ApplyOptions{Boot: true}, []string{"apply", "--boot"}, false},
	} {
		for _, viaCLI := range []bool{false, true} {
			e := machine{mem: GiB, cpus: 4, nics: []NIC{{Name: "eth0", Speed: 1000, RxQueues: 4}}}.build(t)
			os.MkdirAll(e.P("/var/lib"), 0o755)
			if viaCLI {
				// The CLI builds its own Env: the swapfile shows what ran.
				t.Setenv("XUI_TUNE_ROOT", e.Root)
				t.Setenv("XUI_TUNE_FACTS", `{"mem_bytes":1073741824,"cpus":4,"kernel":"6.1.0-25-amd64","init":"systemd","page_size":4096}`)
				var out bytes.Buffer
				if code := run(c.args, "t", &out, &out); code != 0 {
					t.Fatalf("%s: exit %d\n%s", c.name, code, out.String())
				}
				if got := e.exists(SwapFile); got != c.host {
					t.Errorf("%s (CLI): swapfile %v, want %v", c.name, got, c.host)
				}
				continue
			}
			fakeCommands(e, map[string]string{"command -v apt-get": "/usr/bin/apt-get"},
				"apt-get install", "systemctl enable", "systemctl daemon-reload")
			mustApply(t, e, c.o)
			ran := strings.Join(e.Ran, "\n")
			did := false
			for _, h := range hostCommands {
				if strings.Contains(ran, h) {
					did = true
				}
			}
			if did != c.host || e.exists(SwapFile) != c.host {
				t.Errorf("%s: host services run %v (swapfile %v), want %v:\n%s", c.name, did, e.exists(SwapFile), c.host, ran)
			}
		}
	}
}

// Time sync never overrides an admin: timesyncd turned off stays off, and a
// client package the admin removed is not replaced by chrony.
func TestTimeSyncRespectsAdmin(t *testing.T) {
	e := machine{mem: 4 * GiB}.build(t)
	fakeCommands(e, map[string]string{
		"systemctl list-unit-files --no-legend systemd-timesyncd.service": "systemd-timesyncd.service disabled enabled",
		"timedatectl show -p NTP --value":                                 "no",
		"command -v apt-get":                                              "/usr/bin/apt-get",
	}, "apt-get install", "systemctl enable", "systemctl daemon-reload", "timedatectl set-ntp")
	r := mustApply(t, e, ApplyOptions{})
	ran := strings.Join(e.Ran, "\n")
	if strings.Contains(ran, "timedatectl set-ntp") || strings.Contains(ran, "install -y -qq chrony") {
		t.Fatalf("turned time sync on against the admin:\n%s", ran)
	}
	if !strings.Contains(strings.Join(r.Problems, "\n"), "timedatectl set-ntp true") {
		t.Errorf("not reported: %v", r.Problems)
	}

	e2 := machine{mem: 4 * GiB}.build(t)
	fakeCommands(e2, map[string]string{
		"command -v apt-get":    "/usr/bin/apt-get",
		"command -v dpkg-query": "/usr/bin/dpkg-query",
		"dpkg-query -W --showformat=${Package} ${Status}\n chrony systemd-timesyncd ntp ntpsec openntpd": "chrony deinstall ok config-files\n",
	}, "apt-get install", "systemctl enable", "systemctl daemon-reload")
	r = mustApply(t, e2, ApplyOptions{})
	if ran := strings.Join(e2.Ran, "\n"); strings.Contains(ran, "apt-get install -y -qq chrony") {
		t.Fatalf("chrony installed again after the admin removed it:\n%s", ran)
	}
	if !strings.Contains(strings.Join(r.Problems, "\n"), "chrony was removed") {
		t.Errorf("not reported: %v", r.Problems)
	}
}

// irqbalance is not installed when the admin removed it, nor when the NIC's
// interrupts are already placed; interrupts at the kernel's default (also
// on a NUMA node, and a virtio NIC's on its PCI parent) still get it.
func TestIRQBalanceRespectsAdmin(t *testing.T) {
	type irqs map[string]string // IRQ -> smp_affinity
	build := func(t *testing.T, virtio bool, node string, aff irqs) *Env {
		e := machine{mem: 4 * GiB, cpus: 8, nics: []NIC{{Name: "eth0", Speed: 10000, RxQueues: 4}}}.build(t)
		writeT(t, e.Root, "/proc/irq/default_smp_affinity", "ff\n")
		writeT(t, e.Root, "/sys/devices/system/cpu/online", "0-7\n")
		writeT(t, e.Root, "/sys/devices/system/node/node0/cpulist", "0-3\n")
		writeT(t, e.Root, "/sys/devices/system/node/node1/cpulist", "4-7\n")
		pci := "/sys/devices/pci0000:00/0000:00:03.0"
		dev := pci
		if virtio {
			dev = pci + "/virtio0"
		}
		os.MkdirAll(e.P(dev), 0o755)
		for irq, m := range aff {
			writeT(t, e.Root, pci+"/msi_irqs/"+irq, "msix\n")
			writeT(t, e.Root, "/proc/irq/"+irq+"/smp_affinity", m+"\n")
		}
		if node != "" {
			writeT(t, e.Root, dev+"/numa_node", node+"\n")
		}
		link := e.P("/sys/class/net/eth0/device")
		os.RemoveAll(link)
		if err := os.Symlink("../../../.."+dev, link); err != nil {
			t.Fatal(err)
		}
		fakeCommands(e, map[string]string{"command -v apt-get": "/usr/bin/apt-get"}, "apt-get install", "systemctl enable", "systemctl daemon-reload")
		return e
	}
	for _, c := range []struct {
		name    string
		virtio  bool
		node    string
		aff     irqs
		install bool
	}{
		{"default masks", false, "", irqs{"40": "ff", "41": "ff", "42": "ff"}, true},
		{"one queue pinned", false, "", irqs{"40": "ff", "41": "02", "42": "ff"}, false},
		{"all moved off the cores", false, "", irqs{"40": "03", "41": "03", "42": "03"}, false},
		{"NUMA node default", false, "1", irqs{"40": "f0", "41": "f0"}, true},
		{"NUMA node, spread", false, "1", irqs{"40": "10", "41": "20"}, false},
		{"virtio, spread by the driver", true, "", irqs{"24": "ff", "25": "01", "26": "02"}, false},
		{"virtio, default", true, "", irqs{"24": "ff", "25": "ff"}, true},
	} {
		e := build(t, c.virtio, c.node, c.aff)
		r := mustApply(t, e, ApplyOptions{})
		ran := strings.Join(e.Ran, "\n")
		if got := strings.Contains(ran, "apt-get install -y -qq irqbalance"); got != c.install {
			t.Errorf("%s: installed %v, want %v\n%v", c.name, got, c.install, r.Problems)
		}
		if !c.install && !strings.Contains(strings.Join(r.Problems, "\n"), "already have CPUs set") {
			t.Errorf("%s: not reported: %v", c.name, r.Problems)
		}
	}

	// Removed by the admin (dpkg remembers it): not installed again.
	e := build(t, false, "", irqs{"40": "ff"})
	fakeCommands(e, map[string]string{
		"command -v apt-get":    "/usr/bin/apt-get",
		"command -v dpkg-query": "/usr/bin/dpkg-query",
		"dpkg-query -W --showformat=${Package} ${Status}\n irqbalance": "irqbalance deinstall ok config-files\n",
	}, "apt-get install", "systemctl enable", "systemctl daemon-reload")
	r := mustApply(t, e, ApplyOptions{})
	if strings.Contains(strings.Join(e.Ran, "\n"), "install -y -qq irqbalance") {
		t.Fatal("irqbalance installed again after the admin removed it")
	}
	if !strings.Contains(strings.Join(r.Problems, "\n"), "irqbalance: removed") {
		t.Errorf("not reported: %v", r.Problems)
	}
	var buf bytes.Buffer
	e.Out = &buf
	e.Status(false)
	if !strings.Contains(buf.String(), "irqbalance: removed from this server") {
		t.Errorf("status:\n%s", buf.String())
	}
}

func TestSwapUnitName(t *testing.T) {
	if got := swapUnitName("/var/lib/x-ui/swapfile"); got != `var-lib-x\x2dui-swapfile.swap` {
		t.Fatal(got)
	}
}

func TestPathGuard(t *testing.T) {
	e := &Env{Root: t.TempDir()}
	defer func() {
		if recover() == nil {
			t.Fatal("no panic")
		}
	}()
	e.P("/../../etc/passwd")
}

// Property: whatever the live values and other files say, x-ui never plans
// a live value below the current one for a limit, never narrows the port
// range, and never overrides an admin's choice.
func TestNeverLower(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	base := machine{mem: 4 * GiB, cpus: 4}
	e := base.build(t)
	f := e.gatherFacts()
	keys := Targets(f)
	for i := 0; i < 300; i++ {
		files := map[string]string{}
		var mine strings.Builder
		for _, tt := range keys {
			var v string
			switch tt.Class {
			case ClassLimit, ClassBits:
				v = fmt.Sprint(rng.Int63n(4 * max(tt.Num, 4)))
			case ClassField:
				v = fmt.Sprintf("4096 %d %d", rng.Int63n(1<<20), rng.Int63n(1<<26))
			case ClassWiden:
				lo := 1024 + rng.Int63n(40000)
				v = fmt.Sprintf("%d %d", lo, lo+1+rng.Int63n(65535-lo-1))
			case ClassChoice:
				v = []string{"0", "1", "2", "bbr", "cubic", "15", "60"}[rng.Intn(7)]
			}
			writeT(t, e.Root, sysctlPath(tt.Key), v+"\n")
			if rng.Intn(3) == 0 {
				fmt.Fprintf(&mine, "%s = %s\n", tt.Key, v)
			}
		}
		files["/etc/sysctl.d/50-admin.conf"] = mine.String()
		writeT(t, e.Root, "/etc/sysctl.d/50-admin.conf", mine.String())
		st := newState()
		for _, tt := range keys {
			// Sometimes x-ui wrote what is live now, or persisted it.
			if live := normValue(e.readTrim(sysctlPath(tt.Key))); rng.Intn(2) == 0 {
				st.Keys[tt.Key] = &KeyState{Written: live, Orig: "1"}
			} else if rng.Intn(2) == 0 {
				st.Keys[tt.Key] = &KeyState{File: live}
			}
		}
		p := e.plan(e.gatherFacts(), st)
		admin := e.othersSettings()
		for _, k := range p.Keys {
			o, inFile := admin[k.Key]
			switch k.T.Class {
			case ClassLimit:
				if k.Want != "" && i64(k.Want) <= i64(k.Live) {
					t.Fatalf("%s: lowers %s to %s", k.Key, k.Live, k.Want)
				}
				if k.Persist != "" && inFile && i64(k.Persist) <= i64(o.Value) {
					t.Fatalf("%s: persists %s over a file's %s", k.Key, k.Persist, o.Value)
				}
				if k.HandBack && (!inFile || i64(k.Want) != i64(o.Value)) {
					t.Fatalf("%s: hands back %s, the file says %s", k.Key, k.Want, o.Value)
				}
			case ClassField:
				if k.Want != "" && i64(strings.Fields(k.Want)[2]) <= i64(strings.Fields(k.Live)[2]) {
					t.Fatalf("%s: lowers %s to %s", k.Key, k.Live, k.Want)
				}
			case ClassWiden:
				if k.Want != "" {
					w, l := strings.Fields(k.Want), strings.Fields(k.Live)
					if i64(w[0]) > i64(l[0]) || i64(w[1]) < i64(l[1]) {
						t.Fatalf("narrows %s to %s", k.Live, k.Want)
					}
				}
			case ClassBits:
				if k.Want != "" && i64(k.Want)&i64(k.Live) != i64(k.Live) {
					t.Fatalf("%s: drops bits %s -> %s", k.Key, k.Live, k.Want)
				}
			case ClassChoice:
				if inFile && (k.Persist != "" || (k.Want != "" && k.Want != o.Value)) {
					t.Fatalf("%s: overrides the admin's %s (write %q)", k.Key, o.Value, k.Want)
				}
				if k.HandBack && (!inFile || k.Want != o.Value) {
					t.Fatalf("%s: hands back %q, the admin's file says %q", k.Key, k.Want, o.Value)
				}
			}
		}
	}
}

// sysctlBoot applies every sysctl file, x-ui's included, in systemd-sysctl's
// order, first resetting the keys in reset (a boot); with nil it keeps the
// live values (as "sysctl --system" does).
func sysctlBoot(t *testing.T, e *Env, reset map[string]string) {
	t.Helper()
	for k, v := range reset {
		writeT(t, e.Root, sysctlPath(k), v+"\n")
	}
	byName := map[string]string{}
	for _, d := range sysctlDirs {
		for _, f := range e.glob(d + "/*.conf") {
			if _, ok := byName[filepath.Base(f)]; !ok {
				byName[filepath.Base(f)] = f
			}
		}
	}
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		data, err := e.read(e.resolve(byName[n]))
		if err != nil {
			continue
		}
		for _, a := range parseSysctl(data) {
			if e.exists(sysctlPath(a.Key)) {
				writeT(t, e.Root, sysctlPath(a.Key), a.Value+"\n")
			}
		}
	}
}

// A value an admin (or Edge Proxy) sets in a file of their own after x-ui
// applied wins: at boot and on "sysctl --system" for a file named after
// x-ui's, and from x-ui's next start for one named before it. A choice x-ui
// had set is handed back to the admin's file and left to it from then on.
func TestAdminFileAfterApply(t *testing.T) {
	defaults := map[string]string{"net.ipv4.tcp_congestion_control": "cubic", "net.core.somaxconn": "4096", "net.netfilter.nf_conntrack_max": "65536"}
	cc, somax, ct := "net.ipv4.tcp_congestion_control", "net.core.somaxconn", "net.netfilter.nf_conntrack_max"
	for _, file := range []string{"/etc/sysctl.d/60-mine.conf", "/etc/sysctl.d/90-edge-proxy.conf", "/etc/sysctl.conf", "/etc/sysctl.d/30-early.conf"} {
		e := machine{mem: 4 * GiB, cpus: 4, conntrack: true}.build(t)
		if file == "/etc/sysctl.conf" {
			os.MkdirAll(e.P("/etc/sysctl.d"), 0o755)
			if err := os.Symlink("../sysctl.conf", e.P("/etc/sysctl.d/99-sysctl.conf")); err != nil { // Debian, Ubuntu
				t.Fatal(err)
			}
		}
		mustApply(t, e, ApplyOptions{Auto: true})
		conf := e.readTrim(SysctlFile)
		if live(t, e, cc) != "bbr" || !strings.Contains(conf, "net.core.somaxconn = 32768") || !strings.Contains(conf, "nf_conntrack_max = 262144") {
			t.Fatalf("setup: cc %s\n%s", live(t, e, cc), conf)
		}
		// The admin now chooses cubic and raises two limits above x-ui's.
		writeT(t, e.Root, file, "net.ipv4.tcp_congestion_control = cubic\nnet.core.somaxconn = 65535\nnet.netfilter.nf_conntrack_max = 8388608\n")
		early := file == "/etc/sysctl.d/30-early.conf"

		// "sysctl --system" right away, then a reboot: x-ui has not run.
		for i, reset := range []map[string]string{nil, defaults} {
			sysctlBoot(t, e, reset)
			got := fmt.Sprint(live(t, e, cc), " ", live(t, e, somax), " ", live(t, e, ct))
			if want := "cubic 65535 8388608"; !early && got != want {
				t.Errorf("%s, %s before x-ui ran: %s, want %s", file, []string{"sysctl --system", "boot"}[i], got, want)
			}
		}
		// x-ui starts: the boot apply gives everything to the admin's file.
		r := mustApply(t, e, ApplyOptions{Boot: true})
		if got := fmt.Sprint(live(t, e, cc), " ", live(t, e, somax), " ", live(t, e, ct)); got != "cubic 65535 8388608" {
			t.Errorf("%s, after x-ui's boot apply: %s (%v)", file, got, r.Changed)
		}
		conf = e.readTrim(SysctlFile)
		for _, k := range []string{cc, somax, ct} {
			if strings.Contains(conf, k+" =") {
				t.Errorf("%s: x-ui's file still sets %s:\n%s", file, k, conf)
			}
		}
		st, _, _ := e.loadState()
		for _, k := range []string{cc, somax, ct} {
			if ks := st.Keys[k]; ks != nil && ks.Written == live(t, e, k) {
				t.Errorf("%s: x-ui still owns %s: %+v", file, k, ks)
			}
		}
		if e.exists(ModulesLoadFile) {
			t.Errorf("%s: BBR modules file kept for the admin's cubic", file)
		}
		// Every boot from now on, and later applies, keep the admin's values.
		sysctlBoot(t, e, defaults)
		mustApply(t, e, ApplyOptions{Boot: true})
		if r := mustApply(t, e, ApplyOptions{}); live(t, e, cc) != "cubic" || live(t, e, somax) != "65535" || len(r.Changed) != 0 {
			t.Errorf("%s, next boot: cc %s somaxconn %s, changed %v", file, live(t, e, cc), live(t, e, somax), r.Changed)
		}
		// Revert leaves the admin's choice alone.
		if _, err := e.Revert(false, false); err != nil {
			t.Fatal(err)
		}
		if live(t, e, cc) != "cubic" || live(t, e, somax) != "65535" {
			t.Errorf("%s, revert: cc %s somaxconn %s", file, live(t, e, cc), live(t, e, somax))
		}
	}

	// A value the admin set by hand (not x-ui's) is not "handed back".
	e := machine{mem: 4 * GiB, files: map[string]string{"/etc/sysctl.d/60-mine.conf": "net.ipv4.tcp_congestion_control = cubic\n"},
		sysctl: map[string]string{"net.ipv4.tcp_congestion_control": "reno"}}.build(t)
	mustApply(t, e, ApplyOptions{})
	if live(t, e, cc) != "reno" {
		t.Errorf("a hand-set value replaced: %s", live(t, e, cc))
	}
}

// x-ui's file used to be 99-x-ui.conf: an apply (also the boot one) removes
// it, revert removes it too, and one x-ui did not write is left alone.
func TestOldSysctlFileReplaced(t *testing.T) {
	old := Header + "\n# Listen queue\nnet.core.somaxconn = 8192\n"
	e := machine{mem: GiB, files: map[string]string{OldSysctlFile: old}}.build(t)
	var buf bytes.Buffer
	e.Out = &buf
	if d, _ := e.Status(false); !strings.Contains(strings.Join(d, " "), OldSysctlFile) {
		t.Errorf("old file not in the drift: %v", d)
	}
	r := mustApply(t, e, ApplyOptions{Boot: true})
	if e.exists(OldSysctlFile) || !strings.Contains(e.readTrim(SysctlFile), "net.core.somaxconn = 8192") {
		t.Fatalf("old file kept or new one missing: %v", r.Changed)
	}
	if !strings.Contains(strings.Join(r.Changed, "\n"), "removed "+OldSysctlFile) {
		t.Errorf("not reported: %v", r.Changed)
	}
	writeT(t, e.Root, OldSysctlFile, old)
	if _, err := e.Revert(false, false); err != nil {
		t.Fatal(err)
	}
	if e.exists(OldSysctlFile) || e.exists(SysctlFile) {
		t.Fatal("revert left x-ui's sysctl files")
	}

	mine := "net.core.somaxconn = 50000\n"
	e = machine{mem: GiB, files: map[string]string{OldSysctlFile: mine}}.build(t)
	mustApply(t, e, ApplyOptions{})
	if e.readTrim(OldSysctlFile) != strings.TrimSpace(mine) || strings.Contains(e.readTrim(SysctlFile), "net.core.somaxconn =") {
		t.Fatalf("someone else's 99-x-ui.conf touched or overridden:\n%s", e.readTrim(SysctlFile))
	}
}

// The CLI end to end on a fake tree, as the installer runs it.
func TestCLI(t *testing.T) {
	e := machine{mem: 2 * GiB, cpus: 2}.build(t)
	t.Setenv("XUI_TUNE_ROOT", e.Root)
	t.Setenv("XUI_TUNE_FACTS", `{"mem_bytes":2147483648,"cpus":2,"kernel":"6.1.0-25-amd64","init":"systemd","page_size":4096}`)
	t.Setenv("XUI_TUNE_BIN", "/usr/local/x-ui/x-ui")
	var out bytes.Buffer
	if code := run([]string{"status", "--check"}, "t", &out, &out); code != 2 {
		t.Fatalf("check before apply: %d\n%s", code, out.String())
	}
	out.Reset()
	if code := run([]string{"apply", "--dry-run"}, "t", &out, &out); code != 0 || e.exists(SysctlFile) {
		t.Fatalf("dry run: %d\n%s", code, out.String())
	}
	out.Reset()
	if code := run([]string{"apply", "--auto"}, "t", &out, &out); code != 0 || !e.exists(SysctlFile) {
		t.Fatalf("apply: %d\n%s", code, out.String())
	}
	out.Reset()
	if code := run([]string{"status", "--check"}, "t", &out, &out); code != 0 {
		t.Fatalf("check after apply: %d\n%s", code, out.String())
	}
	out.Reset()
	if code := run([]string{"status", "--json"}, "t", &out, &out); code != 0 || !json.Valid(out.Bytes()) {
		t.Fatalf("json: %d\n%s", code, out.String())
	}
	out.Reset()
	if code := run([]string{"revert"}, "t", &out, &out); code != 0 || e.exists(SysctlFile) {
		t.Fatalf("revert: %d\n%s", code, out.String())
	}
	out.Reset()
	if code := run([]string{"bogus"}, "t", &out, &out); code != 1 {
		t.Fatalf("bogus: %d", code)
	}
}
