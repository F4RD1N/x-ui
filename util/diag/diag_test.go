//go:build linux

package diag

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/util/hw"
	"github.com/mhsanaei/3x-ui/v2/util/hw/hwtest"
	"github.com/mhsanaei/3x-ui/v2/util/sys"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

func golden(t *testing.T, name, got string) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if string(want) != got {
		t.Errorf("%s differs (run with -update to rewrite it):\n%s", name, diffLines(string(want), got))
	}
}

func diffLines(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	var b strings.Builder
	for i := 0; i < max(len(w), len(g)); i++ {
		var a, c string
		if i < len(w) {
			a = w[i]
		}
		if i < len(g) {
			c = g[i]
		}
		if a != c {
			fmt.Fprintf(&b, "line %d:\n  want %q\n  got  %q\n", i+1, a, c)
		}
	}
	return b.String()
}

// machines are the golden cases: each builds a fresh fixture, since a
// sample moves its counters on.
var machines = []struct {
	name  string
	build func(t *testing.T) *fixture
}{
	{"production-today", productionToday},
	{"production-after", productionAfter},
	{"vps2", vps2},
	{"container", container},
	{"cpuless-node", cpulessNode},
}

func vps2(t *testing.T) *fixture {
	f := newFixture(t, hwtest.VPS(2))
	f.addInstances("0-1", fakeInst{name: "xray-1", cpus: "0-1", busy: 120, fds: 300, limit: 1048576})
	f.cpuLoad(map[int]uint64{0: 30}, 3, 60, 3)
	f.during = append(f.during, func() {
		f.b.SetStat("eth0", "rx_packets", 1000000+60000)
		f.b.SetStat("eth0", "tx_packets", 1000000+50000)
		f.b.SetStat("eth0", "rx_bytes", 1000000000+60000*900)
		f.b.SetStat("eth0", "tx_bytes", 1000000000+50000*1000)
	})
	f.tcp[sys.LocalEndpoint{IP: "203.0.113.5", Port: 444}] = 812
	for p := 0; p < 30; p++ {
		f.udp = append(f.udp, sys.LocalEndpoint{Port: 30000 + p})
	}
	f.netFiles(netCounters{inuse: 900, tw: 210, mem: 300, maxOrphans: 2048, maxTW: 8192, tcpMem: "18000\t24000\t36000", fileMax: 202000, files: 2600})
	return f
}

func container(t *testing.T) *fixture {
	f := newFixture(t, hwtest.Container())
	f.addInstances("0-15", fakeInst{name: "xray-1", cpus: "0-15", busy: 90})
	f.cpuLoad(nil, 1, 20, 0)
	return f
}

// cpulessNode: two sockets and a memory-only node, an instance on each
// socket.
func cpulessNode(t *testing.T) *fixture {
	f := newFixture(t, hwtest.CPULessNode())
	f.addInstances("0-31",
		fakeInst{name: "xray-1", cpus: "0-7,16-23", busy: 900},
		fakeInst{name: "xray-2", cpus: "8-15,24-31", busy: 600})
	f.cpuLoad(map[int]uint64{0: 9, 1: 9, 2: 9}, 2, 40, 0)
	f.traffic("eno1", func(q int) uint64 { return 2000 }, 32)
	return f
}

func TestGolden(t *testing.T) {
	for _, m := range machines {
		t.Run(m.name, func(t *testing.T) {
			golden(t, m.name+".txt", m.build(t).run("--seconds", "3"))
			out := m.build(t).run("--json", "--seconds", "3")
			var v map[string]any
			if err := json.Unmarshal([]byte(out), &v); err != nil {
				t.Fatalf("--json does not parse: %v", err)
			}
			for _, k := range []string{"time", "kernel", "seconds", "hardware", "nics", "sample", "instances", "tcp", "warnings"} {
				if _, ok := v[k]; !ok {
					t.Errorf("--json lacks %q", k)
				}
			}
			golden(t, m.name+".json", out)
		})
	}
}

// The warnings the spec names for production as it ran, and none after the
// split and the NIC tuning.
func TestProductionWarnings(t *testing.T) {
	c := productionToday(t).gather(3)
	for _, want := range []string{
		"every xray instance spans NUMA nodes 0 and 1 and shares cores with another instance",
		"eno1: RSS interrupts on both threads of 2 cores (11/39, 13/41) while 14 cores have no queue interrupt: x-ui tune apply",
		"RSS interrupts uneven: xray-4, xray-6, xray-8 hold 3; xray-1, xray-2, xray-10 none (share 1.6): x-ui tune apply",
		"eno1 hashes UDP on IP addresses only: x-ui tune apply",
		"eno1 flow director overflowed (+3): TCP flows fall back to the RSS queues",
	} {
		if !slices.Contains(c.r.Warnings, want) {
			t.Errorf("today: missing warning %q in:\n%s", want, strings.Join(c.r.Warnings, "\n"))
		}
	}
	c = productionAfter(t).gather(3)
	if len(c.r.Warnings) != 0 {
		t.Errorf("after: warnings:\n%s", strings.Join(c.r.Warnings, "\n"))
	}
	for _, in := range c.r.Instances {
		if in.NICIRQs.RSS != 1 || len(in.Nodes) != 1 || in.NICIRQs.Share != 1.6 {
			t.Errorf("after: %s has RSS %d (share %v) on nodes %v", in.Name, in.NICIRQs.RSS, in.NICIRQs.Share, in.Nodes)
		}
	}
	if x := c.r.NICs[0].XPS; x.Own != 56 {
		t.Errorf("after: XPS %+v", x)
	}
}

func TestSummary(t *testing.T) {
	tuned := []string{
		"NIC eno1: 56 queues, kept (RSS uses 16)",
		"UDP hashing eno1: IPs and ports (was IPs only)",
		"Interrupts eno1: one queue per CPU; RSS 1 per instance, 6 on free CPUs",
		"XPS eno1: each CPU sends on its own queue",
		"Open files: 2097152 per process (x-ui and its cores)",
		"Conntrack: max 8388608 (kept: /etc/sysctl.d/90-edge-proxy.conf)",
		"Backlog: somaxconn 65535, netdev_max_backlog 16384, tcp_max_syn_backlog 65536",
	}
	f := productionAfter(t)
	f.e.summary = func() []string { return tuned }
	// A summary takes no sample and scans no sockets.
	f.e.sleep = func(time.Duration) { t.Error("--summary took a sample") }
	f.e.tcp = func([]int) (map[sys.LocalEndpoint]int, error) { t.Error("--summary counted TCP"); return nil, nil }
	f.e.udp = func(func(sys.LocalEndpoint)) error { t.Error("--summary counted UDP"); return nil }
	golden(t, "summary-production.txt", f.run("--summary"))

	f = vps2(t)
	f.e.summary = func() []string {
		return []string{"Open files: 1048576 per process (x-ui and its cores)", "Backlog: somaxconn 16384, netdev_max_backlog 16384, tcp_max_syn_backlog 16384", "Congestion control: bbr with fq"}
	}
	golden(t, "summary-vps2.txt", f.run("--summary"))

	// The container's NIC line comes from the tuning; diag adds it when
	// tuning is off.
	f = container(t)
	f.e.summary = func() []string { return []string{"Tuning: off ('x-ui tune apply' turns it on)"} }
	out := f.run("--summary")
	if !strings.Contains(out, "\n  "+containerNIC+"\n") || strings.Count(out, "NIC:") != 1 {
		t.Errorf("container summary:\n%s", out)
	}
	f = container(t)
	f.e.summary = func() []string { return []string{containerNIC, "Open files: 1048576 per process (x-ui and its cores)"} }
	if out := f.run("--summary"); strings.Count(out, containerNIC) != 1 {
		t.Errorf("container summary repeats the NIC line:\n%s", out)
	}
	// No instances yet, nothing tuned, a machine without NUMA.
	f = newFixture(t, hwtest.Desktop())
	f.e.summary = nil
	want := "Detected:\n  1 socket, 8 cores, 16 CPUs (2 threads per core), 32 GiB RAM\n  eno1: Intel I210 Gigabit (igb), 1 Gb/s, 4 queues\n  Xray: no instances yet\nConfigured:\n"
	if out := f.run("--summary"); out != want {
		t.Errorf("desktop summary:\n%s\nwant:\n%s", out, want)
	}
}

// treeHash hashes every path, mode, symlink target and file content below
// root.
func treeHash(t *testing.T, root string) string {
	t.Helper()
	h := sha256.New()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		fmt.Fprintf(h, "%s %v\n", strings.TrimPrefix(p, root), info.Mode())
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			l, _ := os.Readlink(p)
			fmt.Fprintf(h, "-> %s\n", l)
		case info.Mode().IsRegular():
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			h.Write(b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// diag only reads: a read-only tree is left exactly as it was, and no
// ethtool setter is called.
func TestReadOnly(t *testing.T) {
	for _, m := range machines {
		t.Run(m.name, func(t *testing.T) {
			f := m.build(t)
			f.during = nil // the sample's script writes the tree
			root := f.b.Root
			err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
				if err != nil || d.Type()&fs.ModeSymlink != 0 {
					return err
				}
				info, err := d.Info()
				if err != nil {
					return err
				}
				return os.Chmod(p, info.Mode().Perm()&^0o222)
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
					if err == nil && d.IsDir() {
						os.Chmod(p, 0o755)
					}
					return nil
				})
			})
			before := treeHash(t, root)
			f.run("--seconds", "1")
			f.run("--json", "--seconds", "1")
			f.run("--summary")
			if after := treeHash(t, root); after != before {
				t.Error("diag changed the tree")
			}
			for _, call := range f.b.Eth.Calls {
				if strings.HasPrefix(call, "Set") {
					t.Errorf("diag called %s", call)
				}
			}
		})
	}
}

// Without root diag shows what it can and says what needs root; it finds
// the cores by their command line.
func TestNotRoot(t *testing.T) {
	f := productionAfter(t)
	f.e.root = false
	out := f.run("--seconds", "1")
	for _, want := range []string{
		"Not run as root: the cores' open files and connections need root.",
		"needs root: open files, TCP connections",
		"Xray instances (10 running)",
		"open files limit 2097152, UDP ports 50 of 55536 (76.164.201.35)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("not root: missing %q in:\n%s", want, out)
		}
	}
	c := f.gather(0)
	for _, in := range c.r.Instances {
		if in.FDs != -1 || in.TCP != -1 || in.UDP == nil {
			t.Errorf("not root: %s fds %d tcp %d udp %v", in.Name, in.FDs, in.TCP, in.UDP)
		}
	}
}

// Instance names: from instances.json, else from the config's file name;
// configs given relative to the core's working directory.
func TestInstanceNames(t *testing.T) {
	f := newFixture(t, hwtest.Desktop())
	f.addInstances("0-15", fakeInst{name: "edge", cpus: "0-7"}, fakeInst{name: "xray-2", cpus: "8-15"})
	// instances.json names the first one otherwise than its file.
	file := &hw.Instances{Version: 1, Allowed: "0-15", Instances: []hw.Instance{{Name: "edge 1", CPUs: "0-7", Config: binDir + "/config-edge.json"}}}
	f.b.WriteFile(hw.InstancesPath(binDir), string(file.Marshal()))
	// The single core of the old layout, and something that is no core.
	f.b.WriteFile("/proc/3001/cmdline", "/usr/local/x-ui/bin/xray-linux-arm64\x00-config=/usr/local/x-ui/bin/config.json\x00")
	f.b.WriteFile("/proc/3001/status", "Cpus_allowed_list:\t0-15\nThreads:\t9\n")
	f.b.WriteFile("/proc/3002/cmdline", "/usr/bin/python3\x00xray-linux-amd64\x00")
	f.b.WriteFile("/proc/3003/cmdline", "bin/xray-linux-amd64\x00-test\x00-c\x00/tmp/x.json\x00")
	c := f.gather(0)
	var names []string
	for _, in := range c.r.Instances {
		names = append(names, in.Name)
	}
	if want := []string{"edge 1", "xray", "xray-2"}; !slices.Equal(names, want) {
		t.Errorf("names %q, want %q", names, want)
	}
	if got := configArg([]string{"-c", "a.json"}) + configArg([]string{"--config=b.json"}) + configArg([]string{"run"}); got != "a.jsonb.json" {
		t.Errorf("configArg: %q", got)
	}
	if got := portsOf(json.RawMessage(`"1000-1002,2000"`)); !slices.Equal(got, []int{1000, 1001, 1002, 2000}) {
		t.Errorf("portsOf: %v", got)
	}
	if got := nameRanges([]string{"xray-1", "xray-2", "xray-3", "edge", "xray-5", "xray-6", "a01", "a02", "a03"}); got != "xray-1..3, edge, xray-5, xray-6, a01, a02, a03" {
		t.Errorf("nameRanges: %q", got)
	}
}

// Every machine the fixtures know runs through every output without
// trouble, with or without instances.
func TestPresets(t *testing.T) {
	for name, m := range map[string]hwtest.Machine{
		"epyc-nps1": hwtest.EPYC(1), "epyc-nps4": hwtest.EPYC(4), "desktop": hwtest.Desktop(), "vps1": hwtest.VPS(1),
		"restricted": hwtest.Restricted(), "bond": hwtest.Bond(), "proxmox": hwtest.ProxmoxBridge(), "vlan": hwtest.VLAN(),
		"managed": hwtest.ManagedIRQs(), "tunnel": hwtest.Tunnel(),
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, m)
			for _, args := range [][]string{{"--seconds", "1"}, {"--json", "--seconds", "1"}, {"--summary"}} {
				if out := f.run(args...); out == "" {
					t.Errorf("%v: no output", args)
				}
			}
			cpus := f.online()
			half := len(cpus) / 2
			if half == 0 {
				return
			}
			f.addInstances(hw.NewCPUSet(cpus...).List(),
				fakeInst{name: "xray-1", cpus: hw.NewCPUSet(cpus[:half]...).List()},
				fakeInst{name: "xray-2", cpus: hw.NewCPUSet(cpus[half:]...).List()})
			out := f.run("--seconds", "1")
			if !strings.Contains(out, "Xray instances (2 running)") {
				t.Errorf("instances not found:\n%s", out)
			}
		})
	}
	// A bond's ports are both reported, under the bond.
	f := newFixture(t, hwtest.Bond())
	if out := f.run("--summary"); !strings.Contains(out, "eno1 (under bond0): Intel 82599ES") || !strings.Contains(out, "eno2 (under bond0)") {
		t.Errorf("bond summary:\n%s", out)
	}
	// Behind a tunnel there is no NIC to show, and the summary says why.
	f = newFixture(t, hwtest.Tunnel())
	if out := f.run("--summary"); !strings.Contains(out, "Network: the default route leaves through wg0 (a tunnel): no NIC under it") {
		t.Errorf("tunnel summary:\n%s", out)
	}
}
