//go:build linux

package tune

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/util/hw"
	"github.com/mhsanaei/3x-ui/v2/util/hw/hwtest"
)

// onHW builds a tune test machine on a hwtest machine's tree: its CPUs,
// NUMA nodes, NICs, interrupts and fake ethtool.
func onHW(t *testing.T, hm hwtest.Machine, mod ...func(*machine)) (*Env, *hwtest.Built) {
	t.Helper()
	b := hm.Build(t)
	topo, err := hw.ReadTopology(b.FS())
	if err != nil {
		t.Fatal(err)
	}
	m := machine{mem: int64(b.M.MemGiB) * GiB, cpus: len(topo.Online), kernel: b.M.Kernel, root: b.Root}
	if hm.IsContainer() {
		m.virt = hm.Virt
	}
	if b.M.Init != "systemd" {
		m.init = b.M.Init
	}
	for _, f := range mod {
		f(&m)
	}
	e := m.build(t)
	e.Eth = b.Eth
	for k, v := range b.FailWrite {
		e.FailWrite[k] = v
	}
	e.Clock = &fakeClock{now: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)}
	e.Probe = &fakeProbe{}
	return e, b
}

// fakeClock moves only when slept.
type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time        { return c.now }
func (c *fakeClock) Sleep(d time.Duration) { c.now = c.now.Add(d) }

// fakeProbe answers as scripted: Pick fails when none is set, and Reach
// takes its answers in order (true once they run out).
type fakeProbe struct {
	none    bool
	reach   []bool
	reached int
}

func (p *fakeProbe) Pick([]hw.Route, time.Time) string {
	if p.none {
		return ""
	}
	return "fake gateway"
}

func (p *fakeProbe) Reach(string, time.Time) bool {
	p.reached++
	if len(p.reach) == 0 {
		return true
	}
	ok := p.reach[0]
	p.reach = p.reach[1:]
	return ok
}

// instances writes the panel's instances.json.
func instances(t *testing.T, b *hwtest.Built, allowed string, sets ...string) {
	t.Helper()
	in := &hw.Instances{Version: 1, Allowed: allowed}
	for i, s := range sets {
		in.Instances = append(in.Instances, hw.Instance{Name: fmt.Sprintf("xray-%d", i+1), CPUs: s, Config: fmt.Sprintf("/usr/local/x-ui/bin/config-%d.json", i+1)})
	}
	b.WriteFile("/usr/local/x-ui/bin/"+hw.InstancesFile, string(in.Marshal()))
}

// prodFixed is the panel's split of ten instances of 5 CPUs on production;
// 42,43,48,49,54,55 stay free (threads beside instances).
var prodFixed = []string{"1,3,5,29,31", "7,9,33,35,37", "11,13,15,39,41", "17,19,21,45,47", "23,25,27,51,53",
	"0,2,4,28,30", "6,8,32,34,36", "10,12,14,38,40", "16,18,20,44,46", "22,24,26,50,52"}

var prodAuto = []string{"1,3,5,29,31,33", "7,9,11,35,37,39", "13,15,17,41,43,45", "19,21,23,47,49", "25,27,51,53,55",
	"0,2,4,28,30,32", "6,8,10,34,36,38", "12,14,16,40,42,44", "18,20,22,46,48", "24,26,50,52,54"}

func nicPlanOf(t *testing.T, e *Env) *nicPlan {
	t.Helper()
	st, _, err := e.loadState()
	if err != nil {
		t.Fatal(err)
	}
	return e.planNICs(e.gatherFacts(), st, nicOpts{})
}

// queueCPU is where a NIC's queue interrupt is now (its affinity list).
func queueCPU(t *testing.T, e *Env, nic string, q int) string {
	t.Helper()
	n := hw.ReadNIC(e.hw(), e.eth(), nic)
	for _, irq := range n.IRQs {
		if irq.Queue == q {
			return irq.Affinity.List()
		}
	}
	return ""
}

func statusText(t *testing.T, e *Env) string {
	t.Helper()
	var buf bytes.Buffer
	e.Out = &buf
	if _, err := e.Status(false); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// cpusOfQueues is where queues 0..n-1 of a NIC are now.
func cpusOfQueues(t *testing.T, e *Env, nic string, n int) []string {
	t.Helper()
	var out []string
	for q := 0; q < n; q++ {
		out = append(out, queueCPU(t, e, nic, q))
	}
	return out
}

func strs(v ...int) []string {
	var out []string
	for _, x := range v {
		out = append(out, fmt.Sprint(x))
	}
	return out
}

// irqSnapshot is every /proc/irq file and queue file of the tree.
func irqSnapshot(t *testing.T, b *hwtest.Built) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, dir := range []string{"/proc/irq", "/sys/devices"} {
		filepath.WalkDir(b.Path(dir), func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			rel := strings.TrimPrefix(p, b.Root)
			if dir == "/sys/devices" && !strings.Contains(rel, "/queues/") {
				return nil
			}
			data, _ := os.ReadFile(p)
			out[rel] = string(data)
			return nil
		})
	}
	return out
}

func diffMaps(a, b map[string]string) []string {
	var d []string
	for k, v := range a {
		if b[k] != v {
			d = append(d, fmt.Sprintf("%s: %q -> %q", k, v, b[k]))
		}
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			d = append(d, k+" (new)")
		}
	}
	slices.Sort(d)
	return d
}

// Production without an instance split (a fresh install): queues kept (RSS
// uses 16 of 56), UDP hashed on ports, one RSS queue per physical core with
// the NIC's node first, every CPU one queue, XPS one to one, no boot unit.
// A second apply changes nothing; revert puts back every interrupt and
// queue file byte for byte.
func TestNICProduction(t *testing.T) {
	e, b := onHW(t, hwtest.Production())
	before := irqSnapshot(t, b)
	np := nicPlanOf(t, e)
	if np.Skip != "" || len(np.NICs) != 1 {
		t.Fatalf("plan: %q %d", np.Skip, len(np.NICs))
	}
	it := np.NICs[0]
	if q := it.Queues; q.State != "kept" || q.Want != 0 || q.Current != 56 || q.RSSUse != 16 || !strings.Contains(q.Note, "RSS uses 16") {
		t.Errorf("queues %+v", q)
	}
	if len(it.Hash) != 2 || it.Hash[0].Want != "sdfn" || it.Hash[1].Want != "sdfn" {
		t.Errorf("hash %+v %+v", it.Hash[0], it.Hash[1])
	}
	if np.Unit != "" {
		t.Error("boot unit planned")
	}

	r := mustApply(t, e, ApplyOptions{Auto: true})
	b.Settle()
	want := strs(1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 0, 2)
	if got := cpusOfQueues(t, e, "eno1", 16); !slices.Equal(got, want) {
		t.Errorf("RSS queues on %v", got)
	}
	n := hw.ReadNIC(e.hw(), e.eth(), "eno1")
	per := map[string]int{}
	for _, q := range n.IRQs {
		per[q.Affinity.List()]++
		if q.Effective.List() != q.Affinity.List() {
			t.Errorf("IRQ %d effective %v", q.IRQ, q.Effective)
		}
	}
	if len(per) != 56 {
		t.Errorf("%d CPUs have queue interrupts", len(per))
	}
	for q := 0; q < 56; q++ {
		if x := n.XPS[q]; len(x) != 1 || x.List() != queueCPU(t, e, "eno1", q) {
			t.Errorf("XPS tx-%d %v", q, x)
		}
	}
	if d := b.Eth.Devs["eno1"]; d.Hash["udp4"] != hw.HashIPsPorts || d.Hash["udp6"] != hw.HashIPsPorts || d.Resets != 0 {
		t.Errorf("hash %v, resets %d", d.Hash, d.Resets)
	}
	if e.exists(NICUnitFile) || slices.ContainsFunc(b.Eth.Calls, func(c string) bool { return strings.HasPrefix(c, "Set") && !strings.HasPrefix(c, "SetFlowHash") }) {
		t.Errorf("queue or table change on an update: %v", b.Eth.Calls)
	}
	// An update does not touch irqbalance's files.
	if e.exists(IRQBalanceDropIn) || e.exists(IRQBalanceScript) {
		t.Error("irqbalance policy written by an update")
	}
	if !strings.Contains(strings.Join(r.Changed, "\n"), "eno1: 56 interrupts moved (one queue per physical core, the NIC's node first)") {
		t.Errorf("changes: %v", r.Changed)
	}
	st, _, _ := e.loadState()
	ns := st.NICs["0000:82:00.0"]
	if ns == nil || ns.IRQ["q0"] == nil || ns.Hash["udp4"] == nil || ns.XPS["tx-16"] == nil {
		t.Fatalf("state %+v", ns)
	}
	// Queue 0's driver hint is CPU 1, where it goes: its XPS stays.
	if ns.XPS["tx-0"] != nil {
		t.Errorf("XPS tx-0 written: %+v", ns.XPS["tx-0"])
	}
	if ns.Name != "eno1" || ns.Driver != "ixgbe" || ns.IRQ["q0"].Written != "1" || ns.IRQ["q0"].Orig != "1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,45,47,49,51,53,55" ||
		ns.Hash["udp4"].Orig != "sd" || ns.Hash["udp4"].Written != "sdfn" || ns.XPS["tx-16"].Orig != "33" || ns.XPS["tx-16"].Written != "4" || ns.Channels != nil {
		t.Fatalf("state %+v", ns)
	}

	// Again: nothing.
	b.Eth.Calls = nil
	if r := mustApply(t, e, ApplyOptions{Auto: true}); len(r.Changed) != 0 {
		t.Errorf("second apply: %v", r.Changed)
	}
	if d, _ := e.Status(false); len(d) != 0 {
		t.Errorf("drift after apply: %v", d)
	}
	for _, c := range b.Eth.Calls {
		if strings.HasPrefix(c, "Set") {
			t.Errorf("second apply called %s", c)
		}
	}

	// Revert: every value back.
	rv, err := e.Revert(false, false)
	if err != nil {
		t.Fatal(err)
	}
	b.Settle()
	if d := diffMaps(before, irqSnapshot(t, b)); len(d) > 0 {
		t.Errorf("revert left %d differences: %v", len(d), d[:min(5, len(d))])
	}
	if d := b.Eth.Devs["eno1"]; d.Hash["udp4"] != hw.HashIPs || d.Hash["udp6"] != hw.HashIPs {
		t.Errorf("hash after revert %v", d.Hash)
	}
	if strings.Contains(strings.Join(rv.Changed, "\n"), "keeps") || !slices.Contains(rv.Changed, "eno1: 56 interrupts back to their CPUs") ||
		!slices.Contains(rv.Changed, "eno1 udp4 hashing: sdfn -> sd") {
		t.Errorf("revert: %v", rv.Changed)
	}
}

// Production with ten instances of 5 CPUs and 6 free: one RSS queue per
// instance, 6 on the free CPUs; every CPU one queue; XPS one to one.
func TestNICProductionSplit(t *testing.T) {
	e, b := onHW(t, hwtest.Production())
	instances(t, b, "0-55", prodFixed...)
	mustApply(t, e, ApplyOptions{})
	b.Settle()
	want := strs(43, 49, 55, 42, 48, 54, 1, 7, 11, 17, 23, 0, 6, 10, 16, 22)
	if got := cpusOfQueues(t, e, "eno1", 16); !slices.Equal(got, want) {
		t.Errorf("RSS queues on %v\n          want %v", got, want)
	}
	n := hw.ReadNIC(e.hw(), e.eth(), "eno1")
	per := map[string]int{}
	for _, q := range n.IRQs {
		per[q.Affinity.List()]++
	}
	for c := 0; c < 56; c++ {
		if per[fmt.Sprint(c)] != 1 {
			t.Errorf("CPU %d: %d queues", c, per[fmt.Sprint(c)])
		}
	}
	for q := 0; q < 56; q++ {
		if x := n.XPS[q]; x.List() != queueCPU(t, e, "eno1", q) {
			t.Errorf("XPS tx-%d %v", q, x)
		}
	}
	got := statusText(t, e)
	for _, w := range []string{
		"NIC eno1 (ixgbe 0000:82:00.0, NUMA node 1, 10000 Mb/s, default route v4+v6)",
		"queues      56 of 56: kept (RSS uses 16: the card's limit)",
		"RSS table   128 entries, even over queues 0-15: kept",
		"udp4/udp6   IPs and ports (was IPs only)",
		"interrupts  56 placed by the instance split: RSS 1 per instance, 6 on free CPUs 42-43,48-49,54-55",
		"XPS         every CPU sends on its own queue",
		"RPS/RFS     off (multi-queue)",
		"irqbalance  installed, not running; eno1 banned for it (90-x-ui.conf)",
	} {
		if !strings.Contains(got, w) {
			t.Errorf("status lacks %q:\n%s", w, got)
		}
	}
	sum := e.summary()
	for _, w := range []string{"NIC eno1: 56 queues, kept (RSS uses 16)", "UDP hashing eno1: IPs and ports (was IPs only)",
		"Interrupts eno1: one queue per CPU; RSS 1 per instance, 6 on free CPUs", "XPS eno1: each CPU sends on its own queue",
		"irqbalance: not running (eno1 banned when it runs)"} {
		if !slices.Contains(sum, w) {
			t.Errorf("summary lacks %q:\n%s", w, strings.Join(sum, "\n"))
		}
	}

	// The split changes (ten auto instances): "tune nic" re-places them.
	instances(t, b, "0-55", prodAuto...)
	r, err := e.RunNIC(NICOptions{})
	if err != nil {
		t.Fatal(err)
	}
	b.Settle()
	want = strs(1, 7, 13, 0, 6, 12, 19, 25, 18, 24, 3, 9, 15, 2, 8, 14)
	if got := cpusOfQueues(t, e, "eno1", 16); !slices.Equal(got, want) {
		t.Errorf("auto split: RSS queues on %v\n          want %v (%v)", got, want, r.Changed)
	}
	np := nicPlanOf(t, e)
	for i, set := range prodAuto {
		c := np.place.Units["eno1"][fmt.Sprintf("xray-%d", i+1)]
		wantRSS := 1
		if strings.Count(set, ",") == 5 {
			wantRSS = 2
		}
		if c[0] != wantRSS {
			t.Errorf("xray-%d: %d RSS queues", i+1, c[0])
		}
	}
	if d, _ := e.Status(false); len(d) != 0 {
		t.Errorf("drift: %v", d)
	}
}

// EPYC with 16 auto instances of 16 whole cores: 3 or 4 queues each, on
// distinct whole cores of its own node; its CPUs send on its own queues.
func TestNICEPYC(t *testing.T) {
	for _, nps := range []int{1, 4} {
		e, b := onHW(t, hwtest.EPYC(nps))
		var sets []string
		for i := 0; i < 16; i++ {
			sets = append(sets, fmt.Sprintf("%d-%d,%d-%d", 16*i, 16*i+15, 16*i+256, 16*i+271))
		}
		instances(t, b, "0-511", sets...)
		mustApply(t, e, ApplyOptions{Auto: true})
		b.Settle()
		topo, _ := hw.ReadTopology(e.hw())
		n := hw.ReadNIC(e.hw(), e.eth(), "enp65s0f0np0")
		for i, s := range sets {
			set, _ := hw.ParseList(s)
			cores := map[int]bool{}
			for _, q := range n.IRQs {
				cpu := q.Affinity[0]
				if len(q.Affinity) != 1 || !set.Has(cpu) {
					continue
				}
				if cores[topo.CoreOf(cpu).ID] || topo.NodeOf(cpu) != topo.NodeOf(set[0]) {
					t.Errorf("nps%d xray-%d: queue %d on CPU %d", nps, i+1, q.Queue, cpu)
				}
				cores[topo.CoreOf(cpu).ID] = true
				for _, c := range n.XPS[q.Queue] {
					if !set.Has(c) {
						t.Errorf("nps%d: CPU %d sends on xray-%d's queue %d", nps, c, i+1, q.Queue)
					}
				}
			}
			if len(cores) < 3 || len(cores) > 4 {
				t.Errorf("nps%d xray-%d: %d queues", nps, i+1, len(cores))
			}
		}
	}
}

// A 2-vCPU VPS: RPS over both CPUs and RFS, with rps_sock_flow_entries; its
// one queue's interrupts stay where they are.
func TestNICVPS(t *testing.T) {
	e, b := onHW(t, hwtest.VPS(2))
	writeT(t, e.Root, sysctlPath("net.core.rps_sock_flow_entries"), "0\n")
	f := e.gatherFacts()
	if !f.RPSUplink || targetMap(f)["net.core.rps_sock_flow_entries"].Num != 65536 {
		t.Fatalf("RFS target: %v %+v", f.RPSUplink, targetMap(f)["net.core.rps_sock_flow_entries"])
	}
	before := irqSnapshot(t, b)
	mustApply(t, e, ApplyOptions{})
	if live(t, e, "net.core.rps_sock_flow_entries") != "65536" || !strings.Contains(e.readTrim(SysctlFile), "net.core.rps_sock_flow_entries = 65536") {
		t.Errorf("rps_sock_flow_entries %s", live(t, e, "net.core.rps_sock_flow_entries"))
	}
	q := "/sys/class/net/eth0/queues/rx-0/"
	if e.readTrim(q+"rps_cpus") != "3" || e.readTrim(q+"rps_flow_cnt") != "65536" {
		t.Errorf("rps_cpus %q, rps_flow_cnt %q", e.readTrim(q+"rps_cpus"), e.readTrim(q+"rps_flow_cnt"))
	}
	after := irqSnapshot(t, b)
	for k, v := range before {
		if strings.HasPrefix(k, "/proc/irq") && after[k] != v {
			t.Errorf("%s changed", k)
		}
	}
	if sum := e.summary(); !slices.Contains(sum, "RPS/RFS eth0: over CPUs 0-1") || !slices.Contains(sum, "NIC eth0: 1 queues") && !slices.Contains(sum, "NIC eth0: 1 queue") {
		t.Errorf("summary %q", sum)
	}
	if d, _ := e.Status(false); len(d) != 0 {
		t.Errorf("drift %v", d)
	}
	// An admin's RPS mask is kept.
	e2, _ := onHW(t, hwtest.VPS(2))
	writeT(t, e2.Root, q+"rps_cpus", "2\n")
	mustApply(t, e2, ApplyOptions{})
	if e2.readTrim(q+"rps_cpus") != "2" || e2.readTrim(q+"rps_flow_cnt") != "65536" {
		t.Errorf("admin's rps_cpus overwritten: %s", e2.readTrim(q+"rps_cpus"))
	}
	// Revert takes x-ui's back.
	if _, err := e.Revert(false, false); err != nil {
		t.Fatal(err)
	}
	if e.readTrim(q+"rps_cpus") != "0" || e.readTrim(q+"rps_flow_cnt") != "0" {
		t.Errorf("after revert: %s %s", e.readTrim(q+"rps_cpus"), e.readTrim(q+"rps_flow_cnt"))
	}
	// Multi-queue NICs never get RPS, and no RFS target.
	e3, _ := onHW(t, hwtest.Desktop())
	if f := e3.gatherFacts(); f.RPSUplink {
		t.Error("RFS target on a multi-queue NIC")
	}
	mustApply(t, e3, ApplyOptions{})
	if e3.readTrim("/sys/class/net/eno1/queues/rx-0/rps_cpus") != "0000" {
		t.Errorf("RPS on a multi-queue NIC: %q", e3.readTrim("/sys/class/net/eno1/queues/rx-0/rps_cpus"))
	}
	// A one-CPU VPS: no RPS, no target.
	e4, _ := onHW(t, hwtest.VPS(1))
	if f := e4.gatherFacts(); f.RPSUplink {
		t.Error("RFS target with one CPU")
	}
}

// Bridges and VLANs resolve to the NIC under them; bnxt hashing UDP on IPs
// only is reported, not changed (its change re-opens the NIC).
func TestNICUnderBridgeAndVLAN(t *testing.T) {
	e, _ := onHW(t, hwtest.ProxmoxBridge())
	np := nicPlanOf(t, e)
	if len(np.NICs) != 1 || np.NICs[0].NIC.Name != "eno1" || !slices.Equal(np.NICs[0].NIC.Via, []string{"vmbr0"}) {
		t.Fatalf("bridge: %+v", np.NICs)
	}
	m := hwtest.VLAN()
	m.NICs[0].Hash = map[string]uint64{"tcp4": hw.HashIPsPorts, "udp4": hw.HashIPs, "tcp6": hw.HashIPsPorts, "udp6": hw.HashIPs}
	e, b := onHW(t, m)
	np = nicPlanOf(t, e)
	if len(np.NICs) != 1 || np.NICs[0].NIC.Name != "eno1" || np.NICs[0].NIC.Via[0] != "eno1.100" {
		t.Fatalf("vlan: %+v", np.NICs)
	}
	it := np.NICs[0]
	if len(it.Hash) != 0 || it.HashNote != "UDP hashed on IPs only (bnxt_en: left as it is)" {
		t.Errorf("bnxt hash: %+v %q", it.Hash, it.HashNote)
	}
	mustApply(t, e, ApplyOptions{})
	for _, c := range b.Eth.Calls {
		if strings.HasPrefix(c, "SetFlowHash") || strings.HasPrefix(c, "SetChannels") {
			t.Errorf("bnxt: %s", c)
		}
	}
	if b.Eth.Devs["eno1"].Resets != 0 {
		t.Error("bnxt reset")
	}
	// 8 of 74 queues on 8 cores: nothing to raise.
	if q := it.Queues; q.State != "ok" || q.Want != 0 {
		t.Errorf("queues %+v", q)
	}
}

// Kernel-managed interrupts: the kernel spread them (no driver hint), so
// they look placed by someone else and are kept; handed to x-ui, the first
// write fails with EIO, the NIC is marked, none is moved, and XPS follows
// where they are.
func TestNICManagedIRQs(t *testing.T) {
	e, b := onHW(t, hwtest.ManagedIRQs())
	before := irqSnapshot(t, b)
	mustApply(t, e, ApplyOptions{})
	if np := nicPlanOf(t, e); np.NICs[0].keep != "foreign" {
		t.Errorf("kernel spread taken as x-ui's: %q", np.NICs[0].keep)
	}
	r := mustApply(t, e, ApplyOptions{TakeIRQs: true})
	st, _, _ := e.loadState()
	ns := st.NICs["0000:07:00.0"]
	if ns == nil || !ns.Managed || len(ns.IRQ) != 0 {
		t.Fatalf("state %+v, problems %v", ns, r.Problems)
	}
	if !strings.Contains(strings.Join(r.Problems, "\n"), "managed by the kernel") {
		t.Errorf("not reported: %v", r.Problems)
	}
	after := irqSnapshot(t, b)
	for k, v := range before {
		if strings.HasPrefix(k, "/proc/irq") && after[k] != v {
			t.Errorf("%s changed", k)
		}
	}
	// Queue q's interrupts run on CPU 2q: CPUs 2q and 2q+1 (its sibling)
	// send on queue q.
	b.Settle()
	n := hw.ReadNIC(e.hw(), e.eth(), "eth0")
	for q := 0; q < 8; q++ {
		if got := n.XPS[q].List(); got != fmt.Sprintf("%d-%d", 2*q, 2*q+1) {
			t.Errorf("XPS tx-%d %s", q, got)
		}
	}
	if r := mustApply(t, e, ApplyOptions{}); len(r.Changed) != 0 {
		t.Errorf("second apply: %v", r.Changed)
	}
	if got := statusText(t, e); !strings.Contains(got, "interrupts  managed by the kernel: kept") {
		t.Errorf("status:\n%s", got)
	}
}

// Containers, tunnels: nothing at all, and said so.
func TestNICSkipped(t *testing.T) {
	e, b := onHW(t, hwtest.Container())
	before := irqSnapshot(t, b)
	mustApply(t, e, ApplyOptions{})
	if len(b.Eth.Calls) != 0 {
		t.Errorf("ethtool in a container: %v", b.Eth.Calls)
	}
	if d := diffMaps(before, irqSnapshot(t, b)); len(d) > 0 {
		t.Errorf("container: %v", d)
	}
	if sum := e.summary(); !slices.Contains(sum, "NIC: left to the host (container)") {
		t.Errorf("summary %q", sum)
	}
	if !strings.Contains(statusText(t, e), "NIC: left to the host (container)") {
		t.Error("status")
	}
	if r, _ := e.RunNIC(NICOptions{Boot: true}); len(r.Changed)+len(r.Problems) != 0 || len(b.Eth.Calls) != 0 {
		t.Errorf("tune nic in a container: %+v", r)
	}

	e, _ = onHW(t, hwtest.Tunnel())
	np := nicPlanOf(t, e)
	if np.Skip != "the default route leaves through wg0 (a tunnel): no NIC under it" {
		t.Errorf("tunnel: %q", np.Skip)
	}
}

// One interrupt placed by someone else: the NIC's interrupts and XPS are
// kept and reported, until --take-irqs hands them over. The driver's hint,
// the node's default and all CPUs count as nobody's.
func TestNICOwnership(t *testing.T) {
	e, b := onHW(t, hwtest.Production())
	b.WriteFile("/proc/irq/105/smp_affinity_list", "4\n")
	b.Settle()
	before := irqSnapshot(t, b)
	r := mustApply(t, e, ApplyOptions{})
	if d := diffMaps(before, irqSnapshot(t, b)); len(d) > 0 {
		t.Errorf("foreign interrupts moved: %v", d[:min(3, len(d))])
	}
	if want := "eno1: interrupts placed by someone else (IRQ 105 on CPU 4): kept; 'x-ui tune apply --take-irqs' hands them to x-ui"; !slices.Contains(r.Problems, want) {
		t.Errorf("not reported: %v", r.Problems)
	}
	if got := statusText(t, e); !strings.Contains(got, "interrupts  placed by someone else (IRQ 105 on CPU 4): kept; 'x-ui tune apply --take-irqs' hands them to x-ui") {
		t.Errorf("status:\n%s", got)
	}
	mustApply(t, e, ApplyOptions{TakeIRQs: true})
	b.Settle()
	if queueCPU(t, e, "eno1", 4) == "4" {
		t.Error("--take-irqs did not move them")
	}
	st, _, _ := e.loadState()
	if !st.NICs["0000:82:00.0"].TakeIRQs {
		t.Error("TakeIRQs not recorded")
	}

	// Hints (EPYC's mlx5), all CPUs and the node's default are nobody's.
	for _, c := range []struct {
		name string
		aff  string
	}{{"all CPUs", "0-55"}, {"node default", "1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,45,47,49,51,53,55"}, {"hint", "1"}} {
		e, b := onHW(t, hwtest.Production())
		b.WriteFile("/proc/irq/101/smp_affinity_list", c.aff+"\n")
		b.Settle()
		np := nicPlanOf(t, e)
		if np.NICs[0].keep != "" {
			t.Errorf("%s: kept as %s", c.name, np.NICs[0].keep)
		}
	}
}

// An X710's flow director vector ("i40e-<pci>:fdir-TxRx-0") is not queue
// 0's: after x-ui's apply the NIC stays x-ui's, a new split moves its
// interrupts, and revert puts every one back; the vector is never touched.
func TestNICSideVector(t *testing.T) {
	for _, driver := range []string{"i40e", "ice"} {
		m := hwtest.ProxmoxBridge()
		m.NICs[0].Driver = driver
		m.NICs[0].Extra = []string{"i40e-0000:01:00.0:fdir-TxRx-0"}
		if driver == "ice" {
			m.NICs[0].Extra = []string{"ice-0000:01:00.0:ctrl-TxRx-0"}
		}
		e, b := onHW(t, m)
		before := irqSnapshot(t, b)
		instances(t, b, "0-31", "8-15,24-31", "0-7,16-23")
		mustApply(t, e, ApplyOptions{})
		b.Settle()
		if np := nicPlanOf(t, e); np.NICs[0].keep != "" {
			t.Fatalf("%s: kept as %q after x-ui's own apply (%s)", driver, np.NICs[0].keep, np.NICs[0].IRQNote)
		}
		instances(t, b, "0-31", "0-7,16-23", "8-15,24-31")
		r, err := e.RunNIC(NICOptions{})
		if err != nil || len(r.Changed) == 0 {
			t.Errorf("%s: a new split moved nothing: %v %v", driver, r.Changed, err)
		}
		if _, err := e.Revert(false, false); err != nil {
			t.Fatal(err)
		}
		b.Settle()
		if d := diffMaps(before, irqSnapshot(t, b)); len(d) > 0 {
			t.Errorf("%s: revert left %d differences: %v", driver, len(d), d[:min(3, len(d))])
		}
	}
}

// irqbalanceOn installs a distribution's irqbalance unit and defaults.
func irqbalanceOn(t *testing.T, b *hwtest.Built, distro string) {
	t.Helper()
	read := func(name string) string {
		data, err := os.ReadFile(filepath.Join("testdata/irqbalance", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	os.Remove(b.Path("/etc/default/irqbalance"))
	switch distro {
	case "debian12", "ubuntu2404":
		b.WriteFile("/usr/lib/systemd/system/irqbalance.service", read(distro+".service"))
		b.WriteFile("/etc/default/irqbalance", read(distro+".default"))
	case "rhel9":
		b.WriteFile("/usr/lib/systemd/system/irqbalance.service", read("rhel9.service"))
		b.WriteFile("/etc/sysconfig/irqbalance", read("rhel9.sysconfig"))
	case "upstream":
		b.WriteFile("/usr/lib/systemd/system/irqbalance.service", read("upstream.service"))
		b.WriteFile("/usr/etc/default/irqbalance.env", read("upstream.env"))
	}
}

// x-ui's irqbalance files, as golden files, on every distribution's unit:
// RHEL's and upstream's set IRQBALANCE_ARGS="" in their environment file,
// which counts as unset (x-ui's environment file comes after it).
func TestIRQBalancePolicy(t *testing.T) {
	golden := func(name string) string {
		data, err := os.ReadFile(filepath.Join("testdata/irqbalance", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	for _, distro := range []string{"debian12", "ubuntu2404", "rhel9", "upstream"} {
		e, b := onHW(t, hwtest.Production())
		irqbalanceOn(t, b, distro)
		fakeCommands(e, nil, "systemctl daemon-reload", "systemctl try-restart")
		r := mustApply(t, e, ApplyOptions{Auto: true, Host: true})
		for file, g := range map[string]string{IRQBalanceDropIn: "90-x-ui.conf", IRQBalanceEnv: "irqbalance.env", IRQBalanceScript: "irqbalance-policy"} {
			got, _ := e.read(file)
			if got != golden(g) {
				t.Errorf("%s: %s:\n%s", distro, file, got)
			}
		}
		if st, err := os.Stat(e.P(IRQBalanceScript)); err != nil || st.Mode().Perm() != 0o755 {
			t.Errorf("%s: script mode %v", distro, st.Mode())
		}
		ran := strings.Join(e.Ran, "\n")
		if !strings.Contains(ran, "systemctl try-restart irqbalance") || !strings.Contains(ran, "systemctl daemon-reload") {
			t.Errorf("%s: ran %v", distro, e.Ran)
		}
		if !strings.Contains(strings.Join(r.Changed, "\n"), "irqbalance: eno1's interrupts banned for it (90-x-ui.conf)") {
			t.Errorf("%s: %v", distro, r.Changed)
		}
		// Unchanged files: no restart.
		e.Ran = nil
		mustApply(t, e, ApplyOptions{})
		if strings.Contains(strings.Join(e.Ran, "\n"), "irqbalance") {
			t.Errorf("%s: restarted again: %v", distro, e.Ran)
		}
		if !e.isOurs(IRQBalanceScript) {
			t.Error("the script is not recognised as x-ui's")
		}
		// Revert removes them and restarts irqbalance (if it runs).
		e.Ran = nil
		if _, err := e.Revert(false, false); err != nil {
			t.Fatal(err)
		}
		if e.exists(IRQBalanceDropIn) || e.exists(IRQBalanceEnv) || e.exists(IRQBalanceScript) || !strings.Contains(strings.Join(e.Ran, "\n"), "systemctl try-restart irqbalance") {
			t.Errorf("%s: revert: %v", distro, e.Ran)
		}
	}
}

// The policy script bans x-ui's NICs and nothing else.
func TestIRQBalanceScript(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "policy")
	if err := os.WriteFile(p, []byte(renderPolicyScript([]string{"0000:82:00.1", "0000:82:00.0"})), 0o755); err != nil {
		t.Fatal(err)
	}
	for dev, want := range map[string]string{
		"/sys/bus/pci/devices/0000:82:00.0": "ban=true",
		"/sys/bus/pci/devices/0000:82:00.1": "ban=true",
		"/sys/bus/pci/devices/0000:82:00.2": "",
		"/sys/bus/pci/devices/0000:00:1f.6": "",
		"":                                  "",
	} {
		out, err := exec.Command(sh, p, dev, "101").Output()
		if err != nil || strings.TrimSpace(string(out)) != want {
			t.Errorf("%q: %q %v", dev, out, err)
		}
	}
	if got := scriptPCIs(renderPolicyScript([]string{"0000:82:00.1", "0000:82:00.0"})); !slices.Equal(got, []string{"0000:82:00.0", "0000:82:00.1"}) {
		t.Errorf("read back %v", got)
	}
}

// Where x-ui cannot add its policy it writes nothing and says what to do;
// while irqbalance runs without the policy, the NICs' interrupts and XPS
// are left to it. With the policy running, x-ui places them.
func TestIRQBalanceCases(t *testing.T) {
	// IRQBALANCE_ARGS set by the admin.
	e, b := onHW(t, hwtest.Production())
	irqbalanceOn(t, b, "debian12")
	b.WriteFile("/etc/default/irqbalance", "IRQBALANCE_ARGS=\"--hintpolicy=exact\"\n")
	r := mustApply(t, e, ApplyOptions{})
	if e.exists(IRQBalanceDropIn) || e.exists(IRQBalanceScript) {
		t.Error("files written against the admin's IRQBALANCE_ARGS")
	}
	if !strings.Contains(strings.Join(r.Problems, "\n"), "IRQBALANCE_ARGS is set in /etc/default/irqbalance; add --policyscript=/var/lib/x-ui/tune/irqbalance-policy there to let x-ui place eno1's interrupts") {
		t.Errorf("not reported: %v", r.Problems)
	}
	// An Environment= of the admin's in a drop-in.
	e, b = onHW(t, hwtest.Production())
	irqbalanceOn(t, b, "ubuntu2404")
	b.WriteFile("/etc/systemd/system/irqbalance.service.d/override.conf", "[Service]\nEnvironment=\"IRQBALANCE_ARGS=--deepestcache=2\"\n")
	if mustApply(t, e, ApplyOptions{}); e.exists(IRQBalanceDropIn) {
		t.Error("files written against the admin's drop-in")
	}
	// ExecStart without the variable.
	e, b = onHW(t, hwtest.Production())
	irqbalanceOn(t, b, "debian12")
	b.WriteFile("/etc/systemd/system/irqbalance.service.d/exec.conf", "[Service]\nExecStart=\nExecStart=/usr/sbin/irqbalance --foreground\n")
	r = mustApply(t, e, ApplyOptions{})
	if e.exists(IRQBalanceDropIn) || !strings.Contains(strings.Join(r.Problems, "\n"), "does not pass $IRQBALANCE_ARGS") {
		t.Errorf("ExecStart without the variable: %v", r.Problems)
	}

	// Running without the policy (an update, which writes no host files):
	// nothing placed.
	m := hwtest.Production()
	m.IRQBalance = "running"
	e, b = onHW(t, m)
	before := irqSnapshot(t, b)
	r = mustApply(t, e, ApplyOptions{Auto: true})
	if d := diffMaps(before, irqSnapshot(t, b)); len(d) > 0 {
		t.Errorf("placed while irqbalance runs without the policy: %v", d[:min(3, len(d))])
	}
	if !strings.Contains(strings.Join(r.Problems, "\n"), "eno1: interrupts left to irqbalance, which runs without x-ui's policy ('x-ui tune apply' adds it)") {
		t.Errorf("not reported: %v", r.Problems)
	}
	if got := statusText(t, e); !strings.Contains(got, "interrupts  left to irqbalance, which runs without x-ui's policy") || !strings.Contains(got, "XPS         kept with the interrupts") {
		t.Errorf("status:\n%s", got)
	}
	if sum := e.summary(); !slices.Contains(sum, "irqbalance: running without x-ui's policy (eno1 left to it)") {
		t.Errorf("summary %q", sum)
	}
	// The dry run of a manual apply shows what the policy allows.
	var buf bytes.Buffer
	e.Out = &buf
	mustApply(t, e, ApplyOptions{DryRun: true})
	if !strings.Contains(buf.String(), "interrupts  56 to place: one queue per physical core, the NIC's node first (56 to move)") {
		t.Errorf("dry run:\n%s", buf.String())
	}

	// Running with x-ui's policy (from a fresh install) that bans eno1:
	// placed, also from where irqbalance had put them before.
	m.IRQBalance = "running-ours"
	e, b = onHW(t, m)
	b.WriteFile(IRQBalanceScript, renderPolicyScript([]string{"0000:82:00.0"}))
	b.WriteFile("/proc/irq/101/smp_affinity_list", "13\n")
	b.Settle()
	mustApply(t, e, ApplyOptions{Auto: true})
	b.Settle()
	if queueCPU(t, e, "eno1", 0) != "1" {
		t.Errorf("not placed with the policy running: %s", queueCPU(t, e, "eno1", 0))
	}
	// A policy that does not ban this NIC (another one's): left to it.
	e, b = onHW(t, m)
	b.WriteFile(IRQBalanceScript, renderPolicyScript([]string{"0000:03:00.0"}))
	before = irqSnapshot(t, b)
	mustApply(t, e, ApplyOptions{Auto: true})
	if d := diffMaps(before, irqSnapshot(t, b)); len(d) > 0 {
		t.Errorf("placed though irqbalance's policy does not ban eno1: %v", d[:min(3, len(d))])
	}
}

// irqbalance is never installed, whatever the NIC, and never stopped or
// disabled; status reports it.
func TestIRQBalanceRespectsAdmin(t *testing.T) {
	e, _ := onHW(t, hwtest.Desktop())
	fakeCommands(e, map[string]string{"command -v apt-get": "/usr/bin/apt-get"}, "apt-get install", "systemctl enable", "systemctl daemon-reload")
	mustApply(t, e, ApplyOptions{})
	ran := strings.Join(e.Ran, "\n")
	if strings.Contains(ran, "irqbalance") {
		t.Errorf("irqbalance touched: %s", ran)
	}
	if e.exists(IRQBalanceDropIn) {
		t.Error("drop-in for an irqbalance that is not installed")
	}
	if got := statusText(t, e); strings.Contains(got, "irqbalance") {
		t.Errorf("status mentions irqbalance:\n%s", got)
	}
	// Running (the admin's choice): it keeps running, through apply and
	// revert; status says how it runs.
	m := hwtest.Production()
	m.IRQBalance = "running"
	e, _ = onHW(t, m)
	fakeCommands(e, nil, "systemctl daemon-reload", "systemctl try-restart")
	mustApply(t, e, ApplyOptions{})
	e.Revert(false, false)
	for _, c := range e.Ran {
		if strings.Contains(c, "irqbalance") && !strings.HasPrefix(c, "systemctl try-restart irqbalance") {
			t.Errorf("ran %q", c)
		}
	}
	mustApply(t, e, ApplyOptions{})
	if got := statusText(t, e); !strings.Contains(got, "irqbalance  running without x-ui's policy: 'systemctl restart irqbalance' applies it") {
		t.Errorf("status:\n%s", got)
	}
}

// raiseMachine is one 28-core socket (2 threads per core) with a NIC of
// 16 of 63 queues: x-ui wants 28.
func raiseMachine(driver string, rssCap int) hwtest.Machine {
	hash := map[string]uint64{"tcp4": hw.HashIPsPorts, "udp4": hw.HashIPsPorts, "tcp6": hw.HashIPsPorts, "udp6": hw.HashIPsPorts}
	dev := "1572"
	if driver == "ixgbe" {
		hash["udp4"], hash["udp6"], dev = hw.HashIPs, hw.HashIPs, "10fb"
	}
	return hwtest.Machine{Packages: 1, CoresPerPackage: 28, ThreadsPerCore: 2, Numbering: "linear", MemGiB: 64,
		NICs: []hwtest.NICSpec{{Name: "eth1", Driver: driver, PCI: "0000:3b:00.0", Vendor: "8086", Device: dev, Node: 0, SpeedMbps: 25000,
			Channels:  hw.Channels{MaxOther: 1, MaxCombined: 63, Other: 1, Combined: 16},
			TableSize: 512, RSSCap: rssCap, Hash: hash, Affinity: "default", Hint: "spread", XPS: "hint"}},
		Routes: []hwtest.RouteSpec{{Dev: "eth1", Gateway: "198.51.100.1"}}}
}

func chanState(t *testing.T, e *Env, key string) *ChanState {
	t.Helper()
	st, _, err := e.loadState()
	if err != nil {
		t.Fatal(err)
	}
	if st.NICs[key] == nil {
		t.Fatalf("no state for %s", key)
	}
	return st.NICs[key].Channels
}

func calls(b *hwtest.Built, prefix string) []string {
	var out []string
	for _, c := range b.Eth.Calls {
		if strings.HasPrefix(c, prefix) {
			out = append(out, c)
		}
	}
	return out
}

// A raise is planned by an apply (the unit written and enabled, nothing
// changed live), done at boot under the watchdog, re-placed after; revert
// leaves the raised count until the next reboot.
func TestNICQueuesRaise(t *testing.T) {
	e, b := onHW(t, raiseMachine("i40e", 0))
	r := mustApply(t, e, ApplyOptions{Auto: true})
	if !strings.Contains(strings.Join(r.Changed, "\n"), "eth1: queues 16 -> 28 at the next boot (now: x-ui tune queues --now; the link resets for a few seconds)") {
		t.Errorf("changes %v", r.Changed)
	}
	if got := e.readTrim(NICUnitFile); got != strings.TrimSpace(renderNICUnit("/usr/local/x-ui/x-ui")) {
		t.Errorf("unit:\n%s", got)
	}
	if !strings.Contains(strings.Join(e.Ran, "\n"), "systemctl enable x-ui-nic.service") {
		t.Errorf("unit not enabled: %v", e.Ran)
	}
	if len(calls(b, "SetChannels")) != 0 {
		t.Fatal("queues changed by an apply")
	}
	if cs := chanState(t, e, "0000:3b:00.0"); cs == nil || cs.Want != 28 || cs.Orig != nil {
		t.Fatalf("state %+v", cs)
	}
	e.Ran = nil
	if r := mustApply(t, e, ApplyOptions{Auto: true}); len(r.Changed) != 0 || strings.Contains(strings.Join(e.Ran, "\n"), "enable") {
		t.Errorf("second apply: %v %v", r.Changed, e.Ran)
	}
	if d, _ := e.Status(false); len(d) != 0 {
		t.Errorf("a raise waiting for the boot is drift: %v", d)
	}
	if got := statusText(t, e); !strings.Contains(got, "queues      16 of 63: 28 at the next boot (now: x-ui tune queues --now; the link resets for a few seconds)") {
		t.Errorf("status:\n%s", got)
	}
	if sum := e.summary(); !slices.Contains(sum, "NIC eth1: queues 16 -> 28 at the next boot (now: x-ui tune queues --now)") {
		t.Errorf("summary %q", sum)
	}

	// The boot.
	oldIRQ := b.QueueIRQs("eth1")[0]
	r, err := e.RunNIC(NICOptions{Boot: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := calls(b, "SetChannels"); !slices.Equal(got, []string{"SetChannels eth1 rx=0 tx=0 other=1 combined=28"}) {
		t.Errorf("calls %v", got)
	}
	cs := chanState(t, e, "0000:3b:00.0")
	if cs.Want != 28 || cs.Orig == nil || cs.Orig.Combined != 16 || cs.Attempt != nil || cs.Failed != "" || cs.RSSCap != 0 {
		t.Errorf("state %+v (%v %v)", cs, r.Changed, r.Problems)
	}
	b.Settle()
	n := hw.ReadNIC(e.hw(), e.eth(), "eth1")
	if len(n.IRQs) != 28 || n.IRQs[0].IRQ == oldIRQ || n.IRQs[0].Affinity.List() != "0" || n.IRQs[27].Affinity.List() != "27" {
		t.Errorf("not re-placed after the raise: %d irqs, q0 %v q27 %v", len(n.IRQs), n.IRQs[0].Affinity, n.IRQs[27].Affinity)
	}
	if got := statusText(t, e); !strings.Contains(got, "queues      28 of 63: ok (raised from 16 at boot)") {
		t.Errorf("status:\n%s", got)
	}
	if d, _ := e.Status(false); len(d) != 0 {
		t.Errorf("drift after the boot: %v", d)
	}
	// The next boot: the count is already there.
	b.Eth.Calls = nil
	if _, err := e.RunNIC(NICOptions{Boot: true}); err != nil || len(calls(b, "SetChannels")) != 0 {
		t.Errorf("second boot: %v %v", err, b.Eth.Calls)
	}

	// Revert: the unit goes, the queues stay until the reboot.
	e.Ran = nil
	rv, err := e.Revert(false, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(rv.Changed, "\n"), "eth1 keeps 28 queues until the next reboot (16 after it)") || e.exists(NICUnitFile) ||
		!strings.Contains(strings.Join(e.Ran, "\n"), "systemctl disable x-ui-nic.service") || len(calls(b, "SetChannels")) != 0 {
		t.Errorf("revert: %v %v", rv.Changed, e.Ran)
	}
	if r, _ := e.RunNIC(NICOptions{Boot: true}); len(r.Changed) != 0 {
		t.Errorf("tune nic after revert: %v", r.Changed)
	}
}

// The watchdog: the link that does not come back, the gateway that does not
// answer, no gateway to check, a run that died halfway.
func TestNICWatchdog(t *testing.T) {
	setup := func(t *testing.T) (*Env, *hwtest.Built) {
		e, b := onHW(t, raiseMachine("i40e", 0))
		mustApply(t, e, ApplyOptions{Auto: true})
		return e, b
	}

	// No carrier after the raise: the old count goes back, the failure is
	// kept, the unit goes, and nothing retries it but --now.
	e, b := setup(t)
	resets := 0
	b.Eth.Devs["eth1"].BreakLink = true
	b.Eth.DuringReset = func(dev string) {
		if resets++; resets == 2 {
			b.Eth.Devs[dev].BreakLink = false
		}
	}
	r, err := e.Queues(QueuesOptions{Now: true})
	if err != nil {
		t.Fatal(err)
	}
	cs := chanState(t, e, "0000:3b:00.0")
	if b.Eth.Devs["eth1"].Channels.Combined != 16 || !strings.HasPrefix(cs.Failed, "the link did not come back within 30s at 2026-10-13T12:") || cs.Attempt != nil {
		t.Errorf("after a broken link: %d queues, state %+v, %v", b.Eth.Devs["eth1"].Channels.Combined, cs, r.Problems)
	}
	if !strings.Contains(strings.Join(r.Problems, "\n"), "eth1: queues 16 -> 28 undone: the link did not come back within 30s") || e.exists(NICUnitFile) {
		t.Errorf("problems %v, unit %v", r.Problems, e.exists(NICUnitFile))
	}
	b.Eth.Calls = nil
	mustApply(t, e, ApplyOptions{Auto: true})
	if r, _ := e.RunNIC(NICOptions{Boot: true}); len(calls(b, "SetChannels")) != 0 || e.exists(NICUnitFile) {
		t.Errorf("a failed raise tried again: %v %v", b.Eth.Calls, r.Changed)
	}
	if got := statusText(t, e); !strings.Contains(got, "an earlier raise failed (the link did not come back") {
		t.Errorf("status:\n%s", got)
	}
	// --now tries again, and clears the failure.
	if r, err := e.Queues(QueuesOptions{Now: true}); err != nil || chanState(t, e, "0000:3b:00.0").Failed != "" || b.Eth.Devs["eth1"].Channels.Combined != 28 {
		t.Errorf("retry: %v %+v", err, r)
	}

	// The gateway stops answering after the change.
	e, b = setup(t)
	e.Probe = &fakeProbe{reach: []bool{false}}
	r, _ = e.Queues(QueuesOptions{Now: true})
	cs = chanState(t, e, "0000:3b:00.0")
	if b.Eth.Devs["eth1"].Channels.Combined != 16 || !strings.HasPrefix(cs.Failed, "the gateway did not answer within 20s") {
		t.Errorf("gateway lost: %d, %+v %v", b.Eth.Devs["eth1"].Channels.Combined, cs, r.Problems)
	}

	// No probe answers before: no change at all.
	e, b = setup(t)
	e.Probe = &fakeProbe{none: true}
	r, _ = e.Queues(QueuesOptions{Now: true})
	if len(calls(b, "SetChannels")) != 0 || chanState(t, e, "0000:3b:00.0").Failed != "" || !strings.Contains(strings.Join(r.Problems, "\n"), "cannot check the gateway") {
		t.Errorf("no probe: %v %v", b.Eth.Calls, r.Problems)
	}

	// A run that died during a change: a failure, never retried by itself.
	e, b = setup(t)
	st, _, _ := e.loadState()
	st.NICs["0000:3b:00.0"].Channels.Attempt = &ChanAttempt{At: "2026-10-13T11:00:00Z", From: 16, To: 28}
	if err := e.saveState(st, nil); err != nil {
		t.Fatal(err)
	}
	r, _ = e.RunNIC(NICOptions{Boot: true})
	cs = chanState(t, e, "0000:3b:00.0")
	if len(calls(b, "SetChannels")) != 0 || cs.Attempt != nil || cs.Failed != "interrupted (16 -> 28 at 2026-10-13T11:00:00Z)" ||
		!strings.Contains(strings.Join(r.Problems, "\n"), "a queue change was interrupted") {
		t.Errorf("leftover attempt: %+v %v %v", cs, b.Eth.Calls, r.Problems)
	}

	// The driver refuses (EBUSY): skipped, not a failure.
	e, b = setup(t)
	b.Eth.Fail["SetChannels eth1"] = fmt.Errorf("ethtool: %w (%w)", hw.ErrBusy, syscall.EBUSY)
	r, _ = e.Queues(QueuesOptions{Now: true})
	if cs := chanState(t, e, "0000:3b:00.0"); cs.Failed != "" || !strings.Contains(strings.Join(r.Problems, "\n"), "device busy") {
		t.Errorf("busy: %+v %v", cs, r.Problems)
	}
}

// The boot unit does not change the queue count while x-ui runs, nor with
// the root file system on the network.
func TestNICBootGuards(t *testing.T) {
	for _, c := range []struct {
		name, active, cmdline, want string
	}{
		{"x-ui active", "active", "BOOT_IMAGE=/vmlinuz root=UUID=1 ro quiet", "x-ui is running"},
		{"x-ui activating", "activating", "", "x-ui is running"},
		{"ip=", "inactive", "BOOT_IMAGE=/vmlinuz ip=dhcp root=UUID=1", "on the network (ip=dhcp)"},
		{"nfs root", "inactive", "root=/dev/nfs nfsroot=10.0.0.1:/srv", "on the network"},
		{"iscsi", "inactive", "rd.iscsi.initiator=iqn.2026-10.x root=UUID=1", "on the network"},
	} {
		e, b := onHW(t, raiseMachine("i40e", 0))
		mustApply(t, e, ApplyOptions{Auto: true})
		fakeCommands(e, map[string]string{"systemctl is-active x-ui": c.active})
		writeT(t, e.Root, "/proc/cmdline", c.cmdline+"\n")
		r, _ := e.RunNIC(NICOptions{Boot: true})
		if len(calls(b, "SetChannels")) != 0 || !strings.Contains(strings.Join(r.Problems, "\n"), c.want) {
			t.Errorf("%s: %v %v", c.name, b.Eth.Calls, r.Problems)
		}
	}
}

// A bond's slaves are raised one at a time, each back in the aggregator
// before the next; the first failure stops the rest.
func TestNICBondRaise(t *testing.T) {
	m := hwtest.Bond()
	for i := range m.NICs {
		m.NICs[i].Channels.Combined = 8
	}
	e, b := onHW(t, m)
	mustApply(t, e, ApplyOptions{Auto: true})
	np := nicPlanOf(t, e)
	if len(np.NICs) != 2 || np.NICs[0].Queues.Want != 14 || np.NICs[1].Queues.Want != 14 || !e.exists(NICUnitFile) {
		t.Fatalf("plan: %+v", np.NICs)
	}
	// Placed together: their RSS queues alternate over the CPUs.
	if np.place.CPU["eno1"][0] == np.place.CPU["eno2"][0] {
		t.Error("both NICs' first queue on one CPU")
	}
	var order []string
	b.Eth.DuringReset = func(dev string) {
		order = append(order, dev+" mii "+b.ReadFile("/sys/class/net/"+dev+"/bonding_slave/mii_status"))
	}
	if _, err := e.RunNIC(NICOptions{Boot: true}); err != nil {
		t.Fatal(err)
	}
	if got := calls(b, "SetChannels"); !slices.Equal(got, []string{"SetChannels eno1 rx=0 tx=0 other=1 combined=14", "SetChannels eno2 rx=0 tx=0 other=1 combined=14"}) {
		t.Errorf("calls %v", got)
	}
	if !slices.Equal(order, []string{"eno1 mii down\n", "eno2 mii down\n"}) {
		t.Errorf("resets %v", order)
	}

	// eno1's link stays down: put back (that fails too), eno2 not touched.
	e, b = onHW(t, m)
	mustApply(t, e, ApplyOptions{Auto: true})
	b.Eth.Devs["eno1"].BreakLink = true
	r, _ := e.RunNIC(NICOptions{Boot: true})
	if got := calls(b, "SetChannels"); !slices.Equal(got, []string{"SetChannels eno1 rx=0 tx=0 other=1 combined=14", "SetChannels eno1 rx=0 tx=0 other=1 combined=8"}) {
		t.Errorf("calls %v", got)
	}
	if !strings.Contains(strings.Join(r.Problems, "\n"), "putting 8 back failed too") {
		t.Errorf("not loud: %v", r.Problems)
	}
	// An 802.3ad slave that does not rejoin the aggregator.
	e, b = onHW(t, m)
	mustApply(t, e, ApplyOptions{Auto: true})
	b.Eth.DuringReset = func(dev string) { b.WriteFile("/sys/class/net/"+dev+"/bonding_slave/ad_aggregator_id", "2\n") }
	r, _ = e.RunNIC(NICOptions{Boot: true})
	if cs := chanState(t, e, "0000:82:00.0"); !strings.HasPrefix(cs.Failed, "eno1 did not rejoin bond0's aggregator within 1m30s") {
		t.Errorf("aggregator: %+v %v", cs, r.Problems)
	}
}

// After a raise, RSS is checked: an 82599 (16 hashed queues whatever the
// count) goes back to its count and is not raised again; a card that uses
// some of the new queues is raised only that far from then on.
func TestNICRSSFollowUp(t *testing.T) {
	e, b := onHW(t, raiseMachine("ixgbe", 16))
	mustApply(t, e, ApplyOptions{Auto: true})
	if cs := chanState(t, e, "0000:3b:00.0"); cs == nil || cs.Want != 28 {
		t.Fatalf("plan %+v", cs)
	}
	r, _ := e.RunNIC(NICOptions{Boot: true})
	want := []string{"SetChannels eth1 rx=0 tx=0 other=1 combined=28", "SetIndir eth1 default", "SetChannels eth1 rx=0 tx=0 other=1 combined=16"}
	if got := append(calls(b, "SetChannels"), calls(b, "SetIndir")...); len(got) != 3 || got[0] != want[0] || got[1] != want[2] || got[2] != want[1] {
		t.Errorf("calls %v", b.Eth.Calls)
	}
	cs := chanState(t, e, "0000:3b:00.0")
	if cs.RSSCap != 16 || cs.Want != 0 || cs.Failed != "" || b.Eth.Devs["eth1"].Channels.Combined != 16 {
		t.Errorf("state %+v %v", cs, r.Changed)
	}
	mustApply(t, e, ApplyOptions{Auto: true})
	if e.exists(NICUnitFile) {
		t.Error("unit kept after RSS showed the raise is useless")
	}
	if np := nicPlanOf(t, e); np.NICs[0].Queues.State != "ok" || np.NICs[0].Queues.Want != 0 {
		t.Errorf("planned again: %+v", np.NICs[0].Queues)
	}

	// A card whose RSS reaches 20 queues: kept at 28 now, 20 from the next boot.
	e, b = onHW(t, raiseMachine("ixgbe", 20))
	mustApply(t, e, ApplyOptions{Auto: true})
	e.RunNIC(NICOptions{Boot: true})
	cs = chanState(t, e, "0000:3b:00.0")
	if cs.RSSCap != 20 || cs.Want != 20 || b.Eth.Devs["eth1"].Channels.Combined != 28 {
		t.Errorf("partial: %+v, %d queues", cs, b.Eth.Devs["eth1"].Channels.Combined)
	}
	mustApply(t, e, ApplyOptions{Auto: true})
	if cs := chanState(t, e, "0000:3b:00.0"); cs.Want != 20 || !e.exists(NICUnitFile) {
		t.Errorf("after the partial raise: %+v", cs)
	}
}

// Skips of the queue plan: an admin's persisted count, a VF, no systemd, an
// RSS table that uses fewer queues than there are.
func TestNICQueueSkips(t *testing.T) {
	for _, c := range []struct {
		name string
		mod  func(*hwtest.Machine)
		file [2]string
		init string
		want string
	}{
		{"link file", nil, [2]string{"/etc/systemd/network/10-eth1.link", "[Match]\nOriginalName=eth1\n[Link]\nCombinedChannels=16\n"}, "", "an admin sets the queue count (/etc/systemd/network/10-eth1.link)"},
		{"interfaces", nil, [2]string{"/etc/network/interfaces", "iface eth1 inet dhcp\n    post-up ethtool -L eth1 combined 16\n"}, "", "an admin sets the queue count (/etc/network/interfaces)"},
		{"rc.local", nil, [2]string{"/etc/rc.local", "#!/bin/sh\n/sbin/ethtool --set-channels eth1 combined 16\n"}, "", "an admin sets the queue count"},
		{"NetworkManager", nil, [2]string{"/etc/NetworkManager/system-connections/eth1.nmconnection", "[connection]\ninterface-name=eth1\n[ethtool]\nchannels-combined=16\n"}, "", "an admin sets the queue count"},
		{"commented", nil, [2]string{"/etc/rc.local", "#ethtool -L eth1 combined 16\n"}, "", ""},
		{"other device", nil, [2]string{"/etc/rc.local", "ethtool -L eth9 combined 2\n"}, "", ""},
		{"VF", func(m *hwtest.Machine) { m.NICs[0].VF = true }, [2]string{}, "", "SR-IOV VF"},
		{"OpenRC", nil, [2]string{}, "openrc", "none here"},
		{"custom table", func(m *hwtest.Machine) {
			m.NICs[0].Table = make([]uint32, 512)
			for i := range m.NICs[0].Table {
				m.NICs[0].Table[i] = uint32(7 - i%8)
			}
			m.NICs[0].Configured = true
		}, [2]string{}, "", "RSS uses 8: its table: more queues would not be hashed to"},
	} {
		m := raiseMachine("i40e", 0)
		if c.mod != nil {
			c.mod(&m)
		}
		e, b := onHW(t, m, func(mm *machine) {
			if c.init != "" {
				mm.init = c.init
			}
		})
		b.WriteFile("/sys/class/net/eth9/ifindex", "9\n")
		if c.file[0] != "" {
			b.WriteFile(c.file[0], c.file[1])
		}
		q := nicPlanOf(t, e).NICs[0].Queues
		if c.want == "" {
			if q.State != "raise" {
				t.Errorf("%s: %+v", c.name, q)
			}
			continue
		}
		if q.State != "skip" || !strings.Contains(q.Note, c.want) {
			t.Errorf("%s: %+v", c.name, q)
		}
	}
}

// "x-ui tune nic" does nothing before the first apply, after a revert, for
// a NIC this network namespace does not see, or while another run holds
// the lock.
func TestNICRunGating(t *testing.T) {
	e, b := onHW(t, hwtest.Production())
	instances(t, b, "0-55", prodFixed...)
	before := irqSnapshot(t, b)
	if r, err := e.RunNIC(NICOptions{}); err != nil || len(r.Changed)+len(r.Problems) != 0 || len(b.Eth.Calls) != 0 || e.exists(StateDir) {
		t.Errorf("no state: %+v %v (state dir made: %v)", r, b.Eth.Calls, e.exists(StateDir))
	}
	mustApply(t, e, ApplyOptions{Auto: true})
	if _, err := e.Revert(false, false); err != nil {
		t.Fatal(err)
	}
	b.Settle()
	b.Eth.Calls = nil
	if r, _ := e.RunNIC(NICOptions{}); len(r.Changed) != 0 || len(b.Eth.Calls) != 0 {
		t.Errorf("disabled: %+v", r)
	}
	if d := diffMaps(before, irqSnapshot(t, b)); len(d) > 0 {
		t.Errorf("after revert: %v", d[:min(3, len(d))])
	}
	// A state about a NIC that is not here.
	mustApply(t, e, ApplyOptions{})
	st, _, _ := e.loadState()
	st.NICs = map[string]*NICState{"0000:99:00.0": {Name: "eno9", Driver: "ixgbe"}}
	e.saveState(st, nil)
	writeT(t, e.Root, "/proc/irq/101/smp_affinity_list", "1-55\n")
	b.Settle()
	b.Eth.Calls = nil
	if r, _ := e.RunNIC(NICOptions{}); len(r.Changed) != 0 || len(b.Eth.Calls) != 0 {
		t.Errorf("NIC not here: %+v %v", r, b.Eth.Calls)
	}
	// The lock is busy: skipped.
	unlock, err := e.lock(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := e.RunNIC(NICOptions{})
	unlock()
	if len(r.Problems) != 1 || !strings.Contains(r.Problems[0], "another x-ui tune is running") {
		t.Errorf("busy: %v", r.Problems)
	}
}

// "queues --now" runs as a transient unit only in init's network namespace
// under systemd.
func TestNICDetachDecision(t *testing.T) {
	e, _ := onHW(t, hwtest.Desktop())
	link := func(p, target string) {
		os.MkdirAll(filepath.Dir(e.P(p)), 0o755)
		os.Remove(e.P(p))
		if err := os.Symlink(target, e.P(p)); err != nil {
			t.Fatal(err)
		}
	}
	writeT(t, e.Root, "/proc/1/comm", "systemd\n")
	link("/proc/1/ns/net", "net:[4026531840]")
	link("/proc/self/ns/net", "net:[4026531840]")
	if !e.detachable() {
		t.Error("same namespace under systemd: not detached")
	}
	link("/proc/self/ns/net", "net:[4026532513]")
	if e.detachable() {
		t.Error("another network namespace: detached (the unit would act on the host's NICs)")
	}
	link("/proc/self/ns/net", "net:[4026531840]")
	writeT(t, e.Root, "/proc/1/comm", "init\n")
	if e.detachable() {
		t.Error("detached without systemd")
	}
	args := e.detachArgs()
	if !slices.Equal(args[2:], []string{"--collect", "--wait", "--pipe", "--quiet", "-p", "TimeoutStartSec=600", "/usr/local/x-ui/x-ui", "tune", "queues", "--now", "--worker"}) ||
		!strings.HasPrefix(args[1], "--unit=x-ui-queues-") {
		t.Errorf("args %v", args)
	}
}

// The conntrack ceiling is 32M (from 512 GiB); 128 GiB is unchanged.
func TestConntrackCeiling(t *testing.T) {
	for _, c := range []struct {
		g    float64
		want int64
	}{{121, 8388608}, {128, 8388608}, {256, 16777216}, {512, 33554432}, {1024, 33554432}} {
		f := facts(c.g, 64)
		f.Conntrack = true
		if got := targetMap(f)["net.netfilter.nf_conntrack_max"].Num; got != c.want {
			t.Errorf("%g GiB: %d", c.g, got)
		}
		if ServiceTargets(f).Hashsize != c.want/2 {
			t.Errorf("%g GiB: hashsize %d", c.g, ServiceTargets(f).Hashsize)
		}
	}
	f := facts(2, 2)
	if _, ok := targetMap(f)["net.core.rps_sock_flow_entries"]; ok {
		t.Error("RFS target without a single-queue uplink")
	}
	f.RPSUplink = true
	for g, want := range map[float64]int64{0.5: 32768, 1: 32768, 2: 65536, 16: 524288, 64: 1048576} {
		f.G = g
		if got := targetMap(f)["net.core.rps_sock_flow_entries"]; got.Num != want || got.Class != ClassLimit {
			t.Errorf("%g GiB: %+v", g, got)
		}
	}
}

// State files of older versions load; the NIC entries round-trip.
func TestNICStateCompat(t *testing.T) {
	e := machine{mem: GiB}.build(t)
	old := `{"version":1,"xui_version":"2.9.0","keys":{"net.core.somaxconn":{"orig":"4096","written":"8192","file":"8192"}},"enabled":["irqbalance"],"installed":["irqbalance"]}`
	writeT(t, e.Root, StateFile, old)
	st, had, err := e.loadState()
	if err != nil || !had || st.NICs != nil || st.Keys["net.core.somaxconn"].Written != "8192" || st.Installed[0] != "irqbalance" {
		t.Fatalf("old state: %+v %v", st, err)
	}
	st.NICs = map[string]*NICState{"0000:82:00.0": {Name: "eno1", Driver: "ixgbe",
		Channels: &ChanState{Orig: &hw.Channels{MaxCombined: 63, Combined: 16}, Want: 28, RSSCap: 20, Failed: "x", Attempt: &ChanAttempt{At: "t", From: 16, To: 28}},
		Hash:     map[string]*KeyState{"udp4": {Orig: "sd", Written: "sdfn"}}, IRQ: map[string]*IRQState{"q0": {IRQ: 101, Orig: "1-55", Written: "1"}},
		XPS: map[string]*KeyState{"tx-0": {Orig: "-", Written: "1"}}, RPS: map[string]*KeyState{"rx-0/rps_cpus": {Orig: "-", Written: "0-1"}}, Managed: true, TakeIRQs: true}}
	st.IRQBalancePolicy = true
	if err := e.saveState(st, nil); err != nil {
		t.Fatal(err)
	}
	st2, _, err := e.loadState()
	if err != nil || !slices.Equal(stateSnapshot(st), stateSnapshot(st2)) {
		t.Fatalf("round trip: %v\n%s\n%s", err, stateSnapshot(st), stateSnapshot(st2))
	}
	var raw map[string]any
	json.Unmarshal([]byte(e.readTrim(StateFile)), &raw)
	if _, ok := raw["nics"].(map[string]any)["0000:82:00.0"].(map[string]any)["kernel_managed_irqs"]; !ok {
		t.Errorf("json names: %s", e.readTrim(StateFile))
	}
	// Revert of an older state still undoes its irqbalance install.
	e.Ran = nil
	writeT(t, e.Root, StateFile, old)
	if _, err := e.Revert(false, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(e.Ran, "\n"), "systemctl disable --now irqbalance") {
		t.Errorf("ran %v", e.Ran)
	}
}

// The CLI's new commands on a fake tree.
func TestNICCLI(t *testing.T) {
	e, _ := onHW(t, hwtest.Production())
	t.Setenv("XUI_TUNE_ROOT", e.Root)
	t.Setenv("XUI_TUNE_FACTS", `{"mem_bytes":129922760704,"cpus":56,"kernel":"7.0.0-x-ui","init":"systemd","page_size":4096}`)
	t.Setenv("XUI_TUNE_BIN", "/usr/local/x-ui/x-ui")
	var out bytes.Buffer
	for _, c := range []struct {
		args []string
		code int
		has  string
	}{
		{[]string{"queues"}, 0, "eno1: queue counts not readable"}, // no ethtool under a fake root
		{[]string{"queues", "--json"}, 0, `"name": "eno1"`},
		{[]string{"nic", "--quiet", "--instances", "/nowhere/instances.json"}, 0, ""},
		{[]string{"queues", "--now"}, 1, "tuning is not on"},
		{[]string{"apply", "--take-irqs", "--dry-run"}, 0, "NIC eno1"},
		{[]string{"apply", "--take-irqs"}, 0, ""},
		{[]string{"nic", "--boot"}, 0, ""},
		{[]string{"queues", "--now"}, 0, ""},
		{[]string{"help"}, 0, "queues --now"},
	} {
		out.Reset()
		if code := run(c.args, "t", &out, &out); code != c.code || !strings.Contains(out.String(), c.has) {
			t.Errorf("%v: exit %d\n%s", c.args, code, out.String())
		}
	}
}

// Every preset: an apply places interrupts only on CPUs the panel may use,
// a second apply changes nothing, status shows no drift, and revert puts
// every interrupt and queue file back byte for byte (and the UDP hashing).
func TestNICAllPresets(t *testing.T) {
	presets := map[string]hwtest.Machine{
		"Production": hwtest.Production(), "EPYC1": hwtest.EPYC(1), "EPYC4": hwtest.EPYC(4), "Desktop": hwtest.Desktop(),
		"VPS1": hwtest.VPS(1), "VPS2": hwtest.VPS(2), "Restricted": hwtest.Restricted(), "CPULessNode": hwtest.CPULessNode(),
		"Bond": hwtest.Bond(), "ProxmoxBridge": hwtest.ProxmoxBridge(), "VLAN": hwtest.VLAN(), "ManagedIRQs": hwtest.ManagedIRQs(),
		"Container": hwtest.Container(), "Tunnel": hwtest.Tunnel(),
	}
	for name, m := range presets {
		t.Run(name, func(t *testing.T) {
			e, b := onHW(t, m)
			instances(t, b, b.Allowed.List())
			fakeCommands(e, nil, "systemctl daemon-reload", "systemctl try-restart", "systemctl enable", "systemctl disable")
			b.Settle()
			before := irqSnapshot(t, b)
			hashes := map[string]map[string]uint64{}
			for dev, d := range b.Eth.Devs {
				hashes[dev] = map[string]uint64{}
				for k, v := range d.Hash {
					hashes[dev][k] = v
				}
			}
			mustApply(t, e, ApplyOptions{})
			b.Settle()
			np := nicPlanOf(t, e)
			for _, it := range np.NICs {
				n := hw.ReadNIC(e.hw(), e.eth(), it.NIC.Name)
				for _, q := range n.IRQs {
					if it.keep == "" && (len(q.Affinity) != 1 || !b.Allowed.Has(q.Affinity[0])) {
						t.Errorf("%s IRQ %d on %v (allowed %s)", it.NIC.Name, q.IRQ, q.Affinity, b.Allowed.List())
					}
				}
				for q, x := range n.XPS {
					if len(x.Minus(np.topo.Online)) > 0 {
						t.Errorf("%s tx-%d XPS %v outside the online CPUs", it.NIC.Name, q, x)
					}
				}
			}
			if r := mustApply(t, e, ApplyOptions{}); len(r.Changed) != 0 {
				t.Errorf("second apply: %v", r.Changed)
			}
			if d, err := e.Status(false); err != nil || len(d) != 0 {
				t.Errorf("drift %v %v", d, err)
			}
			if _, err := e.Revert(false, false); err != nil {
				t.Fatal(err)
			}
			b.Settle()
			if d := diffMaps(before, irqSnapshot(t, b)); len(d) > 0 {
				t.Errorf("revert left %d differences: %v", len(d), d[:min(3, len(d))])
			}
			for dev, d := range b.Eth.Devs {
				for k, v := range hashes[dev] {
					if d.Hash[k] != v {
						t.Errorf("%s %s hashing %s after revert", dev, k, hw.HashLetters(d.Hash[k]))
					}
				}
			}
			if len(calls(b, "SetChannels")) != 0 || len(calls(b, "SetIndir")) != 0 {
				t.Errorf("queue or table changes by an apply: %v", b.Eth.Calls)
			}
		})
	}
}
