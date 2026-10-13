package hw_test

import (
	"fmt"
	"math/rand"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/util/hw"
	"github.com/mhsanaei/3x-ui/v2/util/hw/hwtest"
)

// natLess orders xray-2 before xray-10, as model.LessInstanceName does for
// the names these tests use.
func natLess(a, b string) bool {
	pa, na := splitNum(a)
	pb, nb := splitNum(b)
	if pa != pb {
		return pa < pb
	}
	return na < nb
}

func splitNum(s string) (string, int) {
	i := strings.LastIndexFunc(s, func(r rune) bool { return r < '0' || r > '9' }) + 1
	n, _ := strconv.Atoi(s[i:])
	return s[:i], n
}

// reqs makes requests xray-1..xray-n with the given CPUs each (0 = auto).
func reqs(cpus ...int) []hw.CPURequest {
	out := make([]hw.CPURequest, len(cpus))
	for i, c := range cpus {
		out[i] = hw.CPURequest{Name: fmt.Sprintf("xray-%d", i+1), CPUs: c}
	}
	return out
}

func repeat(n, v int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = v
	}
	return out
}

func mustList(t *testing.T, s string) hw.CPUSet {
	t.Helper()
	l, err := hw.ParseList(s)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// checkSplit compares a split with want: instance -> CPU list.
func checkSplit(t *testing.T, name string, got map[string][]int, want map[string]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: %d instances, want %d: %v", name, len(got), len(want), got)
	}
	for inst, w := range want {
		if !hw.CPUSet(got[inst]).Equal(mustList(t, w)) {
			t.Errorf("%s: %s = %s, want %s", name, inst, hw.CPUSet(got[inst]).List(), mustList(t, w).List())
		}
	}
}

func TestSplitCPUsProduction(t *testing.T) {
	b := hwtest.Production().Build(t)
	topo, err := hw.ReadTopology(b.FS())
	if err != nil {
		t.Fatal(err)
	}
	cpus := []int(topo.Online)
	if hw.UplinkNode(b.FS()) != 1 {
		t.Fatalf("uplink node %d, want 1", hw.UplinkNode(b.FS()))
	}

	// Ten instances of 5: five on node 1 (the NIC's), five on node 0, each
	// on two whole cores and half a third; 26,52,54 and 27,53,55 stay free.
	got := hw.SplitCPUs(topo, cpus, 1, reqs(repeat(10, 5)...), natLess)
	checkSplit(t, "10x5", got, map[string]string{
		"xray-1": "1,3,5,29,31", "xray-6": "0,2,4,28,30",
		"xray-2": "7,9,33,35,37", "xray-7": "6,8,32,34,36",
		"xray-3": "11,13,15,39,41", "xray-8": "10,12,14,38,40",
		"xray-4": "17,19,43,45,47", "xray-9": "16,18,42,44,46",
		"xray-5": "21,23,25,49,51", "xray-10": "20,22,24,48,50",
	})

	got, how := hw.SplitHow(topo, cpus, 1, reqs(repeat(10, 0)...), natLess)
	if how != "node" {
		t.Errorf("10 auto split by %q, want node", how)
	}
	checkSplit(t, "10 auto", got, map[string]string{
		"xray-1": "1,3,5,29,31,33", "xray-6": "0,2,4,28,30,32",
		"xray-2": "7,9,11,35,37,39", "xray-7": "6,8,10,34,36,38",
		"xray-3": "13,15,17,41,43,45", "xray-8": "12,14,16,40,42,44",
		"xray-4": "19,21,23,47,49", "xray-9": "18,20,22,46,48",
		"xray-5": "25,27,51,53,55", "xray-10": "24,26,50,52,54",
	})

	// Three autos cannot stay on one node each and even: one cut, and only
	// xray-2 straddles the nodes.
	got, how = hw.SplitHow(topo, cpus, 1, reqs(0, 0, 0), natLess)
	if how != "cut" {
		t.Errorf("3 auto split by %q, want cut", how)
	}
	checkSplit(t, "3 auto", got, map[string]string{
		"xray-1": "1,3,5,7,9,11,13,15,17,19,29,31,33,35,37,39,41,43,45",
		"xray-2": "0,2,4,6,8,21,23,25,27,28,30,32,34,36,47,49,51,53,55",
		"xray-3": "10,12,14,16,18,20,22,24,26,38,40,42,44,46,48,50,52,54",
	})
	for inst, want := range map[string]int{"xray-1": 1, "xray-2": 2, "xray-3": 1} {
		if n := len(topo.NodesOf(got[inst])); n != want {
			t.Errorf("3 auto: %s on %d nodes, want %d", inst, n, want)
		}
	}

	// Seven of 8: only the 4th straddles.
	got = hw.SplitCPUs(topo, cpus, 1, reqs(repeat(7, 0)...), natLess)
	checkSplit(t, "7 auto", got, map[string]string{
		"xray-1": "1,3,5,7,29,31,33,35",
		"xray-2": "9,11,13,15,37,39,41,43",
		"xray-3": "17,19,21,23,45,47,49,51",
		"xray-4": "0,2,25,27,28,30,53,55",
		"xray-5": "4,6,8,10,32,34,36,38",
		"xray-6": "12,14,16,18,40,42,44,46",
		"xray-7": "20,22,24,26,48,50,52,54",
	})

	got = hw.SplitCPUs(topo, cpus, 1, reqs(8), natLess)
	checkSplit(t, "1 fixed 8", got, map[string]string{"xray-1": "1,3,5,7,29,31,33,35"})

	// Without a NIC node, node 0 comes first.
	got = hw.SplitCPUs(topo, cpus, -1, reqs(8), natLess)
	checkSplit(t, "1 fixed 8, no NIC node", got, map[string]string{"xray-1": "0,2,4,6,28,30,32,34"})
}

// epycWant is 16 autos on a two-socket EPYC: 16 whole cores each, the first
// eight on package 0.
func epycWant() map[string]string {
	want := map[string]string{}
	for i := 0; i < 16; i++ {
		lo := 16 * i
		want[fmt.Sprintf("xray-%d", i+1)] = fmt.Sprintf("%d-%d,%d-%d", lo, lo+15, lo+256, lo+271)
	}
	return want
}

func TestSplitCPUsEPYC(t *testing.T) {
	for _, nps := range []int{1, 4} {
		topo := hwtest.Topo(t, hwtest.EPYC(nps))
		cpus := []int(topo.Online)
		got, how := hw.SplitHow(topo, cpus, 0, reqs(repeat(16, 0)...), natLess)
		name := fmt.Sprintf("NPS%d 16 auto", nps)
		if how != "node" {
			t.Errorf("%s split by %q, want node", name, how)
		}
		checkSplit(t, name, got, epycWant())
		for inst, l := range got {
			if whole, partial := topo.CoresIn(l); whole != 16 || partial != 0 {
				t.Errorf("%s: %s has %d whole and %d partial cores", name, inst, whole, partial)
			}
		}
	}
	want := epycWant()
	if want["xray-1"] != "0-15,256-271" || want["xray-2"] != "16-31,272-287" ||
		want["xray-8"] != "112-127,368-383" || want["xray-9"] != "128-143,384-399" {
		t.Fatalf("epycWant: %v", want)
	}

	// NPS4 with 12: one node each would not be even, one socket each is:
	// 6 per socket, of 43,43,43,43,42,42.
	topo := hwtest.Topo(t, hwtest.EPYC(4))
	got, how := hw.SplitHow(topo, []int(topo.Online), 0, reqs(repeat(12, 0)...), natLess)
	if how != "package" {
		t.Errorf("NPS4 12 auto split by %q, want package", how)
	}
	sizes := []int{43, 43, 43, 43, 42, 42, 43, 43, 43, 43, 42, 42}
	for i, size := range sizes {
		inst := fmt.Sprintf("xray-%d", i+1)
		l := got[inst]
		if len(l) != size {
			t.Errorf("NPS4 12 auto: %s has %d CPUs, want %d", inst, len(l), size)
		}
		pkgs := map[int]bool{}
		for _, c := range l {
			pkgs[topo.PackageOf(c)] = true
		}
		if len(pkgs) != 1 || !pkgs[i/6] {
			t.Errorf("NPS4 12 auto: %s on packages %v, want %d", inst, pkgs, i/6)
		}
	}
	checkSplit(t, "NPS4 12 auto", map[string][]int{"xray-1": got["xray-1"], "xray-2": got["xray-2"]},
		map[string]string{"xray-1": "0-21,256-276", "xray-2": "22-42,277-298"})
}

func TestSplitCPUsSmall(t *testing.T) {
	topo := hwtest.Topo(t, hwtest.Desktop())
	got := hw.SplitCPUs(topo, []int(topo.Online), -1, reqs(0, 0, 0, 0), natLess)
	checkSplit(t, "desktop 4 auto", got, map[string]string{"xray-1": "0-3", "xray-2": "4-7", "xray-3": "8-11", "xray-4": "12-15"})

	vps := hwtest.Topo(t, hwtest.VPS(2))
	cpus := []int(vps.Online)
	for _, c := range []struct {
		reqs []int
		want map[string]string
	}{
		{[]int{0}, map[string]string{"xray-1": "0,1"}},
		{[]int{0, 0}, map[string]string{"xray-1": "0", "xray-2": "1"}},
		{[]int{0, 0, 0}, map[string]string{"xray-1": "0", "xray-2": "1", "xray-3": "0"}},
		{[]int{1, 0}, map[string]string{"xray-1": "0", "xray-2": "1"}},
		{[]int{2, 0}, map[string]string{"xray-1": "0,1", "xray-2": "0,1"}},
		{[]int{2, 1}, map[string]string{"xray-1": "0,1", "xray-2": "0,1"}},
	} {
		checkSplit(t, fmt.Sprint("vps ", c.reqs), hw.SplitCPUs(vps, cpus, -1, reqs(c.reqs...), natLess), c.want)
	}
}

func TestSplitCPUsRestricted(t *testing.T) {
	b := hwtest.Restricted().Build(t)
	topo, err := hw.ReadTopology(b.FS())
	if err != nil {
		t.Fatal(err)
	}
	// Allowed 0-2,4-6,8-10,12-13: node 0 keeps 0/8, 2/10, 4/12 and 6
	// alone, node 1 keeps 1/9 and 5/13 (3 is offline, 11 not allowed).
	allowed := []int(b.Allowed)
	got := hw.SplitCPUs(topo, allowed, 0, reqs(0, 0, 0), natLess)
	checkSplit(t, "3 auto", got, map[string]string{"xray-1": "0,2,8,10", "xray-2": "4,6,12", "xray-3": "1,5,9,13"})
	// A fixed 4 fits node 1 exactly, which keeps node 0 whole for the
	// autos.
	got = hw.SplitCPUs(topo, allowed, 0, reqs(4, 0, 0), natLess)
	checkSplit(t, "fixed 4 + 2 auto", got, map[string]string{"xray-1": "1,5,9,13", "xray-2": "0,2,8,10", "xray-3": "4,6,12"})
	// CPUs the topology does not know (here 11, which is online but was
	// left out of the read) still get used.
	got = hw.SplitCPUs(topo.Restrict(allowed), []int{0, 1, 11}, 0, reqs(0), natLess)
	checkSplit(t, "unknown CPU", got, map[string]string{"xray-1": "0,1,11"})
}

func TestSplitCPUsCPULessNode(t *testing.T) {
	topo := hwtest.Topo(t, hwtest.CPULessNode())
	if len(topo.Nodes) != 3 || len(topo.Nodes[2].CPUs) != 0 {
		t.Fatalf("nodes %+v", topo.Nodes)
	}
	cpus := []int(topo.Online)
	got := hw.SplitCPUs(topo, cpus, 0, reqs(0, 0, 0, 0), natLess)
	checkSplit(t, "4 auto", got, map[string]string{"xray-1": "0-3,16-19", "xray-2": "4-7,20-23", "xray-3": "8-11,24-27", "xray-4": "12-15,28-31"})
	// 20 fits no node and no package: node 0 whole, then node 1.
	got = hw.SplitCPUs(topo, cpus, 0, reqs(20, 0), natLess)
	checkSplit(t, "fixed 20 + auto", got, map[string]string{"xray-1": "0-9,16-25", "xray-2": "10-15,26-31"})
	// The memory-only node is never preferred into the split.
	got = hw.SplitCPUs(topo, cpus, 2, reqs(0, 0), natLess)
	checkSplit(t, "prefer memory-only", got, map[string]string{"xray-1": "0-7,16-23", "xray-2": "8-15,24-31"})
	for _, l := range got {
		if slices.Contains(topo.NodesOf(l), 2) {
			t.Errorf("CPUs %v on node 2", l)
		}
	}
}

func TestSplitCPUsPackageFixed(t *testing.T) {
	// Two sockets of two nodes (4 cores each, no SMT). A fixed 6 fits no
	// node; it takes the tighter socket, the larger node first.
	m := hwtest.Machine{Packages: 2, CoresPerPackage: 8, ThreadsPerCore: 1, NodesPerPackage: 2}
	topo := hwtest.Topo(t, m)
	got := hw.SplitCPUs(topo, []int(topo.Online), -1, reqs(3, 6), natLess)
	// xray-1 (3) best-fits node 0 (0-3), leaving 1 there; package 0 has 5,
	// package 1 has 8: only package 1 holds 6, nodes 2 (8-11) then 3.
	checkSplit(t, "fixed 3 + 6", got, map[string]string{"xray-1": "0-2", "xray-2": "8-13"})

	// Three autos on two nodes of two: a tie, which goes to the node that
	// comes first (the NIC's).
	topo = hwtest.Topo(t, hwtest.Machine{Packages: 2, CoresPerPackage: 2})
	got = hw.SplitCPUs(topo, []int(topo.Online), -1, reqs(0, 0, 0), natLess)
	checkSplit(t, "tie", got, map[string]string{"xray-1": "0", "xray-2": "1", "xray-3": "2,3"})
	got = hw.SplitCPUs(topo, []int(topo.Online), 1, reqs(0, 0, 0), natLess)
	checkSplit(t, "tie, NIC on node 1", got, map[string]string{"xray-1": "2", "xray-2": "3", "xray-3": "0,1"})
}

// oldAllocate is the split before x-ui knew the topology, kept as the oracle
// for machines of one node and one thread per core.
func oldAllocate(cpus []int, reqs []hw.CPURequest) map[string][]int {
	out := map[string][]int{}
	if len(cpus) == 0 {
		return out
	}
	sorted := append([]hw.CPURequest(nil), reqs...)
	sort.SliceStable(sorted, func(i, j int) bool { return natLess(sorted[i].Name, sorted[j].Name) })
	next := 0
	var autos []string
	for _, r := range sorted {
		if r.CPUs <= 0 {
			autos = append(autos, r.Name)
			continue
		}
		n := r.CPUs
		if next+n > len(cpus) {
			n = len(cpus) - next
		}
		if n <= 0 {
			out[r.Name] = append([]int(nil), cpus...)
			continue
		}
		out[r.Name] = append([]int(nil), cpus[next:next+n]...)
		next += n
	}
	rest := cpus[next:]
	if len(autos) == 0 {
		return out
	}
	if len(rest) == 0 {
		rest = cpus
	}
	if len(autos) > len(rest) {
		for i, name := range autos {
			out[name] = []int{rest[i%len(rest)]}
		}
		return out
	}
	base, extra := len(rest)/len(autos), len(rest)%len(autos)
	at := 0
	for i, name := range autos {
		n := base
		if i < extra {
			n++
		}
		out[name] = append([]int(nil), rest[at:at+n]...)
		at += n
	}
	return out
}

func randReqs(r *rand.Rand, ncpus int) []hw.CPURequest {
	n := r.Intn(9)
	var out []hw.CPURequest
	for _, i := range r.Perm(n) { // any order: the split sorts by name
		c := 0
		if r.Intn(2) == 0 {
			c = 1 + r.Intn(ncpus/2+2)
		}
		out = append(out, hw.CPURequest{Name: fmt.Sprintf("xray-%d", i+1), CPUs: c})
	}
	return out
}

func randCPUs(r *rand.Rand, from []int) []int {
	var out []int
	for _, c := range from {
		if r.Intn(4) != 0 {
			out = append(out, c)
		}
	}
	return out
}

func sameSplit(a, b map[string][]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if !slices.Equal(v, b[k]) {
			return false
		}
	}
	return true
}

func TestSplitCPUsFlatOracle(t *testing.T) {
	// Single-node machines without SMT, as the readers see them.
	var tops []*hw.Topology
	for _, m := range []hwtest.Machine{
		{Packages: 1, CoresPerPackage: 1},
		{Packages: 1, CoresPerPackage: 3},
		{Packages: 1, CoresPerPackage: 8},
		{Packages: 1, CoresPerPackage: 13, NoNUMA: true},
		{Packages: 2, CoresPerPackage: 6, NoNUMA: true, Numbering: "interleaved"},
		hwtest.VPS(4),
	} {
		tops = append(tops, hwtest.Topo(t, m))
	}
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 4000; i++ {
		var cpus []int
		var topo *hw.Topology
		switch i % 3 {
		case 0: // nil: Flat
			cpus = randCPUs(r, ints(0, r.Intn(40)))
		case 1:
			cpus = randCPUs(r, ints(0, r.Intn(40)))
			topo = hw.Flat(cpus)
		default:
			topo = tops[r.Intn(len(tops))]
			cpus = randCPUs(r, topo.Online)
		}
		rq := randReqs(r, len(cpus))
		want := oldAllocate(cpus, rq)
		got := hw.SplitCPUs(topo, cpus, r.Intn(3)-1, rq, natLess)
		if !sameSplit(got, want) {
			t.Fatalf("case %d: cpus %v reqs %v:\n got  %v\n want %v", i, cpus, rq, got, want)
		}
	}
}

// randMachine is any small machine: 1-2 packages, 1-2 nodes per package,
// 1-2 threads per core, any numbering, a few CPUs offline.
func randMachine(r *rand.Rand) hwtest.Machine {
	m := hwtest.Machine{
		Packages:        1 + r.Intn(2),
		CoresPerPackage: 2 * (1 + r.Intn(5)),
		ThreadsPerCore:  1 + r.Intn(2),
		NodesPerPackage: 1 + r.Intn(2),
		Numbering:       []string{"linear", "interleaved", "adjacent"}[r.Intn(3)],
		NoNUMA:          r.Intn(8) == 0,
	}
	n := m.Packages * m.CoresPerPackage * m.ThreadsPerCore
	for c := 1; c < n; c++ {
		if r.Intn(12) == 0 {
			m.Offline = append(m.Offline, c)
		}
	}
	return m
}

func TestSplitCPUsProperties(t *testing.T) {
	r := rand.New(rand.NewSource(2))
	cases := 0
	hows := map[string]int{}
	for mi := 0; mi < 40; mi++ {
		topo := hwtest.Topo(t, randMachine(r))
		for i := 0; i < 60; i++ {
			cpus := randCPUs(r, topo.Online)
			if len(cpus) == 0 {
				continue
			}
			rq := randReqs(r, len(cpus))
			prefer := r.Intn(4) - 1
			got, how := hw.SplitHow(topo, cpus, prefer, rq, natLess)
			hows[how]++
			cases++
			desc := fmt.Sprintf("machine %d: cpus %v prefer %d reqs %v -> %v (%s)", mi, cpus, prefer, rq, got, how)
			checkProperties(t, desc, topo, cpus, rq, got, how)
			if again := hw.SplitCPUs(topo, cpus, prefer, rq, natLess); !sameSplit(again, got) {
				t.Fatalf("%s: not deterministic", desc)
			}
		}
	}
	for _, h := range []string{"node", "package", "cut", "shared"} {
		if hows[h] == 0 {
			t.Errorf("no case split by %q (%v)", h, hows)
		}
	}
	t.Logf("%d cases: %v", cases, hows)
}

func checkProperties(t *testing.T, desc string, topo *hw.Topology, cpus []int, rq []hw.CPURequest, got map[string][]int, how string) {
	t.Helper()
	all := hw.NewCPUSet(cpus...)
	sorted := slices.Clone(rq)
	sort.SliceStable(sorted, func(i, j int) bool { return natLess(sorted[i].Name, sorted[j].Name) })
	if len(got) != len(rq) {
		t.Fatalf("%s: %d results for %d requests", desc, len(got), len(rq))
	}
	for name, l := range got {
		if len(l) == 0 || !slices.IsSorted(l) || len(slices.Compact(slices.Clone(l))) != len(l) {
			t.Fatalf("%s: %s = %v: not a sorted, non-empty set", desc, name, l)
		}
		if len(hw.NewCPUSet(l...).Minus(all)) > 0 {
			t.Fatalf("%s: %s has CPUs outside cpus", desc, name)
		}
	}
	// Fixed instances, in name order: exact sizes, and a span only when no
	// node had room at their turn.
	free := map[int]int{}
	for _, c := range all {
		free[topo.NodeOf(c)]++
	}
	total, fixedSum := len(all), 0
	used := hw.CPUSet{}
	var autos []string
	for _, q := range sorted {
		if q.CPUs <= 0 {
			autos = append(autos, q.Name)
			continue
		}
		fixedSum += q.CPUs
		l := got[q.Name]
		left := total - len(used)
		if left == 0 {
			if !hw.CPUSet(l).Equal(all) {
				t.Fatalf("%s: %s should run on all CPUs", desc, q.Name)
			}
			continue
		}
		k := min(q.CPUs, left)
		if len(l) != k {
			t.Fatalf("%s: %s has %d CPUs, want %d", desc, q.Name, len(l), k)
		}
		if len(hw.NewCPUSet(l...).And(used)) > 0 {
			t.Fatalf("%s: %s reuses CPUs", desc, q.Name)
		}
		roomy := false
		for _, f := range free {
			roomy = roomy || f >= k
		}
		if roomy && len(topo.NodesOf(l)) != 1 {
			t.Fatalf("%s: %s spans nodes though one had room", desc, q.Name)
		}
		for _, c := range l {
			free[topo.NodeOf(c)]--
		}
		used = used.Union(hw.NewCPUSet(l...))
	}
	if len(autos) == 0 {
		return
	}
	rest := all.Minus(used)
	if len(rest) == 0 {
		rest = all
	}
	if how == "shared" {
		if len(autos) <= len(rest) {
			t.Fatalf("%s: shared with enough CPUs", desc)
		}
		for _, name := range autos {
			if len(got[name]) != 1 {
				t.Fatalf("%s: shared %s has %d CPUs", desc, name, len(got[name]))
			}
		}
		return
	}
	// Autos: disjoint, within one of each other, all of rest used.
	lo, hi := len(rest)/len(autos), (len(rest)+len(autos)-1)/len(autos)
	var autoCPUs hw.CPUSet
	n := 0
	for _, name := range autos {
		l := got[name]
		if len(l) < lo || len(l) > hi {
			t.Fatalf("%s: %s has %d CPUs, want %d..%d", desc, name, len(l), lo, hi)
		}
		n += len(l)
		autoCPUs = autoCPUs.Union(hw.NewCPUSet(l...))
		switch how {
		case "node":
			if len(topo.NodesOf(l)) != 1 {
				t.Fatalf("%s: %s spans nodes", desc, name)
			}
		case "package":
			pkgs := map[int]bool{}
			for _, c := range l {
				pkgs[topo.PackageOf(c)] = true
			}
			if len(pkgs) != 1 {
				t.Fatalf("%s: %s spans packages", desc, name)
			}
		}
	}
	if n != len(rest) || !autoCPUs.Equal(rest) {
		t.Fatalf("%s: autos use %v, want %v", desc, autoCPUs, rest)
	}
	// With CPUs enough for everyone, nobody shares.
	if fixedSum+len(autos) <= total && len(used)+len(autoCPUs) != len(used.Union(autoCPUs)) {
		t.Fatalf("%s: CPUs given twice", desc)
	}
}
