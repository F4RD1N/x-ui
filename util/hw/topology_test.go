package hw_test

import (
	"fmt"
	"slices"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/util/hw"
	"github.com/mhsanaei/3x-ui/v2/util/hw/hwtest"
)

const gib = int64(1) << 30

func ints(a, b int) []int {
	var out []int
	for i := a; i <= b; i++ {
		out = append(out, i)
	}
	return out
}

type topoWant struct {
	sockets, cores, cpus, threads, nodes int
	mem                                  int64
}

func checkTopo(t *testing.T, name string, topo *hw.Topology, w topoWant) {
	t.Helper()
	got := topoWant{topo.Sockets(), len(topo.Cores), len(topo.Online), topo.ThreadsPerCore(), len(topo.Nodes), topo.MemBytes}
	if got != w {
		t.Errorf("%s: got %+v, want %+v", name, got, w)
	}
	// Cores are ordered by (node, ID), each core's ID its lowest thread,
	// and every online CPU is in exactly one core.
	seen := map[int]bool{}
	for i, c := range topo.Cores {
		if c.ID != c.Threads[0] {
			t.Errorf("%s: core %v has ID %d", name, c.Threads, c.ID)
		}
		if i > 0 {
			p := topo.Cores[i-1]
			if p.Node > c.Node || (p.Node == c.Node && p.ID >= c.ID) {
				t.Errorf("%s: cores out of order at %d", name, i)
			}
		}
		for _, x := range c.Threads {
			if seen[x] {
				t.Errorf("%s: CPU %d in two cores", name, x)
			}
			seen[x] = true
			if topo.NodeOf(x) != c.Node || topo.CoreOf(x).ID != c.ID {
				t.Errorf("%s: CPU %d lookups", name, x)
			}
		}
	}
	if len(seen) != len(topo.Online) {
		t.Errorf("%s: cores cover %d of %d CPUs", name, len(seen), len(topo.Online))
	}
}

func TestTopologyPresets(t *testing.T) {
	prod := hwtest.Topo(t, hwtest.Production())
	checkTopo(t, "production", prod, topoWant{2, 28, 56, 2, 2, 121 * gib})
	var odd, even []int
	for c := 0; c < 56; c++ {
		if c%2 == 1 {
			odd = append(odd, c)
		} else {
			even = append(even, c)
		}
	}
	if !prod.Nodes[0].CPUs.Equal(hw.NewCPUSet(even...)) || !prod.Nodes[1].CPUs.Equal(hw.NewCPUSet(odd...)) {
		t.Errorf("production nodes: %v / %v", prod.Nodes[0].CPUs.List(), prod.Nodes[1].CPUs.List())
	}
	var order1 []int
	for c := 1; c < 28; c += 2 {
		order1 = append(order1, c, c+28)
	}
	if got := prod.NodeOrder(1); !slices.Equal(got, order1) {
		t.Errorf("production NodeOrder(1) = %v", got)
	}
	if got := prod.NodeOrder(0)[:4]; !slices.Equal(got, []int{0, 28, 2, 30}) {
		t.Errorf("production NodeOrder(0) = %v...", got)
	}
	if s := prod.Siblings(41); s.List() != "13,41" {
		t.Errorf("production siblings of 41: %v", s)
	}
	if prod.Distance(0, 1) != 21 || prod.Distance(1, 1) != 10 || prod.Distance(0, 7) != 20 {
		t.Errorf("production distances %d %d %d", prod.Distance(0, 1), prod.Distance(1, 1), prod.Distance(0, 7))
	}
	if prod.Nodes[1].MemBytes != 121*gib/2 || prod.PackageOf(3) != 1 || prod.PackageOfNode(0) != 0 || prod.NodeOf(99) != -1 || prod.PackageOf(99) != -1 {
		t.Errorf("production: node mem %d, package of 3 %d", prod.Nodes[1].MemBytes, prod.PackageOf(3))
	}
	if prod.Model != "Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz" {
		t.Errorf("model %q", prod.Model)
	}
	if w, p := prod.CoresIn([]int{1, 29, 3}); w != 1 || p != 1 {
		t.Errorf("CoresIn: %d whole, %d partial", w, p)
	}
	if n := prod.PhysicalCores(hw.NewCPUSet(1, 29, 3, 100)); n != 3 {
		t.Errorf("PhysicalCores: %d", n)
	}
	if got := prod.NodesOf([]int{3, 0, 5, 99}); !slices.Equal(got, []int{0, 1}) {
		t.Errorf("NodesOf: %v", got)
	}

	var e4 *hw.Topology
	for _, nps := range []int{1, 4} {
		e := hwtest.Topo(t, hwtest.EPYC(nps))
		e4 = e
		checkTopo(t, fmt.Sprintf("EPYC NPS%d", nps), e, topoWant{2, 256, 512, 2, 2 * nps, 1024 * gib})
		per := 512 / (2 * nps)
		for _, n := range e.Nodes {
			if len(n.CPUs) != per {
				t.Errorf("NPS%d node %d: %d CPUs", nps, n.ID, len(n.CPUs))
			}
		}
		if got := e.NodeOrder(0)[:4]; !slices.Equal(got, []int{0, 256, 1, 257}) {
			t.Errorf("NPS%d NodeOrder(0): %v", nps, got)
		}
		if e.Siblings(7).List() != "7,263" {
			t.Errorf("NPS%d siblings of 7: %v", nps, e.Siblings(7))
		}
	}
	if e4.Nodes[1].CPUs.List() != "32-63,288-319" || e4.Distance(0, 1) != 12 || e4.Distance(0, 4) != 32 || e4.PackageOfNode(5) != 1 {
		t.Errorf("NPS4: node 1 %v, distances %d %d", e4.Nodes[1].CPUs.List(), e4.Distance(0, 1), e4.Distance(0, 4))
	}

	d := hwtest.Topo(t, hwtest.Desktop())
	checkTopo(t, "desktop", d, topoWant{1, 8, 16, 2, 1, 32 * gib})
	if d.Siblings(4).List() != "4-5" || !slices.Equal(d.NodeOrder(0), ints(0, 15)) {
		t.Errorf("desktop: siblings %v, order %v", d.Siblings(4), d.NodeOrder(0))
	}

	// No node directories: one node 0 with every CPU and all the memory.
	v := hwtest.Topo(t, hwtest.VPS(2))
	checkTopo(t, "VPS(2)", v, topoWant{1, 2, 2, 1, 1, 2 * gib})
	if v.Nodes[0].ID != 0 || v.Nodes[0].CPUs.List() != "0-1" || v.Nodes[0].MemBytes != 2*gib {
		t.Errorf("VPS node: %+v", v.Nodes[0])
	}
	checkTopo(t, "VPS(1)", hwtest.Topo(t, hwtest.VPS(1)), topoWant{1, 1, 1, 1, 1, gib})

	// A memory-only node is kept, with no CPUs.
	c := hwtest.Topo(t, hwtest.CPULessNode())
	checkTopo(t, "CPU-less node", c, topoWant{2, 16, 32, 2, 3, 128 * gib})
	if n := c.Nodes[2]; n.ID != 2 || len(n.CPUs) != 0 || n.MemBytes != 64*gib {
		t.Errorf("memory-only node: %+v", n)
	}
	if c.Distance(0, 2) != 17 || c.Distance(1, 2) != 28 || c.Distance(2, 0) != 17 || c.PackageOfNode(2) != -1 || len(c.NodeOrder(2)) != 0 {
		t.Errorf("CPU-less distances: %d %d", c.Distance(0, 2), c.Distance(1, 2))
	}
	for _, m := range []hwtest.Machine{hwtest.Bond(), hwtest.ProxmoxBridge(), hwtest.VLAN(), hwtest.ManagedIRQs(), hwtest.Container(), hwtest.Tunnel()} {
		topo := hwtest.Topo(t, m)
		checkTopo(t, "preset", topo, topoWant{m.Packages, m.Packages * m.CoresPerPackage, m.Packages * m.CoresPerPackage * m.ThreadsPerCore,
			m.ThreadsPerCore, max(1, m.Packages*max(1, m.NodesPerPackage)), topo.MemBytes})
	}
}

// An offline CPU drops out; its online sibling is a core of one thread.
// Restrict keeps what is allowed.
func TestTopologyRestricted(t *testing.T) {
	m := hwtest.Restricted()
	b := m.Build(t)
	topo, err := hw.ReadTopology(b.FS())
	if err != nil {
		t.Fatal(err)
	}
	checkTopo(t, "restricted", topo, topoWant{2, 8, 15, 2, 2, 16 * gib})
	if topo.Online.List() != "0-2,4-15" || topo.CoreOf(11).Threads.List() != "11" || topo.CoreOf(3) != nil {
		t.Errorf("online %v, core of 11 %v", topo.Online.List(), topo.CoreOf(11))
	}
	if w, p := topo.CoresIn(topo.Online); w != 8 || p != 0 {
		t.Errorf("CoresIn(online): %d %d", w, p)
	}
	r := topo.Restrict(b.Allowed)
	if r.Online.List() != "0-2,4-6,8-10,12-13" || len(r.Cores) != 6 {
		t.Fatalf("restricted: %v, %d cores", r.Online.List(), len(r.Cores))
	}
	if got := r.NodeOrder(0); !slices.Equal(got, []int{0, 8, 2, 10, 4, 12, 6}) {
		t.Errorf("Restrict NodeOrder(0): %v", got)
	}
	if got := r.NodeOrder(1); !slices.Equal(got, []int{1, 9, 5, 13}) {
		t.Errorf("Restrict NodeOrder(1): %v", got)
	}
	if r.CoreOf(6).Threads.List() != "6" || r.Sockets() != 2 || r.MemBytes != topo.MemBytes || r.Distance(0, 1) != 21 {
		t.Errorf("Restrict: core of 6 %v", r.CoreOf(6).Threads)
	}
	// The original is untouched.
	if topo.CoreOf(6).Threads.List() != "6,14" {
		t.Error("Restrict changed its receiver")
	}

	// CPUs the topology does not know become cores of their own on the
	// lowest node.
	prod := hwtest.Topo(t, hwtest.Production())
	x := prod.Restrict([]int{1, 29, 100})
	if x.NodeOf(100) != 0 || x.CoreOf(100).Threads.List() != "100" || x.CoreOf(1).Threads.List() != "1,29" || len(x.Nodes) != 2 {
		t.Errorf("unknown CPU: node %d core %v", x.NodeOf(100), x.CoreOf(100))
	}

	// Isolated and nohz_full CPUs.
	m = hwtest.Desktop()
	m.Isolated, m.NohzFull = []int{2, 3}, []int{3, 4}
	if d := hwtest.Topo(t, m); d.Isolated.List() != "2-4" {
		t.Errorf("isolated: %v", d.Isolated)
	}
}

func TestFlat(t *testing.T) {
	f := hw.Flat([]int{3, 1, 2, 2})
	if f.Sockets() != 1 || len(f.Nodes) != 1 || len(f.Cores) != 3 || f.ThreadsPerCore() != 1 || !slices.Equal(f.NodeOrder(0), []int{1, 2, 3}) {
		t.Fatalf("flat: %+v", f)
	}
	for _, c := range f.Cores {
		if len(c.Threads) != 1 || c.Node != 0 || c.Package != 0 {
			t.Errorf("flat core %+v", c)
		}
	}
	if f.Distance(0, 0) != 10 || f.NodeOf(2) != 0 || f.PhysicalCores(hw.NewCPUSet(1, 2)) != 2 {
		t.Error("flat lookups")
	}
	if r := f.Restrict([]int{2, 3}); len(r.Cores) != 2 || r.Online.List() != "2-3" {
		t.Errorf("flat restrict: %+v", r)
	}
}

// A topology made by hand works too.
func TestTopologyByHand(t *testing.T) {
	topo := &hw.Topology{Online: hw.NewCPUSet(0, 1, 2, 3), Nodes: []hw.Node{{ID: 1, CPUs: hw.NewCPUSet(2, 3)}, {ID: 0, CPUs: hw.NewCPUSet(0, 1)}},
		Cores: []hw.Core{{ID: 2, Package: 1, Node: 1, Threads: hw.NewCPUSet(2, 3)}, {ID: 0, Node: 0, Threads: hw.NewCPUSet(0, 1)}}}
	if !slices.Equal(topo.NodeOrder(0), []int{0, 1}) || topo.Sockets() != 2 || topo.NodeOf(3) != 1 || topo.CoreOf(1).ID != 0 || topo.Siblings(2).List() != "2-3" || topo.Nodes[0].ID != 0 {
		t.Errorf("by hand: %+v", topo)
	}
}

func TestReadTopologyFails(t *testing.T) {
	if _, err := hw.ReadTopology(hw.FS{Root: t.TempDir()}); err == nil {
		t.Fatal("no error without CPUs")
	}
}

// The real machine's topology reads (whatever it is).
func TestReadTopologyLive(t *testing.T) {
	topo, err := hw.ReadTopology(hw.FS{})
	if err != nil {
		t.Skip(err)
	}
	if len(topo.Online) == 0 || len(topo.Cores) == 0 || len(topo.Nodes) == 0 || topo.Sockets() == 0 {
		t.Fatalf("live topology: %+v", topo)
	}
	t.Logf("%d sockets, %d cores, %d CPUs, %d nodes, %q", topo.Sockets(), len(topo.Cores), len(topo.Online), len(topo.Nodes), topo.Model)
}
