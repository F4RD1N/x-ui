package hw_test

import (
	"fmt"
	"slices"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/util/hw"
	"github.com/mhsanaei/3x-ui/v2/util/hw/hwtest"
)

func list(t *testing.T, s string) hw.CPUSet {
	t.Helper()
	c, err := hw.ParseList(s)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// placeOn builds a machine and places its first uplink NIC's queues.
func placeOn(t *testing.T, m hwtest.Machine, units []hw.Unit) (*hw.Topology, *hw.NIC, *hw.Placement) {
	t.Helper()
	b := m.Build(t)
	topo, err := hw.ReadTopology(b.FS())
	if err != nil {
		t.Fatal(err)
	}
	nics, _ := hw.UplinkNICs(b.FS(), b.Eth)
	if len(nics) == 0 {
		t.Fatal("no uplink")
	}
	n := nics[0]
	return topo, n, hw.PlaceQueues(topo, topo.Online.Minus(topo.Isolated), units, []hw.PlaceNIC{{NIC: n, RSS: rssOrder(n)}})
}

// rssOrder is the hashed queues by table entries, then index.
func rssOrder(n *hw.NIC) []int {
	use := n.RSSUse()
	if use == nil {
		var all []int
		for q := 0; q < n.Queues(); q++ {
			all = append(all, q)
		}
		return all
	}
	var qs []int
	for q := range use {
		qs = append(qs, q)
	}
	slices.SortFunc(qs, func(a, b int) int {
		if use[a] != use[b] {
			return use[b] - use[a]
		}
		return a - b
	})
	return qs
}

func rssCPUs(pl *hw.Placement, nic string, n int) []int {
	var out []int
	for q := 0; q < n; q++ {
		out = append(out, pl.CPU[nic][q])
	}
	return out
}

// Every CPU has exactly one queue interrupt.
func onePerCPU(t *testing.T, topo *hw.Topology, pl *hw.Placement, nic string) {
	t.Helper()
	per := map[int]int{}
	for _, cpu := range pl.CPU[nic] {
		per[cpu]++
	}
	for _, c := range topo.Online {
		if per[c] != 1 {
			t.Errorf("CPU %d has %d queue interrupts", c, per[c])
		}
	}
}

func productionFixed(t *testing.T) []hw.Unit {
	sets := []string{"1,3,5,29,31", "7,9,33,35,37", "11,13,15,39,41", "17,19,43,45,47", "21,23,25,49,51",
		"0,2,4,28,30", "6,8,32,34,36", "10,12,14,38,40", "16,18,42,44,46", "20,22,24,48,50"}
	var us []hw.Unit
	for i, s := range sets {
		us = append(us, hw.Unit{Name: fmt.Sprintf("xray-%d", i+1), CPUs: list(t, s)})
	}
	return us
}

func productionAuto(t *testing.T) []hw.Unit {
	sets := []string{"1,3,5,29,31,33", "7,9,11,35,37,39", "13,15,17,41,43,45", "19,21,23,47,49", "25,27,51,53,55",
		"0,2,4,28,30,32", "6,8,10,34,36,38", "12,14,16,40,42,44", "18,20,22,46,48", "24,26,50,52,54"}
	var us []hw.Unit
	for i, s := range sets {
		us = append(us, hw.Unit{Name: fmt.Sprintf("xray-%d", i+1), CPUs: list(t, s)})
	}
	return us
}

// rssCoreRule: no core carries two RSS queue interrupts while an eligible
// core has none.
func rssCoreRule(t *testing.T, topo *hw.Topology, eligible hw.CPUSet, pl *hw.Placement, rss map[string]int) {
	t.Helper()
	perCore := map[int]int{}
	for nic, n := range rss {
		for q := 0; q < n; q++ {
			if cpu, ok := pl.CPU[nic][q]; ok {
				perCore[topo.CoreOf(cpu).ID]++
			}
		}
	}
	var idle, double []int
	for _, c := range topo.Cores {
		if len(c.Threads.And(eligible)) == 0 {
			continue
		}
		switch n := perCore[c.ID]; {
		case n == 0:
			idle = append(idle, c.ID)
		case n > 1:
			double = append(double, c.ID)
		}
	}
	if len(idle) > 0 && len(double) > 0 {
		t.Errorf("cores %v carry two RSS queues while cores %v have none", double, idle)
	}
}

// Production with ten instances of 5 CPUs and 6 free CPUs (two free cores,
// two free threads beside instances): the RSS queues go one per core, the
// four free cores' first threads first, then one per instance, then a
// second for the first two instances (on cores of their own: a free core's
// second thread would put two on one core while others have none). The
// other 40 queues put one interrupt on every other CPU; XPS is one to one.
func TestPlaceProductionFixed(t *testing.T) {
	topo, n, pl := placeOn(t, hwtest.Production(), productionFixed(t))
	want := []int{27, 26, 53, 52, 1, 7, 11, 17, 21, 0, 6, 10, 16, 20, 3, 9}
	if got := rssCPUs(pl, "eno1", 16); !slices.Equal(got, want) {
		t.Errorf("RSS queues on %v\n          want %v", got, want)
	}
	onePerCPU(t, topo, pl, "eno1")
	rssCoreRule(t, topo, topo.Online, pl, map[string]int{"eno1": 16})
	per := pl.Units["eno1"]
	for i := 1; i <= 10; i++ {
		want := [2]int{1, 5}
		if i <= 2 {
			want[0] = 2
		}
		if c := per[fmt.Sprintf("xray-%d", i)]; c != want {
			t.Errorf("xray-%d: RSS %d, all %d", i, c[0], c[1])
		}
	}
	if per[""] != [2]int{4, 6} {
		t.Errorf("free CPUs: %v", per[""])
	}
	for q, cpus := range pl.XPS["eno1"] {
		if len(cpus) != 1 || cpus[0] != pl.CPU["eno1"][q] {
			t.Errorf("XPS tx-%d = %v, its interrupt is on %d", q, cpus, pl.CPU["eno1"][q])
		}
	}
	if len(pl.XPS["eno1"]) != n.TxQueues {
		t.Errorf("XPS for %d queues", len(pl.XPS["eno1"]))
	}
	if pl.Owner["eno1"][0] != "" || pl.Owner["eno1"][4] != "xray-1" || pl.Owner["eno1"][9] != "xray-6" {
		t.Errorf("owners %v", pl.Owner["eno1"])
	}
}

// Ten auto instances (no free CPU): the 6-CPU instances get 2 RSS queues,
// the 5-CPU ones 1.
func TestPlaceProductionAuto(t *testing.T) {
	topo, _, pl := placeOn(t, hwtest.Production(), productionAuto(t))
	want := []int{1, 7, 13, 0, 6, 12, 19, 25, 18, 24, 3, 9, 15, 2, 8, 14}
	if got := rssCPUs(pl, "eno1", 16); !slices.Equal(got, want) {
		t.Errorf("RSS queues on %v\n          want %v", got, want)
	}
	onePerCPU(t, topo, pl, "eno1")
	for i, u := range productionAuto(t) {
		wantRSS := 1
		if len(u.CPUs) == 6 {
			wantRSS = 2
		}
		if c := pl.Units["eno1"][u.Name]; c[0] != wantRSS || c[1] != len(u.CPUs) {
			t.Errorf("xray-%d: %v", i+1, c)
		}
	}
}

// Without instances (a fresh install): one queue per physical core, the
// NIC's node first.
func TestPlaceNoSplit(t *testing.T) {
	topo, _, pl := placeOn(t, hwtest.Production(), nil)
	want := []int{1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 0, 2}
	if got := rssCPUs(pl, "eno1", 16); !slices.Equal(got, want) {
		t.Errorf("RSS queues on %v", got)
	}
	onePerCPU(t, topo, pl, "eno1")
	if pl.Owner["eno1"][0] != hw.AllUnit {
		t.Errorf("owner %q", pl.Owner["eno1"][0])
	}
	// Overlapping instances are no usable split either.
	us := productionFixed(t)
	us[1].CPUs = us[0].CPUs
	_, _, pl2 := placeOn(t, hwtest.Production(), us)
	if got := rssCPUs(pl2, "eno1", 16); !slices.Equal(got, want) {
		t.Errorf("overlapping: RSS queues on %v", got)
	}
}

// EPYC with 16 auto instances of 16 whole cores: 4 RSS queues each (one
// gets 3 of the 63), on distinct whole cores of its own node, and its CPUs
// send only on its own queues.
func TestPlaceEPYC(t *testing.T) {
	for _, nps := range []int{1, 4} {
		var us []hw.Unit
		for i := 0; i < 16; i++ {
			lo := 16 * i
			us = append(us, hw.Unit{Name: fmt.Sprintf("xray-%d", i+1), CPUs: list(t, fmt.Sprintf("%d-%d,%d-%d", lo, lo+15, lo+256, lo+271))})
		}
		topo, n, pl := placeOn(t, hwtest.EPYC(nps), us)
		total := 0
		for _, u := range us {
			cores := map[int]bool{}
			nodes := topo.NodesOf(u.CPUs)
			got := 0
			for q, cpu := range pl.CPU[n.Name] {
				if !u.CPUs.Has(cpu) {
					continue
				}
				got++
				c := topo.CoreOf(cpu)
				if cores[c.ID] {
					t.Errorf("nps%d %s: two queues on core %d (queue %d)", nps, u.Name, c.ID, q)
				}
				cores[c.ID] = true
				if topo.NodeOf(cpu) != nodes[0] {
					t.Errorf("nps%d %s: queue %d on node %d", nps, u.Name, q, topo.NodeOf(cpu))
				}
			}
			if got < 3 || got > 4 {
				t.Errorf("nps%d %s: %d queues", nps, u.Name, got)
			}
			total += got
			for _, c := range u.CPUs {
				for q, cpus := range pl.XPS[n.Name] {
					if cpus.Has(c) && !u.CPUs.Has(pl.CPU[n.Name][q]) {
						t.Errorf("nps%d %s: CPU %d sends on queue %d of CPU %d", nps, u.Name, c, q, pl.CPU[n.Name][q])
					}
				}
			}
		}
		if total != 63 {
			t.Errorf("nps%d: %d queues placed", nps, total)
		}
		if c := pl.Units[n.Name]["xray-16"]; c[0] != 3 {
			t.Errorf("nps%d: the last instance has %d (the 63rd queue goes to the NIC's node)", nps, c[0])
		}
	}
}

// A VPS with 4 queues on 4 vCPUs and one instance: queue i on CPU i, which
// is what virtio_net already does.
func TestPlaceVirtioIdentity(t *testing.T) {
	m := hwtest.VPS(4)
	m.NICs[0].Channels = hw.Channels{MaxCombined: 4, Combined: 4}
	topo, n, pl := placeOn(t, m, []hw.Unit{{Name: "xray", CPUs: list(t, "0-3")}})
	for q := 0; q < 4; q++ {
		if pl.CPU[n.Name][q] != q {
			t.Errorf("queue %d on %d", q, pl.CPU[n.Name][q])
		}
		if !pl.XPS[n.Name][q].Equal(hw.CPUSet{q}) {
			t.Errorf("XPS tx-%d %v", q, pl.XPS[n.Name][q])
		}
		irqs := 0
		for _, irq := range n.IRQs {
			if irq.Queue == q {
				irqs++
				if len(irq.Effective) != 1 || irq.Effective[0] != q {
					t.Errorf("virtio already puts queue %d on %v", q, irq.Effective)
				}
			}
		}
		if irqs != 2 {
			t.Errorf("queue %d: %d interrupts (input and output)", q, irqs)
		}
	}
	_ = topo
}

// Two NICs (a bond's slaves) are placed together: their RSS queues
// alternate, and every CPU still gets at most one queue while there are
// CPUs without one.
func TestPlaceTwoNICs(t *testing.T) {
	b := hwtest.Bond().Build(t)
	topo, err := hw.ReadTopology(b.FS())
	if err != nil {
		t.Fatal(err)
	}
	nics, _ := hw.UplinkNICs(b.FS(), b.Eth)
	if len(nics) != 2 {
		t.Fatalf("%d NICs", len(nics))
	}
	var pn []hw.PlaceNIC
	for _, n := range nics {
		pn = append(pn, hw.PlaceNIC{NIC: n, RSS: rssOrder(n)})
	}
	pl := hw.PlaceQueues(topo, topo.Online, productionFixed(t), pn)
	// Free CPUs first, alternating: eno1 q0 27, eno2 q0 26, eno1 q1 53, ...
	if pl.CPU["eno1"][0] != 27 || pl.CPU["eno2"][0] != 26 || pl.CPU["eno1"][1] != 53 || pl.CPU["eno2"][1] != 52 {
		t.Errorf("eno1 %v\neno2 %v", pl.CPU["eno1"], pl.CPU["eno2"])
	}
	rssCoreRule(t, topo, topo.Online, pl, map[string]int{"eno1": 16, "eno2": 16})
	per := map[int]int{}
	for _, n := range []string{"eno1", "eno2"} {
		for _, c := range pl.CPU[n] {
			per[c]++
		}
	}
	for c, k := range per {
		if k > 1 {
			t.Errorf("CPU %d has %d queues (32 queues, 56 CPUs)", c, k)
		}
	}
	// Each instance carries 2 or 3 of the 32 RSS queues, never more.
	for i := 1; i <= 10; i++ {
		name := fmt.Sprintf("xray-%d", i)
		if r := pl.Units["eno1"][name][0] + pl.Units["eno2"][name][0]; r < 2 || r > 3 {
			t.Errorf("%s: %d RSS queues", name, r)
		}
	}
}

// A kept NIC stays where it is and counts as occupying its CPUs; its XPS
// follows its interrupts.
func TestPlaceKeep(t *testing.T) {
	b := hwtest.Production().Build(t)
	topo, _ := hw.ReadTopology(b.FS())
	n := hw.ReadNIC(b.FS(), b.Eth, "eno1")
	pl := hw.PlaceQueues(topo, topo.Online, nil, []hw.PlaceNIC{{NIC: n, RSS: rssOrder(n), Keep: true}})
	for q := 0; q < 16; q++ {
		if pl.CPU["eno1"][q] != 11+2*q {
			t.Errorf("kept queue %d moved to %d", q, pl.CPU["eno1"][q])
		}
	}
	// CPU 11 serves queue 0, so it sends on queue 0.
	if !pl.XPS["eno1"][0].Has(11) {
		t.Errorf("XPS tx-0 %v", pl.XPS["eno1"][0])
	}
	// Nothing on node 0 has a queue: its CPUs send on node 1's (the nearest).
	for q, cpus := range pl.XPS["eno1"] {
		for _, c := range cpus {
			if c%2 == 0 && topo.NodeOf(pl.CPU["eno1"][q]) != 1 {
				t.Errorf("CPU %d sends on queue %d", c, q)
			}
		}
	}
}

// XPS when the queues' CPUs are unknown (unrecognised interrupt names):
// contiguous groups of CPUs by node and core.
func TestPlaceXPSWithoutIRQs(t *testing.T) {
	m := hwtest.Desktop()
	m.NICs[0].IRQNames = "unknown"
	b := m.Build(t)
	topo, _ := hw.ReadTopology(b.FS())
	n := hw.ReadNIC(b.FS(), b.Eth, "eno1")
	if !n.UnknownIRQs {
		t.Fatal("names parsed")
	}
	pl := hw.PlaceQueues(topo, topo.Online, nil, []hw.PlaceNIC{{NIC: n, Keep: true}})
	want := []string{"0-3", "4-7", "8-11", "12-15"}
	for q, w := range want {
		if pl.XPS["eno1"][q].List() != w {
			t.Errorf("tx-%d %s, want %s", q, pl.XPS["eno1"][q].List(), w)
		}
	}
}

// The rule on more machines: the split the panel makes now on production
// (its free CPUs are threads beside instances), 16 and 28 hashed queues, and
// a desktop whose 4 queues meet two instances and one free core.
func TestPlaceOneRSSPerCore(t *testing.T) {
	prod := hwtest.Production()
	topo := hwtest.Topo(t, prod)
	var rq []hw.CPURequest
	for i := 1; i <= 10; i++ {
		rq = append(rq, hw.CPURequest{Name: fmt.Sprintf("xray-%d", i), CPUs: 5})
	}
	var split []hw.Unit
	for name, l := range hw.SplitCPUs(topo, topo.Online, 1, rq, natLess) {
		split = append(split, hw.Unit{Name: name, CPUs: hw.NewCPUSet(l...)})
	}
	slices.SortFunc(split, func(a, b hw.Unit) int { return a.CPUs[0] - b.CPUs[0] })
	for _, queues := range []uint32{16, 28} {
		m := hwtest.Production()
		m.NICs[0].Channels.Combined = queues
		if queues == 28 {
			m.NICs[0].RSSCap = 0
		}
		for _, units := range [][]hw.Unit{split, productionFixed(t), productionAuto(t), nil} {
			topo, n, pl := placeOn(t, m, units)
			rssCoreRule(t, topo, topo.Online, pl, map[string]int{"eno1": len(rssOrder(n))})
		}
	}
	m := hwtest.Desktop()
	topo, n, pl := placeOn(t, m, []hw.Unit{{Name: "xray-1", CPUs: list(t, "0-6")}, {Name: "xray-2", CPUs: list(t, "7-13")}})
	rssCoreRule(t, topo, topo.Online, pl, map[string]int{"eno1": len(rssOrder(n))})
}
