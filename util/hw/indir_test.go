package hw_test

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/util/hw"
	"github.com/mhsanaei/3x-ui/v2/util/hw/hwtest"
)

func countEntries(t []uint32) map[int]int {
	m := map[int]int{}
	for _, q := range t {
		m[int(q)]++
	}
	return m
}

// bond66 is 162.249.124.66: two E5-2699 v4 (22 cores of 2 threads each,
// siblings n and n+44) and an 802.3ad bond over two 82599 ports with 16
// queues each and tables of 128.
func bond66() hwtest.Machine {
	m := hwtest.Bond()
	m.Packages, m.CoresPerPackage, m.Numbering, m.MemGiB = 2, 22, "linear", 256
	m.Model = "Intel(R) Xeon(R) CPU E5-2699 v4 @ 2.20GHz"
	return m
}

// split66 is the panel's split there: 20 instances of 4 CPUs, 8 left free.
func split66(t *testing.T, topo *hw.Topology) []hw.Unit {
	t.Helper()
	var reqs []hw.CPURequest
	for i := 1; i <= 20; i++ {
		reqs = append(reqs, hw.CPURequest{Name: fmt.Sprintf("xray-%d", i), CPUs: 4})
	}
	natural := func(a, b string) bool { return len(a) < len(b) || len(a) == len(b) && a < b }
	got := hw.SplitCPUs(topo, topo.Online, 1, reqs, natural)
	var units []hw.Unit
	for _, r := range reqs {
		units = append(units, hw.Unit{Name: r.Name, CPUs: hw.NewCPUSet(got[r.Name]...)})
	}
	return units
}

// On the .66 split the instances hold one or two RSS queues; weighted by
// CPUs per queue, both NICs' tables give every instance the same share
// within one entry per NIC, and the free CPUs' queues keep an even share.
func TestRSSWeights66(t *testing.T) {
	b := bond66().Build(t)
	topo, err := hw.ReadTopology(b.FS())
	if err != nil {
		t.Fatal(err)
	}
	nics, _ := hw.UplinkNICs(b.FS(), b.Eth)
	if len(nics) != 2 {
		t.Fatalf("%d uplinks", len(nics))
	}
	units := split66(t, topo)
	var pn []hw.PlaceNIC
	rss := map[string][]int{}
	for _, n := range nics {
		pn = append(pn, hw.PlaceNIC{NIC: n, RSS: rssOrder(n)})
		rss[n.Name] = rssOrder(n)
	}
	pl := hw.PlaceQueues(topo, topo.Online, units, pn)
	if !pl.Split || pl.CPUs[""] != 8 || pl.CPUs["xray-20"] != 4 {
		t.Fatalf("split %v, CPUs %v", pl.Split, pl.CPUs)
	}
	held := map[string]int{}
	for _, n := range nics {
		for u, c := range pl.Units[n.Name] {
			held[u] += c[0]
		}
	}
	two := 0
	for _, u := range units {
		if held[u.Name] == 2 {
			two++
		}
	}
	if held[""] != 4 || two != 8 {
		t.Fatalf("RSS queues held: %v", held)
	}

	w := pl.RSSWeights(rss)
	total := map[string]int{}
	for _, n := range nics {
		if !hw.Uneven(w[n.Name]) {
			t.Errorf("%s: weights even", n.Name)
		}
		for q, x := range w[n.Name] {
			if x.Queues != held[x.Unit] || x.CPUs != pl.CPUs[x.Unit] || x.Unit != pl.Owner[n.Name][q] {
				t.Errorf("%s q%d: %+v", n.Name, q, x)
			}
		}
		table := hw.WeightedTable(n.Indir, w[n.Name])
		use := countEntries(table)
		if len(table) != 128 || len(use) != 16 {
			t.Fatalf("%s: %d entries over %d queues", n.Name, len(table), len(use))
		}
		for q, c := range use {
			total[pl.Owner[n.Name][q]] += c
		}
	}
	lo, hi := 256, 0
	for _, u := range units {
		lo, hi = min(lo, total[u.Name]), max(hi, total[u.Name])
	}
	if hi-lo > len(nics) || total[""] != 8*held[""] {
		t.Errorf("entries per instance %d-%d, free CPUs %d: %v", lo, hi, total[""], total)
	}
	// Even, each would hold 8 per queue: 16 for xray-1..8, 8 for the rest.
	if lo < 11 || hi > 12 {
		t.Errorf("entries per instance %d-%d", lo, hi)
	}
}

// The weighted table keeps base's queues, gives each instance its
// largest-remainder part (one a queue at least) shared evenly over its
// queues, leaves the free CPUs' queues an even share, moves only what it
// must, stays interleaved, and is its own fixed point.
func TestWeightedTable(t *testing.T) {
	base := hw.DefaultTable(128, 16)
	w := map[int]hw.Weight{}
	for q := 0; q < 16; q++ {
		w[q] = hw.Weight{Unit: fmt.Sprint(q), CPUs: 4, Queues: 1}
	}
	if hw.Uneven(w) {
		t.Error("equal weights uneven")
	}
	if got := hw.WeightedTable(base, w); !slices.Equal(got, base) {
		t.Errorf("equal weights changed the table: %v", got[:16])
	}
	// Four instances of 3 CPUs over a table of 100: two hold three queues
	// (1 CPU/queue), two hold two (1.5). Parted by queue, the 1.5s would get
	// 12.5 -> 13 each, the 1s 8.3 -> 8: 26 against 24. Parted by instance,
	// each gets its 25, an instance's extra one to its first queue.
	base = hw.DefaultTable(100, 10)
	w = map[int]hw.Weight{}
	for q, u := range []string{"a", "a", "a", "b", "b", "b", "c", "c", "d", "d"} {
		w[q] = hw.Weight{Unit: u, CPUs: 3, Queues: 3 - q/6}
	}
	if !hw.Uneven(w) {
		t.Error("uneven weights even")
	}
	got := hw.WeightedTable(base, w)
	use := countEntries(got)
	want := []int{9, 8, 8, 9, 8, 8, 13, 12, 13, 12}
	for q := range want {
		if use[q] != want[q] {
			t.Errorf("q%d: %d entries, want %d (%v)", q, use[q], want[q], use)
		}
	}
	moved := 0
	for i := range got {
		if got[i] != base[i] {
			moved++
		}
	}
	if moved != 3+2+3+2 {
		t.Errorf("%d entries moved", moved)
	}
	// Every queue in every quarter of the table.
	for q := 0; q < 10; q++ {
		for i := 0; i < 100; i += 25 {
			if !slices.Contains(got[i:i+25], uint32(q)) {
				t.Errorf("q%d not in entries %d-%d: %v", q, i, i+24, got)
			}
		}
	}
	if again := hw.WeightedTable(got, w); !slices.Equal(again, got) {
		t.Error("not its own fixed point")
	}
	// Built on an even table laid out otherwise: the same parts.
	odd := reversed(base)
	if use := countEntries(hw.WeightedTable(odd, w)); use[0]+use[1]+use[2] != 25 || use[3]+use[4]+use[5] != 25 || use[6]+use[7] != 25 || use[8] != 13 {
		t.Errorf("on a reversed table: %v", use)
	}

	// The free CPUs' queues keep an even share, the floor or the ceiling of
	// size/queues, whatever they had; their weights make nothing uneven.
	free := maps.Clone(w)
	free[0], free[9] = hw.Weight{CPUs: 6, Queues: 2}, hw.Weight{CPUs: 6, Queues: 2}
	use = countEntries(hw.WeightedTable(got, free))
	if use[0] != 10 || use[9] != 10 || use[3]+use[4]+use[5] != use[6]+use[7] {
		t.Errorf("free queues: %v", use)
	}
	if use := countEntries(hw.WeightedTable(hw.DefaultTable(105, 10), free)); use[0] != 11 || use[9] != 10 {
		t.Errorf("free queues on 105 entries: %v", use)
	}
	for q := 1; q < 9; q++ {
		free[q] = hw.Weight{Unit: fmt.Sprint(q), CPUs: 4, Queues: 1}
	}
	if hw.Uneven(free) {
		t.Error("the free CPUs' weights made it uneven")
	}
	for q := 1; q < 9; q++ {
		free[q] = hw.Weight{CPUs: 4, Queues: 1}
	}
	if hw.WeightedTable(base, free) != nil {
		t.Error("weighted with no instance's queue")
	}

	// One entry at least, however light the queue.
	light := maps.Clone(w)
	light[0] = hw.Weight{Unit: "light", CPUs: 1, Queues: 64}
	use = countEntries(hw.WeightedTable(base, light))
	sum := 0
	for _, c := range use {
		sum += c
	}
	if use[0] != 1 || sum != 100 || len(use) != 10 {
		t.Errorf("light queue: %v", use)
	}
	// So many raised to one that the rest pays them back.
	tiny := hw.DefaultTable(4, 4)
	tw := map[int]hw.Weight{0: {Unit: "a", CPUs: 1, Queues: 1}, 1: {Unit: "b", CPUs: 1, Queues: 1}, 2: {Unit: "c", CPUs: 1, Queues: 1}, 3: {Unit: "d", CPUs: 100, Queues: 1}}
	if got := hw.WeightedTable(tiny, tw); !slices.Equal(got, tiny) {
		t.Errorf("tiny: %v", got)
	}
	// A queue of the table without a weight; only the table's queues.
	delete(light, 5)
	if hw.WeightedTable(base, light) != nil {
		t.Error("weighted without q5's weight")
	}
	more := maps.Clone(w)
	more[20] = hw.Weight{Unit: "20", CPUs: 400, Queues: 1}
	if got2 := hw.WeightedTable(base, more); !slices.Equal(got2, got) {
		t.Errorf("a queue the table does not use: %v", countEntries(got2))
	}
}

func reversed(t []uint32) []uint32 {
	r := slices.Clone(t)
	slices.Reverse(r)
	return r
}

func TestTableSum(t *testing.T) {
	a, b := hw.DefaultTable(128, 16), hw.DefaultTable(128, 16)
	if hw.TableSum(a) != hw.TableSum(b) || !strings.HasPrefix(hw.TableSum(a), "128:") || len(hw.TableSum(a)) != 4+16 {
		t.Errorf("sum %q", hw.TableSum(a))
	}
	b[127] = 0
	if hw.TableSum(a) == hw.TableSum(b) || hw.TableSum(a[:64]) == hw.TableSum(a) {
		t.Error("sums of different tables equal")
	}
	if !hw.DefaultForm(hw.DefaultTable(512, 63), 63) {
		t.Error("DefaultTable")
	}
}
