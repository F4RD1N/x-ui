//go:build linux

package tune

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/util/hw"
)

// The RSS table, weighted for the instance split. hw.PlaceQueues shares the
// RSS queues out by Sainte-Laguë on the instances' CPUs, but when they do
// not divide evenly some instances hold a queue more than others, and the
// table hashes evenly over the queues: those instances get more of the
// packets (two queues against one on 162.249.124.66, three against two on
// the EPYC servers). So x-ui writes a table that gives each instance's RSS
// queues its CPUs over the RSS queues it holds: every instance's share of
// the hashed packets follows its CPUs. The free CPUs' queues keep an even
// share (they run no xray), and where the instances' queues weigh the same
// already (one each on 76.164.201.34) the table stays even. It does so only
// on NICs whose interrupts it places, only over a table that is even or the
// one x-ui wrote last (a table someone else set stays), and only on drivers
// that change the table without a reset. When weighting is no longer called
// for, x-ui's table is made even again.

// weightDrivers write the RSS table to the card with a register or firmware
// write, no reset (mlx4, for one, restarts the port for it).
var weightDrivers = []string{"ixgbe", "igb", "igc", "i40e", "ice", "mlx5_core"}

// rssPlan is what x-ui does about a NIC's RSS table: weigh it for the
// instance split (or keep the weighted one), or make x-ui's even again.
type rssPlan struct {
	Queues []*rssQueue `json:"queues,omitempty"` // the weighted table's queues
	Write  string      `json:"write,omitempty"`  // "weighted", "even"; "" leaves the table
	Why    string      `json:"why,omitempty"`    // why x-ui's table is made even again
	table  []uint32    // the weighted table
}

// rssQueue is one queue of a weighted table.
type rssQueue struct {
	Queue   int       `json:"queue"`
	Weight  hw.Weight `json:"weight"` // its unit's CPUs over the RSS queues the unit holds (unit "": the free CPUs, an even share)
	Entries int       `json:"entries"`
	Live    int       `json:"live"`
}

// ourTable says whether the NIC's live RSS table is the weighted one x-ui
// wrote last.
func ourTable(n *hw.NIC, ns *NICState) bool {
	return ns != nil && ns.Table != nil && ns.Table.Written != "" && n.Indir != nil && hw.TableSum(n.Indir) == ns.Table.Written
}

// tableUse counts a table's entries per queue.
func tableUse(t []uint32) map[int]int {
	return (&hw.NIC{Indir: t}).RSSUse()
}

// planTables plans the NICs' RSS tables, once their interrupts are placed.
func (np *nicPlan) planTables() {
	var weights map[string]map[int]hw.Weight
	if np.place != nil {
		rss := map[string][]int{}
		for _, it := range np.NICs {
			if it.keep == "" {
				rss[it.NIC.Name] = it.rss
			}
		}
		weights = np.place.RSSWeights(rss)
	}
	for _, it := range np.NICs {
		it.RSS = np.planTable(it, weights[it.NIC.Name])
		it.Table = tableText(it, false)
	}
}

// planTable weighs a NIC's RSS table when its RSS queues' weights differ,
// and makes x-ui's weighted table even again when they no longer do, or
// when there is nothing to weigh by. nil leaves the table as it is.
func (np *nicPlan) planTable(it *nicItem, w map[int]hw.Weight) *rssPlan {
	n := it.NIC
	if n.Indir == nil || n.VF || !slices.Contains(weightDrivers, n.Driver) {
		return nil
	}
	k := len(n.RSSUse())
	if !it.ours && !hw.EvenOver(n.Indir, k) {
		return nil // someone else's
	}
	why := ""
	switch {
	case np.place == nil || !np.place.Split:
		why = "no usable instance split"
	case it.keep != "":
		why = "x-ui does not place its interrupts"
	case k < 2:
		why = "one RSS queue"
	case it.ours && it.ns.Table.Rings == k && n.RxRings > k:
		// Queues were added since, and the driver kept x-ui's table (mlx5
		// does): the default spreads over them, then they are weighted.
		why = "the NIC has more queues than when x-ui weighted it"
	case !hw.Uneven(w):
		why = "the instances' RSS queues weigh the same"
	}
	var t []uint32
	if why == "" {
		if t = hw.WeightedTable(n.Indir, w); t == nil {
			why = "not every RSS queue is placed"
		}
	}
	switch {
	case why != "" && it.ours:
		return &rssPlan{Write: "even", Why: why}
	case why != "", !it.ours && slices.Equal(t, n.Indir):
		return nil
	}
	rp := &rssPlan{table: t}
	if !slices.Equal(t, n.Indir) {
		rp.Write = "weighted"
	}
	use, live := tableUse(t), n.RSSUse()
	for _, q := range sortedKeys(use) {
		rp.Queues = append(rp.Queues, &rssQueue{Queue: q, Weight: w[q], Entries: use[q], Live: live[q]})
	}
	return rp
}

// weightsText sums a weighted table up: the entries per queue by its unit's
// CPUs per queue, the lightest first, then the free CPUs' queues.
func weightsText(rp *rssPlan) string {
	type group struct {
		free           bool
		per            float64
		lo, hi, queues int
	}
	var gs []*group
	for _, rq := range rp.Queues {
		free, per := rq.Weight.Unit == "", math.Round(rq.Weight.PerQueue()*100)/100
		if free {
			per = 0
		}
		i := slices.IndexFunc(gs, func(g *group) bool { return g.free == free && g.per == per })
		if i < 0 {
			gs = append(gs, &group{free: free, per: per, lo: rq.Entries, hi: rq.Entries})
			i = len(gs) - 1
		}
		g := gs[i]
		g.lo, g.hi = min(g.lo, rq.Entries), max(g.hi, rq.Entries)
		g.queues++
	}
	sort.Slice(gs, func(i, j int) bool { return !gs[i].free && (gs[j].free || gs[i].per < gs[j].per) })
	var parts []string
	for i, g := range gs {
		s := strconv.Itoa(g.lo)
		if g.hi != g.lo {
			s += "-" + strconv.Itoa(g.hi)
		}
		if i == 0 {
			s += " entries per queue"
		}
		cpus := "CPUs"
		if g.per == 1 {
			cpus = "CPU"
		}
		if g.free {
			s += fmt.Sprintf(" on the free CPUs (%d queue%s)", g.queues, plural(g.queues))
		} else {
			s += fmt.Sprintf(" at %s %s/queue (%d queue%s)", strconv.FormatFloat(g.per, 'f', -1, 64), cpus, g.queues, plural(g.queues))
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ", ")
}

// tableText describes a NIC's RSS table (dry: what an apply does).
func tableText(it *nicItem, dry bool) string {
	n := it.NIC
	if n.Indir == nil {
		return "not readable"
	}
	use := n.RSSUse()
	size := len(n.Indir)
	even := fmt.Sprintf("%d entries, even over queues %s", size, hw.CPUSet(sortedKeys(use)).List())
	ours := fmt.Sprintf("%d entries weighted by x-ui", size)
	rp := it.RSS
	switch {
	case rp == nil && hw.EvenOver(n.Indir, len(use)):
		return even + ": kept"
	case rp == nil:
		return fmt.Sprintf("%d entries over %d queues, uneven (set by someone): kept", size, len(use))
	case rp.Write == "even" && dry:
		return ours + " -> even (" + rp.Why + ")"
	case rp.Write == "even":
		return ours + ", no longer called for (" + rp.Why + "): 'x-ui tune apply' makes it even again"
	case rp.Write == "weighted" && dry:
		if it.ours {
			even = ours + " for another split"
		}
		return even + " -> weighted for the instance split: " + weightsText(rp)
	case rp.Write == "weighted" && it.ours:
		return ours + " for another split ('x-ui tune apply' weights it for this one)"
	case rp.Write == "weighted":
		return even + " ('x-ui tune apply' weights it for the instance split)"
	}
	return fmt.Sprintf("%d entries weighted for the instance split: %s", size, weightsText(rp))
}

// writeTable writes a NIC's weighted RSS table, or makes x-ui's even again.
func (e *Env) writeTable(it *nicItem, ns *NICState, r *Result) {
	n, rp := it.NIC, it.RSS
	if rp == nil || rp.Write == "" {
		return
	}
	if rp.Write == "even" {
		if err := e.evenTable(n, ns.Table); err != nil {
			r.problem("%s: RSS table not made even: %s", n.Name, ethNote(err))
			return
		}
		ns.Table, it.RSS = nil, nil
		r.change("%s: RSS table even again (%s)", n.Name, rp.Why)
		return
	}
	err := e.eth().SetIndir(n.Name, rp.table)
	if err == nil {
		if t, gerr := e.eth().Indir(n.Name); gerr != nil || !slices.Equal(t, rp.table) {
			err = errors.New("the driver did not take it")
			_ = e.evenTable(n, nil)
		}
	}
	if err != nil {
		r.problem("%s: RSS table not weighted: %s", n.Name, ethNote(err))
		if ns.Table != nil {
			ns.Table.Pending = ""
			if ns.Table.Written == "" {
				ns.Table = nil
			}
		}
		return
	}
	ns.Table = &TableState{Written: hw.TableSum(rp.table), Rings: n.RxRings}
	n.Indir, it.ours, rp.Write = rp.table, true, ""
	r.change("%s: RSS table weighted for the instance split: %s", n.Name, weightsText(rp))
}

// evenTable makes x-ui's weighted table even again over the queues it
// hashes to (0..k-1): the driver's default where that is over the same
// queues (size 0, which also clears "set by the user"), else the kernel's
// default form written out (an 82599 with more queues than its table can
// address refuses a default over all of them). A table that hashed to all
// the rings there were when x-ui weighted it (ts) gets the default too, over
// the rings added since. n.Indir follows.
func (e *Env) evenTable(n *hw.NIC, ts *TableState) error {
	k := len(n.RSSUse())
	even := hw.DefaultTable(len(n.Indir), k)
	var err error
	if n.RxRings == k || ts != nil && ts.Rings == k && n.RxRings > k {
		even = hw.DefaultTable(len(n.Indir), n.RxRings)
		err = e.eth().SetIndir(n.Name, nil)
	} else {
		err = e.eth().SetIndir(n.Name, even)
	}
	if err == nil {
		n.Indir = even
	}
	return err
}
