package hw

import (
	"slices"
	"sort"
)

// Unit is a group of CPUs that shares the packet work: one xray instance's
// CPUs. Units are given in the panel's natural name order.
type Unit struct {
	Name string
	CPUs CPUSet
}

// PlaceNIC is a NIC whose queue interrupts are to be placed.
type PlaceNIC struct {
	NIC *NIC
	// RSS are the queues the RSS table hashes to, by their table entries
	// (most first), then by index; all queues when the table is unreadable.
	RSS []int
	// Keep: the NIC's interrupts stay where they are (placed by someone
	// else, managed by the kernel, or left to irqbalance). They still count
	// as occupying their CPUs, and its XPS follows them.
	Keep bool
}

// Placement is where each queue's interrupts go and which queues each CPU
// sends on.
type Placement struct {
	CPU   map[string]map[int]int       // nic -> queue -> CPU
	Owner map[string]map[int]string    // nic -> queue -> unit ("" for free CPUs)
	XPS   map[string]map[int]CPUSet    // nic -> tx queue -> CPUs (no entry: no XPS for the NIC)
	Units map[string]map[string][2]int // nic -> unit -> {RSS queues, all queues} on its CPUs
	Split bool                         // the instances were the units (else one unit of all eligible CPUs)
}

// AllUnit names the single unit used when there is no usable instance split.
const AllUnit = "all"

type punit struct {
	name string
	cpus CPUSet
	free bool
	idx  int
	rss  int // RSS queues on its CPUs
}

type placer struct {
	t      *Topology
	units  []*punit // the free pool (if any) first, then the instances
	unitOf map[int]*punit
	inst   CPUSet      // CPUs of all instances
	cpuQ   map[int]int // queues on a CPU
	coreQ  map[int]int // queues on a core
}

func (p *placer) coreKey(cpu int) int {
	if c := p.t.CoreOf(cpu); c != nil {
		return c.ID
	}
	return -1 - cpu
}

func (p *placer) threads(cpu int) CPUSet {
	if c := p.t.CoreOf(cpu); c != nil {
		return c.Threads
	}
	return CPUSet{cpu}
}

func (p *placer) occupy(cpu int) {
	p.cpuQ[cpu]++
	p.coreQ[p.coreKey(cpu)]++
}

// dist is a CPU's NUMA distance to a NIC's node, 0 when either is unknown.
func (p *placer) dist(cpu, node int) int {
	n := p.t.NodeOf(cpu)
	if node < 0 || n < 0 {
		return 0
	}
	return p.t.Distance(n, node)
}

func (p *placer) minDist(u *punit, node int) int {
	best := -1
	for _, c := range u.cpus {
		if d := p.dist(c, node); best < 0 || d < best {
			best = d
		}
	}
	return best
}

// whole says whether all of a CPU's core threads belong to the unit.
func (p *placer) whole(u *punit, cpu int) bool {
	for _, x := range p.threads(cpu) {
		if !u.cpus.Has(x) {
			return false
		}
	}
	return true
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// less orders keys of ints lexicographically.
func lessKey(a, b []int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// pickIn chooses a CPU of the unit: cores with fewer queues first, then
// CPUs with fewer queues, cores wholly the unit's, nearer the NIC, by core
// and CPU. With onlyFree, only CPUs without a queue are candidates.
func (p *placer) pickIn(u *punit, node int, onlyFree bool) int {
	best, bestKey := -1, []int(nil)
	for _, c := range u.cpus {
		if onlyFree && p.cpuQ[c] > 0 {
			continue
		}
		k := []int{p.coreQ[p.coreKey(c)], p.cpuQ[c], b2i(!p.whole(u, c)), p.dist(c, node), p.coreKey(c), c}
		if best < 0 || lessKey(k, bestKey) {
			best, bestKey = c, k
		}
	}
	return best
}

// pickFree takes an RSS queue for the free CPUs, from the classes given: 0
// the first thread of a free core that has no queue yet, 1 another thread of
// a free core, 2 a free thread beside an instance on a core with no queue.
// -1 when none is left.
func (p *placer) pickFree(free *punit, node int, classes ...int) int {
	for _, class := range classes {
		best, bestKey := -1, []int(nil)
		for _, c := range free.cpus {
			th := p.threads(c)
			shared := len(th.And(p.inst)) > 0
			ok := false
			switch class {
			case 0:
				ok = !shared && p.coreQ[p.coreKey(c)] == 0 && c == th.And(free.cpus)[0]
			case 1:
				ok = !shared && p.cpuQ[c] == 0
			case 2:
				ok = shared && p.coreQ[p.coreKey(c)] == 0
			}
			if !ok {
				continue
			}
			k := []int{p.dist(c, node), p.coreKey(c), c}
			if best < 0 || lessKey(k, bestKey) {
				best, bestKey = c, k
			}
		}
		if best >= 0 {
			return best
		}
	}
	return -1
}

// pickInstance takes an RSS queue for the instance with the lowest share
// (Sainte-Laguë), on its core with the fewest queues; with emptyCore, only
// among instances that have a core with no queue yet. -1 when none is left.
func (p *placer) pickInstance(us []*punit, node int, emptyCore bool) int {
	var best *punit
	for _, u := range us {
		if u.free {
			continue
		}
		if emptyCore && !slices.ContainsFunc(u.cpus, func(c int) bool { return p.coreQ[p.coreKey(c)] == 0 }) {
			continue
		}
		if best == nil || p.lowerShare(u, best, u.rss, best.rss, node) {
			best = u
		}
	}
	if best == nil {
		return -1
	}
	return p.pickIn(best, node, false)
}

// lowerShare says whether unit a's (n+0.5)/cpus is below b's, with ties to
// the unit nearer the NIC, then the earlier one.
func (p *placer) lowerShare(a, b *punit, na, nb, node int) bool {
	l, r := (2*na+1)*len(b.cpus), (2*nb+1)*len(a.cpus)
	if l != r {
		return l < r
	}
	if da, db := p.minDist(a, node), p.minDist(b, node); da != db {
		return da < db
	}
	return a.idx < b.idx
}

func (p *placer) allOn(u *punit) int {
	n := 0
	for _, c := range u.cpus {
		n += p.cpuQ[c]
	}
	return n
}

type pqueue struct {
	nic   int
	queue int
	rss   bool
}

// PlaceQueues places the queue interrupts of the NICs on the eligible CPUs
// and works out XPS. It is pure.
//
// With instances, the RSS queues (whose packets are spread by hash, whoever
// they belong to) go one per physical core while any core has none: first
// to free CPUs (a free core, then a free thread beside an instance), then to
// the instances by Sainte-Laguë on their CPU counts, so no instance carries
// more than its share of the hashed work; inside an instance, one per core
// of its own first and nearer the NIC first. Only when every core has one
// does a second thread take one (a free core's first, then the instances'
// by share). The other queues (steered traffic, XPS)
// then fill one per CPU the same way. Without a usable split (no instances,
// or instances sharing CPUs) all eligible CPUs are one unit, which puts one
// queue per physical core, NIC-local cores first.
//
// XPS: each CPU sends on the queues served on that CPU, else on its core,
// else in its instance on its node, else on its node, else on the nearest
// node; outside the first case the least used of them.
func PlaceQueues(t *Topology, eligible CPUSet, units []Unit, nics []PlaceNIC) *Placement {
	pl := &Placement{CPU: map[string]map[int]int{}, Owner: map[string]map[int]string{},
		XPS: map[string]map[int]CPUSet{}, Units: map[string]map[string][2]int{}}
	p := &placer{t: t, unitOf: map[int]*punit{}, cpuQ: map[int]int{}, coreQ: map[int]int{}}

	var us []*punit
	var seen CPUSet
	overlap := false
	for _, u := range units {
		c := u.CPUs.And(eligible)
		if len(c) == 0 {
			continue
		}
		if len(seen.And(c)) > 0 {
			overlap = true
		}
		seen = seen.Union(c)
		us = append(us, &punit{name: u.Name, cpus: c})
	}
	var free *punit
	if len(us) == 0 || overlap {
		us = []*punit{{name: AllUnit, cpus: slices.Clone(eligible)}}
	} else {
		pl.Split = true
		p.inst = seen
		if f := eligible.Minus(seen); len(f) > 0 {
			free = &punit{cpus: f, free: true}
			us = append([]*punit{free}, us...)
		}
	}
	for i, u := range us {
		u.idx = i
		for _, c := range u.cpus {
			p.unitOf[c] = u
		}
	}
	p.units = us
	owner := func(cpu int) string {
		if u := p.unitOf[cpu]; u != nil {
			return u.name
		}
		return ""
	}

	rssOf := make([]map[int]bool, len(nics))
	queuesOf := make([][]int, len(nics))
	for i, pn := range nics {
		name := pn.NIC.Name
		pl.CPU[name], pl.Owner[name] = map[int]int{}, map[int]string{}
		rssOf[i] = map[int]bool{}
		for _, q := range pn.RSS {
			rssOf[i][q] = true
		}
		qs := map[int]bool{}
		for _, irq := range pn.NIC.IRQs {
			qs[irq.Queue] = true
		}
		for q := range qs {
			queuesOf[i] = append(queuesOf[i], q)
		}
		sort.Ints(queuesOf[i])
	}

	// Kept NICs occupy the CPUs their interrupts run on.
	for i, pn := range nics {
		if !pn.Keep {
			continue
		}
		for _, q := range queuesOf[i] {
			cpu := keptCPU(pn.NIC, q)
			if cpu < 0 {
				continue
			}
			pl.CPU[pn.NIC.Name][q], pl.Owner[pn.NIC.Name][q] = cpu, owner(cpu)
			p.occupy(cpu)
			if u := p.unitOf[cpu]; u != nil && rssOf[i][q] {
				u.rss++
			}
		}
	}

	// The order: RSS queues of all NICs interleaved, then the others.
	var order []pqueue
	for _, rss := range []bool{true, false} {
		lists := make([][]int, len(nics))
		longest := 0
		for i, pn := range nics {
			if pn.Keep {
				continue
			}
			has := map[int]bool{}
			for _, q := range queuesOf[i] {
				has[q] = true
			}
			if rss {
				for _, q := range pn.RSS {
					if has[q] {
						lists[i] = append(lists[i], q)
						delete(has, q)
					}
				}
			} else {
				for _, q := range queuesOf[i] {
					if !rssOf[i][q] {
						lists[i] = append(lists[i], q)
					}
				}
			}
			longest = max(longest, len(lists[i]))
		}
		for j := 0; j < longest; j++ {
			for i := range nics {
				if j < len(lists[i]) {
					order = append(order, pqueue{i, lists[i][j], rss})
				}
			}
		}
	}

	for _, pq := range order {
		nic := nics[pq.nic].NIC
		node := nic.Node
		cpu := -1
		if pq.rss {
			// A core without a queue first, wherever there is one: free
			// CPUs, then an instance's (by share, among those that have
			// one); only then a second thread of a core.
			if free != nil {
				cpu = p.pickFree(free, node, 0, 2)
			}
			if cpu < 0 {
				cpu = p.pickInstance(us, node, true)
			}
			if cpu < 0 && free != nil {
				cpu = p.pickFree(free, node, 1)
			}
			if cpu < 0 {
				cpu = p.pickInstance(us, node, false)
			}
		} else {
			var best *punit
			for _, u := range us {
				if p.pickIn(u, node, true) < 0 {
					continue
				}
				if best == nil || p.lowerShare(u, best, p.allOn(u), p.allOn(best), node) {
					best = u
				}
			}
			if best != nil {
				cpu = p.pickIn(best, node, true)
			} else {
				var bestKey []int
				for _, c := range eligible {
					k := []int{p.cpuQ[c], p.coreQ[p.coreKey(c)], p.dist(c, node), c}
					if cpu < 0 || lessKey(k, bestKey) {
						cpu, bestKey = c, k
					}
				}
			}
		}
		if cpu < 0 {
			continue // no eligible CPU at all
		}
		pl.CPU[nic.Name][pq.queue], pl.Owner[nic.Name][pq.queue] = cpu, owner(cpu)
		p.occupy(cpu)
		if u := p.unitOf[cpu]; u != nil && pq.rss {
			u.rss++
		}
	}

	for i, pn := range nics {
		name := pn.NIC.Name
		per := map[string][2]int{}
		for q, cpu := range pl.CPU[name] {
			u := p.unitOf[cpu]
			if u == nil {
				continue
			}
			c := per[u.name]
			if rssOf[i][q] {
				c[0]++
			}
			c[1]++
			per[u.name] = c
		}
		pl.Units[name] = per
		if pn.NIC.TCs || pn.NIC.TxQueues < 2 {
			continue
		}
		pl.XPS[name] = p.xps(pn.NIC, pl.CPU[name])
	}
	return pl
}

// keptCPU is the CPU a kept queue's interrupts run on: the effective CPU of
// its first interrupt, else the first CPU it may run on.
func keptCPU(n *NIC, q int) int {
	for _, irq := range n.IRQs {
		if irq.Queue != q {
			continue
		}
		if len(irq.Effective) > 0 {
			return irq.Effective[0]
		}
		if len(irq.Affinity) > 0 {
			return irq.Affinity[0]
		}
	}
	return -1
}

// xps maps every online CPU to the TX queues it sends on.
func (p *placer) xps(n *NIC, qcpu map[int]int) map[int]CPUSet {
	out := map[int]CPUSet{}
	for q := 0; q < n.TxQueues; q++ {
		out[q] = nil
	}
	var queues []int // TX queues with a known CPU
	for q, cpu := range qcpu {
		if q < n.TxQueues && cpu >= 0 {
			queues = append(queues, q)
		}
	}
	sort.Ints(queues)
	mapped := map[int]int{}
	assign := func(cpu, q int) {
		out[q] = append(out[q], cpu)
		mapped[q]++
	}
	done := map[int]bool{}
	cpus := p.t.Online

	if len(queues) == 0 {
		// No queue's CPU is known: contiguous groups of CPUs, by node and
		// core, one group per queue.
		var all []int
		for _, nd := range p.t.Nodes {
			all = append(all, p.t.NodeOrder(nd.ID)...)
		}
		for j, cpu := range all {
			assign(cpu, j*n.TxQueues/len(all))
		}
		for q := range out {
			out[q] = NewCPUSet(out[q]...)
		}
		return out
	}

	// Class 1: the queues served on the CPU itself (all of them).
	for _, c := range cpus {
		for _, q := range queues {
			if qcpu[q] == c {
				assign(c, q)
				done[c] = true
			}
		}
	}
	nodeOf := func(cpu int) int { return p.t.NodeOf(cpu) }
	classes := []func(c, cpu int) bool{
		func(c, cpu int) bool { return p.threads(c).Has(cpu) }, // its core
		func(c, cpu int) bool {
			u := p.unitOf[c]
			return u != nil && u.cpus.Has(cpu) && nodeOf(cpu) == nodeOf(c)
		}, // its unit on its node
		func(c, cpu int) bool { return nodeOf(cpu) == nodeOf(c) }, // its node
	}
	pickLeast := func(c int, match func(q int) bool) bool {
		best := -1
		for _, q := range queues {
			if match(q) && (best < 0 || mapped[q] < mapped[best]) {
				best = q
			}
		}
		if best < 0 {
			return false
		}
		assign(c, best)
		done[c] = true
		return true
	}
	for _, class := range classes {
		for _, c := range cpus {
			if done[c] {
				continue
			}
			pickLeast(c, func(q int) bool { return class(c, qcpu[q]) })
		}
	}
	// The nearest node with queues.
	for _, c := range cpus {
		if done[c] {
			continue
		}
		home := nodeOf(c)
		bestD := -1
		for _, q := range queues {
			d := 0
			if home >= 0 && nodeOf(qcpu[q]) >= 0 {
				d = p.t.Distance(home, nodeOf(qcpu[q]))
			}
			if bestD < 0 || d < bestD {
				bestD = d
			}
		}
		pickLeast(c, func(q int) bool {
			d := 0
			if home >= 0 && nodeOf(qcpu[q]) >= 0 {
				d = p.t.Distance(home, nodeOf(qcpu[q]))
			}
			return d == bestD
		})
	}
	for q := range out {
		out[q] = NewCPUSet(out[q]...)
	}
	return out
}
