package hw

import (
	"slices"
	"sort"
)

// CPURequest is what an xray instance asks for: a fixed number of logical
// CPUs, or 0 for an even share of what the fixed instances leave.
type CPURequest struct {
	Name string
	CPUs int // 0 = auto
}

// SplitCPUs gives every instance its CPUs out of cpus.
//
// The CPUs are split in pools: one per NUMA node (and per package within a
// node, for machines with NUMA off), the package of the uplink NIC's node
// (prefer, -1 for none) first with that node first in it, then the other
// packages. Instances with a fixed number go first, in name order, each to
// the pool with the least free CPUs that still holds it, so the large free
// runs stay whole for later requests; when no pool holds one it takes a
// package, and only when no package does it spans packages. The auto
// instances then split the rest as evenly as before (sizes differ by one at
// most), one pool each when that keeps the split even, else one package
// each, else in one contiguous cut over the pools in order.
//
// Inside a pool every instance takes whole cores first (both threads of a
// core to the same instance), in core order. What is left of it (an odd
// count on two threads per core) takes a thread of a free core while enough
// free cores remain for the instances after it, else the free thread of a
// core another instance took half of: two instances share a core only when
// the pool cannot give each its own.
//
// Like the old split, a fixed instance with nothing left runs on all cpus
// (unpinned), and when there are more auto instances than CPUs they share
// them one CPU each, round-robin. On a machine of one node, one package and
// one thread per core (t nil means that machine) the result is exactly the
// old one. Every list is sorted ascending.
func SplitCPUs(t *Topology, cpus []int, prefer int, reqs []CPURequest, less func(a, b string) bool) map[string][]int {
	out, _ := split(t, cpus, prefer, reqs, less)
	return out
}

// How the auto instances were split (split's second result).
const (
	splitNoAutos = ""
	splitShared  = "shared"  // more autos than CPUs: one CPU each, round-robin
	splitByNode  = "node"    // each auto in one pool (a node)
	splitByPkg   = "package" // each auto in one package
	splitContig  = "cut"     // one contiguous cut over the pools
)

// pool is the CPUs of one node (one package of it, with NUMA off). The
// instances are promised counts first (asks); layout then picks the CPUs.
type pool struct {
	node, pkg int
	cores     []CPUSet // the cores' threads, cores in ID order
	left      int      // CPUs not promised yet
	asks      []ask    // what the instances take from it, in order
}

type ask struct {
	name string
	n    int
}

func (p *pool) give(name string, n int) {
	if n > 0 {
		p.asks = append(p.asks, ask{name, n})
		p.left -= n
	}
}

func split(t *Topology, cpus []int, prefer int, reqs []CPURequest, less func(a, b string) bool) (map[string][]int, string) {
	out := map[string][]int{}
	all := NewCPUSet(cpus...)
	if len(all) == 0 {
		return out, splitNoAutos
	}
	if t == nil {
		t = Flat(all)
	}
	t = t.Restrict(all)
	if less == nil {
		less = func(a, b string) bool { return a < b }
	}
	sorted := slices.Clone(reqs)
	sort.SliceStable(sorted, func(i, j int) bool { return less(sorted[i].Name, sorted[j].Name) })

	pools := nodePools(t, prefer)
	var autos []string
	for _, r := range sorted {
		if r.CPUs <= 0 {
			autos = append(autos, r.Name)
			continue
		}
		if !takeFixed(pools, r.Name, r.CPUs) {
			// More CPUs were promised than this machine has (it lost
			// CPUs since): run unpinned rather than not at all.
			out[r.Name] = slices.Clone([]int(all))
		}
	}
	how := splitNoAutos
	apools := pools
	if len(autos) > 0 && leftCount(pools) == 0 {
		// The fixed instances took everything: the autos share all the
		// CPUs, as before.
		layout(pools, out)
		apools = nodePools(t, prefer)
	}
	switch {
	case len(autos) == 0:
	case len(autos) > leftCount(apools):
		layout(apools, out)
		var flat []int
		for _, p := range apools {
			for _, c := range p.cores {
				flat = append(flat, c...)
			}
		}
		flat = NewCPUSet(flat...).Minus(given(apools, out))
		for i, name := range autos {
			out[name] = []int{flat[i%len(flat)]}
		}
		how = splitShared
	default:
		how = splitAutos(apools, autos)
	}
	if how != splitShared {
		layout(apools, out)
	}
	for _, l := range out {
		slices.Sort(l)
	}
	return out, how
}

// given is the CPUs the pools' layout handed out.
func given(pools []*pool, out map[string][]int) CPUSet {
	var mine CPUSet
	for _, p := range pools {
		for _, c := range p.cores {
			mine = mine.Union(c)
		}
	}
	var used []int
	for _, p := range pools {
		for _, a := range p.asks {
			used = append(used, out[a.name]...)
		}
	}
	return NewCPUSet(used...).And(mine)
}

// nodePools makes a pool of every node that has CPUs, split by package
// where a node spans packages (NUMA off on a multi-socket machine; the
// cores of each package then stay together). Memory-only nodes have no
// cores, so they never appear. Order: the package of the prefer node first
// (that node first in it, its other nodes by ID), then the other packages
// by ID, each package's nodes by ID: a cut over the pools in order crosses
// from one package to the next only once.
func nodePools(t *Topology, prefer int) []*pool {
	type key struct{ node, pkg int }
	byKey := map[key]*pool{}
	var keys []key
	for _, c := range t.Cores {
		k := key{c.Node, c.Package}
		p := byKey[k]
		if p == nil {
			p = &pool{node: c.Node, pkg: c.Package}
			byKey[k] = p
			keys = append(keys, k)
		}
		p.cores = append(p.cores, c.Threads) // Cores are ordered by node, then ID
		p.left += len(c.Threads)
	}
	prefPkg := -1
	if prefer >= 0 {
		prefPkg = t.PackageOfNode(prefer)
	}
	sort.SliceStable(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.pkg != b.pkg {
			if (a.pkg == prefPkg) != (b.pkg == prefPkg) {
				return a.pkg == prefPkg
			}
			return a.pkg < b.pkg
		}
		if (a.node == prefer) != (b.node == prefer) {
			return a.node == prefer
		}
		return a.node < b.node
	})
	out := make([]*pool, 0, len(keys))
	for _, k := range keys {
		out = append(out, byKey[k])
	}
	return out
}

func leftCount(pools []*pool) int {
	n := 0
	for _, p := range pools {
		n += p.left
	}
	return n
}

// takeFixed promises k CPUs (or what is left, when less) to a fixed
// instance; false when nothing is left.
func takeFixed(pools []*pool, name string, k int) bool {
	free := leftCount(pools)
	if free == 0 {
		return false
	}
	k = min(k, free)
	// Best fit on a pool: the tightest one that holds it leaves the roomier
	// ones whole for the instances after it.
	var best *pool
	for _, p := range pools {
		if p.left >= k && (best == nil || p.left < best.left) {
			best = p
		}
	}
	if best != nil {
		best.give(name, k)
		return true
	}
	// Too big for any pool: the tightest package that holds it, so it
	// crosses nodes but not sockets.
	var bestPkg []*pool
	bestFree := 0
	for _, g := range packagePools(pools) {
		if f := leftCount(g); f >= k && (bestPkg == nil || f < bestFree) {
			bestPkg, bestFree = g, f
		}
	}
	if bestPkg != nil {
		giveMostFree(bestPkg, name, k)
		return true
	}
	giveMostFree(pools, name, k)
	return true
}

// packagePools groups the pools by package, packages in the order of their
// first pool, each package's pools in pool order.
func packagePools(pools []*pool) [][]*pool {
	var out [][]*pool
	at := map[int]int{}
	for _, p := range pools {
		i, ok := at[p.pkg]
		if !ok {
			i = len(out)
			at[p.pkg] = i
			out = append(out, nil)
		}
		out[i] = append(out[i], p)
	}
	return out
}

// giveMostFree promises k CPUs from the pools with the most free CPUs first
// (ties in pool order), so the instance spans as few nodes as it can.
func giveMostFree(pools []*pool, name string, k int) {
	order := slices.Clone(pools)
	sort.SliceStable(order, func(i, j int) bool { return order[i].left > order[j].left })
	for _, p := range order {
		if k == 0 {
			break
		}
		n := min(k, p.left)
		p.give(name, n)
		k -= n
	}
}

// giveRun promises the next n free CPUs of the pools, in pool order.
func giveRun(pools []*pool, name string, n int) {
	for _, p := range pools {
		if n == 0 {
			break
		}
		k := min(n, p.left)
		p.give(name, k)
		n -= k
	}
}

// splitAutos shares the free CPUs among the auto instances (in name order,
// fewer of them than free CPUs) and says how.
func splitAutos(pools []*pool, autos []string) string {
	a, r := len(autos), leftCount(pools)
	lo, hi := r/a, (r+a-1)/a

	// One pool per instance, else one package per instance: accepted only
	// when it keeps every size within lo..hi, as even as one cut would be.
	var byNode, byPkg [][]*pool
	for _, p := range pools {
		if p.left > 0 {
			byNode = append(byNode, []*pool{p})
		}
	}
	for _, g := range packagePools(pools) {
		if leftCount(g) > 0 {
			byPkg = append(byPkg, g)
		}
	}
	for _, level := range []struct {
		how    string
		groups [][]*pool
	}{{splitByNode, byNode}, {splitByPkg, byPkg}} {
		sizes := make([]int, len(level.groups))
		for g, list := range level.groups {
			sizes[g] = leftCount(list)
		}
		seats, ok := apportion(sizes, a, lo, hi)
		if !ok {
			continue
		}
		i := 0
		for g, list := range level.groups {
			c, f := seats[g], sizes[g]
			for j := 0; j < c; j++ {
				n := f / c
				if j < f%c {
					n++
				}
				giveRun(list, autos[i], n)
				i++
			}
		}
		return level.how
	}

	// The old split: one cut over the pools in order; only the instances
	// at a pool's boundary straddle it.
	for i, name := range autos {
		n := lo
		if i < r%a {
			n = hi
		}
		giveRun(pools, name, n)
	}
	return splitContig
}

// apportion shares n instances among groups of these sizes, largest
// remainder first (ties to the earlier group). ok says every group got at
// least one and every instance's size, the group's CPUs split as evenly as
// they go, stays within lo..hi.
func apportion(sizes []int, n, lo, hi int) (seats []int, ok bool) {
	total := 0
	for _, s := range sizes {
		total += s
	}
	if total == 0 {
		return nil, false
	}
	seats = make([]int, len(sizes))
	rem := make([]int, len(sizes))
	left := n
	for i, s := range sizes {
		seats[i] = n * s / total
		rem[i] = n * s % total
		left -= seats[i]
	}
	order := make([]int, len(sizes))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(x, y int) bool { return rem[order[x]] > rem[order[y]] })
	for _, i := range order[:left] {
		seats[i]++
	}
	for i, f := range sizes {
		c := seats[i]
		if c < 1 || f/c < lo || (f+c-1)/c > hi {
			return seats, false
		}
	}
	return seats, true
}

// layout picks the CPUs of every pool's asks.
func layout(pools []*pool, out map[string][]int) {
	for _, p := range pools {
		p.layout(out)
	}
}

// layout hands the pool's CPUs to its asks, in order. Each takes the free
// cores that it fills whole, in core order. The rest of it, fewer CPUs than
// a core has threads, takes a free core of its own while that leaves a core
// for every core's worth the asks after it need; else it takes the free
// threads of a core taken in part (the one it fills best), so two instances
// share a core only where the pool is too small for each to have its own.
func (p *pool) layout(out map[string][]int) {
	tpc := 1
	for _, c := range p.cores {
		tpc = max(tpc, len(c))
	}
	free := make([]CPUSet, len(p.cores))
	for i, c := range p.cores {
		free[i] = slices.Clone(c)
	}
	fresh := func(i int) bool { return len(free[i]) > 0 && len(free[i]) == len(p.cores[i]) }
	for ai, a := range p.asks {
		need := a.n
		var got []int
		take := func(i, n int) {
			got = append(got, free[i][:n]...)
			free[i] = free[i][n:]
			need -= n
		}
		for i := range p.cores {
			if need > 0 && fresh(i) && len(free[i]) <= need {
				take(i, len(free[i]))
			}
		}
		if need > 0 {
			future := 0
			for _, b := range p.asks[ai+1:] {
				future += (b.n + tpc - 1) / tpc
			}
			nFresh, first := 0, -1
			for i := range p.cores {
				if fresh(i) {
					nFresh++
					if first < 0 {
						first = i
					}
				}
			}
			if nFresh > future {
				take(first, need)
			}
		}
		for need > 0 {
			best := -1
			for i := range p.cores {
				if fresh(i) || len(free[i]) == 0 {
					continue
				}
				// The core it fills exactly or best, else the one with the
				// most free threads.
				if best < 0 || betterFit(len(free[i]), len(free[best]), need) {
					best = i
				}
			}
			if best < 0 {
				break
			}
			take(best, min(need, len(free[best])))
		}
		for i := range p.cores {
			if need > 0 && len(free[i]) > 0 {
				take(i, min(need, len(free[i])))
			}
		}
		out[a.name] = append(out[a.name], got...)
	}
}

// betterFit says whether a core with a free threads suits an ask of need
// better than one with b: one that holds it, the fewest threads left over;
// else the most threads.
func betterFit(a, b, need int) bool {
	switch {
	case a >= need && b >= need:
		return a < b
	case a >= need || b >= need:
		return a >= need
	}
	return a > b
}
