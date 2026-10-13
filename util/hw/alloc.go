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
// Each instance takes a run of one NUMA node's CPUs in core-major order, so
// it gets whole cores (both threads of a core go to the same instance) and
// its memory, cache and threads stay on one node. Instances with a fixed
// number go first, in name order, each to the node with the least free CPUs
// that still holds it, so the large free runs stay whole for later requests;
// the node of the uplink NIC (prefer, -1 for none) comes first among equals.
// When no node holds one it takes a package, and only when no package does
// it spans packages. The auto instances then split the rest as evenly as
// before (sizes differ by one at most), one node each when that keeps the
// split even, else one package each, else in one contiguous cut.
//
// Like the old split, a fixed instance with nothing left runs on all cpus
// (unpinned), and when there are more auto instances than CPUs they share
// them one CPU each, round-robin. On a machine of one node and one thread
// per core (t nil means that machine) the result is exactly the old one.
// Every list is sorted ascending.
func SplitCPUs(t *Topology, cpus []int, prefer int, reqs []CPURequest, less func(a, b string) bool) map[string][]int {
	out, _ := split(t, cpus, prefer, reqs, less)
	return out
}

// How the auto instances were split (split's second result).
const (
	splitNoAutos = ""
	splitShared  = "shared"  // more autos than CPUs: one CPU each, round-robin
	splitByNode  = "node"    // each auto on one node
	splitByPkg   = "package" // each auto in one package
	splitContig  = "cut"     // one contiguous cut over the nodes
)

// pool is one node's free CPUs, in core-major order; CPUs are handed out
// from the front.
type pool struct {
	node, pkg int
	free      []int
}

func (p *pool) take(n int) []int {
	out := slices.Clone(p.free[:n])
	p.free = p.free[n:]
	return out
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
		if got := takeFixed(pools, r.CPUs); got != nil {
			out[r.Name] = got
		} else {
			// More CPUs were promised than this machine has (it lost
			// CPUs since): run unpinned rather than not at all.
			out[r.Name] = slices.Clone([]int(all))
		}
	}
	how := splitNoAutos
	if len(autos) > 0 {
		if freeCount(pools) == 0 {
			// The fixed instances took everything: the autos share all
			// the CPUs, as before.
			pools = nodePools(t, prefer)
		}
		how = splitAutos(pools, autos, out)
	}
	for _, l := range out {
		slices.Sort(l)
	}
	return out, how
}

// nodePools lists the nodes that have CPUs, prefer first, then by ID.
// Memory-only nodes have no cores, so they never appear.
func nodePools(t *Topology, prefer int) []*pool {
	var ids []int
	for _, c := range t.Cores {
		if len(ids) == 0 || ids[len(ids)-1] != c.Node {
			ids = append(ids, c.Node) // Cores are ordered by node
		}
	}
	if i := slices.Index(ids, prefer); i > 0 {
		ids = append(append([]int{prefer}, ids[:i]...), ids[i+1:]...)
	}
	out := make([]*pool, 0, len(ids))
	for _, id := range ids {
		pkg := t.PackageOfNode(id)
		out = append(out, &pool{node: id, pkg: pkg, free: t.NodeOrder(id)})
	}
	return out
}

func freeCount(pools []*pool) int {
	n := 0
	for _, p := range pools {
		n += len(p.free)
	}
	return n
}

// takeFixed takes k CPUs (or what is left, when less) for a fixed instance;
// nil when nothing is left.
func takeFixed(pools []*pool, k int) []int {
	free := freeCount(pools)
	if free == 0 {
		return nil
	}
	k = min(k, free)
	// Best fit on a node: the tightest node that holds it leaves the
	// roomier ones whole for the instances after it.
	var best *pool
	for _, p := range pools {
		if len(p.free) >= k && (best == nil || len(p.free) < len(best.free)) {
			best = p
		}
	}
	if best != nil {
		return best.take(k)
	}
	// Too big for any node: the tightest package that holds it, so it
	// crosses nodes but not sockets.
	var bestPkg []*pool
	bestFree := 0
	for _, g := range packagePools(pools) {
		if f := freeCount(g); f >= k && (bestPkg == nil || f < bestFree) {
			bestPkg, bestFree = g, f
		}
	}
	if bestPkg != nil {
		return takeMostFree(bestPkg, k)
	}
	return takeMostFree(pools, k)
}

// packagePools groups the pools by package, packages in the order of their
// first node, each package's nodes in node order.
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

// takeMostFree takes k CPUs from the pools with the most free CPUs first
// (ties in pool order), so the instance spans as few nodes as it can.
func takeMostFree(pools []*pool, k int) []int {
	order := slices.Clone(pools)
	sort.SliceStable(order, func(i, j int) bool { return len(order[i].free) > len(order[j].free) })
	var out []int
	for _, p := range order {
		if k == 0 {
			break
		}
		n := min(k, len(p.free))
		out = append(out, p.take(n)...)
		k -= n
	}
	return out
}

// splitAutos shares the free CPUs among the auto instances (in name order)
// and says how.
func splitAutos(pools []*pool, autos []string, out map[string][]int) string {
	a, r := len(autos), freeCount(pools)
	if a > r {
		flat := concatFree(pools)
		for i, name := range autos {
			out[name] = []int{flat[i%len(flat)]}
		}
		return splitShared
	}
	lo, hi := r/a, (r+a-1)/a

	// One node per instance, else one package per instance: accepted only
	// when it keeps every size within lo..hi, as even as one cut would be.
	var byNode, byPkg [][]int
	for _, p := range pools {
		if len(p.free) > 0 {
			byNode = append(byNode, p.free)
		}
	}
	for _, g := range packagePools(pools) {
		if l := concatFree(g); len(l) > 0 {
			byPkg = append(byPkg, l)
		}
	}
	for _, level := range []struct {
		how    string
		groups [][]int
	}{{splitByNode, byNode}, {splitByPkg, byPkg}} {
		seats, ok := apportion(level.groups, a, lo, hi)
		if !ok {
			continue
		}
		i := 0
		for g, list := range level.groups {
			c, f := seats[g], len(list)
			at := 0
			for j := 0; j < c; j++ {
				n := f / c
				if j < f%c {
					n++
				}
				out[autos[i]] = slices.Clone(list[at : at+n])
				at += n
				i++
			}
		}
		return level.how
	}

	// The old split: one cut over the nodes in order; only the instances
	// at a node's boundary straddle it.
	flat := concatFree(pools)
	at := 0
	for i, name := range autos {
		n := lo
		if i < r%a {
			n = hi
		}
		out[name] = slices.Clone(flat[at : at+n])
		at += n
	}
	return splitContig
}

func concatFree(pools []*pool) []int {
	var out []int
	for _, p := range pools {
		out = append(out, p.free...)
	}
	return out
}

// apportion shares n instances among the groups by their sizes, largest
// remainder first (ties to the earlier group). ok says every group got at
// least one and every instance's size, the group's CPUs split as evenly as
// they go, stays within lo..hi.
func apportion(groups [][]int, n, lo, hi int) (seats []int, ok bool) {
	total := 0
	for _, g := range groups {
		total += len(g)
	}
	if total == 0 {
		return nil, false
	}
	seats = make([]int, len(groups))
	rem := make([]int, len(groups))
	left := n
	for i, g := range groups {
		seats[i] = n * len(g) / total
		rem[i] = n * len(g) % total
		left -= seats[i]
	}
	order := make([]int, len(groups))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(x, y int) bool { return rem[order[x]] > rem[order[y]] })
	for _, i := range order[:left] {
		seats[i]++
	}
	for i, g := range groups {
		c, f := seats[i], len(g)
		if c < 1 || f/c < lo || (f+c-1)/c > hi {
			return seats, false
		}
	}
	return seats, true
}
