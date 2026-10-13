package hw

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Core is one physical core: the threads that share its execution units.
type Core struct {
	ID      int // lowest online CPU of the core (the core's key; never core_id, which repeats across packages)
	Package int
	Node    int
	Threads CPUSet // online threads, ascending
}

// Node is a NUMA node.
type Node struct {
	ID       int
	CPUs     CPUSet      // online CPUs; empty for a memory-only (CPU-less) node
	MemBytes int64       // its memory
	Distance map[int]int // SLIT row: node -> distance; empty when unknown
}

// Topology is how the online CPUs group into cores, NUMA nodes and packages.
type Topology struct {
	Online   CPUSet
	Isolated CPUSet // cpu/isolated and cpu/nohz_full
	Cores    []Core // ordered by (Node, ID)
	Nodes    []Node // by ID, memory-only nodes included
	Packages []int
	MemBytes int64  // /proc/meminfo MemTotal
	Model    string // /proc/cpuinfo "model name"

	core map[int]int // cpu -> index in Cores
	node map[int]int // cpu -> node ID
}

const cpuDir = "/sys/devices/system/cpu"
const nodeDir = "/sys/devices/system/node"

// ReadTopology reads the topology from sysfs. It fails only when the online
// CPUs cannot be read.
func ReadTopology(fs FS) (*Topology, error) {
	online, err := ParseList(fs.ReadTrim(cpuDir + "/online"))
	if err != nil {
		return nil, err
	}
	if len(online) == 0 {
		return nil, errors.New("no online CPUs in " + cpuDir + "/online")
	}
	t := &Topology{Online: online}
	iso, _ := ParseList(fs.ReadTrim(cpuDir + "/isolated"))
	nohz, _ := ParseList(fs.ReadTrim(cpuDir + "/nohz_full"))
	t.Isolated = iso.Union(nohz).And(online)
	t.MemBytes = meminfoBytes(fs.ReadTrim("/proc/meminfo"), "MemTotal")
	t.Model = cpuModel(fs.ReadTrim("/proc/cpuinfo"))

	// Nodes first: a core takes the node of its lowest thread.
	nodeOf := map[int]int{}
	var ids []int
	for _, d := range fs.Glob(nodeDir + "/node[0-9]*") {
		id, err := strconv.Atoi(strings.TrimPrefix(d[strings.LastIndex(d, "/")+1:], "node"))
		if err == nil {
			ids = append(ids, id)
		}
	}
	sort.Ints(ids)
	for _, id := range ids {
		d := fmt.Sprintf("%s/node%d", nodeDir, id)
		cpus, _ := ParseList(fs.ReadTrim(d + "/cpulist"))
		n := Node{ID: id, CPUs: cpus.And(online), Distance: map[int]int{}}
		n.MemBytes = meminfoBytes(fs.ReadTrim(d+"/meminfo"), fmt.Sprintf("Node %d MemTotal", id))
		// The row lists the distances to the nodes in ID order.
		if row := strings.Fields(fs.ReadTrim(d + "/distance")); len(row) == len(ids) {
			for i, v := range row {
				if x, err := strconv.Atoi(v); err == nil {
					n.Distance[ids[i]] = x
				}
			}
		}
		for _, c := range n.CPUs {
			if _, ok := nodeOf[c]; !ok {
				nodeOf[c] = id
			}
		}
		t.Nodes = append(t.Nodes, n)
	}
	if len(t.Nodes) == 0 {
		t.Nodes = []Node{{ID: 0, CPUs: online, MemBytes: t.MemBytes, Distance: map[int]int{}}}
		for _, c := range online {
			nodeOf[c] = 0
		}
	}
	// Online CPUs no node lists go to the lowest node that has CPUs.
	var stray CPUSet
	for _, c := range online {
		if _, ok := nodeOf[c]; !ok {
			stray = append(stray, c)
		}
	}
	if len(stray) > 0 {
		i := lowestCPUNode(t.Nodes)
		t.Nodes[i].CPUs = t.Nodes[i].CPUs.Union(stray)
		for _, c := range stray {
			nodeOf[c] = t.Nodes[i].ID
		}
	}

	// Cores: keyed by their lowest online thread.
	seen := map[int]bool{}
	for _, c := range online {
		if seen[c] {
			continue
		}
		d := fmt.Sprintf("%s/cpu%d/topology", cpuDir, c)
		threads := CPUSet{c}
		if l, err := ParseList(fs.ReadTrim(d + "/core_cpus_list")); err == nil && len(l) > 0 {
			threads = l
		} else if l, err := ParseList(fs.ReadTrim(d + "/thread_siblings_list")); err == nil && len(l) > 0 {
			threads = l
		}
		threads = threads.And(online)
		if !threads.Has(c) {
			threads = threads.Union(CPUSet{c})
		}
		// A thread already counted elsewhere (inconsistent files) stays there.
		var own CPUSet
		for _, x := range threads {
			if !seen[x] {
				own = append(own, x)
				seen[x] = true
			}
		}
		pkg, err := strconv.Atoi(fs.ReadTrim(d + "/physical_package_id"))
		if err != nil || pkg < 0 {
			pkg = 0
		}
		t.Cores = append(t.Cores, Core{ID: own[0], Package: pkg, Node: nodeOf[own[0]], Threads: own})
	}
	t.index()
	return t, nil
}

func lowestCPUNode(nodes []Node) int {
	for i, n := range nodes {
		if len(n.CPUs) > 0 {
			return i
		}
	}
	return 0
}

// index sorts the cores and nodes and builds the CPU lookups.
func (t *Topology) index() {
	sort.Slice(t.Cores, func(i, j int) bool {
		if t.Cores[i].Node != t.Cores[j].Node {
			return t.Cores[i].Node < t.Cores[j].Node
		}
		return t.Cores[i].ID < t.Cores[j].ID
	})
	sort.Slice(t.Nodes, func(i, j int) bool { return t.Nodes[i].ID < t.Nodes[j].ID })
	t.core = map[int]int{}
	t.node = map[int]int{}
	pkgs := map[int]bool{}
	for i, c := range t.Cores {
		for _, x := range c.Threads {
			t.core[x] = i
			t.node[x] = c.Node
		}
		pkgs[c.Package] = true
	}
	t.Packages = t.Packages[:0]
	for p := range pkgs {
		t.Packages = append(t.Packages, p)
	}
	sort.Ints(t.Packages)
}

// Flat is a machine of one node and one package, each CPU a core of its own:
// how x-ui split CPUs before it knew the topology.
func Flat(cpus []int) *Topology {
	set := NewCPUSet(cpus...)
	t := &Topology{Online: set, Nodes: []Node{{ID: 0, CPUs: set, Distance: map[int]int{}}}}
	for _, c := range set {
		t.Cores = append(t.Cores, Core{ID: c, Package: 0, Node: 0, Threads: CPUSet{c}})
	}
	t.index()
	return t
}

// Restrict is the topology of only these CPUs. A core keeps the threads that
// remain (its ID becomes the lowest of them); CPUs t does not know become
// single-thread cores on its lowest node with CPUs. Nodes keep their memory
// and distances, whether CPUs remain on them or not.
func (t *Topology) Restrict(cpus []int) *Topology {
	set := NewCPUSet(cpus...)
	r := &Topology{Online: set, Isolated: t.Isolated.And(set), MemBytes: t.MemBytes, Model: t.Model}
	for _, n := range t.Nodes {
		r.Nodes = append(r.Nodes, Node{ID: n.ID, CPUs: n.CPUs.And(set), MemBytes: n.MemBytes, Distance: n.Distance})
	}
	for _, c := range t.Cores {
		if th := c.Threads.And(set); len(th) > 0 {
			r.Cores = append(r.Cores, Core{ID: th[0], Package: c.Package, Node: c.Node, Threads: th})
		}
	}
	var unknown CPUSet
	for _, c := range set {
		if t.CoreOf(c) == nil {
			unknown = append(unknown, c)
		}
	}
	if len(unknown) > 0 {
		if len(r.Nodes) == 0 {
			r.Nodes = []Node{{ID: 0, Distance: map[int]int{}}}
		}
		i := lowestCPUNode(t.Nodes)
		if i >= len(r.Nodes) {
			i = 0
		}
		node := r.Nodes[i].ID
		pkg := t.PackageOfNode(node)
		if pkg < 0 {
			pkg = 0
		}
		r.Nodes[i].CPUs = r.Nodes[i].CPUs.Union(unknown)
		for _, c := range unknown {
			r.Cores = append(r.Cores, Core{ID: c, Package: pkg, Node: node, Threads: CPUSet{c}})
		}
	}
	r.index()
	return r
}

// indexed builds the lookups of a Topology made by hand (ReadTopology, Flat
// and Restrict build them).
func (t *Topology) indexed() {
	if t.core == nil {
		t.index()
	}
}

// CoreOf is the core a CPU belongs to, nil when the CPU is unknown.
func (t *Topology) CoreOf(cpu int) *Core {
	t.indexed()
	i, ok := t.core[cpu]
	if !ok {
		return nil
	}
	return &t.Cores[i]
}

// NodeOf is the NUMA node of a CPU, -1 when unknown.
func (t *Topology) NodeOf(cpu int) int {
	t.indexed()
	if n, ok := t.node[cpu]; ok {
		return n
	}
	return -1
}

// PackageOf is the package (socket) of a CPU, -1 when unknown.
func (t *Topology) PackageOf(cpu int) int {
	if c := t.CoreOf(cpu); c != nil {
		return c.Package
	}
	return -1
}

// PackageOfNode is the package a node's CPUs are in, -1 when it has none.
func (t *Topology) PackageOfNode(node int) int {
	for _, c := range t.Cores {
		if c.Node == node {
			return c.Package
		}
	}
	return -1
}

// Siblings are the threads of a CPU's core, the CPU included.
func (t *Topology) Siblings(cpu int) CPUSet {
	if c := t.CoreOf(cpu); c != nil {
		return slices.Clone(c.Threads)
	}
	return CPUSet{cpu}
}

// NodeOrder lists a node's CPUs core-major: the cores by ID, each core's
// threads together and ascending.
func (t *Topology) NodeOrder(node int) []int {
	t.indexed()
	var out []int
	for _, c := range t.Cores {
		if c.Node == node {
			out = append(out, c.Threads...)
		}
	}
	return out
}

// NodesOf lists the nodes the known CPUs are on, ascending.
func (t *Topology) NodesOf(cpus []int) []int {
	var out []int
	for _, c := range cpus {
		if n := t.NodeOf(c); n >= 0 {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// CoresIn counts the cores whose threads are all among cpus (whole) and
// those only some of whose threads are (partial).
func (t *Topology) CoresIn(cpus []int) (whole, partial int) {
	set := NewCPUSet(cpus...)
	for _, c := range t.Cores {
		in := len(c.Threads.And(set))
		switch {
		case in == 0:
		case in == len(c.Threads):
			whole++
		default:
			partial++
		}
	}
	return whole, partial
}

// PhysicalCores counts the distinct cores the CPUs touch; an unknown CPU
// counts as a core of its own.
func (t *Topology) PhysicalCores(cpus CPUSet) int {
	seen := map[int]bool{}
	n := 0
	for _, c := range cpus {
		key := -1 - c
		if core := t.CoreOf(c); core != nil {
			key = core.ID
		}
		if !seen[key] {
			seen[key] = true
			n++
		}
	}
	return n
}

// ThreadsPerCore is the most threads any core has (at least 1).
func (t *Topology) ThreadsPerCore() int {
	n := 1
	for _, c := range t.Cores {
		n = max(n, len(c.Threads))
	}
	return n
}

// Distance is the SLIT distance between two nodes: 10 on the same node, 20
// when unknown.
func (t *Topology) Distance(a, b int) int {
	if a == b {
		return 10
	}
	for _, n := range t.Nodes {
		if n.ID == a {
			if d, ok := n.Distance[b]; ok && d > 0 {
				return d
			}
			break
		}
	}
	return 20
}

// Sockets is the number of packages.
func (t *Topology) Sockets() int {
	t.indexed()
	return len(t.Packages)
}

// meminfoBytes reads "Key: N kB" from a meminfo-style file, in bytes.
func meminfoBytes(s, key string) int64 {
	for _, l := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok || strings.TrimSpace(k) != key {
			continue
		}
		fs := strings.Fields(v)
		if len(fs) == 0 {
			return 0
		}
		n, _ := strconv.ParseInt(fs[0], 10, 64)
		if len(fs) > 1 && fs[1] == "kB" {
			n *= 1024
		}
		return n
	}
	return 0
}

func cpuModel(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if k, v, ok := strings.Cut(l, ":"); ok && strings.TrimSpace(k) == "model name" {
			return strings.Join(strings.Fields(v), " ")
		}
	}
	return ""
}
