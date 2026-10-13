// Package hwtest builds fake /sys, /proc and /etc trees of whole machines,
// and a fake ethtool tied to them, for the tests of util/hw, util/tune and
// util/diag. It is imported by tests only.
package hwtest

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/util/hw"
)

// Machine describes a fake server. Zero values take sensible defaults (one
// package of one single-thread core, linear numbering, one node, 1 GiB).
type Machine struct {
	Packages        int
	CoresPerPackage int
	ThreadsPerCore  int
	NodesPerPackage int // NUMA nodes per package (AMD NPS); a package's cores split into equal contiguous groups
	// Numbering of global core g's threads:
	//   "linear"      package g/C, CPU g + thread*P*C (siblings n and n+P*C)
	//   "interleaved" package g%P, CPU g + thread*P*C (Intel two-socket: node 0 even, node 1 odd)
	//   "adjacent"    package g/C, CPU g*T + thread (siblings 2k and 2k+1)
	Numbering    string
	Offline      []int
	Isolated     []int
	NohzFull     []int
	MemGiB       int     // RAM of the nodes with CPUs, split evenly
	MemOnlyNodes []int   // GiB of each memory-only node; their IDs follow the others
	NoNUMA       bool    // no /sys/devices/system/node at all
	SLIT         [][]int // node distances; nil: 10 same node, 12 same package, 21 otherwise
	Model        string
	Kernel       string
	Virt         string // "" bare metal, a VM ("kvm", "vmware", ...) or a container ("docker", "lxc", ...)
	Init         string // "systemd" (default), "openrc" or "none"

	NICs    []NICSpec
	Bonds   []BondSpec
	Bridges []BridgeSpec
	VLANs   []VLANSpec
	Links   []LinkSpec // other devices without hardware: tunnels, veth
	Routes  []RouteSpec
	// IRQBalance: "" not installed, "installed" (unit and defaults file, not
	// running), "running", "running-ours" (with x-ui's policy script).
	IRQBalance         string
	DefaultSMPAffinity []int // nil: all CPUs
	Allowed            []int // Built.Allowed; nil: the online CPUs
}

// Built is a machine's tree.
type Built struct {
	Root string
	Eth  *FakeEthtool
	// FailWrite lists kernel files whose writes fail (tune.Env.FailWrite):
	// the affinity files of kernel-managed interrupts (EIO).
	FailWrite map[string]error
	Allowed   hw.CPUSet
	M         Machine // with the defaults filled in

	t       testing.TB
	nodeOf  map[int]int   // CPU -> node
	spread  map[int][]int // node -> cpumask_local_spread order
	cpus    int           // nr_cpu_ids
	online  hw.CPUSet
	cores   []fcore
	nodes   []fnode
	times   map[int]*[10]uint64 // /proc/stat fields per CPU
	softnet map[int]*[3]uint64  // processed, dropped, time_squeeze
	irqs    map[int]*fakeIRQ
	nextIRQ int
	nics    map[string]*fakeNIC
	ifindex int
}

type fcore struct {
	g, pkg, idx, node int
	cpus              []int // all threads, offline ones included
}

type fnode struct {
	id   int
	pkg  int // -1 for memory-only
	cpus hw.CPUSet
	kb   int64
}

// FS is the tree as an hw.FS.
func (b *Built) FS() hw.FS { return hw.FS{Root: b.Root} }

// Path maps a system path into the tree.
func (b *Built) Path(abs string) string { return filepath.Join(b.Root, abs) }

// WriteFile writes a file into the tree, creating its directory.
func (b *Built) WriteFile(abs, data string) {
	b.t.Helper()
	p := b.Path(abs)
	err := os.WriteFile(p, []byte(data), 0o644)
	if os.IsNotExist(err) {
		if err = os.MkdirAll(filepath.Dir(p), 0o755); err == nil {
			err = os.WriteFile(p, []byte(data), 0o644)
		}
	}
	if err != nil {
		b.t.Fatal(err)
	}
}

// ReadFile reads a file of the tree ("" when missing).
func (b *Built) ReadFile(abs string) string {
	data, _ := os.ReadFile(b.Path(abs))
	return string(data)
}

func (b *Built) mkdir(abs string) {
	b.t.Helper()
	if err := os.MkdirAll(b.Path(abs), 0o755); err != nil {
		b.t.Fatal(err)
	}
}

// symlink makes a relative link at abs pointing to the system path target,
// as sysfs does: a relative link resolves inside the tree, whatever reads it.
func (b *Built) symlink(target, abs string) {
	b.t.Helper()
	b.mkdir(filepath.Dir(abs))
	rel, err := filepath.Rel(filepath.Dir(abs), target)
	if err != nil {
		b.t.Fatal(err)
	}
	_ = os.Remove(b.Path(abs))
	if err := os.Symlink(rel, b.Path(abs)); err != nil {
		b.t.Fatal(err)
	}
}

func (m *Machine) defaults() {
	if m.Packages < 1 {
		m.Packages = 1
	}
	if m.CoresPerPackage < 1 {
		m.CoresPerPackage = 1
	}
	if m.ThreadsPerCore < 1 {
		m.ThreadsPerCore = 1
	}
	if m.NodesPerPackage < 1 || m.CoresPerPackage%m.NodesPerPackage != 0 {
		m.NodesPerPackage = 1
	}
	if m.Numbering == "" {
		m.Numbering = "linear"
	}
	if m.MemGiB < 1 {
		m.MemGiB = 1
	}
	if m.Model == "" {
		m.Model = "Fake CPU"
	}
	if m.Kernel == "" {
		m.Kernel = "6.8.0-1-amd64"
	}
	if m.Init == "" {
		m.Init = "systemd"
	}
}

// IsContainer says whether Virt names a container.
func (m Machine) IsContainer() bool {
	switch m.Virt {
	case "", "none", "kvm", "qemu", "vmware", "xen", "microsoft", "oracle", "amazon", "bochs", "parallels":
		return false
	}
	return true
}

// layout numbers every core and its threads.
func (m Machine) layout() []fcore {
	P, C, T := m.Packages, m.CoresPerPackage, m.ThreadsPerCore
	per := C / m.NodesPerPackage
	var out []fcore
	for g := 0; g < P*C; g++ {
		c := fcore{g: g}
		switch m.Numbering {
		case "interleaved":
			c.pkg, c.idx = g%P, g/P
		default:
			c.pkg, c.idx = g/C, g%C
		}
		c.node = c.pkg*m.NodesPerPackage + c.idx/per
		for t := 0; t < T; t++ {
			if m.Numbering == "adjacent" {
				c.cpus = append(c.cpus, g*T+t)
			} else {
				c.cpus = append(c.cpus, g+t*P*C)
			}
		}
		out = append(out, c)
	}
	return out
}

// Build writes the machine's tree into a temporary directory.
func (m Machine) Build(t testing.TB) *Built {
	t.Helper()
	m.defaults()
	b := &Built{Root: t.TempDir(), M: m, t: t, FailWrite: map[string]error{}, times: map[int]*[10]uint64{},
		softnet: map[int]*[3]uint64{}, irqs: map[int]*fakeIRQ{}, nics: map[string]*fakeNIC{}, nextIRQ: 100, ifindex: 1}
	b.Eth = &FakeEthtool{Devs: map[string]*FakeDev{}, Fail: map[string]error{}, b: b}
	b.cores = m.layout()
	b.cpus = m.Packages * m.CoresPerPackage * m.ThreadsPerCore
	var all []int
	for i := 0; i < b.cpus; i++ {
		all = append(all, i)
	}
	b.online = hw.NewCPUSet(all...).Minus(hw.NewCPUSet(m.Offline...))
	b.Allowed = b.online
	if m.Allowed != nil {
		b.Allowed = hw.NewCPUSet(m.Allowed...)
	}
	b.writeCPUs()
	b.writeNodes()
	b.writeProc()
	b.writeNet()
	b.writeIRQBalance()
	return b
}

// Topo builds the machine and reads its topology.
func Topo(t testing.TB, m Machine) *hw.Topology {
	t.Helper()
	b := m.Build(t)
	topo, err := hw.ReadTopology(b.FS())
	if err != nil {
		t.Fatal(err)
	}
	return topo
}

func (b *Built) writeCPUs() {
	m := b.M
	d := "/sys/devices/system/cpu"
	all := hw.NewCPUSet()
	for i := 0; i < b.cpus; i++ {
		all = append(all, i)
	}
	b.WriteFile(d+"/possible", all.List()+"\n")
	b.WriteFile(d+"/present", all.List()+"\n")
	b.WriteFile(d+"/online", b.online.List()+"\n")
	b.WriteFile(d+"/offline", all.Minus(b.online).List()+"\n")
	b.WriteFile(d+"/kernel_max", "8191\n")
	b.WriteFile(d+"/isolated", hw.NewCPUSet(m.Isolated...).List()+"\n")
	if len(m.NohzFull) > 0 {
		b.WriteFile(d+"/nohz_full", hw.NewCPUSet(m.NohzFull...).List()+"\n")
	} else {
		b.WriteFile(d+"/nohz_full", "  (null)\n")
	}
	pkgCPUs := map[int]hw.CPUSet{}
	for _, c := range b.cores {
		pkgCPUs[c.pkg] = append(pkgCPUs[c.pkg], c.cpus...)
	}
	for p, l := range pkgCPUs {
		pkgCPUs[p] = hw.NewCPUSet(l...).And(b.online)
	}
	for _, c := range b.cores {
		threads := hw.NewCPUSet(c.cpus...).And(b.online)
		for _, cpu := range c.cpus {
			cd := fmt.Sprintf("%s/cpu%d", d, cpu)
			if cpu != 0 {
				on := "1"
				if !b.online.Has(cpu) {
					on = "0"
				}
				b.WriteFile(cd+"/online", on+"\n")
			}
			if !b.online.Has(cpu) {
				continue // an offline CPU has no topology directory
			}
			td := cd + "/topology"
			b.WriteFile(td+"/physical_package_id", fmt.Sprintf("%d\n", c.pkg))
			b.WriteFile(td+"/die_id", "0\n")
			b.WriteFile(td+"/core_id", fmt.Sprintf("%d\n", c.idx))
			b.WriteFile(td+"/core_cpus_list", threads.List()+"\n")
			b.WriteFile(td+"/core_cpus", threads.Mask(b.cpus)+"\n")
			b.WriteFile(td+"/thread_siblings_list", threads.List()+"\n")
			b.WriteFile(td+"/thread_siblings", threads.Mask(b.cpus)+"\n")
			b.WriteFile(td+"/package_cpus_list", pkgCPUs[c.pkg].List()+"\n")
		}
	}
}

// nodeOfCPU is the node a CPU's core is on.
func (b *Built) nodeOfCPU(cpu int) int {
	if b.nodeOf == nil {
		b.nodeOf = map[int]int{}
		for _, c := range b.cores {
			for _, x := range c.cpus {
				b.nodeOf[x] = c.node
			}
		}
	}
	if n, ok := b.nodeOf[cpu]; ok {
		return n
	}
	return -1
}

func (b *Built) distance(a, c int) int {
	m := b.M
	if a == c {
		return 10
	}
	if m.SLIT != nil && a < len(m.SLIT) && c < len(m.SLIT[a]) {
		return m.SLIT[a][c]
	}
	if a >= 0 && c >= 0 && a < len(b.nodes) && c < len(b.nodes) && b.nodes[a].pkg == b.nodes[c].pkg && b.nodes[a].pkg >= 0 {
		return 12
	}
	return 21
}

func (b *Built) writeNodes() {
	m := b.M
	n := m.Packages * m.NodesPerPackage
	kb := int64(m.MemGiB) * 1024 * 1024 / int64(n)
	for id := 0; id < n; id++ {
		fn := fnode{id: id, pkg: id / m.NodesPerPackage, kb: kb}
		for _, c := range b.cores {
			if c.node == id {
				fn.cpus = append(fn.cpus, c.cpus...)
			}
		}
		fn.cpus = hw.NewCPUSet(fn.cpus...).And(b.online)
		b.nodes = append(b.nodes, fn)
	}
	for _, g := range m.MemOnlyNodes {
		b.nodes = append(b.nodes, fnode{id: len(b.nodes), pkg: -1, kb: int64(g) * 1024 * 1024})
	}
	if m.NoNUMA {
		return
	}
	d := "/sys/devices/system/node"
	var ids, withCPU hw.CPUSet
	for _, fn := range b.nodes {
		ids = append(ids, fn.id)
		if len(fn.cpus) > 0 {
			withCPU = append(withCPU, fn.id)
		}
	}
	b.WriteFile(d+"/online", ids.List()+"\n")
	b.WriteFile(d+"/possible", ids.List()+"\n")
	b.WriteFile(d+"/has_cpu", withCPU.List()+"\n")
	b.WriteFile(d+"/has_memory", ids.List()+"\n")
	b.WriteFile(d+"/has_normal_memory", ids.List()+"\n")
	for _, fn := range b.nodes {
		nd := fmt.Sprintf("%s/node%d", d, fn.id)
		b.WriteFile(nd+"/cpulist", fn.cpus.List()+"\n")
		b.WriteFile(nd+"/cpumap", fn.cpus.Mask(b.cpus)+"\n")
		b.WriteFile(nd+"/meminfo", fmt.Sprintf("Node %d MemTotal:       %d kB\nNode %d MemFree:        %d kB\nNode %d MemUsed:        %d kB\n",
			fn.id, fn.kb, fn.id, fn.kb/2, fn.id, fn.kb-fn.kb/2))
		var row []string
		for _, o := range b.nodes {
			row = append(row, fmt.Sprint(b.distance(fn.id, o.id)))
		}
		b.WriteFile(nd+"/distance", strings.Join(row, " ")+"\n")
	}
}

func (b *Built) totalKB() int64 {
	var kb int64
	for _, n := range b.nodes {
		kb += n.kb
	}
	return kb
}

func (b *Built) writeProc() {
	m := b.M
	kb := b.totalKB()
	b.WriteFile("/proc/meminfo", fmt.Sprintf("MemTotal:       %d kB\nMemFree:        %d kB\nMemAvailable:   %d kB\nBuffers:        0 kB\nCached:         %d kB\nSwapTotal:      0 kB\nSwapFree:       0 kB\n",
		kb, kb/2, kb*3/4, kb/8))
	var ci strings.Builder
	flags := "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx lm constant_tsc pni ssse3 sse4_1 sse4_2 popcnt aes avx"
	if m.Virt != "" && !m.IsContainer() {
		flags += " hypervisor"
	}
	for _, cpu := range b.online {
		var c fcore
		for _, x := range b.cores {
			if slices.Contains(x.cpus, cpu) {
				c = x
			}
		}
		fmt.Fprintf(&ci, "processor\t: %d\nvendor_id\t: GenuineIntel\nmodel name\t: %s\nphysical id\t: %d\nsiblings\t: %d\ncore id\t\t: %d\ncpu cores\t: %d\nflags\t\t: %s\n\n",
			cpu, m.Model, c.pkg, m.CoresPerPackage*m.ThreadsPerCore, c.idx, m.CoresPerPackage, flags)
	}
	b.WriteFile("/proc/cpuinfo", ci.String())
	for _, cpu := range b.online {
		b.times[cpu] = &[10]uint64{1000, 0, 500, 100000, 10, 0, 50, 0, 0, 0}
		b.softnet[cpu] = &[3]uint64{100000, 0, 0}
	}
	b.writeStat()
	b.writeSoftnet()
	b.WriteFile("/proc/sys/kernel/osrelease", m.Kernel+"\n")
	numa := "0"
	if len(b.nodes) > 1 && !m.NoNUMA {
		numa = "1"
	}
	b.WriteFile("/proc/sys/kernel/numa_balancing", numa+"\n")
	if m.Init == "systemd" {
		b.mkdir("/run/systemd/system")
	} else if m.Init == "openrc" {
		b.mkdir("/run/openrc")
	}
	switch m.Virt {
	case "docker":
		b.WriteFile("/.dockerenv", "")
	case "podman":
		b.WriteFile("/run/.containerenv", "")
	case "", "none":
	default:
		if m.IsContainer() {
			b.WriteFile("/proc/1/environ", "container="+m.Virt+"\x00")
		} else {
			vendor := map[string]string{"kvm": "QEMU", "qemu": "QEMU", "vmware": "VMware, Inc.", "xen": "Xen", "microsoft": "Microsoft Corporation"}[m.Virt]
			b.WriteFile("/sys/class/dmi/id/sys_vendor", vendor+"\n")
		}
	}
}

// writeStat writes /proc/stat from the CPU times.
func (b *Built) writeStat() {
	var sum [10]uint64
	var lines strings.Builder
	for _, cpu := range b.online {
		v := b.times[cpu]
		for i := range sum {
			sum[i] += v[i]
		}
		fmt.Fprintf(&lines, "cpu%d %s\n", cpu, joinU(v[:]))
	}
	b.WriteFile("/proc/stat", fmt.Sprintf("cpu  %s\n%sintr 0\nctxt 0\nbtime 1760000000\nprocesses 1000\nprocs_running 1\nprocs_blocked 0\nsoftirq 0 0 0 0 0 0 0 0 0 0 0\n",
		joinU(sum[:]), lines.String()))
}

func joinU(v []uint64) string {
	s := make([]string, len(v))
	for i, x := range v {
		s[i] = fmt.Sprint(x)
	}
	return strings.Join(s, " ")
}

// SetCPUTimes sets a CPU's /proc/stat times (in USER_HZ ticks).
func (b *Built) SetCPUTimes(cpu int, user, system, softirq, steal, idle uint64) {
	b.t.Helper()
	v := b.times[cpu]
	if v == nil {
		b.t.Fatalf("hwtest: CPU %d is not online", cpu)
	}
	// user nice system idle iowait irq softirq steal guest guest_nice
	*v = [10]uint64{user, 0, system, idle, 0, 0, softirq, steal, 0, 0}
	b.writeStat()
}

// writeSoftnet writes /proc/net/softnet_stat: one row per online CPU, the
// CPU in column 13 (Linux 5.10 and later).
func (b *Built) writeSoftnet() {
	var s strings.Builder
	for _, cpu := range b.online {
		v := b.softnet[cpu]
		fmt.Fprintf(&s, "%08x %08x %08x 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 %08x 00000000 00000000\n",
			uint32(v[0]), uint32(v[1]), uint32(v[2]), cpu)
	}
	b.WriteFile("/proc/net/softnet_stat", s.String())
}

// SetSoftnet sets a CPU's softnet_stat counters.
func (b *Built) SetSoftnet(cpu int, processed, dropped, squeeze uint64) {
	b.t.Helper()
	v := b.softnet[cpu]
	if v == nil {
		b.t.Fatalf("hwtest: CPU %d is not online", cpu)
	}
	*v = [3]uint64{processed, dropped, squeeze}
	b.writeSoftnet()
}

// localSpread is cpumask_local_spread: the i-th CPU counting the node's own
// CPUs first, then the others by distance.
func (b *Built) localSpread(i, node int) int {
	if b.spread == nil {
		b.spread = map[int][]int{}
	}
	order, ok := b.spread[node]
	if !ok {
		order = slices.Clone(b.online)
		if node >= 0 {
			sort.SliceStable(order, func(x, y int) bool {
				dx, dy := b.distance(node, b.nodeOfCPU(order[x])), b.distance(node, b.nodeOfCPU(order[y]))
				if dx != dy {
					return dx < dy
				}
				return order[x] < order[y]
			})
		}
		b.spread[node] = order
	}
	return order[i%len(order)]
}

// defaultMask is the default affinity's CPUs (all when not set).
func (b *Built) defaultMask() hw.CPUSet {
	if b.M.DefaultSMPAffinity != nil {
		return hw.NewCPUSet(b.M.DefaultSMPAffinity...)
	}
	all := hw.NewCPUSet()
	for i := 0; i < b.cpus; i++ {
		all = append(all, i)
	}
	return all
}

// nodeDefault is hw.DefaultIRQMask for a device on the node.
func (b *Built) nodeDefault(node int) hw.CPUSet {
	m := b.defaultMask().And(b.online)
	if node >= 0 && node < len(b.nodes) {
		if x := m.And(b.nodes[node].cpus); len(x) > 0 {
			return x
		}
	}
	return m
}
