//go:build linux

package diag

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/util/hw"
)

// warnings are the plain one-line findings, each with its fix where there
// is one: the packet path, the NIC's setup, how the interrupts fall on the
// instances, how the instances sit on the CPUs, and limits close to full.
func (c *ctx) warnings() []string {
	var w []string
	add := func(format string, a ...any) { w = append(w, fmt.Sprintf(format, a...)) }
	r, s := c.r, c.r.Sample

	// The packet path, from the sample.
	if s != nil {
		if s.Softnet.Drops > 0 {
			add("softnet: %d packets dropped because a CPU's backlog was full: raise net.core.netdev_max_backlog (x-ui tune apply)", s.Softnet.Drops)
		}
		if s.Softnet.SqueezeRate > 100 {
			add("softnet: the CPUs ran out of packet budget %s times a second (time_squeeze): raise net.core.netdev_budget (x-ui tune apply)", num(s.Softnet.SqueezeRate))
		}
		for _, ns := range s.NICs {
			var lost, allowance []string
			for _, k := range sortedKeys(ns.Counters) {
				d := ns.Counters[k].Delta
				switch {
				case d == 0 || k == "fdir_overflow":
				case strings.Contains(k, "allowance_exceeded"):
					allowance = append(allowance, fmt.Sprintf("%s +%d", k, d))
				default:
					lost = append(lost, fmt.Sprintf("%s +%d", k, d))
				}
			}
			if len(lost) > 0 {
				add("%s dropped packets in the sample: %s", ns.Name, strings.Join(lost, ", "))
			}
			if len(allowance) > 0 {
				add("%s went over the cloud provider's allowance: %s (the provider's limit, not this server's)", ns.Name, strings.Join(allowance, ", "))
			}
			if ns.Counters["fdir_overflow"].Delta > 0 {
				add("%s flow director overflowed (+%d): TCP flows fall back to the RSS queues", ns.Name, ns.Counters["fdir_overflow"].Delta)
			}
		}
		if s.Listen.Overflows > 0 {
			add("TCP listen queues overflowed %d times: raise net.core.somaxconn (x-ui tune apply)", s.Listen.Overflows)
		}
	}

	// The NICs' setup.
	for _, nr := range r.NICs {
		if nr.Queues >= 2 {
			var ipsOnly bool
			for _, f := range []string{"udp4", "udp6"} {
				ipsOnly = ipsOnly || nr.nic.Hash[f] == hw.HashIPs
			}
			if ipsOnly {
				switch nr.Driver {
				case "ixgbe", "igb", "igc":
					add("%s hashes UDP on IP addresses only: x-ui tune apply", nr.Name)
				default:
					add("%s hashes UDP on IP addresses only (its driver's setting)", nr.Name)
				}
			}
			// RPS is redundant with a hardware queue per CPU; with fewer
			// queues it may spread the work (kernel scaling.rst).
			if nr.RPS.On && nr.Queues >= r.Hardware.CPUs {
				add("%s has %d queues and RPS is on: it moves packets between CPUs for nothing; clear its queues/rx-*/rps_cpus", nr.Name, nr.Queues)
			}
		} else if !nr.RPS.On && r.Hardware.CPUs >= 2 && !r.Hardware.Container {
			add("%s has one queue and RPS is off: one CPU takes all its packets; x-ui tune apply", nr.Name)
		}
	}

	// The interrupts against the instances.
	idle := c.coresWithoutQueueIRQ()
	for _, nr := range r.NICs {
		if len(nr.Siblings) > 0 && idle > 0 {
			add("%s: RSS interrupts on both threads of %s (%s) while %s no queue interrupt: x-ui tune apply",
				nr.Name, plural(len(nr.Siblings), "core", "cores"), short(nr.Siblings, 4), plural(idle, "core has", "cores have"))
		}
	}
	if msg := c.unevenRSS(); msg != "" {
		add("%s", msg)
	}
	if s != nil {
		var hi, lo *InstanceReport
		for _, in := range r.Instances {
			if !in.pinned || in.SoftirqPct == nil {
				continue
			}
			if hi == nil || *in.SoftirqPct > *hi.SoftirqPct {
				hi = in
			}
			if lo == nil || *in.SoftirqPct < *lo.SoftirqPct {
				lo = in
			}
		}
		if hi != nil && hi != lo && *hi.SoftirqPct > 2**lo.SoftirqPct && *hi.SoftirqPct > 5 {
			add("packet work uneven: %s spends %s%% of its CPUs in softirq, %s %s%%", hi.Name, num(*hi.SoftirqPct), lo.Name, num(*lo.SoftirqPct))
		}
	}
	var unruly []string
	for _, nr := range r.NICs {
		if nr.Managed && c.irqb.Running && !c.irqb.Policy {
			unruly = append(unruly, nr.Name)
		}
	}
	if len(unruly) > 0 {
		add("irqbalance runs without x-ui's policy script and moves %s's interrupts: x-ui tune apply (if you set IRQBALANCE_ARGS, add %s=%s to it first)",
			strings.Join(unruly, " and "), policyFlag, irqbalancePol)
	}
	if c.nodesWithCPUs() > 1 {
		for _, nr := range r.NICs {
			if nr.XPS.Remote > 0 {
				add("%s: %s on queues whose interrupt is on another NUMA node (XPS): x-ui tune apply", nr.Name, plural(nr.XPS.Remote, "CPU sends", "CPUs send"))
			}
		}
	}

	// The instances on the CPUs.
	w = append(w, c.layoutWarnings()...)

	// Limits.
	t := r.TCP
	if t.MaxOrphans > 0 && t.Orphans*2 > t.MaxOrphans {
		add("orphaned TCP sockets: %d of %d (net.ipv4.tcp_max_orphans): x-ui tune apply", t.Orphans, t.MaxOrphans)
	}
	if near(t.TimeWait, t.MaxTimeWait) {
		add("TIME_WAIT sockets: %d of %d (net.ipv4.tcp_max_tw_buckets): x-ui tune apply", t.TimeWait, t.MaxTimeWait)
	}
	if len(t.TCPMem) == 3 && t.TCPMem[1] > 0 && t.MemPages >= t.TCPMem[1] {
		add("TCP memory: %d pages, past the pressure mark %d (net.ipv4.tcp_mem): x-ui tune apply", t.MemPages, t.TCPMem[1])
	}
	if g := t.Conntrack; g != nil && near(g.Count, g.Max) {
		add("conntrack table: %d of %d entries (net.netfilter.nf_conntrack_max)", g.Count, g.Max)
	}
	if g := t.Files; g != nil && near(g.Count, g.Max) {
		add("open files on the system: %d of %d (fs.file-max)", g.Count, g.Max)
	}
	for _, in := range r.Instances {
		if in.FDs >= 0 && near(int64(in.FDs), in.FDLimit) {
			add("%s has %d open files of its limit %d", in.Name, in.FDs, in.FDLimit)
		}
		if u := in.UDP; u != nil && near(int64(u.Used), int64(u.Pool)) {
			if u.IP == "" {
				add("%s's UDP sockets hold %d of %d local ports of the default address: give it an outgoing IP of its own", in.Name, u.Used, u.Pool)
			} else {
				add("%s's UDP sockets hold %d of %d local ports of %s", in.Name, u.Used, u.Pool, u.IP)
			}
		}
	}
	if s != nil && s.Steal >= 5 {
		add("steal %s%%: the host runs other guests on this VM's CPUs", num(s.Steal))
	}
	return w
}

// near: count is at 80% of max or more (max unknown: never). Limits like
// file-max can be near the top of int64.
func near(count, max int64) bool {
	return max > 0 && float64(count) >= 0.8*float64(max)
}

// coresWithoutQueueIRQ counts the cores open to queue interrupts (a thread
// x-ui tune may put one on: allowed, in the default interrupt affinity, not
// isolated) that no uplink's queue interrupt runs on.
func (c *ctx) coresWithoutQueueIRQ() int {
	if c.topo == nil {
		return 0
	}
	busy := map[int]bool{}
	for _, nr := range c.r.NICs {
		for _, cpu := range queueCPUs(nr.nic) {
			if core := c.topo.CoreOf(cpu); core != nil {
				busy[core.ID] = true
			}
		}
	}
	open := c.allowed
	if d, err := hw.ParseMask(c.e.fs.ReadTrim("/proc/irq/default_smp_affinity")); err == nil && len(open.And(d)) > 0 {
		open = open.And(d)
	}
	open = open.Minus(c.topo.Isolated)
	n := 0
	for _, core := range c.topo.Cores {
		if len(core.Threads.And(open)) > 0 && !busy[core.ID] {
			n++
		}
	}
	return n
}

// unevenRSS: some instance holds at least one RSS interrupt more than its
// share rounded up, while another holds less than its share rounded down.
func (c *ctx) unevenRSS() string {
	if !c.split() {
		return ""
	}
	over, under := map[int][]string{}, map[int][]string{}
	var shares []float64
	for _, in := range c.r.Instances {
		sh := in.NICIRQs.Share
		if sh <= 0 {
			continue
		}
		shares = append(shares, sh)
		n := in.NICIRQs.RSS
		if n >= int(math.Ceil(sh))+1 {
			over[n] = append(over[n], in.Name)
		}
		if float64(n) < math.Floor(sh) {
			under[n] = append(under[n], in.Name)
		}
	}
	if len(over) == 0 || len(under) == 0 {
		return ""
	}
	var parts []string
	for _, n := range sortedCounts(over, true) {
		verb := "holds"
		if len(over[n]) > 1 {
			verb = "hold"
		}
		parts = append(parts, fmt.Sprintf("%s %s %d", short(over[n], 8), verb, n))
	}
	for _, n := range sortedCounts(under, true) {
		what := "none"
		if n > 0 {
			what = "hold " + strconv.Itoa(n)
			if len(under[n]) == 1 {
				what = "holds " + strconv.Itoa(n)
			}
		}
		parts = append(parts, fmt.Sprintf("%s %s", short(under[n], 8), what))
	}
	sort.Float64s(shares)
	share := "share " + num(shares[0])
	if shares[0] != shares[len(shares)-1] {
		share = "shares " + num(shares[0]) + "-" + num(shares[len(shares)-1])
	}
	return fmt.Sprintf("RSS interrupts uneven: %s (%s): x-ui tune apply", strings.Join(parts, "; "), share)
}

func sortedCounts(m map[int][]string, desc bool) []int {
	var out []int
	for n := range m {
		out = append(out, n)
	}
	sort.Ints(out)
	if desc {
		for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
			out[i], out[j] = out[j], out[i]
		}
	}
	return out
}

// layoutWarnings: an instance on two NUMA nodes though one node could hold
// it, and instances sharing more than one physical core with others. An
// instance on the CPUs x-ui's own split gives it is left out: where that
// split has to cut a node or share a core, no setting but the instances'
// CPU counts changes it.
func (c *ctx) layoutWarnings() []string {
	t := c.topo
	insts := c.r.Instances
	if t == nil || len(insts) == 0 {
		return nil
	}
	biggest := 0
	for _, n := range t.Nodes {
		biggest = max(biggest, len(n.CPUs.And(c.allowed)))
	}
	own := c.ownSplit()
	var span, share []string
	var spanned []int
	for _, in := range insts {
		if !in.pinned || (own[in.Name] != nil && own[in.Name].Equal(in.CPUs)) {
			continue
		}
		if len(in.Nodes) > 1 && len(in.CPUs) <= biggest {
			span = append(span, in.Name)
			spanned = append(spanned, in.Nodes...)
		}
		if c.sharedCores(in) > 1 {
			share = append(share, in.Name)
		}
	}
	nodes := joinAnd(intStrings(hw.NewCPUSet(spanned...)))
	all := len(insts) > 1
	if all && len(span) == len(insts) && len(share) == len(insts) {
		return []string{fmt.Sprintf("every xray instance spans NUMA nodes %s and shares cores with another instance", nodes)}
	}
	var out []string
	switch {
	case len(span) == 0:
	case all && len(span) == len(insts):
		out = append(out, fmt.Sprintf("every xray instance spans NUMA nodes %s though one node could hold it", nodes))
	case len(span) == 1:
		out = append(out, fmt.Sprintf("%s spans NUMA nodes %s though one node could hold it", span[0], nodes))
	default:
		out = append(out, fmt.Sprintf("%s span NUMA nodes %s though one node could hold each", short(span, 8), nodes))
	}
	switch {
	case len(share) == 0:
	case all && len(share) == len(insts):
		out = append(out, "every xray instance shares more than one physical core with other instances")
	case len(share) == 1:
		out = append(out, share[0]+" shares more than one physical core with other instances")
	default:
		out = append(out, short(share, 8)+" share more than one physical core with other instances")
	}
	return out
}

// ownSplit is the CPUs x-ui's split gives the instances in instances.json
// on this machine (as the panel makes it: hw.SplitCPUs over the allowed
// CPUs, the uplink's node first); nil without the file.
func (c *ctx) ownSplit() map[string]hw.CPUSet {
	if c.file == nil || c.topo == nil {
		return nil
	}
	allowed, err := hw.ParseList(c.file.Allowed)
	if err != nil || len(allowed) == 0 {
		return nil
	}
	var reqs []hw.CPURequest
	for _, in := range c.file.Instances {
		reqs = append(reqs, hw.CPURequest{Name: in.Name, CPUs: in.Cores})
	}
	out := map[string]hw.CPUSet{}
	for name, l := range hw.SplitCPUs(c.topo, allowed, hw.UplinkNode(c.e.fs), reqs, model.LessInstanceName) {
		out[name] = hw.NewCPUSet(l...)
	}
	return out
}

// sharedCores counts the cores where an instance has a thread and another
// instance has another.
func (c *ctx) sharedCores(in *InstanceReport) int {
	n := 0
	seen := map[int]bool{}
	for _, cpu := range in.CPUs {
		core := c.topo.CoreOf(cpu)
		if core == nil || seen[core.ID] {
			continue
		}
		seen[core.ID] = true
		for _, th := range core.Threads {
			if in.CPUs.Has(th) {
				continue
			}
			if o := c.owners[th]; len(o) > 0 {
				n++
				break
			}
		}
	}
	return n
}

func (c *ctx) nodesWithCPUs() int {
	if c.topo == nil {
		return 0
	}
	n := 0
	for _, nd := range c.topo.Nodes {
		if len(nd.CPUs) > 0 {
			n++
		}
	}
	return n
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func intStrings(v []int) []string {
	out := make([]string, len(v))
	for i, x := range v {
		out[i] = strconv.Itoa(x)
	}
	return out
}

// joinAnd writes "0", "0 and 1", "0, 1 and 2".
func joinAnd(s []string) string {
	switch len(s) {
	case 0:
		return ""
	case 1:
		return s[0]
	}
	return strings.Join(s[:len(s)-1], ", ") + " and " + s[len(s)-1]
}

// short joins a list, cut after n items: "a, b, c and 7 more".
func short(items []string, n int) string {
	if len(items) <= n+1 {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(items[:n], ", "), len(items)-n)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

// num writes a number with at most one decimal.
func num(x float64) string {
	return strconv.FormatFloat(round1(x), 'f', -1, 64)
}
