//go:build linux

package diag

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/mhsanaei/3x-ui/v2/util/hw"
)

// containerNIC is the line "x-ui tune" gives a container's NICs; diag adds
// it when the tuning lines lack one, so the installer always says it.
const containerNIC = "NIC: left to the host (container)"

// summaryLines is what the installer prints after starting x-ui: what the
// machine is, and how x-ui set it up.
func (c *ctx) summaryLines() []string {
	r := c.r
	out := []string{"Detected:"}
	if c.topo != nil {
		out = append(out, "  "+topoLine(r.Hardware))
	}
	for _, nr := range r.NICs {
		out = append(out, "  "+nicLine(nr))
	}
	if len(r.NICs) == 0 && !r.Hardware.Container {
		for _, n := range r.NetNotes {
			out = append(out, "  Network: "+n)
		}
	}
	switch n := len(r.Instances); n {
	case 0:
		out = append(out, "  Xray: no instances yet")
	default:
		out = append(out, "  Xray: "+plural(n, "instance", "instances")+" running")
	}

	out = append(out, "Configured:")
	if l := c.xrayCPUsLine(); l != "" {
		out = append(out, "  "+l)
	}
	var tuned []string
	if c.e.summary != nil {
		tuned = c.e.summary()
	}
	if r.Hardware.Container {
		has := false
		for _, l := range tuned {
			has = has || strings.HasPrefix(l, "NIC")
		}
		if !has {
			out = append(out, "  "+containerNIC)
		}
	}
	for _, l := range tuned {
		out = append(out, "  "+l)
	}
	return out
}

// topoLine is "2 sockets, 28 cores, 56 CPUs (2 threads per core), 2 NUMA
// nodes, 121 GiB RAM".
func topoLine(h Hardware) string {
	s := topoText(h)
	withCPUs, memOnly := 0, 0
	for _, n := range h.Nodes {
		if n.MemoryOnly {
			memOnly++
		} else {
			withCPUs++
		}
	}
	if withCPUs > 1 || memOnly > 0 {
		s += ", " + plural(withCPUs, "NUMA node", "NUMA nodes")
		if memOnly > 0 {
			s += fmt.Sprintf(" (+%d memory-only)", memOnly)
		}
	}
	s += ", " + bytesText(h.MemBytes) + " RAM"
	switch {
	case h.Container:
		s += ", a " + h.Virt + " container"
	case h.Virt == "vm":
		s += ", a VM"
	case h.Virt != "":
		s += ", a " + h.Virt + " VM"
	}
	return s
}

// nicLine is "eno1: Intel 82599ES 10-Gigabit SFI/SFP+ (ixgbe), 10 Gb/s,
// NUMA node 1, 56 queues (RSS uses 16)".
func nicLine(nr *NICReport) string {
	name := nr.Name
	if len(nr.Via) > 0 {
		name += " (under " + nr.Via[len(nr.Via)-1] + ")"
	}
	var parts []string
	switch {
	case nr.Model != "" && nr.Driver != "":
		parts = append(parts, nr.Model+" ("+nr.Driver+")")
	case nr.Driver != "":
		parts = append(parts, nr.Driver)
	}
	if nr.SpeedMbps > 0 {
		parts = append(parts, speedText(nr.SpeedMbps))
	}
	if nr.Node >= 0 {
		parts = append(parts, fmt.Sprintf("NUMA node %d", nr.Node))
	}
	q := plural(nr.Queues, "queue", "queues")
	if nr.RSS != nil && nr.RSS.Queues < nr.Queues {
		q += fmt.Sprintf(" (RSS uses %d)", nr.RSS.Queues)
	}
	parts = append(parts, q)
	return name + ": " + strings.Join(parts, ", ")
}

// xrayCPUsLine says how the instances sit on the CPUs: "Xray CPUs: whole
// cores, one NUMA node each (node 1: xray-1..5; node 0: xray-6..10); 6 CPUs
// free".
func (c *ctx) xrayCPUsLine() string {
	insts := c.r.Instances
	t := c.topo
	if len(insts) == 0 || t == nil {
		return ""
	}
	pinned := 0
	for _, in := range insts {
		if in.pinned {
			pinned++
		}
	}
	if pinned == 0 {
		names := make([]string, len(insts))
		for i, in := range insts {
			names[i] = in.Name
		}
		return fmt.Sprintf("Xray CPUs: %s on all %s", nameRanges(names), plural(len(c.allowed), "CPU", "CPUs"))
	}
	var desc []string
	if t.ThreadsPerCore() > 1 {
		// Cores an instance shares with another one (a free thread
		// beside it takes nothing from it).
		most := 0
		for _, in := range insts {
			if in.pinned {
				most = max(most, c.sharedCores(in))
			}
		}
		switch most {
		case 0:
			desc = append(desc, "whole cores")
		case 1:
			desc = append(desc, "whole cores but one shared with a neighbour")
		default:
			desc = append(desc, "cores shared between instances")
		}
	}
	if c.nodesWithCPUs() > 1 {
		var order []int
		byNode := map[int][]string{}
		var spans []string
		for _, in := range insts {
			if !in.pinned {
				continue
			}
			if len(in.Nodes) != 1 {
				spans = append(spans, in.Name)
				continue
			}
			n := in.Nodes[0]
			if _, ok := byNode[n]; !ok {
				order = append(order, n)
			}
			byNode[n] = append(byNode[n], in.Name)
		}
		var groups []string
		for _, n := range order {
			groups = append(groups, fmt.Sprintf("node %d: %s", n, nameRanges(byNode[n])))
		}
		switch {
		case len(spans) == 0 && pinned == 1:
			desc = append(desc, "one NUMA node ("+strings.Join(groups, "; ")+")")
		case len(spans) == 0:
			desc = append(desc, "one NUMA node each ("+strings.Join(groups, "; ")+")")
		default:
			desc = append(desc, nameRanges(spans)+" on more than one NUMA node")
		}
	} else {
		var each []string
		for _, in := range insts {
			if in.pinned {
				each = append(each, in.Name+" "+in.CPUs.List())
			}
		}
		if len(each) <= 4 {
			desc = append(desc, strings.Join(each, ", "))
		} else {
			lo, hi := 0, 0
			for _, in := range insts {
				if !in.pinned {
					continue
				}
				if lo == 0 || len(in.CPUs) < lo {
					lo = len(in.CPUs)
				}
				hi = max(hi, len(in.CPUs))
			}
			size := strconv.Itoa(lo)
			if hi != lo {
				size += "-" + strconv.Itoa(hi)
			}
			desc = append(desc, fmt.Sprintf("%d instances of %s CPUs", pinned, size))
		}
	}
	line := "Xray CPUs: " + strings.Join(desc, ", ")
	used := hw.CPUSet{}
	for _, in := range insts {
		used = used.Union(in.CPUs)
	}
	if free := len(c.allowed.Minus(used)); free > 0 {
		line += "; " + plural(free, "CPU", "CPUs") + " free"
	}
	return line
}

// nameRanges shortens runs of names that differ only in a final number:
// "xray-1..5, edge".
func nameRanges(names []string) string {
	split := func(s string) (string, int, bool) {
		i := len(s)
		for i > 0 && unicode.IsDigit(rune(s[i-1])) {
			i--
		}
		if i == len(s) || (len(s)-i > 1 && s[i] == '0') {
			return s, 0, false
		}
		n, err := strconv.Atoi(s[i:])
		return s[:i], n, err == nil
	}
	var out []string
	for i := 0; i < len(names); {
		pre, n, ok := split(names[i])
		j := i + 1
		for ok && j < len(names) {
			p2, n2, ok2 := split(names[j])
			if !ok2 || p2 != pre || n2 != n+(j-i) {
				break
			}
			j++
		}
		switch {
		case j-i >= 3:
			_, last, _ := split(names[j-1])
			out = append(out, fmt.Sprintf("%s..%d", names[i], last))
		default:
			out = append(out, names[i:j]...)
		}
		i = j
	}
	return strings.Join(out, ", ")
}
