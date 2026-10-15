//go:build linux

package diag

import (
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/util/hw"
)

// pr writes the text report: sections of "label  value" lines.
type pr struct {
	w io.Writer
}

func (p pr) title(s string) { fmt.Fprintf(p.w, "\n%s\n", s) }

// kv writes a labelled value; lines after the first are indented under it.
// A label too long for its column gets a line of its own.
func (p pr) kv(label string, lines ...string) {
	if len(label) > 11 {
		fmt.Fprintf(p.w, "  %s\n", label)
		label = ""
	}
	for i, l := range lines {
		if i == 0 {
			fmt.Fprintf(p.w, "  %-12s%s\n", label, l)
		} else {
			fmt.Fprintf(p.w, "  %-12s%s\n", "", l)
		}
	}
}

func (c *ctx) render(w io.Writer) {
	r := c.r
	p := pr{w}
	head := fmt.Sprintf("x-ui diag %s, %s", r.Version, r.Time.Format("2006-01-02 15:04:05 UTC"))
	if r.Kernel != "" {
		head += ", kernel " + r.Kernel
	}
	fmt.Fprintln(w, head)
	if !r.Root {
		fmt.Fprintln(w, "Not run as root: the cores' open files and connections need root.")
	}
	c.renderHardware(p)
	for _, nr := range r.NICs {
		c.renderNIC(p, nr)
	}
	if len(r.NICs) == 0 {
		p.title("Network")
		notes := r.NetNotes
		if len(notes) == 0 {
			notes = []string{"no NIC found under the default routes"}
		}
		p.kv("uplink", notes...)
	}
	if r.Sample != nil {
		c.renderSample(p)
	}
	c.renderInstances(p)
	c.renderTCP(p)
	if len(r.Warnings) == 0 {
		fmt.Fprintln(w, "\nWarnings: none")
		return
	}
	p.title("Warnings")
	for _, x := range r.Warnings {
		fmt.Fprintf(w, "  - %s\n", x)
	}
}

func (c *ctx) renderHardware(p pr) {
	h := c.r.Hardware
	p.title("Hardware")
	if h.Note != "" {
		p.kv("CPUs", h.Note)
	} else {
		cpus := topoText(h)
		if h.Model != "" {
			cpus += ": " + h.Model
		}
		p.kv("CPUs", cpus)
		if len(h.Isolated) > 0 {
			p.kv("isolated", "CPUs "+h.Isolated.List())
		}
	}
	if len(h.Nodes) > 1 {
		var lines []string
		for _, n := range h.Nodes {
			if n.MemoryOnly {
				lines = append(lines, fmt.Sprintf("node %d: no CPUs (memory only), %s", n.ID, bytesText(n.MemBytes)))
			} else {
				lines = append(lines, fmt.Sprintf("node %d: CPUs %s, %s", n.ID, n.CPUs.List(), bytesText(n.MemBytes)))
			}
		}
		if h.NUMABalancing != "" {
			lines = append(lines, "automatic NUMA balancing "+h.NUMABalancing)
		}
		p.kv("NUMA", lines...)
	}
	p.kv("memory", bytesText(h.MemBytes))
	p.kv("machine", virtText(h))
}

// topoText is "2 sockets, 28 cores, 56 CPUs (2 threads per core)".
func topoText(h Hardware) string {
	s := fmt.Sprintf("%s, %s, %s", plural(h.Sockets, "socket", "sockets"), plural(h.Cores, "core", "cores"), plural(h.CPUs, "CPU", "CPUs"))
	if h.ThreadsPerCore > 1 {
		s += fmt.Sprintf(" (%d threads per core)", h.ThreadsPerCore)
	}
	return s
}

func virtText(h Hardware) string {
	switch {
	case h.Container:
		return "a container (" + h.Virt + "): the host owns the NICs"
	case h.Virt == "vm":
		return "a virtual machine"
	case h.Virt != "":
		return "a virtual machine (" + h.Virt + ")"
	}
	return "bare metal"
}

func (c *ctx) renderNIC(p pr, nr *NICReport) {
	head := fmt.Sprintf("NIC %s (default route %s", nr.Name, nr.Routes)
	if len(nr.Via) > 0 {
		head += " via " + strings.Join(nr.Via, " > ")
	}
	p.title(head + ")")
	dev := nr.Model
	if nr.Vendor != "" && nr.Device != "" {
		if dev != "" {
			dev += " "
		}
		dev += "[" + nr.Vendor + ":" + nr.Device + "]"
	}
	parts := []string{}
	for _, s := range []string{dev, nr.Driver} {
		if s != "" {
			parts = append(parts, s)
		}
	}
	if nr.PCI != "" {
		parts = append(parts, "PCI "+nr.PCI)
	}
	if nr.Node >= 0 {
		parts = append(parts, fmt.Sprintf("NUMA node %d", nr.Node))
	}
	if nr.VF {
		parts = append(parts, "an SR-IOV virtual function")
	}
	p.kv("device", strings.Join(parts, ", "))
	link := "down"
	switch {
	case nr.Up && nr.Carrier:
		link = "up"
	case nr.Up:
		link = "up, no carrier"
	}
	if nr.SpeedMbps > 0 {
		link += ", " + speedText(nr.SpeedMbps)
	}
	if nr.nic.Bond != nil {
		b := nr.nic.Bond
		link += fmt.Sprintf("; in %s (%s), MII %s", b.Bond, b.Mode, b.MIIStatus)
	}
	p.kv("link", link)

	q := plural(nr.Queues, "queue", "queues")
	if ch := nr.Channels; ch != nil {
		cur, mx := ch.Count()
		q = fmt.Sprintf("%d of %d", cur, mx)
	}
	if nr.RSS != nil && nr.RSS.Queues < nr.Queues {
		q += fmt.Sprintf(" (RSS uses %d)", nr.RSS.Queues)
	}
	p.kv("queues", q)
	if rr := nr.RSS; rr != nil {
		form := "even over queues " + rr.Used.List()
		switch {
		case rr.Weighted:
			form = "weighted by x-ui tune for the instance split: queues " + rr.Used.List()
		case !rr.Even:
			form = "custom: queues " + rr.Used.List() + " (an admin's table)"
		}
		p.kv("RSS table", fmt.Sprintf("%d entries, %s", rr.Size, form))
	} else {
		p.kv("RSS table", "not readable")
	}
	var hash []string
	none := 0
	for _, f := range hw.HashFlows {
		if b, ok := nr.nic.Hash[f.String()]; ok {
			hash = append(hash, f.String()+" "+hw.HashText(b))
		} else if slices.Contains(nr.nic.HashNone, f.String()) {
			hash = append(hash, f.String()+" "+hw.HashText(0))
			none++
		}
	}
	switch {
	case len(hash) == 0:
		hash = []string{"not readable"}
	case none == len(hash):
		hash = []string{hw.HashText(0)}
	}
	p.kv("hashing", strings.Join(hash, ", "))
	if len(nr.Offloads) > 0 {
		var on, off []string
		for _, k := range sortedKeys(nr.Offloads) {
			if nr.Offloads[k] {
				on = append(on, k)
			} else {
				off = append(off, k)
			}
		}
		s := "on: " + strings.Join(on, " ")
		if len(off) > 0 {
			s += "; off: " + strings.Join(off, " ")
		}
		p.kv("offloads", s)
	}
	c.renderIRQs(p, nr)
	p.kv("irqbalance", irqbalanceText(nr))
	p.kv("XPS", xpsText(nr.XPS))
	rps := "off"
	if nr.RPS.On {
		var qs []string
		for _, k := range sortedKeys(nr.RPS.Queues) {
			s := k + " over CPUs " + nr.RPS.Queues[k]
			if n := nr.RPS.FlowCnt[k]; n > 0 {
				s += fmt.Sprintf(", %d flows", n)
			}
			qs = append(qs, s)
		}
		rps = strings.Join(qs, "; ")
	}
	if nr.Queues >= 2 && !nr.RPS.On {
		rps += " (multi-queue)"
	}
	p.kv("RPS/RFS", rps)
	if nr.Managed {
		p.kv("x-ui tune", "manages it (x-ui tune status)")
	}
	if len(nr.Notes) > 0 {
		p.kv("notes", nr.Notes...)
	}
}

// renderIRQs writes the queue -> CPU map: "q0 11 xray-3", RSS queues first.
func (c *ctx) renderIRQs(p pr, nr *NICReport) {
	if len(nr.IRQs) == 0 {
		note := nr.IRQNote
		if note == "" {
			note = "none found"
		}
		p.kv("interrupts", note)
		return
	}
	var rss, other []string
	for _, ir := range nr.IRQs {
		if ir.Kind == "tx" && hasRx(nr, ir.Queue) {
			continue
		}
		cpu := "-"
		if len(ir.Effective) > 0 {
			cpu = ir.Effective.List()
		} else if len(ir.CPUs) > 0 {
			cpu = ir.CPUs.List()
		}
		cell := fmt.Sprintf("q%d %s", ir.Queue, cpu)
		if ir.Owner != "" {
			cell += " " + ir.Owner
		}
		if ir.RSS {
			rss = append(rss, cell)
		} else {
			other = append(other, cell)
		}
	}
	if len(other) == 0 {
		p.kv("interrupts", grid(rss)...)
	} else {
		p.kv("RSS IRQs", grid(rss)...)
		p.kv("other IRQs", grid(other)...)
	}
	if len(nr.Siblings) > 0 {
		p.kv("siblings", "RSS interrupts on both threads of "+short(nr.Siblings, 8))
	}
	if nr.IRQNote != "" {
		p.kv("", nr.IRQNote)
	}
}

func hasRx(nr *NICReport, q int) bool {
	for _, ir := range nr.IRQs {
		if ir.Queue == q && ir.Kind != "tx" {
			return true
		}
	}
	return false
}

// grid lays cells out in columns, at most 66 characters a line.
func grid(cells []string) []string {
	w := 0
	for _, c := range cells {
		w = max(w, len(c))
	}
	w += 3
	per := max(1, 66/w)
	var lines []string
	for i := 0; i < len(cells); i += per {
		var b strings.Builder
		for j := i; j < min(i+per, len(cells)); j++ {
			if j < min(i+per, len(cells))-1 {
				fmt.Fprintf(&b, "%-*s", w, cells[j])
			} else {
				b.WriteString(cells[j])
			}
		}
		lines = append(lines, b.String())
	}
	return lines
}

func irqbalanceText(nr *NICReport) string {
	b := nr.IRQBal
	var s string
	switch {
	case b.Running && b.Policy:
		s = "running with x-ui's policy"
	case b.Running:
		s = "running without x-ui's policy"
	case b.Installed:
		s = "installed, not running"
	default:
		s = "not installed"
	}
	if b.Banned {
		s += "; " + nr.Name + " banned for it"
		if b.DropIn {
			s += " (90-x-ui.conf)"
		}
	}
	return s
}

func xpsText(x XPSReport) string {
	if !x.Available {
		return "n/a (" + x.Note + ")"
	}
	if x.Set == 0 {
		return "off (the kernel picks the queue by flow)"
	}
	total := x.Own + x.Core + x.Node + x.Remote + x.None
	if x.Own == total {
		return "every CPU sends on its own queue"
	}
	var parts []string
	for _, p := range []struct {
		n    int
		what string
	}{{x.Own, "itself"}, {x.Core, "its core"}, {x.Node, "its node"}, {x.Remote, "another node"}, {x.None, "no queue set"}} {
		if p.n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", p.what, p.n))
		}
	}
	return fmt.Sprintf("%d of %d queues set; CPUs by where their queue's interrupt runs: %s", x.Set, x.Queues, strings.Join(parts, ", "))
}

func (c *ctx) renderSample(p pr) {
	s := c.r.Sample
	p.title(fmt.Sprintf("Sample (%s s)", num(s.Seconds)))
	p.kv("CPU", fmt.Sprintf("%s%% busy on average, %s%% softirq, %s%% steal", num(s.Busy), num(s.Softirq), num(s.Steal)))
	var hot []string
	for _, x := range s.hottest(5) {
		l := fmt.Sprintf("CPU %d: %s%% busy, %s%% softirq", x.CPU, num(x.Busy), num(x.Softirq))
		var who []string
		if o := c.owner(x.CPU); o != "" {
			who = append(who, o)
		}
		if q := c.queuesOn(x.CPU); q != "" {
			who = append(who, q)
		}
		if len(who) > 0 {
			l += " (" + strings.Join(who, "; ") + ")"
		}
		hot = append(hot, l)
	}
	if len(hot) > 0 {
		p.kv("hottest", hot...)
	}
	for _, ns := range s.NICs {
		lines := []string{fmt.Sprintf("rx %s %s, tx %s %s; dropped %d, errors %d",
			rateText(ns.RxBps), ppsText(ns.RxPps), rateText(ns.TxBps), ppsText(ns.TxPps), ns.Dropped, ns.Errors)}
		if ns.RSSShare != nil {
			since := ""
			if ns.ShareAll {
				since = " since boot"
			}
			var rssQ hw.CPUSet
			for _, nr := range c.r.NICs {
				if nr.Name == ns.Name && nr.RSS != nil {
					rssQ = nr.RSS.Used
				}
			}
			lines = append(lines, fmt.Sprintf("RSS queues %s got %s%% of the received packets%s", rssQ.List(), num(*ns.RSSShare), since))
		}
		var cs []string
		for _, k := range sortedKeys(ns.Counters) {
			if x := ns.Counters[k]; x.Total > 0 {
				cs = append(cs, fmt.Sprintf("%s +%d (%d)", k, x.Delta, x.Total))
			}
		}
		if len(cs) > 0 {
			lines = append(lines, "counters "+strings.Join(cs, ", "))
		}
		p.kv(ns.Name, lines...)
	}
	sn := s.Softnet
	p.kv("softnet", fmt.Sprintf("dropped +%d (%d since boot), time_squeeze %s/s (%d since boot)", sn.Drops, sn.DropsTotal, num(sn.SqueezeRate), sn.SqueezeTotal))
	p.kv("TCP listen", fmt.Sprintf("overflows +%d, drops +%d", s.Listen.Overflows, s.Listen.Drops))
}

func (c *ctx) renderInstances(p pr) {
	insts := c.r.Instances
	if len(insts) == 0 {
		fmt.Fprintln(p.w, "\nXray instances: none running")
		return
	}
	p.title(fmt.Sprintf("Xray instances (%d running)", len(insts)))
	for _, in := range insts {
		cpus := "CPUs " + in.CPUs.List()
		if !in.pinned {
			cpus = "all CPUs"
		}
		if len(in.Nodes) > 1 || c.nodesWithCPUs() > 1 {
			word := "node"
			if len(in.Nodes) > 1 {
				word = "nodes"
			}
			cpus += " (" + word + " " + joinAnd(intStrings(in.Nodes)) + ")"
		}
		l1 := fmt.Sprintf("pid %d, %s", in.PID, cpus)
		if in.CPUPct != nil {
			l1 += fmt.Sprintf(", %s%% busy", num(*in.CPUPct))
		}
		l1 += fmt.Sprintf(", %d threads, %s", in.Threads, bytesText(in.RSSBytes))
		var l2 []string
		switch {
		case in.FDs >= 0:
			l2 = append(l2, fmt.Sprintf("open files %d of %d", in.FDs, in.FDLimit))
		case in.FDLimit > 0:
			l2 = append(l2, fmt.Sprintf("open files limit %d", in.FDLimit))
		}
		if in.TCP >= 0 {
			l2 = append(l2, fmt.Sprintf("TCP %d", in.TCP))
		}
		if u := in.UDP; u != nil {
			from := "the default address"
			if u.IP != "" {
				from = u.IP
			}
			l2 = append(l2, fmt.Sprintf("UDP ports %d of %d (%s)", u.Used, u.Pool, from))
		}
		lines := []string{l1}
		if len(l2) > 0 {
			lines = append(lines, strings.Join(l2, ", "))
		}
		if len(c.r.NICs) > 0 && in.pinned {
			l3 := fmt.Sprintf("NIC interrupts on its CPUs: RSS %d", in.NICIRQs.RSS)
			if in.NICIRQs.Share > 0 {
				l3 += " (share " + num(in.NICIRQs.Share) + ")"
			}
			l3 += fmt.Sprintf(", other %d", in.NICIRQs.Other)
			if in.SoftirqPct != nil {
				l3 += "; softirq " + num(*in.SoftirqPct) + "%"
			}
			lines = append(lines, l3)
		}
		var root []string
		for _, n := range in.Notes {
			if what, ok := strings.CutSuffix(n, ": "+needsRoot); ok {
				root = append(root, what)
			} else {
				lines = append(lines, n)
			}
		}
		if len(root) > 0 {
			lines = append(lines, needsRoot+": "+strings.Join(root, ", "))
		}
		p.kv(in.Name, lines...)
	}
}

func (c *ctx) renderTCP(p pr) {
	t := c.r.TCP
	p.title("TCP")
	s := fmt.Sprintf("%d in use", t.InUse)
	if t.InUse6 > 0 {
		s += fmt.Sprintf(" (+%d IPv6)", t.InUse6)
	}
	s += fmt.Sprintf(", orphans %d of %d, TIME_WAIT %d of %d", t.Orphans, t.MaxOrphans, t.TimeWait, t.MaxTimeWait)
	p.kv("sockets", s)
	if len(t.TCPMem) == 3 {
		p.kv("memory", fmt.Sprintf("%d pages; pressure at %d, limit %d (tcp_mem)", t.MemPages, t.TCPMem[1], t.TCPMem[2]))
	}
	p.kv("listen", fmt.Sprintf("overflows %d, drops %d since boot; aborts for lack of memory %d", t.ListenOverflows, t.ListenDrops, t.AbortOnMemory))
	if g := t.Conntrack; g != nil {
		p.kv("conntrack", fmt.Sprintf("%d of %d entries", g.Count, g.Max))
	}
	if g := t.Files; g != nil {
		p.kv("open files", fmt.Sprintf("%d of %d on the system", g.Count, g.Max))
	}
}

// bytesText is "121 GiB", "60.5 GiB", "512 MiB".
func bytesText(b int64) string {
	const gib = 1 << 30
	switch {
	case b >= 100*gib:
		return fmt.Sprintf("%.0f GiB", float64(b)/gib)
	case b >= gib:
		return num(float64(b)/gib) + " GiB"
	case b >= 1<<20:
		return fmt.Sprintf("%.0f MiB", float64(b)/(1<<20))
	}
	return fmt.Sprintf("%d KiB", b/1024)
}

// speedText is "10 Gb/s", "2.5 Gb/s", "100 Mb/s".
func speedText(mbps int) string {
	if mbps >= 1000 {
		return num(float64(mbps)/1000) + " Gb/s"
	}
	return strconv.Itoa(mbps) + " Mb/s"
}

func rateText(bps float64) string {
	switch {
	case bps >= 1e9:
		return fmt.Sprintf("%.2f Gb/s", bps/1e9)
	case bps >= 1e6:
		return fmt.Sprintf("%.1f Mb/s", bps/1e6)
	case bps >= 1e3:
		return fmt.Sprintf("%.1f kb/s", bps/1e3)
	}
	return fmt.Sprintf("%.0f b/s", bps)
}

func ppsText(pps float64) string {
	switch {
	case pps >= 1e6:
		return fmt.Sprintf("%.2fM pkt/s", pps/1e6)
	case pps >= 1e3:
		return fmt.Sprintf("%.1fk pkt/s", pps/1e3)
	}
	return fmt.Sprintf("%.0f pkt/s", pps)
}
