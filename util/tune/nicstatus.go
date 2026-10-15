//go:build linux

package tune

import (
	"fmt"
	"os"
	"strings"
)

// osMode is a file mode from its bits.
func osMode(m uint32) os.FileMode { return os.FileMode(m) }

// nicHead describes a NIC: driver, PCI function, model, node, speed, routes.
func nicHead(it *nicItem) string {
	n := it.NIC
	var parts []string
	d := n.Driver
	if n.PCI != "" {
		d += " " + n.PCI
	}
	parts = append(parts, strings.TrimSpace(d))
	if n.Model != "" {
		parts = append(parts, n.Model)
	}
	if n.Node >= 0 {
		parts = append(parts, fmt.Sprintf("NUMA node %d", n.Node))
	}
	if n.SpeedMbps > 0 {
		parts = append(parts, fmt.Sprintf("%d Mb/s", n.SpeedMbps))
	}
	if n.VF {
		parts = append(parts, "SR-IOV VF")
	}
	v4, v6 := false, false
	for _, r := range n.Routes {
		if r.V6 {
			v6 = true
		} else {
			v4 = true
		}
	}
	route := ""
	switch {
	case v4 && v6:
		route = "default route v4+v6"
	case v4:
		route = "default route v4"
	case v6:
		route = "default route v6"
	}
	if len(n.Via) > 0 && route != "" {
		route += " via " + strings.Join(n.Via, ", ")
	}
	if route != "" {
		parts = append(parts, route)
	}
	return n.Name + " (" + strings.Join(parts, ", ") + ")"
}

// hashLine is the UDP hashing of a NIC, for status (dry: what an apply
// does).
func hashLine(it *nicItem, dry bool) (label, text string) {
	if len(it.Hash) == 0 {
		if it.HashNote != "" {
			return "udp4/udp6", it.HashNote
		}
		return "", ""
	}
	var keys []string
	text = ""
	for _, ip := range it.Hash {
		keys = append(keys, ip.Key)
		t := hashWords(ip.Live)
		switch {
		case ip.Want != "" && dry:
			t += " -> " + hashWords(ip.Want)
		case ip.Want != "":
			t += " ('x-ui tune apply' hashes on ports)"
		case ip.Note != "":
			t += " (" + ip.Note + ")"
		}
		if text == "" {
			text = t
		} else if text != t {
			text += "; " + ip.Key + " " + t
		}
	}
	return strings.Join(keys, "/"), text
}

// placedText is how the interrupts are placed, after "placed".
func (np *nicPlan) placedText(it *nicItem, cpus bool) string {
	s := np.irqSummaryList(it, cpus)
	if np.place != nil && np.place.Split {
		return " by the instance split: " + s
	}
	return ": " + s
}

// irqSummaryList is irqSummary with or without the free CPUs' list.
func (np *nicPlan) irqSummaryList(it *nicItem, cpus bool) string {
	s := np.irqSummary(it)
	if !cpus {
		if i := strings.Index(s, " on free CPUs "); i >= 0 {
			s = s[:i] + " on free CPUs"
		}
	}
	return s
}

// printNICs is the NIC part of status and of a dry run.
func (e *Env) printNICs(np *nicPlan, st *State, dry bool) {
	if np.Skip != "" {
		e.printf("\nNIC: %s\n", np.Skip)
		return
	}
	for _, n := range np.Notes {
		e.printf("\nNIC: %s\n", n)
	}
	line := func(label, text string) {
		if text != "" {
			e.printf("  %-11s %s\n", label, text)
		}
	}
	for _, it := range np.NICs {
		e.printf("\nNIC %s\n", nicHead(it))
		q := it.Queues
		qt := queuesText(it)
		if q.State != "unsupported" {
			qt = strings.Replace(qt, " queues", "", 1)
		}
		line("queues", qt)
		line("RSS table", it.Table)
		label, text := hashLine(it, dry)
		line(label, text)

		moves := 0
		for _, ip := range it.IRQs {
			if ip.Want != "" {
				moves++
			}
		}
		switch {
		case it.IRQNote != "":
			line("interrupts", it.IRQNote)
		case len(it.IRQs) == 0:
		case moves == 0:
			line("interrupts", fmt.Sprintf("%d placed%s", len(it.IRQs), np.placedText(it, true)))
		case dry:
			line("interrupts", fmt.Sprintf("%d to place%s (%d to move)", len(it.IRQs), np.placedText(it, true), moves))
		default:
			line("interrupts", fmt.Sprintf("%d of %d not placed yet ('x-ui tune apply' places them)%s", moves, len(it.IRQs), np.placedText(it, true)))
		}

		xmoves := 0
		for _, ip := range it.XPS {
			if ip.Want != "" {
				xmoves++
			}
		}
		switch {
		case it.XPSNote != "":
			line("XPS", it.XPSNote)
		case xmoves == 0:
			line("XPS", np.xpsSummary(it))
		case dry:
			line("XPS", fmt.Sprintf("%s (%d queues to set)", np.xpsSummary(it), xmoves))
		default:
			line("XPS", fmt.Sprintf("%d queues not set yet: %s", xmoves, np.xpsSummary(it)))
		}

		rps := it.RPSNote
		for _, ip := range it.RPS {
			switch {
			case ip.Want != "" && dry:
				rps += fmt.Sprintf("; %s %s -> %s", ip.Key, shown(ip.Live), shown(ip.Want))
			case ip.Want != "":
				rps += fmt.Sprintf("; %s not set yet", ip.Key)
			case ip.Note != "":
				rps += fmt.Sprintf("; %s %s", ip.Key, ip.Note)
			}
		}
		line("RPS/RFS", rps)
		if it.Qdisc != nil {
			line("qdisc", it.Qdisc.text(dry))
		}
	}
	if ib := np.IRQBalance; ib != nil && (ib.Unit != "" || ib.Running) {
		e.printf("  %-11s %s\n", "irqbalance", ib.text())
	}
	if np.Unit != "" {
		e.printf("  %-11s %s raises the queues at boot\n", "boot unit", NICUnitFile)
	}
}

// nicDrift lists the NIC settings an apply would still change: kernel
// state, and x-ui-nic.service. A raise waiting for the boot is not drift.
func (e *Env) nicDrift(np *nicPlan, f *Facts) []string {
	var d []string
	if np.Skip != "" {
		return nil
	}
	for _, it := range np.NICs {
		add := func(what string, pending bool) {
			if pending {
				d = append(d, "NIC "+it.NIC.Name+" "+what)
			}
		}
		pend := func(items []*itemPlan) bool {
			for _, ip := range items {
				if ip.Want != "" {
					return true
				}
			}
			return false
		}
		irq := false
		for _, ip := range it.IRQs {
			if ip.Want != "" {
				irq = true
			}
		}
		add("UDP hashing", pend(it.Hash))
		add("interrupts", irq)
		add("XPS", pend(it.XPS))
		add("RPS", pend(it.RPS))
		add("qdisc", it.Qdisc != nil && (it.Qdisc.Want != "" || it.Qdisc.later))
	}
	if f.Init == "systemd" {
		have, _ := e.read(NICUnitFile)
		if np.Unit != have && (np.Unit != "" || e.isOurs(NICUnitFile)) {
			d = append(d, NICUnitFile)
		}
	}
	return d
}

// nicSummary is the installer's "Configured:" lines about the NICs.
func (np *nicPlan) summary() []string {
	if np.Skip != "" {
		return []string{"NIC: " + np.Skip}
	}
	var out []string
	for _, it := range np.NICs {
		n, q := it.NIC.Name, it.Queues
		switch q.State {
		case "raise":
			out = append(out, fmt.Sprintf("NIC %s: queues %d -> %d at the next boot (now: x-ui tune queues --now)", n, q.Current, q.Want))
		case "kept":
			note := q.Note
			if i := strings.Index(note, ":"); i >= 0 {
				note = note[:i]
			}
			out = append(out, fmt.Sprintf("NIC %s: %d queues, kept (%s)", n, q.Current, note))
		case "unsupported":
			out = append(out, fmt.Sprintf("NIC %s: %d queue%s", n, it.NIC.RxQueues, plural(it.NIC.RxQueues)))
		case "skip":
			out = append(out, fmt.Sprintf("NIC %s: %d queues (%s)", n, q.Current, q.Note))
		default:
			out = append(out, fmt.Sprintf("NIC %s: %d queues", n, q.Current))
		}
		for _, ip := range it.Hash {
			if strings.HasPrefix(ip.Note, "was ") || ip.Want != "" {
				_, text := hashLine(it, false)
				out = append(out, "UDP hashing "+n+": "+text)
				break
			}
		}
		if len(it.Hash) == 0 && it.HashNote != "" {
			out = append(out, "UDP hashing "+n+": "+strings.TrimPrefix(it.HashNote, "UDP hashed on "))
		}
		switch {
		case it.keep == "single":
		case it.IRQNote != "":
			out = append(out, "Interrupts "+n+": "+it.IRQNote)
		case len(it.IRQs) > 0:
			spread := fmt.Sprintf("%d queues", len(it.IRQs))
			if np.onePerCPU(it) {
				spread = "one queue per CPU"
			}
			out = append(out, "Interrupts "+n+": "+spread+"; "+np.irqSummaryList(it, false))
		}
		if it.XPSNote == "" && len(it.XPS) > 0 {
			out = append(out, "XPS "+n+": "+strings.Replace(np.xpsSummary(it), "every CPU", "each CPU", 1))
		}
		if strings.HasPrefix(it.RPSNote, "over CPUs") {
			out = append(out, "RPS/RFS "+n+": "+it.RPSNote)
		}
		if it.Qdisc != nil {
			out = append(out, "Qdisc "+n+": "+it.Qdisc.text(false))
		}
	}
	if ib := np.IRQBalance; ib != nil && (ib.Unit != "" || ib.Running) {
		names := strings.Join(ib.nics, ", ")
		paren := func(s string) string {
			if names == "" {
				return ""
			}
			return " (" + names + s + ")"
		}
		switch {
		case ib.Running && ib.Ours && !ib.Shadow:
			out = append(out, "irqbalance: running"+paren(" banned"))
		case ib.Running:
			out = append(out, "irqbalance: running without x-ui's policy"+paren(" left to it"))
		case len(ib.Banned) > 0:
			out = append(out, "irqbalance: not running"+paren(" banned when it runs"))
		default:
			out = append(out, "irqbalance: not running")
		}
	}
	return out
}

// onePerCPU says whether every eligible CPU serves exactly one of the
// NIC's queues.
func (np *nicPlan) onePerCPU(it *nicItem) bool {
	if np.place == nil {
		return false
	}
	per := map[int]int{}
	for _, cpu := range np.place.CPU[it.NIC.Name] {
		per[cpu]++
	}
	for _, c := range np.Eligible {
		if per[c] != 1 {
			return false
		}
	}
	return len(per) == len(np.Eligible)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
