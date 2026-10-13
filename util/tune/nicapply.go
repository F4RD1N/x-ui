//go:build linux

package tune

import (
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mhsanaei/3x-ui/v2/util/hw"
)

// applyNICs is an apply's NIC part (never the boot one): the uplinks' state
// entries, irqbalance's policy (host), the kernel state and UDP hashing, the
// queue raise to wait for the boot, and the unit that does it.
func (e *Env) applyNICs(f *Facts, st *State, o ApplyOptions, r *Result) {
	if f.Container() {
		return
	}
	host := !o.Auto || o.Host
	no := nicOpts{Instances: o.Instances, Host: host}
	e.endAttempts(st, r)
	np := e.planNICs(f, st, no)
	for _, n := range np.Notes {
		if np.Skip == "" {
			r.problem("NIC: %s", n)
		}
	}
	if np.Skip != "" {
		if !strings.HasSuffix(np.Skip, "(container)") {
			r.problem("NIC: %s", np.Skip)
		}
		e.applyNICUnit(f, st, r)
		return
	}
	if e.syncNICState(st, np, o.TakeIRQs) {
		np = e.planNICs(f, st, no)
	}
	if host && e.applyIRQBalance(np, st, r) {
		np = e.planNICs(f, st, no) // irqbalance restarted: what does it run with now?
	}
	if ib := np.IRQBalance; ib != nil && ib.Note != "" {
		r.problem("irqbalance: %s", ib.Note)
	}
	for _, it := range np.NICs {
		if it.keep == "irqbalance" || it.keep == "foreign" {
			r.problem("%s: interrupts %s", it.NIC.Name, it.IRQNote)
		}
	}
	np = e.applyNICKernel(f, st, np, no, r)
	e.recordQueues(st, np, r)
	e.applyNICUnit(f, st, r)
}

// syncNICState makes the state entries of the uplinks: a new one for a NIC
// x-ui has not seen at that address (or with another driver there). It
// reports whether an entry changed what the plan depends on.
func (e *Env) syncNICState(st *State, np *nicPlan, takeIRQs bool) bool {
	if st.NICs == nil {
		st.NICs = map[string]*NICState{}
	}
	replan := false
	for _, it := range np.NICs {
		ns := st.NICs[it.Key]
		if ns == nil || ns.Driver != it.NIC.Driver {
			ns = &NICState{Driver: it.NIC.Driver}
			st.NICs[it.Key] = ns
			replan = true
		}
		ns.Name = it.NIC.Name
		if takeIRQs && !ns.TakeIRQs {
			ns.TakeIRQs, replan = true, true
		}
	}
	return replan
}

// endAttempts turns a queue change that a dead run left half done into a
// failure: it is not tried again automatically.
func (e *Env) endAttempts(st *State, r *Result) {
	for _, k := range sortedStrings(st.NICs) {
		cs := st.NICs[k].Channels
		if cs == nil || cs.Attempt == nil {
			continue
		}
		a := cs.Attempt
		cs.Attempt = nil
		cs.Failed = fmt.Sprintf("interrupted (%d -> %d at %s)", a.From, a.To, a.At)
		r.problem("%s: a queue change was interrupted (%d -> %d at %s): not tried again; 'x-ui tune queues --now' does", st.NICs[k].Name, a.From, a.To, a.At)
	}
}

// applyNICKernel writes the planned kernel state of the NICs that have a
// state entry: UDP hashing, interrupt CPUs, XPS, RPS. A NIC whose
// interrupts turn out to be kernel-managed is planned again with them kept.
func (e *Env) applyNICKernel(f *Facts, st *State, np *nicPlan, no nicOpts, r *Result) *nicPlan {
	for round := 0; round < 3; round++ {
		managed := false
		for _, it := range np.NICs {
			ns := st.NICs[it.Key]
			if ns == nil {
				continue
			}
			e.writeHash(f, it, ns, r)
			if e.writeIRQs(f, np, it, ns, r) {
				managed = true
			}
		}
		if managed {
			np = e.planNICs(f, st, no)
			continue
		}
		for _, it := range np.NICs {
			if ns := st.NICs[it.Key]; ns != nil {
				e.writeQueueFiles(f, np, it, ns, r)
			}
		}
		break
	}
	return np
}

func (e *Env) writeHash(f *Facts, it *nicItem, ns *NICState, r *Result) {
	var done []string
	from, to := "", ""
	for _, ip := range it.Hash {
		if ip.Want == "" {
			continue
		}
		fl := hw.FlowUDP4
		if ip.Key == "udp6" {
			fl = hw.FlowUDP6
		}
		if err := e.eth().SetFlowHash(it.NIC.Name, fl, hw.HashIPsPorts); err != nil {
			r.problem("%s: %s hashing: %s", it.NIC.Name, ip.Key, ethNote(err))
			continue
		}
		bits, err := e.eth().FlowHash(it.NIC.Name, fl)
		if err != nil || bits != hw.HashIPsPorts {
			r.problem("%s: %s hashing did not take (%s)", it.NIC.Name, ip.Key, hw.HashLetters(bits))
			continue
		}
		if ns.Hash == nil {
			ns.Hash = map[string]*KeyState{}
		}
		ks := ns.Hash[ip.Key]
		if ks == nil || (ks.Orig == "" && ks.Written == "") {
			ks = &KeyState{Orig: ip.Live}
			ns.Hash[ip.Key] = ks
		}
		ks.Written = ip.Want
		done = append(done, ip.Key)
		from, to = hashWords(ip.Live), hashWords(ip.Want)
		ip.Live, ip.Want, ip.Note = ip.Want, "", "was "+hashWords(ks.Orig)
	}
	if len(done) > 0 {
		r.change("%s: UDP hashing (%s): %s -> %s (the driver logs \"fragmented packets may arrive out of order\": harmless for QUIC and WireGuard)",
			it.NIC.Name, strings.Join(done, ", "), from, to)
	}
}

// ethNote says why an ethtool call failed.
func ethNote(err error) string {
	switch {
	case errors.Is(err, hw.ErrNotSupported):
		return "not supported"
	case errors.Is(err, hw.ErrBusy):
		return "device busy"
	case errors.Is(err, syscall.EPERM):
		return "not permitted"
	case errors.Is(err, syscall.EROFS):
		return "read-only"
	}
	return err.Error()
}

// writeIRQs moves the interrupts. It reports whether they turned out to be
// managed by the kernel (EIO): then none is moved, and XPS follows them.
func (e *Env) writeIRQs(f *Facts, np *nicPlan, it *nicItem, ns *NICState, r *Result) bool {
	moved := 0
	for _, ip := range it.IRQs {
		if ip.Want == "" {
			continue
		}
		p := fmt.Sprintf("/proc/irq/%d/smp_affinity_list", ip.IRQ)
		err := e.writeKernel(p, ip.Want)
		if errors.Is(err, syscall.ENOSPC) && np.topo != nil {
			// No vector left on that CPU: its sibling, if any.
			for _, s := range np.topo.Siblings(ip.CPU) {
				if s != ip.CPU && np.Eligible.Has(s) {
					if err = e.writeKernel(p, strconv.Itoa(s)); err == nil {
						ip.Want, ip.CPU = strconv.Itoa(s), s
						break
					}
				}
			}
		}
		if errors.Is(err, syscall.EIO) {
			ns.Managed = true
			r.problem("%s: its interrupts are managed by the kernel: kept; XPS follows them", it.NIC.Name)
			return true
		}
		if err != nil {
			_, note := errState(err, f)
			if errors.Is(err, syscall.ENOSPC) {
				note = "no interrupt vector left on that CPU"
			}
			r.problem("%s: IRQ %d to CPU %s: %s", it.NIC.Name, ip.IRQ, ip.Want, note)
			continue
		}
		if ns.IRQ == nil {
			ns.IRQ = map[string]*IRQState{}
		}
		is := ns.IRQ[ip.Key]
		if is == nil || is.IRQ != ip.IRQ || (is.Orig == "" && is.Written == "") {
			// New, or renumbered (a queue change, a driver reload): its
			// value now is the one to go back to.
			is = &IRQState{IRQ: ip.IRQ, Orig: ip.Live}
			ns.IRQ[ip.Key] = is
		}
		is.Written = ip.Want
		ip.Live, ip.Want = ip.Want, ""
		moved++
	}
	if moved > 0 {
		r.change("%s: %d interrupts moved (%s)", it.NIC.Name, moved, np.irqSummary(it))
	}
	return false
}

// writeQueueFiles writes XPS and RPS.
func (e *Env) writeQueueFiles(f *Facts, np *nicPlan, it *nicItem, ns *NICState, r *Result) {
	write := func(ip *itemPlan, m map[string]*KeyState, val string) (map[string]*KeyState, bool) {
		if err := e.writeKernel(ip.Path, val); err != nil {
			_, note := errState(err, f)
			r.problem("%s: %s: %s", it.NIC.Name, ip.Key, note)
			return m, false
		}
		if m == nil {
			m = map[string]*KeyState{}
		}
		ks := m[ip.Key]
		if ks == nil || (ks.Orig == "" && ks.Written == "") {
			ks = &KeyState{Orig: ip.Live}
			m[ip.Key] = ks
		}
		ks.Written = ip.Want
		ip.Live, ip.Want = ip.Want, ""
		return m, true
	}
	xps := 0
	for _, ip := range it.XPS {
		if ip.Want == "" {
			continue
		}
		set, _ := parseCPUText(ip.Want)
		var ok bool
		if ns.XPS, ok = write(ip, ns.XPS, set.Mask(np.nrCPU)); ok {
			xps++
		}
	}
	if xps > 0 {
		r.change("%s: XPS set on %d queues (%s)", it.NIC.Name, xps, np.xpsSummary(it))
	}
	var rps []string
	for _, ip := range it.RPS {
		if ip.Want == "" {
			continue
		}
		val := ip.Want
		if strings.HasSuffix(ip.Key, "_cpus") {
			set, _ := parseCPUText(ip.Want)
			val = set.Mask(np.nrCPU)
		}
		want := ip.Want
		var ok bool
		if ns.RPS, ok = write(ip, ns.RPS, val); ok {
			rps = append(rps, path.Base(ip.Key)+" "+shown(want))
		}
	}
	if len(rps) > 0 {
		r.change("%s: RPS/RFS: %s", it.NIC.Name, strings.Join(rps, ", "))
	}
}

// recordQueues keeps the planned raises in the state, for the boot unit.
func (e *Env) recordQueues(st *State, np *nicPlan, r *Result) {
	for _, it := range np.NICs {
		ns := st.NICs[it.Key]
		if ns == nil {
			continue
		}
		q := it.Queues
		cs := ns.Channels
		switch {
		case q.Want > 0:
			if cs == nil {
				cs = &ChanState{}
				ns.Channels = cs
			}
			if cs.Want != q.Want {
				cs.Want = q.Want
				if q.State == "raise" {
					r.change("%s: queues %d -> %d at the next boot (now: x-ui tune queues --now; the link resets for a few seconds)", it.NIC.Name, q.Current, q.Want)
				}
			}
		case cs != nil && q.State != "skip":
			cs.Want = 0
		}
		if cs != nil && cs.Orig == nil && cs.Want == 0 && cs.RSSCap == 0 && cs.Failed == "" && cs.Attempt == nil {
			ns.Channels = nil
		}
	}
}

// stateWantsUnit says whether a raise waits for the boot.
func stateWantsUnit(st *State) bool {
	for _, ns := range st.NICs {
		if cs := ns.Channels; cs != nil && cs.Want > 0 && cs.Failed == "" {
			return true
		}
	}
	return false
}

// applyNICUnit writes and enables x-ui-nic.service while a raise waits for
// the boot, and disables and removes it otherwise.
func (e *Env) applyNICUnit(f *Facts, st *State, r *Result) {
	unit := ""
	if f.Init == "systemd" && !f.Container() && stateWantsUnit(st) {
		unit = renderNICUnit(e.Bin)
	}
	if unit == "" && e.isOurs(NICUnitFile) {
		_, _ = e.run("systemctl", "disable", "x-ui-nic.service")
	}
	changed := e.ownFile(NICUnitFile, unit, r)
	if changed {
		if _, err := e.run("systemctl", "daemon-reload"); err != nil && !e.fake() {
			r.problem("systemctl daemon-reload: %v", err)
		}
	}
	if unit != "" && (changed || (!e.fake() && !e.unitEnabled("x-ui-nic.service"))) {
		if _, err := e.run("systemctl", "enable", "x-ui-nic.service"); err != nil && !e.fake() {
			r.problem("systemctl enable x-ui-nic.service: %v", err)
		}
	}
}

func (e *Env) unitEnabled(u string) bool {
	out, _ := e.run("systemctl", "is-enabled", u)
	return out == "enabled"
}

// nicNameOf is the device a NIC state entry is about, in this network
// namespace ("" when it is not here).
func (e *Env) nicNameOf(key string) string {
	if !strings.Contains(key, ":") {
		if e.exists("/sys/class/net/" + key) {
			return key
		}
		return ""
	}
	for _, g := range []string{"/sys/bus/pci/devices/" + key + "/net/*", "/sys/bus/pci/devices/" + key + "/virtio*/net/*"} {
		if m := e.glob(g); len(m) > 0 {
			return path.Base(m[0])
		}
	}
	return ""
}

// revertNICs puts back every value x-ui changed that is still what x-ui
// wrote. A raised queue count stays until the next reboot: changing it
// would reset the link.
func (e *Env) revertNICs(f *Facts, st *State, dry bool, r *Result) {
	if f.Container() || len(st.NICs) == 0 {
		return
	}
	nr := 0
	if t, err := hw.ReadTopology(e.hw()); err == nil {
		nr = e.nrCPUs(t)
	}
	for _, key := range sortedStrings(st.NICs) {
		ns := st.NICs[key]
		name := e.nicNameOf(key)
		if name == "" {
			r.problem("%s (%s) is not here: its interrupts and queues come back at the next reboot", ns.Name, key)
			continue
		}
		n := hw.ReadNIC(e.hw(), e.eth(), name)
		// Interrupts and XPS are counted per NIC; RPS and hashing named.
		counted := map[string]int{}
		back := func(what, live, written, orig string, set func() error) {
			group := ""
			switch {
			case strings.HasPrefix(what, "IRQ "):
				group = "interrupts back to their CPUs"
			case strings.HasPrefix(what, "tx-"):
				group = "XPS masks back"
			}
			switch {
			case written == "":
			case live != written:
				r.problem("%s %s left at %s: changed since x-ui set %s", name, what, shown(live), shown(written))
			case dry && group != "":
				counted["would put "+group]++
			case dry:
				r.change("would restore %s %s to %s", name, what, shown(orig))
			default:
				if err := set(); err != nil {
					r.problem("%s %s: %v", name, what, err)
					return
				}
				if group != "" {
					counted[group]++
				} else {
					r.change("%s %s: %s -> %s", name, what, shown(live), shown(orig))
				}
			}
		}
		irqs := map[string]hw.QueueIRQ{}
		for _, q := range n.IRQs {
			irqs[irqKey(q)] = q
		}
		for _, k := range sortedStrings(ns.IRQ) {
			is := ns.IRQ[k]
			q, ok := irqs[k]
			if !ok || q.IRQ != is.IRQ {
				continue // gone, or a new interrupt since: the kernel's own
			}
			back(fmt.Sprintf("IRQ %d", q.IRQ), q.Affinity.List(), is.Written, is.Orig, func() error {
				return e.writeKernel(fmt.Sprintf("/proc/irq/%d/smp_affinity_list", q.IRQ), is.Orig)
			})
		}
		for _, group := range []struct {
			name string
			m    map[string]*KeyState
		}{{"XPS", ns.XPS}, {"RPS", ns.RPS}} {
			for _, k := range sortedStrings(group.m) {
				ks := group.m[k]
				p := "/sys/class/net/" + name + "/queues/" + k
				if group.name == "XPS" {
					p += "/xps_cpus"
				}
				if !e.exists(p) {
					continue
				}
				live := e.rpsLive(p)
				back(k, live, ks.Written, ks.Orig, func() error {
					val := ks.Orig
					if strings.HasSuffix(p, "_cpus") {
						set, err := parseCPUText(ks.Orig)
						if err != nil {
							return err
						}
						val = set.Mask(nr)
					}
					return e.writeKernel(p, val)
				})
			}
		}
		for _, k := range sortedStrings(ns.Hash) {
			ks := ns.Hash[k]
			fl := hw.FlowUDP4
			if k == "udp6" {
				fl = hw.FlowUDP6
			}
			bits, err := e.eth().FlowHash(name, fl)
			if err != nil {
				continue
			}
			back(k+" hashing", hw.HashLetters(bits), ks.Written, ks.Orig, func() error {
				want := uint64(hw.HashIPs)
				if ks.Orig == "sdfn" {
					want = hw.HashIPsPorts
				}
				return e.eth().SetFlowHash(name, fl, want)
			})
		}
		for _, g := range sortedStrings(counted) {
			r.change("%s: %d %s", name, counted[g], g)
		}
		if cs := ns.Channels; cs != nil && cs.Orig != nil && n.Channels != nil {
			cur, _ := chanCount(*n.Channels)
			orig, _ := chanCount(*cs.Orig)
			if cur != orig {
				r.change("%s keeps %d queues until the next reboot (%d after it)", name, cur, orig)
			}
		}
	}
}

// shown is a state value for people: "none" for the empty CPU set.
func shown(v string) string {
	if v == "-" {
		return "none"
	}
	return v
}

// irqSummary describes where an item's interrupts go.
func (np *nicPlan) irqSummary(it *nicItem) string {
	if np.place == nil {
		return ""
	}
	per := np.place.Units[it.NIC.Name]
	if !np.place.Split {
		return "one queue per physical core, the NIC's node first"
	}
	lo, hi := -1, 0
	for _, u := range np.units {
		c := per[u.Name][0]
		if lo < 0 || c < lo {
			lo = c
		}
		hi = max(hi, c)
	}
	s := fmt.Sprintf("RSS %d per instance", lo)
	if hi != lo {
		s = fmt.Sprintf("RSS %d-%d per instance", lo, hi)
	}
	if free := per[""]; free[0] > 0 {
		var cpus hw.CPUSet
		for q, cpu := range np.place.CPU[it.NIC.Name] {
			if np.place.Owner[it.NIC.Name][q] == "" && slicesContains(it.rss, q) {
				cpus = append(cpus, cpu)
			}
		}
		s += fmt.Sprintf(", %d on free CPUs %s", free[0], hw.NewCPUSet(cpus...).List())
	}
	return s
}

func slicesContains(s []int, x int) bool {
	for _, v := range s {
		if v == x {
			return true
		}
	}
	return false
}

// xpsSummary describes an item's XPS.
func (np *nicPlan) xpsSummary(it *nicItem) string {
	if np.place == nil {
		return ""
	}
	xps, cpu := np.place.XPS[it.NIC.Name], np.place.CPU[it.NIC.Name]
	if len(cpu) == 0 {
		return "the CPUs in groups by node and core, one group per queue"
	}
	own := true
	for q, cpus := range xps {
		for _, c := range cpus {
			if at, ok := cpu[q]; !ok || at != c {
				own = false
			}
		}
	}
	if own && len(cpu) > 0 {
		return "every CPU sends on its own queue"
	}
	return "each CPU sends on a queue of its core, else of its instance or node"
}

// clock and prober default to the real ones.
func (e *Env) clock() Clock {
	if e.Clock != nil {
		return e.Clock
	}
	return realClock{}
}

type realClock struct{}

func (realClock) Now() time.Time        { return time.Now() }
func (realClock) Sleep(d time.Duration) { time.Sleep(d) }
