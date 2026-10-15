//go:build linux

package tune

import (
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// The uplinks' root qdisc. net.core.default_qdisc only applies to qdiscs
// made after it is set: an uplink that came up before (at boot, before
// sysctl.d applies; or before the first apply) keeps the kernel's default of
// then, mq over pfifo_fast or fq_codel, and BBR runs without fq's pacing.
// While x-ui stands behind fq as the default qdisc, such a root is replaced:
// by mq on a multi-queue NIC, whose queues get the default qdisc (fq), by fq
// on a single queue. A root someone set up is never touched. A replace drops
// what is queued at that instant, so it is done once, not on every run;
// x-ui's own root is made again only when queues added since run something
// else (queues past the count mq was made with get pfifo_fast).

// tcQdisc is one qdisc as "tc -j qdisc show" lists it.
type tcQdisc struct {
	Kind   string `json:"kind"`
	Handle string `json:"handle"` // "8001:"; "0:" is one the kernel attached
	Root   bool   `json:"root,omitempty"`
	Parent string `json:"parent,omitempty"` // ":3" under "mq 0:", "8001:3"
}

// major is a handle's or a parent's major number ("8001:3": 0x8001).
func major(h string) uint64 {
	m, _, _ := strings.Cut(h, ":")
	n, _ := strconv.ParseUint(m, 16, 16)
	return n
}

// qdiscTree is a device's root qdisc and the qdiscs right under it (one per
// queue under mq).
type qdiscTree struct {
	root *tcQdisc
	kids []tcQdisc
	all  []tcQdisc
}

var errNoTC = errors.New("tc not found")

// readQdiscs reads a device's qdiscs.
func (e *Env) readQdiscs(dev string) (*qdiscTree, error) {
	out, err := e.run("tc", "-j", "qdisc", "show", "dev", dev)
	if err != nil {
		return nil, tcErr(out, err)
	}
	t := &qdiscTree{}
	if err := json.Unmarshal([]byte(out), &t.all); err != nil {
		return nil, fmt.Errorf("tc: %w", err)
	}
	for i := range t.all {
		if t.all[i].Root {
			t.root = &t.all[i]
		}
	}
	if t.root == nil {
		return nil, errors.New("tc lists no root qdisc")
	}
	for _, q := range t.all {
		if !q.Root && q.Parent != "" && major(q.Parent) == major(t.root.Handle) {
			t.kids = append(t.kids, q)
		}
	}
	return t, nil
}

// tcErr is why a tc command failed: what tc said, or that it is missing.
func tcErr(out string, err error) error {
	if errors.Is(err, exec.ErrNotFound) {
		return errNoTC
	}
	if l, _, _ := strings.Cut(out, "\n"); l != "" {
		return errors.New(strings.TrimPrefix(l, "Error: "))
	}
	return err
}

// fq says whether the root runs fq: fq itself, or mq with fq on each queue.
func (t *qdiscTree) fq() bool {
	switch t.root.Kind {
	case "fq":
		return true
	case "mq":
		return len(t.kids) > 0 && !slices.ContainsFunc(t.kids, func(q tcQdisc) bool { return q.Kind != "fq" })
	}
	return false
}

// foreign says whether someone made a qdisc under a root of the kernel's
// or x-ui's: those under them have handle 0:.
func (t *qdiscTree) foreign() bool {
	return slices.ContainsFunc(t.kids, func(q tcQdisc) bool { return q.Handle != "0:" })
}

// text describes the root: "mq, fq on 16 queues", "mq, fq on 14 queues,
// pfifo_fast on 2", "fq_codel", "htb 1:" (the handle when it is someone's).
func (t *qdiscTree) text(handle bool) string {
	s := t.root.Kind
	if handle && t.root.Handle != "0:" {
		s += " " + t.root.Handle
	}
	if t.root.Kind != "mq" || len(t.kids) == 0 {
		return s
	}
	n := map[string]int{}
	for _, q := range t.kids {
		n[q.Kind]++
	}
	kinds := sortedStrings(n)
	sort.SliceStable(kinds, func(i, j int) bool { return n[kinds[i]] > n[kinds[j]] })
	for i, k := range kinds {
		s += fmt.Sprintf(", %s on %d", k, n[k])
		if i == 0 {
			s += " queue" + plural(n[k])
		}
	}
	return s
}

// freeHandle is a handle no qdisc of the device has: a replace of x-ui's mq
// by another mq without a new handle would only change it in place.
func (t *qdiscTree) freeHandle() string {
	used := map[uint64]bool{}
	for _, q := range t.all {
		used[major(q.Handle)] = true
	}
	for h := uint64(0x8001); h < 0xffff; h++ {
		if !used[h] {
			return fmt.Sprintf("%x:", h)
		}
	}
	return ""
}

// owns says whether a root is x-ui's: its kind and handle, from this boot,
// with nothing of someone else's under it.
func (qs *QdiscState) owns(t *qdiscTree, boot string) bool {
	return qs != nil && qs.Handle != "" && qs.Handle == t.root.Handle && qs.Kind == t.root.Kind && qs.Boot == boot && !t.foreign()
}

// bootID tells this boot from the others.
func (e *Env) bootID() string { return e.readTrim("/proc/sys/kernel/random/boot_id") }

// qdiscPlan is a NIC's root qdisc.
type qdiscPlan struct {
	Live string `json:"live,omitempty"`  // "mq, fq on 16 queues"; "" not readable
	Want string `json:"write,omitempty"` // the root x-ui puts in, "mq" or "fq"; "" leaves it
	Note string `json:"note,omitempty"`

	tree  *qdiscTree
	ours  bool   // the root is x-ui's
	to    string // the root fq takes ("mq" or "fq"), also while an apply must set fq first
	later bool   // an apply makes fq the default, then switches the root
	fresh string // the handle x-ui's root is made again with
	by    string // the command that switches it
}

// fqDefault says whether x-ui stands behind fq as the default qdisc now (it
// sets net.core.default_qdisc to fq, BBR's pairing, and fq is the live
// value), or that an apply sets it first (later), or why the roots are left.
func (e *Env) fqDefault(f *Facts, st *State) (on, later bool, why string) {
	var k *KeyPlan
	for _, t := range Targets(f) {
		if t.Key == "net.core.default_qdisc" {
			k = e.planKey(t, f, st, e.othersSettings())
		}
	}
	switch {
	case k == nil:
		return false, false, "x-ui sets no default qdisc without BBR: kept"
	case k.HandBack || (k.State == "kept" && k.Others != k.Target):
		return false, false, fmt.Sprintf("the default qdisc is an admin's choice, %s in %s: kept", k.Others, k.OthersFile)
	case k.Live == k.Target && k.Want == "":
		return true, false, ""
	case k.Want == k.Target:
		return false, true, ""
	}
	return false, false, "net.core.default_qdisc is " + orDefault(k.Live, "not here") + ": kept"
}

// planQdisc plans a NIC's root qdisc.
func (e *Env) planQdisc(it *nicItem, st *State, on, later bool, why string) {
	qp := &qdiscPlan{by: "x-ui tune apply"}
	it.Qdisc = qp
	if it.ns != nil && !st.Disabled {
		qp.by = "x-ui tune nic"
	}
	t, err := e.readQdiscs(it.NIC.Name)
	if err != nil {
		qp.Note = "not readable (" + err.Error() + ")"
		return
	}
	qp.tree = t
	var qs *QdiscState
	if it.ns != nil {
		qs = it.ns.Qdisc
	}
	qp.ours = qs.owns(t, e.bootID())
	qp.Live = t.text(!qp.ours)
	qp.to = "fq"
	if t.root.Kind == "mq" {
		qp.to = "mq"
	}
	switch {
	case t.fq():
		if qp.ours {
			qp.Note = "was " + qs.Orig
		}
	case !qp.ours && (t.root.Handle != "0:" || t.foreign()):
		qp.Note = "set by someone else: kept"
	case t.root.Kind == "noqueue" || t.root.Kind == "noop":
		qp.Note = "kept"
	case !on:
		qp.Note, qp.later = why, later
	default:
		qp.Want = qp.to
		if qp.ours {
			qp.fresh = t.freeHandle()
		}
	}
}

// toText is the root fq takes, for people.
func (qp *qdiscPlan) toText() string {
	if qp.to == "mq" {
		return "mq, fq on each queue"
	}
	return "fq"
}

// text is the root qdisc line (dry: what an apply does).
func (qp *qdiscPlan) text(dry bool) string {
	switch {
	case qp.Live == "":
		return qp.Note
	case (qp.Want != "" || qp.later) && dry:
		return qp.Live + " -> " + qp.toText()
	case qp.Want != "":
		return qp.Live + " ('" + qp.by + "' switches it to fq)"
	case qp.later:
		return qp.Live + " ('x-ui tune apply' makes fq the default and switches it)"
	case qp.Note != "":
		return qp.Live + " (" + qp.Note + ")"
	}
	return qp.Live
}

// qdiscLag lists the uplinks that do not run fq: "eno1 still runs mq,
// pfifo_fast on 16 queues ('x-ui tune nic' switches it to fq)".
func (np *nicPlan) qdiscLag() string {
	var out []string
	for _, it := range np.NICs {
		if qp := it.Qdisc; qp != nil && qp.tree != nil && !qp.tree.fq() {
			out = append(out, it.NIC.Name+" still runs "+qp.text(false))
		}
	}
	return strings.Join(out, "; ")
}

// markQdisc records the root about to be put in (write ahead), with what
// runs now to go back to when the entry is new or about an earlier root.
func markQdisc(it *nicItem, ns *NICState) bool {
	qp := it.Qdisc
	if qp == nil || qp.Want == "" {
		return false
	}
	if ns.Qdisc == nil || !qp.ours {
		ns.Qdisc = &QdiscState{Orig: qp.Live}
	}
	ns.Qdisc.Pending = qp.Want
	return true
}

// unmarkQdisc forgets a root that was not put in.
func unmarkQdisc(ns *NICState) {
	if qs := ns.Qdisc; qs != nil && qs.Pending != "" {
		qs.Pending = ""
		if qs.Handle == "" {
			ns.Qdisc = nil
		}
	}
}

// settleQdisc ends a replace a dead run left marked: a root of the marked
// kind with a handle is x-ui's (the replace was done).
func (e *Env) settleQdisc(ns *NICState, name string) {
	qs := ns.Qdisc
	if qs == nil || qs.Pending == "" {
		return
	}
	if name != "" {
		if t, err := e.readQdiscs(name); err == nil && t.root.Kind == qs.Pending && t.root.Handle != "0:" {
			qs.Kind, qs.Handle, qs.Boot = t.root.Kind, t.root.Handle, e.bootID()
		}
	}
	unmarkQdisc(ns)
}

// writeQdisc puts the planned root in, and checks that every queue runs fq
// then. A NIC whose root is no longer x-ui's (a reboot, a driver reload,
// someone's tc) has nothing of x-ui's left to take back.
func (e *Env) writeQdisc(it *nicItem, ns *NICState, r *Result) {
	qp := it.Qdisc
	if qp == nil || qp.tree == nil {
		return
	}
	if qp.Want == "" {
		if ns.Qdisc != nil && ns.Qdisc.Pending == "" && !qp.ours {
			ns.Qdisc = nil
		}
		return
	}
	if ns.Qdisc == nil {
		markQdisc(it, ns)
	}
	name := it.NIC.Name
	args := []string{"qdisc", "replace", "dev", name, "root"}
	if qp.fresh != "" {
		args = append(args, "handle", qp.fresh)
	}
	out, err := e.run("tc", append(args, qp.Want)...)
	// The root as it is now says whether the replace took, also when tc
	// failed: a tc the timeout killed while it waited for the kernel's lock
	// still made the change.
	t, rerr := e.readQdiscs(name)
	if rerr != nil || t.root.Kind != qp.Want || t.root.Handle == "0:" || t.root.Handle == qp.tree.root.Handle {
		switch {
		case err != nil:
			r.problem("%s: root qdisc %s: %v", name, qp.Want, tcErr(out, err))
		case rerr != nil:
			r.problem("%s: root qdisc %s replaced, but not read back (%v): the next run checks it", name, qp.Want, rerr)
		default:
			r.problem("%s: root qdisc %s did not take (%s)", name, qp.Want, t.text(true))
		}
		if rerr != nil {
			// Not known whether it took: the mark stays, and the next run
			// settles it like a dead run's.
			ns.Qdisc.ran = true
			return
		}
		unmarkQdisc(ns)
		return
	}
	qs := ns.Qdisc
	qs.Kind, qs.Handle, qs.Boot, qs.Pending = t.root.Kind, t.root.Handle, e.bootID(), ""
	live := t.text(false)
	if t.fq() {
		r.change("%s: root qdisc %s -> %s", name, qp.Live, live)
	} else {
		r.problem("%s: root qdisc %s -> %s, not fq on each queue", name, qp.Live, live)
	}
	qp.tree, qp.ours, qp.Live, qp.Want, qp.fresh, qp.Note = t, true, live, "", "", "was "+qs.Orig
}

// revertQdiscs takes x-ui's root qdiscs off the NICs that still have them:
// the kernel attaches its default again, of the default qdisc as it is now
// (revert puts the sysctls back first). fq took over the pacing of every
// socket it carried, for good: BBR's own pacing does not come back for the
// connections open then, so the change says so when the new root is not fq.
func (e *Env) revertQdiscs(f *Facts, st *State, dry bool, r *Result) {
	if f.Container() {
		return
	}
	boot := e.bootID()
	for _, key := range sortedStrings(st.NICs) {
		qs := st.NICs[key].Qdisc
		name := e.nicNameOf(key)
		if qs == nil || qs.Handle == "" || qs.Boot != boot || name == "" {
			continue // none, gone with a reboot, or not here
		}
		t, err := e.readQdiscs(name)
		switch {
		case err != nil:
			r.problem("%s root qdisc: %v", name, err)
		case !qs.owns(t, boot):
			if t.root.Handle != "0:" {
				r.problem("%s root qdisc changed since x-ui set %s %s (now %s): left", name, qs.Kind, qs.Handle, t.text(true))
			}
		case dry:
			r.change("would put back %s's default root qdisc (was %s)", name, qs.Orig)
		default:
			if out, err := e.run("tc", "qdisc", "del", "dev", name, "root"); err != nil {
				r.problem("%s root qdisc: %v", name, tcErr(out, err))
				continue
			}
			now, paced := "the kernel's default", false
			if t2, err := e.readQdiscs(name); err == nil {
				now, paced = t2.text(true), t2.fq()
			}
			if !paced {
				now += " (BBR connections open now send unpaced until they close; an x-ui restart closes xray's)"
			}
			r.change("%s root qdisc: %s -> %s", name, t.text(false), now)
		}
	}
}
