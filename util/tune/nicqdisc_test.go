//go:build linux

package tune

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/util/hw"
	"github.com/mhsanaei/3x-ui/v2/util/hw/hwtest"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// fakeTC is tc over the devices of a fake tree, doing what the kernel does
// (checked on 6.8 in a network namespace): a device comes up with the
// kernel's default root, "mq 0:" with the default qdisc of then on each
// queue (that qdisc alone on one queue); "replace root mq" makes a root
// whose queues get the default qdisc of now, but queues added after it get
// pfifo_fast; a replace by the same kind without a handle changes nothing;
// "del root" brings the kernel's default back, and fails on handle 0:.
type fakeTC struct {
	e       *Env
	roots   map[string]*fakeRoot
	next    uint64            // the handle the kernel picked last
	fail    map[string]string // a command and what tc says when it fails
	missing bool              // tc is not installed
	calls   []string          // the commands that change something
	after   func(cmd string)  // runs after each change
}

type fakeRoot struct {
	kind, handle string
	kids         []string       // each queue's qdisc as the root was made
	own          map[int]string // a queue's qdisc someone put there: "pfifo 8010:"
}

// withTC is onHW with tc: the devices come up with the kernel's default
// root of the default qdisc boot.
func withTC(t *testing.T, hm hwtest.Machine, boot string, devs ...string) (*Env, *hwtest.Built, *fakeTC) {
	t.Helper()
	e, b := onHW(t, hm)
	tc := &fakeTC{e: e, roots: map[string]*fakeRoot{}, next: 0x8000, fail: map[string]string{}}
	for _, d := range devs {
		tc.up(d, boot)
	}
	prev := e.Run
	e.Run = func(d time.Duration, name string, args ...string) (string, error) {
		if name != "tc" {
			return prev(d, name, args...)
		}
		e.Ran = append(e.Ran, "tc "+strings.Join(args, " "))
		return tc.run(args)
	}
	return e, b, tc
}

func (tc *fakeTC) queues(dev string) int {
	return len(tc.e.glob("/sys/class/net/" + dev + "/queues/tx-*"))
}

func (tc *fakeTC) dflt() string {
	return normValue(tc.e.readTrim(sysctlPath("net.core.default_qdisc")))
}

// up is the kernel's default root, made with the default qdisc kind.
func (tc *fakeTC) up(dev, kind string) {
	r := &fakeRoot{kind: kind, handle: "0:"}
	if n := tc.queues(dev); n > 1 {
		r.kind = "mq"
		for q := 0; q < n; q++ {
			r.kids = append(r.kids, kind)
		}
	}
	tc.roots[dev] = r
}

var errExit = errors.New("exit status 2")

func (tc *fakeTC) run(args []string) (string, error) {
	if tc.missing {
		return "", &exec.Error{Name: "tc", Err: exec.ErrNotFound}
	}
	cmd := strings.Join(args, " ")
	if msg, ok := tc.fail[cmd]; ok {
		return msg, errExit
	}
	// "-j qdisc show dev X", "qdisc replace dev X root [handle H] KIND",
	// "qdisc del dev X root".
	if len(args) == 5 && args[0] == "-j" && args[3] == "dev" {
		return tc.show(args[4])
	}
	if len(args) < 5 || args[0] != "qdisc" || args[2] != "dev" || args[4] != "root" {
		return "Command line is not complete.", errExit
	}
	dev := args[3]
	r := tc.roots[dev]
	if r == nil {
		return fmt.Sprintf("Cannot find device %q", dev), errExit
	}
	switch args[1] {
	case "replace":
		rest := args[5:]
		if len(rest) != 1 && (len(rest) != 3 || rest[0] != "handle") {
			return "Command line is not complete.", errExit
		}
		kind, handle := rest[len(rest)-1], ""
		if len(rest) == 3 {
			handle = rest[1]
		}
		if handle == "" && r.handle != "0:" && r.kind == kind {
			break // changed in place: nothing to change
		}
		if handle == "" {
			tc.next++
			handle = fmt.Sprintf("%x:", tc.next)
		}
		n := tc.queues(dev)
		if kind == "mq" && n < 2 {
			return "Error: Specified qdisc kind is not supported on this device.", errExit
		}
		nr := &fakeRoot{kind: kind, handle: handle}
		if kind == "mq" {
			for q := 0; q < n; q++ {
				nr.kids = append(nr.kids, tc.dflt())
			}
		}
		tc.roots[dev] = nr
	case "del":
		if r.handle == "0:" {
			return "Error: Cannot delete qdisc with handle of zero.", errExit
		}
		tc.up(dev, tc.dflt())
	default:
		return "Command \"" + args[1] + "\" is unknown, try \"tc qdisc help\".", errExit
	}
	tc.calls = append(tc.calls, cmd)
	if tc.after != nil {
		tc.after(cmd)
	}
	return "", nil
}

func (tc *fakeTC) show(dev string) (string, error) {
	r := tc.roots[dev]
	if r == nil {
		return fmt.Sprintf("Cannot find device %q", dev), errExit
	}
	type q map[string]any
	list := []q{{"kind": r.kind, "handle": r.handle, "root": true, "options": q{}}}
	if r.kind == "mq" {
		pre := r.handle
		if pre == "0:" {
			pre = ":"
		}
		for i := tc.queues(dev) - 1; i >= 0; i-- {
			kind, handle := "pfifo_fast", "0:"
			if i < len(r.kids) {
				kind = r.kids[i]
			}
			if o, ok := r.own[i]; ok {
				kind, handle, _ = strings.Cut(o, " ")
			}
			list = append(list, q{"kind": kind, "handle": handle, "parent": pre + strconv.Itoa(i+1), "options": q{}})
		}
	}
	out, _ := json.Marshal(list)
	return string(out), nil
}

// text is what runs on a device, as status says it.
func (tc *fakeTC) text(t *testing.T, dev string) string {
	t.Helper()
	tr, err := tc.e.readQdiscs(dev)
	if err != nil {
		t.Fatal(err)
	}
	return tr.text(true)
}

func qdiscState(t *testing.T, e *Env, key string) *QdiscState {
	t.Helper()
	st, _, err := e.loadState()
	if err != nil || st.NICs[key] == nil {
		t.Fatalf("no state for %s: %v", key, err)
	}
	return st.NICs[key].Qdisc
}

func joined(s []string) string { return strings.Join(s, "\n") }

// unpaced ends a revert's change that leaves a root without fq.
const unpaced = " (BBR connections open now send unpaced until they close; an x-ui restart closes xray's)"

// keyLine is a key's row in status.
func keyLine(status, key string) string {
	for _, l := range strings.Split(status, "\n") {
		if strings.HasPrefix(l, key+" ") {
			return l
		}
	}
	return ""
}

// The uplink came up before fq was the default (pfifo_fast on production,
// fq_codel on the EPYC boxes): status says so, an apply puts mq in its
// place, whose queues all get fq, once; status and the summary show it;
// revert takes x-ui's root off after the sysctls, so the kernel's default
// comes back with the default qdisc of before.
func TestQdiscKernelDefault(t *testing.T) {
	for _, c := range []struct {
		boot, nic, key string
		m              hwtest.Machine
		queues         int
	}{
		{"pfifo_fast", "eno1", "0000:82:00.0", hwtest.Production(), 56},
		{"fq_codel", "enp65s0f0np0", "0000:41:00.0", hwtest.EPYC(1), 63},
	} {
		e, _, tc := withTC(t, c.m, c.boot, c.nic)
		was := fmt.Sprintf("mq, %s on %d queues", c.boot, c.queues)
		now := fmt.Sprintf("mq, fq on %d queues", c.queues)
		got := statusText(t, e)
		if !strings.Contains(got, "qdisc       "+was+" ('x-ui tune apply' makes fq the default and switches it)") {
			t.Errorf("%s: status before:\n%s", c.boot, got)
		}
		if d, _ := e.Status(false); !slices.Contains(d, "NIC "+c.nic+" qdisc") {
			t.Errorf("%s: drift %v", c.boot, d)
		}
		var out strings.Builder
		e.Out = &out
		if _, err := e.Apply(ApplyOptions{DryRun: true}, "t"); err != nil || !strings.Contains(out.String(), "qdisc       "+was+" -> mq, fq on each queue") || len(tc.calls) != 0 {
			t.Errorf("%s: dry run %v %v:\n%s", c.boot, err, tc.calls, out.String())
		}

		r := mustApply(t, e, ApplyOptions{Auto: true})
		if !slices.Contains(r.Changed, c.nic+": root qdisc "+was+" -> "+now) || !slices.Equal(tc.calls, []string{"qdisc replace dev " + c.nic + " root mq"}) {
			t.Errorf("%s: apply %v %v %v", c.boot, r.Changed, r.Problems, tc.calls)
		}
		if qs := qdiscState(t, e, c.key); qs == nil || *qs != (QdiscState{Orig: was, Kind: "mq", Handle: "8001:"}) {
			t.Errorf("%s: state %+v", c.boot, qs)
		}
		// Again, and "tune nic": nothing.
		if r := mustApply(t, e, ApplyOptions{Auto: true}); len(r.Changed) != 0 {
			t.Errorf("%s: second apply %v", c.boot, r.Changed)
		}
		if r, err := e.RunNIC(NICOptions{}); err != nil || len(r.Changed)+len(r.Problems) != 0 || len(tc.calls) != 1 {
			t.Errorf("%s: tune nic %v %v %v", c.boot, r, err, tc.calls)
		}
		got = statusText(t, e)
		if !strings.Contains(got, "qdisc       "+now+" (was "+was+")") || strings.Contains(got, "partly") {
			t.Errorf("%s: status:\n%s", c.boot, got)
		}
		if d, _ := e.Status(false); len(d) != 0 {
			t.Errorf("%s: drift %v", c.boot, d)
		}
		sum := e.summary()
		if !slices.Contains(sum, "Qdisc "+c.nic+": "+now+" (was "+was+")") || !slices.Contains(sum, "Congestion control: bbr with fq") {
			t.Errorf("%s: summary\n%s", c.boot, joined(sum))
		}

		rv, err := e.Revert(false, false)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(rv.Changed, c.nic+" root qdisc: "+now+" -> mq, fq_codel on "+strconv.Itoa(c.queues)+" queues"+unpaced) ||
			!slices.Contains(tc.calls, "qdisc del dev "+c.nic+" root") || tc.roots[c.nic].handle != "0:" {
			t.Errorf("%s: revert %v %v %v", c.boot, rv.Changed, rv.Problems, tc.calls)
		}
		if r, _ := e.RunNIC(NICOptions{}); len(r.Changed) != 0 {
			t.Errorf("%s: tune nic after revert: %v", c.boot, r.Changed)
		}
	}
}

// Already fq (the uplink came up after the sysctl): nothing is replaced and
// nothing recorded. A single-queue NIC gets fq itself as its root; a bond's
// slaves each get mq, the bond (noqueue) is not touched.
func TestQdiscKinds(t *testing.T) {
	e, _, tc := withTC(t, hwtest.Production(), "fq", "eno1")
	mustApply(t, e, ApplyOptions{Auto: true})
	if len(tc.calls) != 0 || qdiscState(t, e, "0000:82:00.0") != nil {
		t.Errorf("already fq: %v %+v", tc.calls, qdiscState(t, e, "0000:82:00.0"))
	}
	if got := statusText(t, e); !strings.Contains(got, "qdisc       mq, fq on 56 queues\n") {
		t.Errorf("already fq: status\n%s", got)
	}

	// fq the default already, from elsewhere, but the uplink came up before:
	// revert brings the kernel's default back with fq, so nothing goes
	// unpaced.
	e, b, tc := withTC(t, hwtest.Production(), "pfifo_fast", "eno1")
	b.WriteFile(sysctlPath("net.core.default_qdisc"), "fq\n")
	mustApply(t, e, ApplyOptions{Auto: true})
	rv, _ := e.Revert(false, false)
	if !slices.Equal(tc.calls, []string{"qdisc replace dev eno1 root mq", "qdisc del dev eno1 root"}) ||
		!slices.Contains(rv.Changed, "eno1 root qdisc: mq, fq on 56 queues -> mq, fq on 56 queues") {
		t.Errorf("fq the default already: %v %v %v", tc.calls, rv.Changed, rv.Problems)
	}

	e, _, tc = withTC(t, hwtest.VPS(2), "pfifo_fast", "eth0")
	r := mustApply(t, e, ApplyOptions{})
	if !slices.Contains(r.Changed, "eth0: root qdisc pfifo_fast -> fq") || !slices.Equal(tc.calls, []string{"qdisc replace dev eth0 root fq"}) {
		t.Errorf("single queue: %v %v %v", r.Changed, r.Problems, tc.calls)
	}
	if qs := qdiscState(t, e, "0000:00:03.0"); qs == nil || *qs != (QdiscState{Orig: "pfifo_fast", Kind: "fq", Handle: "8001:"}) {
		t.Errorf("single queue: state %+v", qs)
	}
	if got := statusText(t, e); !strings.Contains(got, "qdisc       fq (was pfifo_fast)") {
		t.Errorf("single queue: status\n%s", got)
	}
	if rv, _ := e.Revert(false, false); !slices.Contains(rv.Changed, "eth0 root qdisc: fq -> fq_codel"+unpaced) {
		t.Errorf("single queue: revert %v %v", rv.Changed, rv.Problems)
	}

	e, _, tc = withTC(t, hwtest.Bond(), "pfifo_fast", "eno1", "eno2")
	tc.roots["bond0"] = &fakeRoot{kind: "noqueue", handle: "0:"}
	r = mustApply(t, e, ApplyOptions{Auto: true})
	if !slices.Equal(tc.calls, []string{"qdisc replace dev eno1 root mq", "qdisc replace dev eno2 root mq"}) || tc.roots["bond0"].kind != "noqueue" ||
		slices.ContainsFunc(e.Ran, func(c string) bool { return strings.Contains(c, "bond0") }) {
		t.Errorf("bond: %v %v", tc.calls, e.Ran)
	}
	for _, k := range []string{"0000:82:00.0", "0000:82:00.1"} {
		if qs := qdiscState(t, e, k); qs == nil || qs.Kind != "mq" || qs.Orig != "mq, pfifo_fast on 16 queues" {
			t.Errorf("bond: %s state %+v", k, qs)
		}
	}
	if tc.text(t, "eno1") != "mq 8001:, fq on 16 queues" || tc.text(t, "eno2") != "mq 8002:, fq on 16 queues" {
		t.Errorf("bond: %s / %s", tc.text(t, "eno1"), tc.text(t, "eno2"))
	}

	// A device that is down (noop) or has no queue is left.
	e, _, tc = withTC(t, hwtest.Production(), "pfifo_fast", "eno1")
	tc.roots["eno1"] = &fakeRoot{kind: "noqueue", handle: "0:"}
	mustApply(t, e, ApplyOptions{})
	if len(tc.calls) != 0 {
		t.Errorf("noqueue: %v", tc.calls)
	}
}

// A root someone set up (htb 1:, or a queue's qdisc under the kernel's mq)
// is kept and shown; while fq is the default, status does not call it fine.
// A default qdisc an admin chose, or one x-ui does not set, keeps the roots
// too.
func TestQdiscKept(t *testing.T) {
	e, _, tc := withTC(t, hwtest.Production(), "pfifo_fast", "eno1")
	tc.roots["eno1"] = &fakeRoot{kind: "htb", handle: "1:"}
	r := mustApply(t, e, ApplyOptions{Auto: true})
	if len(tc.calls) != 0 || len(r.Problems) != 0 || qdiscState(t, e, "0000:82:00.0") != nil {
		t.Errorf("htb: %v %v", tc.calls, r.Problems)
	}
	got := statusText(t, e)
	if !strings.Contains(got, "qdisc       htb 1: (set by someone else: kept)") ||
		!strings.Contains(keyLine(got, "net.core.default_qdisc"), "  partly: eno1 still runs htb 1: (set by someone else: kept) [") {
		t.Errorf("htb: status\n%s", got)
	}
	if d, _ := e.Status(false); len(d) != 0 {
		t.Errorf("htb: drift %v", d)
	}
	if sum := e.summary(); !slices.Contains(sum, "Congestion control: bbr with fq, but eno1 still runs htb 1: (set by someone else: kept)") {
		t.Errorf("htb: summary\n%s", joined(sum))
	}
	tc.up("eno1", "pfifo_fast")
	tc.roots["eno1"].own = map[int]string{3: "cake 8010:"}
	mustApply(t, e, ApplyOptions{Auto: true})
	if len(tc.calls) != 0 {
		t.Errorf("a queue's qdisc: %v", tc.calls)
	}
	if got := statusText(t, e); !strings.Contains(got, "qdisc       mq, pfifo_fast on 55 queues, cake on 1 (set by someone else: kept)") {
		t.Errorf("a queue's qdisc: status\n%s", got)
	}

	// The admin's default qdisc.
	e, b, tc := withTC(t, hwtest.Production(), "pfifo_fast", "eno1")
	b.WriteFile("/etc/sysctl.d/90-admin.conf", "net.core.default_qdisc = fq_codel\n")
	mustApply(t, e, ApplyOptions{Auto: true})
	if len(tc.calls) != 0 || live(t, e, "net.core.default_qdisc") != "fq_codel" {
		t.Errorf("admin's default: %v %s", tc.calls, live(t, e, "net.core.default_qdisc"))
	}
	if got := statusText(t, e); !strings.Contains(got, "qdisc       mq, pfifo_fast on 56 queues (the default qdisc is an admin's choice, fq_codel in /etc/sysctl.d/90-admin.conf: kept)") {
		t.Errorf("admin's default: status\n%s", got)
	}
	if d, _ := e.Status(false); len(d) != 0 {
		t.Errorf("admin's default: drift %v", d)
	}
	// Set live by someone after the apply: "tune nic" leaves the root.
	e, b, tc = withTC(t, hwtest.Production(), "fq", "eno1")
	mustApply(t, e, ApplyOptions{Auto: true})
	b.WriteFile(sysctlPath("net.core.default_qdisc"), "cake\n")
	tc.up("eno1", "pfifo_fast")
	if r, _ := e.RunNIC(NICOptions{}); len(tc.calls) != 0 || len(r.Changed) != 0 {
		t.Errorf("default changed live: %v %v", tc.calls, r.Changed)
	}
	// No BBR, so no default qdisc of x-ui's.
	e, _, tc = withTC(t, hwtest.Production(), "pfifo_fast", "eno1")
	e.Facts.Kernel = "4.9.0"
	mustApply(t, e, ApplyOptions{Auto: true})
	if got := statusText(t, e); len(tc.calls) != 0 || !strings.Contains(got, "qdisc       mq, pfifo_fast on 56 queues (x-ui sets no default qdisc without BBR: kept)") {
		t.Errorf("no BBR: %v\n%s", tc.calls, got)
	}
	// fq only in an admin's file, not live yet, or no default qdisc to
	// read: a new mq's queues would not get fq, so every run would make it
	// again. No run replaces the root.
	for _, c := range []struct {
		what, note string
		set        func(b *hwtest.Built)
	}{
		{"fq in an admin's file only", "net.core.default_qdisc is fq_codel: kept", func(b *hwtest.Built) {
			b.WriteFile("/etc/sysctl.d/90-admin.conf", "net.core.default_qdisc = fq\n")
			b.WriteFile(sysctlPath("net.core.default_qdisc"), "fq_codel\n")
		}},
		{"no default qdisc", "net.core.default_qdisc is not here: kept", func(b *hwtest.Built) {
			if err := os.Remove(b.Path(sysctlPath("net.core.default_qdisc"))); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		e, b, tc := withTC(t, hwtest.Production(), "pfifo_fast", "eno1")
		c.set(b)
		mustApply(t, e, ApplyOptions{Auto: true})
		for i := 0; i < 2; i++ {
			if _, err := e.RunNIC(NICOptions{}); err != nil {
				t.Fatal(err)
			}
		}
		if len(tc.calls) != 0 {
			t.Errorf("%s: %v", c.what, tc.calls)
		}
		if got := statusText(t, e); !strings.Contains(got, "qdisc       mq, pfifo_fast on 56 queues ("+c.note+")") {
			t.Errorf("%s: status\n%s", c.what, got)
		}
	}
}

// Revert deletes only x-ui's own root: not one someone put in its place, not
// after a reboot (the kernel's default is back, and handles start over), and
// not with someone's qdisc under it. After a reboot whose uplink came up
// before the sysctl, "tune nic" switches it again, and status says so until
// then.
func TestQdiscRevertAndReboot(t *testing.T) {
	e, _, tc := withTC(t, hwtest.Production(), "pfifo_fast", "eno1")
	mustApply(t, e, ApplyOptions{Auto: true})
	tc.roots["eno1"] = &fakeRoot{kind: "htb", handle: "1:"}
	rv, _ := e.Revert(false, false)
	if !slices.Equal(rv.Problems, []string{"eno1 root qdisc changed since x-ui set mq 8001: (now htb 1:): left"}) || slices.Contains(tc.calls, "qdisc del dev eno1 root") {
		t.Errorf("someone's root: %v %v", rv.Problems, tc.calls)
	}
	// Someone's root at the handle x-ui's had: the kind tells them apart.
	e, _, tc = withTC(t, hwtest.Production(), "pfifo_fast", "eno1")
	mustApply(t, e, ApplyOptions{Auto: true})
	tc.roots["eno1"] = &fakeRoot{kind: "htb", handle: "8001:"}
	rv, _ = e.Revert(false, false)
	if !slices.Equal(rv.Problems, []string{"eno1 root qdisc changed since x-ui set mq 8001: (now htb 8001:): left"}) || slices.Contains(tc.calls, "qdisc del dev eno1 root") {
		t.Errorf("someone's root at x-ui's handle: %v %v", rv.Problems, tc.calls)
	}

	e, _, tc = withTC(t, hwtest.Production(), "pfifo_fast", "eno1")
	mustApply(t, e, ApplyOptions{Auto: true})
	tc.roots["eno1"].own = map[int]string{0: "pfifo 8010:"}
	if rv, _ := e.Revert(false, false); slices.Contains(tc.calls, "qdisc del dev eno1 root") || len(rv.Problems) != 1 {
		t.Errorf("someone's qdisc under x-ui's: %v %v", rv.Problems, tc.calls)
	}

	// A reboot: another boot ID, the kernel's default back, fq_codel at boot.
	e, b, tc := withTC(t, hwtest.Production(), "pfifo_fast", "eno1")
	b.WriteFile("/proc/sys/kernel/random/boot_id", "boot-1\n")
	mustApply(t, e, ApplyOptions{Auto: true})
	if qs := qdiscState(t, e, "0000:82:00.0"); qs == nil || qs.Boot != "boot-1" {
		t.Fatalf("state %+v", qs)
	}
	b.WriteFile("/proc/sys/kernel/random/boot_id", "boot-2\n")
	tc.next = 0x8000
	tc.up("eno1", "fq_codel")
	got := statusText(t, e)
	if !strings.Contains(got, "qdisc       mq, fq_codel on 56 queues ('x-ui tune nic' switches it to fq)") ||
		!strings.Contains(keyLine(got, "net.core.default_qdisc"), "  partly: eno1 still runs mq, fq_codel on 56 queues ('x-ui tune nic' switches it to fq) [") {
		t.Errorf("after the reboot: status\n%s", got)
	}
	// The usage says so of the command status names.
	if _, nic, _ := strings.Cut(usage, "\n  nic [--boot]"); !strings.Contains(strings.SplitN(nic, "\n\n", 2)[0], "fq") {
		t.Errorf("usage: 'nic' does not say it puts fq on the uplinks:\n%s", usage)
	}
	if d, _ := e.Status(false); !slices.Equal(d, []string{"NIC eno1 qdisc"}) {
		t.Errorf("after the reboot: drift %v", d)
	}
	// Someone's mq got the handle x-ui's had before the reboot: not x-ui's.
	tc.roots["eno1"] = &fakeRoot{kind: "mq", handle: "8001:", kids: []string{"fq_codel"}}
	if r, _ := e.RunNIC(NICOptions{}); len(tc.calls) != 1 || len(r.Changed) != 0 {
		t.Errorf("someone's mq after the reboot: %v %v", tc.calls, r.Changed)
	}
	if rv, _ := e.Revert(false, true); slices.ContainsFunc(rv.Changed, func(c string) bool { return strings.Contains(c, "root qdisc") }) {
		t.Errorf("dry revert after the reboot: %v", rv.Changed)
	}
	tc.up("eno1", "fq_codel")
	r, _ := e.RunNIC(NICOptions{})
	if !slices.Contains(r.Changed, "eno1: root qdisc mq, fq_codel on 56 queues -> mq, fq on 56 queues") {
		t.Errorf("tune nic after the reboot: %v %v", r.Changed, r.Problems)
	}
	if qs := qdiscState(t, e, "0000:82:00.0"); qs == nil || *qs != (QdiscState{Orig: "mq, fq_codel on 56 queues", Kind: "mq", Handle: "8001:", Boot: "boot-2"}) {
		t.Errorf("after the reboot: state %+v", qs)
	}
	if rv, _ := e.Revert(false, true); !slices.Contains(rv.Changed, "would put back eno1's default root qdisc (was mq, fq_codel on 56 queues)") {
		t.Errorf("dry revert: %v", rv.Changed)
	}
	// The next reboot comes up with fq (the sysctl first): the old entry goes.
	b.WriteFile("/proc/sys/kernel/random/boot_id", "boot-3\n")
	tc.up("eno1", "fq")
	if r, _ := e.RunNIC(NICOptions{}); len(r.Changed) != 0 || qdiscState(t, e, "0000:82:00.0") != nil {
		t.Errorf("a boot with fq: %v %+v", r.Changed, qdiscState(t, e, "0000:82:00.0"))
	}
	if rv, _ := e.Revert(false, false); slices.Contains(tc.calls, "qdisc del dev eno1 root") || len(rv.Problems) != 0 {
		t.Errorf("revert after a boot with fq: %v %v", rv.Problems, tc.calls)
	}
}

// A queue raise at boot: the queues added under mq run pfifo_fast, so the
// root is made again (x-ui's, with a new handle; the kernel's default of a
// boot that came up before the sysctl, like any other).
func TestQdiscAfterRaise(t *testing.T) {
	for _, c := range []struct {
		before, replace, from, orig string
	}{
		{"x-ui's", "qdisc replace dev eth1 root handle 8002: mq", "mq, fq on 16 queues, pfifo_fast on 12", "mq, fq_codel on 16 queues"},
		{"the kernel's", "qdisc replace dev eth1 root mq", "mq, fq_codel on 16 queues, pfifo_fast on 12", "mq, fq_codel on 16 queues, pfifo_fast on 12"},
	} {
		e, b, tc := withTC(t, raiseMachine("i40e", 0), "fq_codel", "eth1")
		b.WriteFile("/proc/sys/kernel/random/boot_id", "boot-1\n")
		mustApply(t, e, ApplyOptions{Auto: true})
		if c.before == "the kernel's" {
			b.WriteFile("/proc/sys/kernel/random/boot_id", "boot-2\n")
			tc.up("eth1", "fq_codel")
		}
		r, err := e.RunNIC(NICOptions{Boot: true})
		if err != nil || len(calls(b, "SetChannels")) != 1 {
			t.Fatalf("%s: %v %v", c.before, err, b.Eth.Calls)
		}
		if !slices.Equal(tc.calls, []string{"qdisc replace dev eth1 root mq", c.replace}) || tc.text(t, "eth1") != "mq 8002:, fq on 28 queues" || len(r.Problems) != 0 {
			t.Errorf("%s: %v %s %v", c.before, tc.calls, tc.text(t, "eth1"), r.Problems)
		}
		if !slices.Contains(r.Changed, "eth1: root qdisc "+c.from+" -> mq, fq on 28 queues") {
			t.Errorf("%s: changes %v", c.before, r.Changed)
		}
		if qs := qdiscState(t, e, "0000:3b:00.0"); qs == nil || qs.Orig != c.orig || qs.Handle != "8002:" {
			t.Errorf("%s: state %+v", c.before, qs)
		}
		if d, _ := e.Status(false); len(d) != 0 {
			t.Errorf("%s: drift %v", c.before, d)
		}
	}
}

// tc missing, or failing: status says so, the run goes on without it.
func TestQdiscTCProblems(t *testing.T) {
	e, _, tc := withTC(t, hwtest.Production(), "pfifo_fast", "eno1")
	tc.missing = true
	r := mustApply(t, e, ApplyOptions{Auto: true})
	if strings.Contains(joined(r.Problems), "qdisc") || qdiscState(t, e, "0000:82:00.0") != nil || !strings.Contains(joined(r.Changed), "interrupts moved") {
		t.Errorf("no tc: %v %v", r.Changed, r.Problems)
	}
	if got := statusText(t, e); !strings.Contains(got, "qdisc       not readable (tc not found)") {
		t.Errorf("no tc: status\n%s", got)
	}
	if d, _ := e.Status(false); len(d) != 0 {
		t.Errorf("no tc: drift %v", d)
	}
	if sum := e.summary(); !slices.Contains(sum, "Qdisc eno1: not readable (tc not found)") || !slices.Contains(sum, "Congestion control: bbr with fq") {
		t.Errorf("no tc: summary\n%s", joined(sum))
	}

	e, _, tc = withTC(t, hwtest.Production(), "pfifo_fast", "eno1")
	tc.fail["qdisc replace dev eno1 root mq"] = "RTNETLINK answers: Operation not permitted"
	r = mustApply(t, e, ApplyOptions{Auto: true})
	if !slices.Contains(r.Problems, "eno1: root qdisc mq: RTNETLINK answers: Operation not permitted") || qdiscState(t, e, "0000:82:00.0") != nil {
		t.Errorf("replace fails: %v %+v", r.Problems, qdiscState(t, e, "0000:82:00.0"))
	}
	if d, _ := e.Status(false); !slices.Contains(d, "NIC eno1 qdisc") {
		t.Errorf("replace fails: drift %v", d)
	}

	// Making x-ui's root again fails: the root it had is still x-ui's, not
	// taken for the new one.
	e, _, tc = withTC(t, hwtest.Production(), "pfifo_fast", "eno1")
	mustApply(t, e, ApplyOptions{Auto: true})
	tc.roots["eno1"].kids[0] = "pfifo_fast"
	tc.fail["qdisc replace dev eno1 root handle 8002: mq"] = "RTNETLINK answers: Cannot allocate memory"
	r, _ = e.RunNIC(NICOptions{})
	if !slices.Equal(r.Problems, []string{"eno1: root qdisc mq: RTNETLINK answers: Cannot allocate memory"}) || len(r.Changed) != 0 {
		t.Errorf("x-ui's root again fails: %v %v", r.Changed, r.Problems)
	}
	if qs := qdiscState(t, e, "0000:82:00.0"); qs == nil || *qs != (QdiscState{Orig: "mq, pfifo_fast on 56 queues", Kind: "mq", Handle: "8001:"}) {
		t.Errorf("x-ui's root again fails: state %+v", qs)
	}

	// tc killed by the timeout while it waited for the kernel's lock: the
	// kernel made the change all the same, and it is x-ui's.
	e, _, tc = withTC(t, hwtest.Production(), "pfifo_fast", "eno1")
	run := e.Run
	e.Run = func(d time.Duration, name string, args ...string) (string, error) {
		out, err := run(d, name, args...)
		if name == "tc" && args[0] == "qdisc" {
			return "", errors.New("signal: killed")
		}
		return out, err
	}
	r = mustApply(t, e, ApplyOptions{Auto: true})
	if strings.Contains(joined(r.Problems), "qdisc") || !slices.Contains(r.Changed, "eno1: root qdisc mq, pfifo_fast on 56 queues -> mq, fq on 56 queues") {
		t.Errorf("tc killed: %v %v", r.Changed, r.Problems)
	}
	if qs := qdiscState(t, e, "0000:82:00.0"); qs == nil || *qs != (QdiscState{Orig: "mq, pfifo_fast on 56 queues", Kind: "mq", Handle: "8001:"}) {
		t.Errorf("tc killed: state %+v", qs)
	}

	// Replaced, but tc cannot list the qdiscs after: the mark stays, the
	// next run takes the root as x-ui's (no second replace), and revert
	// takes it off.
	e, _, tc = withTC(t, hwtest.Production(), "pfifo_fast", "eno1")
	tc.after = func(string) { tc.fail["-j qdisc show dev eno1"] = "Dump terminated" }
	r = mustApply(t, e, ApplyOptions{Auto: true})
	if !slices.Contains(r.Problems, "eno1: root qdisc mq replaced, but not read back (Dump terminated): the next run checks it") || len(tc.calls) != 1 {
		t.Errorf("not read back: %v %v", r.Problems, tc.calls)
	}
	if qs := qdiscState(t, e, "0000:82:00.0"); qs == nil || *qs != (QdiscState{Orig: "mq, pfifo_fast on 56 queues", Pending: "mq"}) {
		t.Errorf("not read back: state %+v", qs)
	}
	tc.after = nil
	delete(tc.fail, "-j qdisc show dev eno1")
	if r, err := e.RunNIC(NICOptions{}); err != nil || len(r.Changed)+len(r.Problems) != 0 || len(tc.calls) != 1 {
		t.Errorf("not read back: the run after: %v %v %v", r, err, tc.calls)
	}
	if qs := qdiscState(t, e, "0000:82:00.0"); qs == nil || *qs != (QdiscState{Orig: "mq, pfifo_fast on 56 queues", Kind: "mq", Handle: "8001:"}) {
		t.Errorf("not read back: state after %+v", qs)
	}
	if rv, _ := e.Revert(false, false); !slices.Contains(tc.calls, "qdisc del dev eno1 root") {
		t.Errorf("not read back: revert %v %v %v", rv.Changed, rv.Problems, tc.calls)
	}
}

// A state written before x-ui switched root qdiscs (NIC entries without
// one) loads, and the next "tune nic" switches the root and records it.
func TestQdiscOldState(t *testing.T) {
	e, b, tc := withTC(t, hwtest.Production(), "pfifo_fast", "eno1")
	b.WriteFile(sysctlPath("net.core.default_qdisc"), "fq\n")
	writeT(t, e.Root, StateFile, `{"version":1,"xui_version":"2.9.1","keys":{"net.core.default_qdisc":{"orig":"fq_codel","written":"fq","file":"fq"}},`+
		`"nics":{"0000:82:00.0":{"name":"eno1","driver":"ixgbe","hash":{"udp4":{"orig":"sd","written":"sdfn"}}}}}`)
	r, err := e.RunNIC(NICOptions{})
	if err != nil || !slices.Contains(r.Changed, "eno1: root qdisc mq, pfifo_fast on 56 queues -> mq, fq on 56 queues") {
		t.Fatalf("%v %v %v", err, r.Changed, r.Problems)
	}
	st, _, err := e.loadState()
	if ns := st.NICs["0000:82:00.0"]; err != nil || ns.Hash["udp4"].Written != "sdfn" || ns.Qdisc == nil || ns.Qdisc.Handle != "8001:" {
		t.Errorf("state %+v %v", ns, err)
	}
	if rv, _ := e.Revert(false, false); !slices.Contains(rv.Changed, "eno1 root qdisc: mq, fq on 56 queues -> mq, fq_codel on 56 queues"+unpaced) || tc.roots["eno1"].handle != "0:" {
		t.Errorf("revert %v %v", rv.Changed, rv.Problems)
	}
}

// A run killed right after the replace: the state on disk has the root
// marked as being put in, and the next run takes the live one as x-ui's
// (no second replace); revert then takes it off. Killed right before it,
// the kernel's default (handle 0:) is not taken as x-ui's: the next run
// replaces it, once.
func TestQdiscKilledHalfway(t *testing.T) {
	for _, before := range []bool{false, true} {
		e, _, tc := withTC(t, hwtest.Production(), "pfifo_fast", "eno1")
		mustApply(t, e, ApplyOptions{Auto: true})
		tc.up("eno1", "pfifo_fast")
		st, _, _ := e.loadState()
		st.NICs["0000:82:00.0"].Qdisc = nil
		e.saveState(st, nil)
		type killed struct{}
		onDisk := ""
		run := e.Run
		e.Run = func(d time.Duration, name string, args ...string) (string, error) {
			change := name == "tc" && args[0] == "qdisc"
			if change && before {
				onDisk, _ = e.read(StateFile)
				panic(killed{})
			}
			out, err := run(d, name, args...)
			if change {
				onDisk, _ = e.read(StateFile)
				panic(killed{})
			}
			return out, err
		}
		func() {
			defer func() {
				if v := recover(); v != (killed{}) {
					panic(v)
				}
			}()
			e.RunNIC(NICOptions{})
			t.Fatal("not killed")
		}()
		e.Run = run
		if !strings.Contains(onDisk, `"pending": "mq"`) {
			t.Fatalf("before %v: no pending mark saved before the replace:\n%s", before, onDisk)
		}
		writeT(t, e.Root, StateFile, onDisk)
		tc.calls = nil
		var calls, changes []string
		if before {
			calls = []string{"qdisc replace dev eno1 root mq"}
			changes = []string{"eno1: root qdisc mq, pfifo_fast on 56 queues -> mq, fq on 56 queues"}
		}
		if r, err := e.RunNIC(NICOptions{}); err != nil || !slices.Equal(r.Changed, changes) || len(r.Problems) != 0 || !slices.Equal(tc.calls, calls) {
			t.Errorf("before %v: the run after: %v %v %v", before, r, err, tc.calls)
		}
		if qs := qdiscState(t, e, "0000:82:00.0"); qs == nil || *qs != (QdiscState{Orig: "mq, pfifo_fast on 56 queues", Kind: "mq", Handle: "8002:"}) {
			t.Errorf("before %v: state %+v", before, qs)
		}
		if rv, _ := e.Revert(false, false); !slices.Contains(tc.calls, "qdisc del dev eno1 root") || len(rv.Problems) != 0 {
			t.Errorf("before %v: revert %v %v %v", before, rv.Changed, rv.Problems, tc.calls)
		}
	}
}

// The real kernel, in a throwaway network namespace (root, XUI_TUNE_LIVE=1,
// fq as this host's default qdisc, the tun driver there): a multi-queue tap
// whose queues added after it came up run pfifo_fast under the kernel's
// mq 0: gets mq, fq on each queue, once; more queues after that make x-ui's
// root again with a new handle; a single queue that came up with fq is
// left, and so is a root someone set; revert brings the kernel's default
// back.
func TestQdiscLive(t *testing.T) {
	if os.Getenv("XUI_TUNE_LIVE") != "1" || os.Geteuid() != 0 {
		t.Skip("needs root and XUI_TUNE_LIVE=1")
	}
	if _, err := os.Stat("/sys/class/misc/tun"); err != nil {
		t.Skip("the tun driver is not loaded (this test loads no module)")
	}
	// This thread only, never unlocked: the namespace ends with the test's
	// goroutine, and the commands it runs start in it.
	runtime.LockOSThread()
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	e := &Env{Root: root, Out: os.Stdout}
	e.Run = func(d time.Duration, name string, args ...string) (string, error) {
		out, err := exec.Command(name, args...).CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	st := &State{NICs: map[string]*NICState{"xq0": {Name: "xq0"}, "xq1": {Name: "xq1"}}}
	for k := range st.NICs {
		os.MkdirAll(e.P("/sys/class/net/"+k), 0o755)
	}
	plan := func(dev string) *nicItem {
		it := &nicItem{NIC: &hw.NIC{Name: dev}, Key: dev, ns: st.NICs[dev]}
		e.planQdisc(it, st, true, false, "")
		return it
	}
	apply := func(dev string) (*nicItem, *Result) {
		it, r := plan(dev), &Result{}
		markQdisc(it, it.ns)
		e.writeQdisc(it, it.ns, r)
		return it, r
	}
	// A single queue comes up with the default qdisc alone (the sysctl is
	// not in a namespace's /proc/sys).
	liveTap(t, "xq1", false, 1)
	liveUp(t, "xq1")
	if it := plan("xq1"); it.Qdisc.Live != "fq" || it.Qdisc.Want != "" {
		t.Skipf("the default qdisc here is not fq: %+v", it.Qdisc)
	}

	liveTap(t, "xq0", true, 2)
	liveUp(t, "xq0")
	liveTap(t, "xq0", true, 2) // after it is up: pfifo_fast under mq 0:
	if it := plan("xq0"); it.Qdisc.Live != "mq, fq on 2 queues, pfifo_fast on 2" || it.Qdisc.Want != "mq" {
		t.Fatalf("kernel's default: %+v", it.Qdisc)
	}
	it, r := apply("xq0")
	qs := st.NICs["xq0"].Qdisc
	if !slices.Equal(r.Changed, []string{"xq0: root qdisc mq, fq on 2 queues, pfifo_fast on 2 -> mq, fq on 4 queues"}) || qs == nil || qs.Handle == "0:" || qs.Kind != "mq" || !it.Qdisc.ours {
		t.Fatalf("replace: %v %v %+v", r.Changed, r.Problems, qs)
	}
	first := qs.Handle
	if it := plan("xq0"); it.Qdisc.Want != "" || !it.Qdisc.ours || it.Qdisc.Note != "was mq, fq on 2 queues, pfifo_fast on 2" {
		t.Errorf("again: %+v", it.Qdisc)
	}
	liveTap(t, "xq0", true, 2) // a raise
	if it, r := apply("xq0"); !slices.Equal(r.Changed, []string{"xq0: root qdisc mq, fq on 4 queues, pfifo_fast on 2 -> mq, fq on 6 queues"}) || it.Qdisc.Live != "mq, fq on 6 queues" {
		t.Errorf("after a raise: %v %v", r.Changed, r.Problems)
	}
	if qs.Handle == first || qs.Orig != "mq, fq on 2 queues, pfifo_fast on 2" {
		t.Errorf("after a raise: %+v (first %s)", qs, first)
	}

	if out, err := e.run("tc", "qdisc", "replace", "dev", "xq1", "root", "pfifo_fast"); err != nil {
		t.Fatal(out, err)
	}
	if it := plan("xq1"); !strings.HasPrefix(it.Qdisc.Live, "pfifo_fast 8") || it.Qdisc.Want != "" || it.Qdisc.Note != "set by someone else: kept" {
		t.Errorf("someone's root: %+v", it.Qdisc)
	}

	rv := &Result{}
	e.revertQdiscs(&Facts{}, st, false, rv)
	tr, err := e.readQdiscs("xq0")
	if err != nil || tr.root.Handle != "0:" || tr.text(true) != "mq, fq on 6 queues" || !slices.Equal(rv.Changed, []string{"xq0 root qdisc: mq, fq on 6 queues -> mq, fq on 6 queues"}) {
		t.Errorf("revert: %v %v %v", rv.Changed, rv.Problems, err)
	}
	if tr, _ := e.readQdiscs("xq1"); tr == nil || tr.root.Kind != "pfifo_fast" {
		t.Errorf("revert took someone's root: %+v", tr)
	}
}

// liveTap attaches n queues to a tap (multi-queue or not), made by the
// first; each queue is one open file, closed when the test ends.
func liveTap(t *testing.T, name string, mq bool, n int) {
	t.Helper()
	flags := uint16(unix.IFF_TAP | unix.IFF_NO_PI)
	if mq {
		flags |= unix.IFF_MULTI_QUEUE
	}
	for i := 0; i < n; i++ {
		fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { unix.Close(fd) })
		ifr, err := unix.NewIfreq(name)
		if err != nil {
			t.Fatal(err)
		}
		ifr.SetUint16(flags)
		if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
			t.Fatal(err)
		}
	}
}

func liveUp(t *testing.T, name string) {
	t.Helper()
	l, err := netlink.LinkByName(name)
	if err == nil {
		err = netlink.LinkSetUp(l)
	}
	if err != nil {
		t.Fatal(err)
	}
}
