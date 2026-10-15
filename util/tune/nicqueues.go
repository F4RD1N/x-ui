//go:build linux

package tune

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mhsanaei/3x-ui/v2/util/hw"
)

// A queue count change resets the link on most drivers, so it happens only
// with nothing to lose (at boot, before x-ui starts) or when an admin asks
// ("x-ui tune queues --now"), and always under this watchdog: the gateway
// must answer before (or nothing changes), the link must come back and the
// gateway answer again within seconds after, or the old count is put back.
// A failed raise is recorded and never tried again automatically; a run
// that dies in the middle leaves an attempt in the state, which the next
// run turns into a failure.

// Clock is time for the watchdog.
type Clock interface {
	Now() time.Time
	Sleep(time.Duration)
}

// Prober checks that a NIC's gateway answers.
type Prober interface {
	// Pick finds a probe of a gateway behind the routes that answers now,
	// trying until the deadline: "" when none does.
	Pick(routes []hw.Route, deadline time.Time) string
	// Reach says whether the probe answers before the deadline.
	Reach(probe string, deadline time.Time) bool
}

// The watchdog's waits. The gateway's covers a switch port that runs
// classic STP without portfast (listening and learning: 30 s after the
// link); a Linux bridge with STP on adds its own forward delay twice to the
// link's (stpDelay).
const (
	pickWait  = 20 * time.Second // a probe that works, before the change
	linkWait  = 30 * time.Second // carrier and operstate after it
	reachWait = 45 * time.Second // the gateway after it
	aggWait   = 90 * time.Second // an 802.3ad slave back in the bond's aggregator
	pollEvery = 250 * time.Millisecond
)

// raiseReserve is what a raise and its undoing may take on a NIC: two queue
// changes (the raise, and the old count back when RSS does not use the new
// queues), each with its probe and two waits for the link and the gateway
// (after it, and after putting the old count back).
func (e *Env) raiseReserve(n *hw.NIC) time.Duration {
	return 2 * (pickWait + 2*(linkWait+e.stpDelay(n)+reachWait))
}

// stpDelay is how much longer a bridge with STP on keeps the route's device
// down after the NIC's link is back: its ports listen and learn for the
// forward delay each before they forward (plus a margin).
func (e *Env) stpDelay(n *hw.NIC) time.Duration {
	var d time.Duration
	for _, dev := range routeDevs(n) {
		br := "/sys/class/net/" + dev + "/bridge/"
		if st := e.readTrim(br + "stp_state"); st == "" || st == "0" {
			continue
		}
		fd, err := strconv.Atoi(e.readTrim(br + "forward_delay")) // in 1/100 s
		if err != nil || fd < 0 {
			fd = 1500
		}
		d = max(d, 2*time.Duration(fd)*10*time.Millisecond+2*time.Second)
	}
	return d
}

func (e *Env) prober() Prober {
	if e.Probe != nil {
		return e.Probe
	}
	return sysProber{}
}

// critical is a stretch in which the queue count may be changed: hangups
// and interrupts are ignored, and SIGTERM makes it undo the change.
type critical struct {
	term chan os.Signal
	got  bool
}

func enterCritical() *critical {
	signal.Ignore(syscall.SIGHUP, syscall.SIGINT, syscall.SIGPIPE)
	c := &critical{term: make(chan os.Signal, 1)}
	signal.Notify(c.term, syscall.SIGTERM)
	return c
}

func (c *critical) stopped() bool {
	select {
	case <-c.term:
		c.got = true
	default:
	}
	return c.got
}

// leave ends it. After a SIGTERM the run stops once the state is saved.
func (e *Env) leave(c *critical) {
	if c.stopped() {
		e.stopped = true
	}
	signal.Stop(c.term)
	signal.Reset(syscall.SIGHUP, syscall.SIGINT, syscall.SIGPIPE, syscall.SIGTERM)
}

// until polls cond until it holds or d passes (or SIGTERM).
func (e *Env) until(c *critical, d time.Duration, cond func() bool) bool {
	clk := e.clock()
	end := clk.Now().Add(d)
	for {
		if cond() {
			return true
		}
		if !clk.Now().Before(end) || (c != nil && c.stopped()) {
			return false
		}
		clk.Sleep(pollEvery)
	}
}

// routeDevs are the devices a NIC's default routes use (bond0, eno1.100,
// vmbr0, or the NIC itself).
func routeDevs(n *hw.NIC) []string {
	var out []string
	for _, r := range n.Routes {
		if !slices.Contains(out, r.Dev) {
			out = append(out, r.Dev)
		}
	}
	if len(out) == 0 {
		out = []string{n.Name}
	}
	return out
}

// linkBack waits for the NIC's link (and its place in a bond), then for the
// gateway. It says what did not come back.
func (e *Env) linkBack(c *critical, n *hw.NIC, probe string) (bool, string) {
	base := "/sys/class/net/" + n.Name
	devs := routeDevs(n)
	up := func() bool {
		if e.readTrim(base+"/carrier") != "1" {
			return false
		}
		for _, d := range devs {
			if s := e.readTrim("/sys/class/net/" + d + "/operstate"); s != "up" && s != "unknown" {
				return false
			}
		}
		return true
	}
	if wait := linkWait + e.stpDelay(n); !e.until(c, wait, up) {
		return false, fmt.Sprintf("the link did not come back within %s", wait)
	}
	if b := n.Bond; b != nil {
		if !e.until(c, linkWait, func() bool { return e.readTrim(base+"/bonding_slave/mii_status") == "up" }) {
			return false, fmt.Sprintf("%s did not come back up in %s within %s", n.Name, b.Bond, linkWait)
		}
		if b.Mode == "802.3ad" {
			agg := func() bool {
				mine := e.readTrim(base + "/bonding_slave/ad_aggregator_id")
				return mine != "" && mine == e.readTrim("/sys/class/net/"+b.Bond+"/bonding/ad_aggregator")
			}
			if !e.until(c, aggWait, agg) {
				return false, fmt.Sprintf("%s did not rejoin %s's aggregator within %s", n.Name, b.Bond, aggWait)
			}
		}
	}
	if c != nil && c.stopped() {
		return false, "stopped (SIGTERM)"
	}
	if !e.prober().Reach(probe, e.clock().Now().Add(reachWait)) {
		return false, fmt.Sprintf("the gateway did not answer within %s", reachWait)
	}
	return true, ""
}

type raiseResult int

const (
	raised raiseResult = iota
	skipped
	failed
)

// setQueues changes a NIC's queue count from old to the count to, under the
// watchdog, putting old back when the link or the gateway does not come
// back. It records the attempt first, and the failure after.
func (e *Env) setQueues(st *State, it *nicItem, old hw.Channels, to uint32, r *Result) (raiseResult, string) {
	n := it.NIC
	ns := st.NICs[it.Key]
	if ns.Channels == nil {
		ns.Channels = &ChanState{}
	}
	cs := ns.Channels
	from, _ := old.Count()
	clk := e.clock()
	probe := e.prober().Pick(n.Routes, clk.Now().Add(pickWait))
	if probe == "" {
		r.problem("%s: queues %d -> %d not changed: cannot check the gateway", n.Name, from, to)
		return skipped, ""
	}
	stamp := func() string { return clk.Now().UTC().Format(time.RFC3339) }
	cs.Attempt = &ChanAttempt{At: stamp(), From: from, To: to}
	if err := e.saveState(st, nil); err != nil {
		cs.Attempt = nil
		r.problem("%s: queues not changed: saving the state: %v", n.Name, err)
		return skipped, ""
	}
	c := enterCritical()
	defer e.leave(c)
	err := e.eth().SetChannels(n.Name, withCount(old, to))
	if err != nil && (errors.Is(err, hw.ErrNotSupported) || errors.Is(err, hw.ErrBusy) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EROFS)) {
		cs.Attempt = nil
		r.problem("%s: queues %d -> %d: %s", n.Name, from, to, ethNote(err))
		return skipped, ""
	}
	why := ""
	if err != nil {
		why = fmt.Sprintf("the driver refused %d queues (%v)", to, err)
	}
	ok, lost := e.linkBack(c, n, probe)
	if err == nil && ok {
		cs.Attempt = nil
		return raised, ""
	}
	if why == "" {
		why = lost
	}
	// Put the old count back (the driver may have changed it even when it
	// refused), with the same waits.
	cur, cerr := e.eth().Channels(n.Name)
	restored, rwhy := true, ""
	if cerr != nil || cur != old {
		if rerr := e.eth().SetChannels(n.Name, old); rerr != nil {
			restored, rwhy = false, rerr.Error()
		} else if back, w := e.linkBack(nil, n, probe); !back {
			restored, rwhy = false, w
		}
	} else if !ok {
		restored, rwhy = e.linkBack(nil, n, probe)
	}
	cs.Attempt = nil
	cs.Failed = fmt.Sprintf("%s at %s", why, stamp())
	if !restored {
		r.problem("%s: queues %d -> %d failed (%s), and putting %d back failed too (%s): the link may be down; the provider's console is the way back in", n.Name, from, to, why, from, rwhy)
	} else {
		r.problem("%s: queues %d -> %d undone: %s; not tried again automatically ('x-ui tune queues --now' tries again)", n.Name, from, to, why)
	}
	return failed, why
}

// raise raises one NIC's queue count, then checks that RSS uses the new
// queues: when it does not, the old count goes back and x-ui never raises
// that NIC again; when it uses some, later boots raise only that far.
func (e *Env) raise(st *State, it *nicItem, to uint32, r *Result) raiseResult {
	n := it.NIC
	old := *n.Channels
	from, _ := old.Count()
	res, _ := e.setQueues(st, it, old, to, r)
	if res != raised {
		return res
	}
	cs := st.NICs[it.Key].Channels
	if cs.Orig == nil {
		o := old
		cs.Orig = &o
	}
	cs.Want, cs.Failed = to, ""
	r.change("%s: queues %d -> %d", n.Name, from, to)

	// RSS: a table still in the old default form, or x-ui's weighted one,
	// is reset to the driver's default over the new queues (size 0, which
	// also clears "configured"); the weights follow the new placement.
	t, err := e.eth().Indir(n.Name)
	if err != nil || len(t) == 0 {
		return raised
	}
	ns := st.NICs[it.Key]
	if hw.DefaultForm(t, int(from)) || (ns.Table != nil && hw.TableSum(t) == ns.Table.Written) {
		if e.eth().SetIndir(n.Name, nil) == nil {
			ns.Table = nil
			if t2, err := e.eth().Indir(n.Name); err == nil && len(t2) > 0 {
				t = t2
			}
		}
	}
	k := 0
	seen := map[uint32]bool{}
	for _, q := range t {
		if !seen[q] {
			seen[q] = true
			k++
		}
	}
	switch {
	case k <= int(from):
		cur, err := e.eth().Channels(n.Name)
		if err != nil {
			return raised
		}
		after := *it
		res, _ := e.setQueues(st, &after, cur, from, r)
		if res == raised {
			cs.RSSCap, cs.Want = k, 0
			r.change("%s: back to %d queues: RSS uses %d whatever the count (the card's limit); not raised again", n.Name, from, k)
		}
		return res
	case k < int(to):
		cs.RSSCap, cs.Want = k, uint32(k)
		r.change("%s: RSS uses %d of the %d queues; later boots raise to %d", n.Name, k, to, k)
	}
	return raised
}

// raisePending raises the queue counts the plan asks for, one NIC at a time
// (a bond's slaves too), stopping at the first failure. At boot, a raise
// also needs an apply to have recorded it (the state's Want), and goes no
// further than that.
func (e *Env) raisePending(st *State, np *nicPlan, boot bool, deadline time.Time, r *Result) bool {
	any := false
	for _, it := range np.NICs {
		ns := it.state(st)
		if ns == nil || it.NIC.Channels == nil || it.Queues.State != "raise" {
			continue
		}
		cur, _ := it.NIC.Channels.Count()
		to := it.Queues.Want
		if boot {
			to = 0
			if cs := ns.Channels; cs != nil && cs.Failed == "" {
				to = min(cs.Want, it.Queues.Want)
			}
		}
		if to == 0 || to <= cur {
			continue
		}
		if !deadline.IsZero() && e.clock().Now().Add(e.raiseReserve(it.NIC)).After(deadline) {
			r.problem("%s: queues not raised: out of time", it.NIC.Name)
			return any
		}
		// x-ui's weighted RSS table is made even first: a driver may refuse
		// a queue change while a table of the user's is set (bnxt_en when
		// the change resizes it), and raise's look at the new queues needs
		// the default. The caller weighs it again for the new queues.
		if ourTable(it.NIC, ns) {
			if err := e.evenTable(it.NIC, ns.Table); err != nil {
				r.problem("%s: RSS table not made even before the queue raise: %s", it.NIC.Name, ethNote(err))
			} else {
				ns.Table = nil
				any = true
			}
		}
		res := e.raise(st, it, to, r)
		any = any || res != skipped
		if res == failed || e.stopped {
			return any
		}
	}
	return any
}

// QueuesOptions are "x-ui tune queues"'s.
type QueuesOptions struct {
	Now    bool // raise now, under the watchdog
	Worker bool // the detached run itself
	JSON   bool
}

// Queues shows the queue plan, or raises the queues now. It returns the
// result of a raise (nil when it only showed the plan).
func (e *Env) Queues(o QueuesOptions) (*Result, error) {
	if !o.Now {
		st, _, err := e.loadState()
		if err != nil {
			return nil, err
		}
		f := e.gatherFacts()
		np := e.planNICs(f, st, nicOpts{})
		if o.JSON {
			enc := json.NewEncoder(e.Out)
			enc.SetIndent("", "  ")
			return nil, enc.Encode(np)
		}
		e.printQueues(np)
		return nil, nil
	}
	unlock, err := e.lock(60 * time.Second)
	if err != nil {
		return nil, err
	}
	defer unlock()
	r := &Result{}
	st, had, err := e.loadState()
	if err != nil {
		return nil, err
	}
	if !had || st.Disabled {
		return nil, errors.New("tuning is not on: 'x-ui tune apply' first")
	}
	f := e.gatherFacts()
	if f.Container() {
		r.problem("NIC: left to the host (container)")
		return r, nil
	}
	e.endAttempts(st, r)
	e.settlePending(st)
	no := nicOpts{Retry: true}
	np := e.planNICs(f, st, no)
	if np.Skip != "" {
		r.problem("NIC: %s", np.Skip)
		return r, e.saveState(st, nil)
	}
	e.syncNICState(st, np, false)
	for _, it := range np.NICs {
		switch it.Queues.State {
		case "raise":
			if cs := st.NICs[it.Key].Channels; cs != nil {
				cs.Failed = "" // asked for: tried again
			}
		case "ok":
		default:
			r.problem("%s: queues %d of %d: %s", it.NIC.Name, it.Queues.Current, it.Queues.Max, orDefault(it.Queues.Note, it.Queues.State))
		}
	}
	if e.raisePending(st, np, false, time.Time{}, r) {
		e.applyNICKernel(f, st, e.planNICs(f, st, nicOpts{}), nicOpts{}, r)
	}
	e.applyNICUnit(f, st, r)
	return r, e.saveState(st, nil)
}

// printQueues is "x-ui tune queues".
func (e *Env) printQueues(np *nicPlan) {
	if np.Skip != "" {
		e.printf("NIC: %s\n", np.Skip)
		return
	}
	for _, it := range np.NICs {
		e.printf("%s: %s\n", it.NIC.Name, queuesText(it))
	}
}

// queuesText is a NIC's queue line.
func queuesText(it *nicItem) string {
	q := it.Queues
	if q.State == "unsupported" {
		return q.Note
	}
	s := fmt.Sprintf("%d of %d queues", q.Current, q.Max)
	switch q.State {
	case "raise":
		return s + fmt.Sprintf(": %d at the next boot (now: x-ui tune queues --now; the link resets for a few seconds)", q.Want)
	case "kept", "skip":
		return s + ": " + q.State + " (" + q.Note + ")"
	}
	if q.Note != "" {
		return s + ": ok (" + q.Note + ")"
	}
	return s + ": ok"
}

// detachable says whether "queues --now" should run as a transient unit so
// a dropped SSH session cannot stop it halfway: PID 1 is systemd and this
// process is in its network namespace (a unit started from another
// namespace would act on the host's NICs).
func (e *Env) detachable() bool {
	if e.readTrim("/proc/1/comm") != "systemd" {
		return false
	}
	self, err1 := os.Readlink(e.P("/proc/self/ns/net"))
	init, err2 := os.Readlink(e.P("/proc/1/ns/net"))
	return err1 == nil && err2 == nil && self != "" && self == init
}

// detachQueues says whether "queues --now" goes to a transient unit: only
// when it has a raise to do (a container, tuning that is off and nothing to
// raise are answered here at once), and only when systemd-run can wait for
// the unit, which needs the D-Bus system bus (systemd's own socket is not
// enough for --wait and --pipe).
func (e *Env) detachQueues() bool {
	if !e.detachable() || !e.systemBus() {
		return false
	}
	st, had, err := e.loadState()
	if err != nil || !had || st.Disabled {
		return false
	}
	f := e.gatherFacts()
	if f.Container() {
		return false
	}
	for _, it := range e.planNICs(f, st, nicOpts{Retry: true}).NICs {
		if it.Queues.State == "raise" {
			return true
		}
	}
	return false
}

// systemBus reports whether the D-Bus system bus is there: its socket, or an
// address someone set (systemd-run then finds out itself).
func (e *Env) systemBus() bool {
	if os.Getenv("DBUS_SYSTEM_BUS_ADDRESS") != "" {
		return true
	}
	fi, err := os.Stat(e.P("/run/dbus/system_bus_socket"))
	return err == nil && fi.Mode()&os.ModeSocket != 0
}

// detachArgs is the transient unit's command.
func (e *Env) detachArgs() []string {
	return []string{"systemd-run", "--unit=x-ui-queues-" + strconv.FormatInt(time.Now().Unix(), 10), "--collect", "--wait", "--pipe", "--quiet",
		"-p", "TimeoutStartSec=600", e.Bin, "tune", "queues", "--now", "--worker"}
}

// runDetached runs "queues --now" in its transient unit and returns the
// unit's exit code. ran is false when systemd-run started nothing because it
// could not reach the bus or is missing; the caller then runs it itself.
func (e *Env) runDetached(stdout, stderr io.Writer) (code int, ran bool) {
	args := e.detachArgs()
	w := &busCheck{w: stderr}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, stdout, w
	err := cmd.Run()
	if err != nil && (w.noBus || errors.Is(err, exec.ErrNotFound)) {
		return 0, false
	}
	w.flush()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, true
	case errors.As(err, &ee):
		return ee.ExitCode(), true
	}
	fmt.Fprintln(stderr, "x-ui tune:", err)
	return 1, true
}

// busCheck passes systemd-run's errors on, but holds the first line back
// until it is sure it does not say the bus is out of reach: systemd-run then
// started nothing, and the line would only confuse.
type busCheck struct {
	w     io.Writer
	held  []byte
	open  bool // the first line was something else: everything passes
	noBus bool
}

// Write never fails: the unit must never block on a full pipe because the
// terminal went away.
func (b *busCheck) Write(p []byte) (int, error) {
	if b.open {
		b.w.Write(p)
		return len(p), nil
	}
	b.held = append(b.held, p...)
	if b.noBus {
		return len(p), nil
	}
	i := bytes.IndexByte(b.held, '\n')
	if i < 0 && len(b.held) < 4096 {
		return len(p), nil
	}
	if i >= 0 && noBusLine(string(b.held[:i])) {
		b.noBus = true
		return len(p), nil
	}
	b.open = true
	b.flush()
	return len(p), nil
}

// flush passes on what is held back.
func (b *busCheck) flush() {
	if len(b.held) > 0 {
		b.w.Write(b.held)
		b.held = nil
	}
}

// noBusLine is systemd-run's error for a bus it cannot reach: "Failed to
// connect to bus: ...", "Failed to connect to system scope bus via local
// transport: ..." or, from older versions, "Failed to create bus
// connection: ...".
func noBusLine(l string) bool {
	return strings.HasPrefix(l, "Failed to create bus connection") ||
		strings.HasPrefix(l, "Failed to connect to") && strings.Contains(l, " bus")
}

// nicBootGuard says why the boot unit must not change the queue count now:
// x-ui already runs (its users would lose their connections), or the root
// file system is on the network.
func (e *Env) nicBootGuard() string {
	if out, _ := e.run("systemctl", "is-active", "x-ui"); out == "active" || out == "activating" || out == "reloading" {
		return "x-ui is running (queues are raised before it starts)"
	}
	for _, w := range strings.Fields(e.readTrim("/proc/cmdline")) {
		switch {
		case strings.HasPrefix(w, "ip="), strings.HasPrefix(w, "netroot="), strings.HasPrefix(w, "nfsroot="),
			w == "root=/dev/nfs", strings.HasPrefix(w, "rd.neednet"), strings.Contains(w, "iscsi"):
			return "the root file system is on the network (" + w + ")"
		}
	}
	return ""
}
