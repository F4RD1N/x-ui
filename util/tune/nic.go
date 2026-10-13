//go:build linux

package tune

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/util/hw"
)

// NIC tuning: the uplink NICs' queue count, UDP hashing, interrupt CPUs, XPS
// and RPS. Three kinds of change:
//
//   - kernel state (interrupt CPUs, XPS, RPS/RFS) and the UDP hash on
//     ixgbe, igb and igc (a register write, no link reset) are set by every
//     apply but the boot one, and by "x-ui tune nic" (the panel, when the
//     instance split changes; the boot unit);
//   - the queue count is only ever raised, and only by x-ui-nic.service at
//     boot (before x-ui starts) or by "x-ui tune queues --now", under a
//     watchdog that puts the old count back when the gateway stops
//     answering: most drivers reset the link to change it;
//   - irqbalance gets a policy script that keeps it off these NICs (a host
//     service change: a fresh install or a manual apply).
//
// The interrupts follow the xray instances' CPU split (instances.json): the
// queues RSS hashes to are spread so that no instance carries more than its
// share of the hashed work (see hw.PlaceQueues).

// nicOpts says what a NIC plan is for.
type nicOpts struct {
	Instances string          // instances.json; "" the one next to the binary
	Host      bool            // the irqbalance policy may be written
	Assume    bool            // plan as if that policy were in effect (dry run)
	Retry     bool            // "tune queues --now": a failed raise is tried again
	Only      map[string]bool // only these NICs (by state key); nil all
}

// nicPlan is what x-ui would do about the uplink NICs.
type nicPlan struct {
	Skip       string      `json:"skip,omitempty"` // why nothing is done
	Notes      []string    `json:"notes,omitempty"`
	NICs       []*nicItem  `json:"nics,omitempty"`
	Split      string      `json:"split,omitempty"`
	Eligible   hw.CPUSet   `json:"eligible,omitempty"`
	IRQBalance *irqbalance `json:"irqbalance,omitempty"`
	Unit       string      `json:"-"` // x-ui-nic.service, "" when no raise is pending

	topo  *hw.Topology
	place *hw.Placement
	units []hw.Unit
	nrCPU int
	rpsF  int64
}

// nicItem is one NIC's plan.
type nicItem struct {
	NIC      *hw.NIC     `json:"nic"`
	Key      string      `json:"key"`
	Queues   queuePlan   `json:"queues"`
	Table    string      `json:"rss_table,omitempty"`
	Hash     []*itemPlan `json:"hash,omitempty"`
	HashNote string      `json:"hash_note,omitempty"`
	IRQs     []*irqPlan  `json:"irqs,omitempty"`
	IRQNote  string      `json:"irq_note,omitempty"` // why the interrupts stay where they are
	XPS      []*itemPlan `json:"xps,omitempty"`
	XPSNote  string      `json:"xps_note,omitempty"`
	RPS      []*itemPlan `json:"rps,omitempty"`
	RPSNote  string      `json:"rps_note,omitempty"`

	// keep: why the interrupts are not moved: "foreign" (placed by
	// someone else), "managed" (by the kernel), "irqbalance", "unknown"
	// (queues not known), "single" (one queue), "readonly"
	// (XUI_TUNE_ONLY=net); "" moved.
	keep    string
	example string // a foreign interrupt, for the note
	rss     []int
	ns      *NICState // its state entry (nil: none, or another device's)
}

// queuePlan is the queue count.
type queuePlan struct {
	Current uint32 `json:"current"`
	Max     uint32 `json:"max"`
	Target  uint32 `json:"target,omitempty"`
	Want    uint32 `json:"want,omitempty"`    // raised to at boot; 0 none
	RSSUse  int    `json:"rss_use,omitempty"` // queues the RSS table uses
	State   string `json:"state"`             // ok, kept, raise, skip, unsupported
	Note    string `json:"note,omitempty"`
}

// itemPlan is one value: a UDP hash, a queue's XPS or RPS.
type itemPlan struct {
	Key  string `json:"key"`
	Path string `json:"path,omitempty"`
	Live string `json:"live"`
	Want string `json:"write,omitempty"` // "" leaves it
	Note string `json:"note,omitempty"`
}

// irqPlan is one queue interrupt.
type irqPlan struct {
	Key   string `json:"key"` // "q3" (txrx), "q3rx", "q3tx"
	IRQ   int    `json:"irq"`
	Queue int    `json:"queue"`
	RSS   bool   `json:"rss,omitempty"`
	Live  string `json:"live"` // smp_affinity_list
	CPU   int    `json:"cpu"`
	Want  string `json:"write,omitempty"`
	Owner string `json:"owner,omitempty"`
}

// hashDrivers set UDP hashing on ports with a register write only (their
// set_rxfh_fields rewrites MRQC: no reset), and hash UDP on IPs only by
// default.
var hashDrivers = []string{"ixgbe", "igb", "igc"}

// softQueues are drivers without an RSS table whose receive queue follows
// the sender's (virtio_net's host, veth's peer).
var softQueues = []string{"virtio_net", "veth"}

// cpuText writes a CPU list for the state; "-" is the empty set.
func cpuText(c hw.CPUSet) string {
	if len(c) == 0 {
		return "-"
	}
	return c.List()
}

func parseCPUText(s string) (hw.CPUSet, error) {
	if s == "-" {
		return nil, nil
	}
	return hw.ParseList(s)
}

// nicKey is a NIC's state key (hw.NIC.Key).
func nicKey(n *hw.NIC) string { return n.Key() }

func irqKey(q hw.QueueIRQ) string {
	if q.Kind == "txrx" {
		return fmt.Sprintf("q%d", q.Queue)
	}
	return fmt.Sprintf("q%d%s", q.Queue, q.Kind)
}

// uplinkNICs reads the NICs under the default routes (or the forced ones).
func (e *Env) uplinkNICs() ([]*hw.NIC, []string) {
	var nics []*hw.NIC
	var notes []string
	if len(e.ForceNIC) > 0 {
		routes := hw.DefaultRoutes(e.hw())
		for _, name := range e.ForceNIC {
			if !e.exists("/sys/class/net/" + name) {
				notes = append(notes, name+": not found")
				continue
			}
			n := hw.ReadNIC(e.hw(), e.eth(), name)
			for _, r := range routes {
				if r.Dev == name {
					n.Routes = append(n.Routes, r)
				}
			}
			nics = append(nics, n)
		}
	} else {
		nics, notes = hw.UplinkNICs(e.hw(), e.eth())
	}
	for _, n := range nics {
		if n.Driver == "" {
			if di, err := e.eth().DrvInfo(n.Name); err == nil {
				n.Driver = di.Driver
			}
		}
	}
	return nics, notes
}

// instancesPath is instances.json in the panel's bin folder.
func (e *Env) instancesPath(o string) string {
	if o != "" {
		return o
	}
	return filepath.Join(filepath.Dir(e.Bin), "bin", hw.InstancesFile)
}

// eligibleCPUs are the CPUs queue interrupts may go to: those the panel may
// use (instances.json, else all online), within the default interrupt
// affinity, without isolated and nohz_full CPUs.
func (e *Env) eligibleCPUs(t *hw.Topology, inst *hw.Instances) hw.CPUSet {
	el := t.Online
	if inst != nil {
		if a, err := hw.ParseList(inst.Allowed); err == nil && len(a) > 0 {
			el = a.And(t.Online)
		}
	}
	if d, err := hw.ParseMask(e.readTrim("/proc/irq/default_smp_affinity")); err == nil {
		if x := el.And(d); len(x) > 0 {
			el = x
		}
	}
	return el.Minus(t.Isolated)
}

// nrCPUs is nr_cpu_ids, the width of the kernel's CPU masks.
func (e *Env) nrCPUs(t *hw.Topology) int {
	if p, err := hw.ParseList(e.readTrim("/sys/devices/system/cpu/possible")); err == nil && len(p) > 0 {
		return p[len(p)-1] + 1
	}
	if len(t.Online) > 0 {
		return t.Online[len(t.Online)-1] + 1
	}
	return 1
}

// rpsFlowEntries is RFS's flow table size: 32768 per GiB, 32768..1048576.
func rpsFlowEntries(f *Facts) int64 {
	return clamp(pow2ceil(32768*f.G), 32768, 1048576)
}

// planNICs works out everything about the uplink NICs. It reads but never
// writes (ethtool getters only).
func (e *Env) planNICs(f *Facts, st *State, o nicOpts) *nicPlan {
	np := &nicPlan{rpsF: rpsFlowEntries(f)}
	if f.Container() {
		np.Skip = "left to the host (container)"
		return np
	}
	nics, notes := e.uplinkNICs()
	np.Notes = notes
	if o.Only != nil {
		var keep []*hw.NIC
		for _, n := range nics {
			if o.Only[nicKey(n)] {
				keep = append(keep, n)
			}
		}
		nics = keep
	}
	if len(nics) == 0 {
		np.Skip = "no NIC under the default route"
		if len(notes) > 0 {
			np.Skip = notes[0]
		}
		return np
	}
	t, err := hw.ReadTopology(e.hw())
	if err != nil {
		np.Skip = "CPU topology: " + err.Error()
		return np
	}
	np.topo, np.nrCPU = t, e.nrCPUs(t)
	inst, ierr := hw.ReadInstances(e.hw(), e.instancesPath(o.Instances))
	if ierr != nil {
		inst = nil
	}
	np.Eligible = e.eligibleCPUs(t, inst)
	if inst != nil {
		for _, in := range inst.Instances {
			c, err := hw.ParseList(in.CPUs)
			if err != nil || len(c) == 0 {
				c = np.Eligible // unpinned: it runs anywhere
			}
			np.units = append(np.units, hw.Unit{Name: in.Name, CPUs: c})
		}
	}

	admin := e.adminChannelFiles()
	for _, n := range nics {
		it := &nicItem{NIC: n, Key: nicKey(n)}
		ns := st.NICs[it.Key]
		if ns != nil && ns.Driver != n.Driver {
			ns = nil // another device at the same address
		}
		it.ns = ns
		it.Queues = e.planQueues(f, t, np.Eligible, n, ns, o.Retry, admin)
		it.Table = tableText(n)
		e.planHash(it, ns)
		it.rss = rssOrder(n)
		np.NICs = append(np.NICs, it)
	}

	// Whose interrupts are they? irqbalance running with x-ui's policy
	// script, which bans the NIC, has left them to x-ui: where it put them
	// earlier is not an admin's choice. irqbalance running without it
	// places them itself: where they are is irqbalance's doing, unless an
	// admin keeps them from it (--banirq, or a policy script of their own).
	ibRunning, ibArgs := e.irqbalanceProc()
	ibOurs, ibOther, ibBans := irqbalanceArgs(ibArgs)
	_, shadow := e.irqbalanceShadowed()
	var banned []string
	if s, err := e.read(IRQBalanceScript); err == nil && e.isOurs(IRQBalanceScript) {
		banned = scriptPCIs(s)
	}
	for _, it := range np.NICs {
		n, ns := it.NIC, it.ns
		released := ibRunning && ibOurs && !shadow && slices.Contains(banned, n.PCI)
		balanced := ibRunning && !released && !ibOther && !slices.ContainsFunc(n.IRQs, func(q hw.QueueIRQ) bool { return ibBans[q.IRQ] })
		switch {
		case n.RxQueues <= 1 && n.TxQueues <= 1:
			it.keep = "single"
		case len(n.IRQs) == 0 || n.UnknownIRQs || n.SharedIRQ:
			it.keep = "unknown"
		case ns != nil && ns.Managed:
			it.keep = "managed"
		case e.OnlyNet:
			it.keep = "readonly"
		case released, balanced:
		default:
			if q := e.foreignIRQ(n, ns, t); q != nil {
				it.keep, it.example = "foreign", fmt.Sprintf("IRQ %d on CPU %s", q.IRQ, q.Affinity.List())
			}
		}
	}
	np.IRQBalance = e.irqbalancePlan(np, st, o)
	// While irqbalance runs without the policy for a NIC, it moves that
	// NIC's interrupts: they are left to it.
	if ib := np.IRQBalance; ib.Running && !(o.Assume && ib.Script != "") {
		for _, it := range np.NICs {
			if it.keep == "" && (!ib.Ours || ib.Shadow || !slices.Contains(ib.Banned, it.NIC.PCI)) {
				it.keep = "irqbalance"
			}
		}
	}

	var pn []hw.PlaceNIC
	for _, it := range np.NICs {
		pn = append(pn, hw.PlaceNIC{NIC: it.NIC, RSS: it.rss, Keep: it.keep != ""})
	}
	if len(np.Eligible) > 0 {
		np.place = hw.PlaceQueues(t, np.Eligible, np.units, pn)
	}
	np.Split = "no instance split"
	if n := len(np.units); n > 0 && np.place != nil {
		if np.place.Split {
			np.Split = fmt.Sprintf("the instance split (%d instances)", n)
		} else {
			np.Split = "no usable instance split (instances share CPUs)"
		}
	}
	for _, it := range np.NICs {
		e.planIRQs(np, it)
		e.planRPS(np, it, it.ns)
	}
	np.Unit = e.nicUnitFor(np, st)
	return np
}

// foreignIRQ is a queue interrupt someone else placed, nil when x-ui may
// move them all: each is at the kernel's default for the NIC's node, at all
// online CPUs, at its driver's hint, or where x-ui put it; or the admin
// handed them over (--take-irqs).
func (e *Env) foreignIRQ(n *hw.NIC, ns *NICState, t *hw.Topology) *hw.QueueIRQ {
	if ns != nil && ns.TakeIRQs {
		return nil
	}
	def := hw.DefaultIRQMask(e.hw(), n.Node, t.Online)
	for i := range n.IRQs {
		q := n.IRQs[i]
		a := q.Affinity.And(t.Online)
		switch {
		case len(a) == 0:
		case def != nil && a.Equal(def):
		case a.Equal(t.Online):
		case len(q.Hint) > 0 && a.Equal(q.Hint.And(t.Online)):
		case ns != nil && ns.IRQ[irqKey(q)] != nil && ns.IRQ[irqKey(q)].IRQ == q.IRQ && slices.Contains([]string{ns.IRQ[irqKey(q)].Written, ns.IRQ[irqKey(q)].Pending}, a.List()):
		default:
			return &q
		}
	}
	return nil
}

// rssOrder is the queues RSS hashes to, by their table entries (most first),
// then index; all queues when the table is unreadable.
func rssOrder(n *hw.NIC) []int {
	use := n.RSSUse()
	if use == nil {
		var all []int
		for q := 0; q < n.Queues(); q++ {
			all = append(all, q)
		}
		return all
	}
	qs := make([]int, 0, len(use))
	for q := range use {
		qs = append(qs, q)
	}
	sort.Slice(qs, func(i, j int) bool {
		if use[qs[i]] != use[qs[j]] {
			return use[qs[i]] > use[qs[j]]
		}
		return qs[i] < qs[j]
	})
	return qs
}

func tableText(n *hw.NIC) string {
	if n.Indir == nil {
		return "not readable"
	}
	use := n.RSSUse()
	k := len(use)
	switch {
	case hw.EvenOver(n.Indir, k):
		return fmt.Sprintf("%d entries, even over queues %s: kept", len(n.Indir), hw.CPUSet(sortedKeys(use)).List())
	default:
		return fmt.Sprintf("%d entries over %d queues, uneven (set by someone): kept", len(n.Indir), k)
	}
}

func sortedKeys(m map[int]int) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

// chanCount is the queue count channels give: combined, else RX (also on a
// NIC set to separate RX and TX channels).
func chanCount(c hw.Channels) (cur, maxN uint32) {
	if c.MaxCombined > 0 && !separateChannels(c) {
		return c.Combined, c.MaxCombined
	}
	if c.MaxRx == 0 {
		return c.Rx, c.MaxCombined
	}
	return c.Rx, c.MaxRx
}

// separateChannels says whether a NIC that has combined channels runs on
// dedicated RX or TX ones (ethtool -L rx N tx N): x-ui keeps that as it is
// (bnxt_en and ice refuse combined and dedicated ones together).
func separateChannels(c hw.Channels) bool {
	return c.MaxCombined > 0 && (c.Rx > 0 || c.Tx > 0)
}

// withCount is c with its queue count set to n.
func withCount(c hw.Channels, n uint32) hw.Channels {
	if c.MaxCombined > 0 {
		c.Combined = n
		return c
	}
	c.Rx = min(n, c.MaxRx)
	if c.MaxTx > 0 {
		c.Tx = max(c.Tx, min(n, c.MaxTx))
	}
	return c
}

// planQueues works out a raise of the queue count. It only ever raises, to
// one queue per physical core near the NIC (vCPU for virtio), at most 64,
// and never past what RSS was found to use.
func (e *Env) planQueues(f *Facts, t *hw.Topology, eligible hw.CPUSet, n *hw.NIC, ns *NICState, retry bool, admin map[string]string) queuePlan {
	q := queuePlan{}
	if n.Indir != nil {
		q.RSSUse = len(n.RSSUse())
	}
	if n.Channels == nil {
		q.State, q.Note = "unsupported", "queue counts not readable"
		return q
	}
	q.Current, q.Max = chanCount(*n.Channels)
	if q.Max == 0 {
		q.State, q.Note = "unsupported", "queue counts not readable"
		return q
	}
	if separateChannels(*n.Channels) {
		q.State, q.Note = "kept", "separate RX and TX channels"
		return q
	}
	var cs *ChanState
	if ns != nil {
		cs = ns.Channels
	}
	local := eligible
	if n.Node >= 0 {
		if pkg := t.PackageOfNode(n.Node); pkg >= 0 {
			local = nil
			for _, c := range eligible {
				if t.PackageOf(c) == pkg {
					local = append(local, c)
				}
			}
		}
	}
	p := t.PhysicalCores(local)
	if slices.Contains(softQueues, n.Driver) {
		p = len(local) // vCPUs are host threads
	}
	target := min(int(q.Max), p, 64)
	if cs != nil && cs.RSSCap > 0 {
		target = min(target, cs.RSSCap)
	}
	q.Target = uint32(max(target, 0))
	base := q.Current
	if cs != nil && cs.Orig != nil {
		base, _ = chanCount(*cs.Orig)
	}
	rssNote := ""
	if q.RSSUse > 0 && q.RSSUse < int(q.Current) {
		why := "the card's limit"
		if !hw.DefaultForm(n.Indir, q.RSSUse) {
			why = "its table"
		}
		rssNote = fmt.Sprintf("RSS uses %d: %s", q.RSSUse, why)
	}
	if q.Target <= base {
		q.State = "ok"
		switch {
		case rssNote != "":
			q.State, q.Note = "kept", rssNote
		case q.Target < q.Current:
			q.State, q.Note = "kept", "never lowered"
		}
		return q
	}
	switch {
	case n.VF:
		q.State, q.Note = "skip", "an SR-IOV VF: its queues are the host's"
	case f.Init != "systemd":
		q.State, q.Note = "skip", "queues are raised at boot by a systemd unit; none here"
	case cs != nil && cs.Failed != "" && !retry:
		q.State, q.Note = "skip", "an earlier raise failed ("+cs.Failed+"); 'x-ui tune queues --now' tries again"
	case admin[n.Name] != "":
		q.State, q.Note = "skip", "an admin sets the queue count ("+admin[n.Name]+")"
	case (cs == nil || cs.RSSCap == 0) && n.Indir != nil && q.RSSUse < int(q.Current):
		q.State, q.Note = "skip", rssNote+": more queues would not be hashed to"
	case n.Indir == nil && !slices.Contains(softQueues, n.Driver):
		q.State, q.Note = "skip", "RSS table not readable: more queues may not be used"
	default:
		q.Want = q.Target
		q.State = "raise"
		if q.Current >= q.Want {
			q.State, q.Note = "ok", fmt.Sprintf("raised from %d at boot", base)
		}
	}
	return q
}

// adminChannelFiles finds queue counts an admin persists (best effort): by
// device name, or "*" for a file that names no uplink. It looks where they
// are set at boot: systemd .link files, ifupdown (interfaces and its hook
// directories), NetworkManager (connections and dispatcher scripts),
// networkd-dispatcher, RHEL and SUSE ifcfg files (ETHTOOL_OPTS), systemd
// units, rc.local, udev rules and cron's @reboot lines. Hook scripts a
// package ships (Debian's ethtool hooks) are not an admin's.
func (e *Env) adminChannelFiles() map[string]string {
	type hit struct{ file, data string }
	var hits []hit
	scan := func(files []string, hooks bool, match func(line string) bool) {
		for _, f := range files {
			data, err := e.read(f)
			if err != nil {
				continue
			}
			for _, l := range strings.Split(data, "\n") {
				l = strings.TrimSpace(l)
				if l == "" || l[0] == '#' || l[0] == ';' {
					continue
				}
				if match(l) {
					if !hooks || !e.pkgOwned(f) {
						hits = append(hits, hit{f, data})
					}
					break
				}
			}
		}
	}
	ethtoolL := func(l string) bool { return strings.Contains(l, "ethtool") && setsChannels(l) }
	scan(e.glob("/etc/systemd/network/*.link"), false, func(l string) bool {
		for _, k := range []string{"CombinedChannels=", "RxChannels=", "TxChannels="} {
			if strings.HasPrefix(l, k) {
				return true
			}
		}
		return false
	})
	var files, hooks []string
	files = append(files, "/etc/network/interfaces", "/etc/rc.local", "/etc/rc.d/rc.local", "/etc/crontab")
	for _, g := range []string{"/etc/network/interfaces.d/*", "/etc/udev/rules.d/*", "/etc/cron.d/*", "/var/spool/cron/*", "/var/spool/cron/crontabs/*"} {
		files = append(files, e.glob(g)...)
	}
	files = append(files, e.walk("/etc/systemd/system")...)
	for _, d := range []string{"/etc/network/if-pre-up.d", "/etc/network/if-up.d", "/etc/network/if-post-up.d", "/etc/NetworkManager/dispatcher.d", "/etc/networkd-dispatcher"} {
		hooks = append(hooks, e.walk(d)...)
	}
	scan(files, false, ethtoolL)
	scan(hooks, true, ethtoolL)
	scan(e.glob("/etc/NetworkManager/system-connections/*"), false, func(l string) bool { return strings.HasPrefix(l, "channels-") })
	var ifcfg []string
	for _, g := range []string{"/etc/sysconfig/network-scripts/ifcfg-*", "/etc/sysconfig/network/ifcfg-*"} {
		ifcfg = append(ifcfg, e.glob(g)...)
	}
	scan(ifcfg, false, func(l string) bool {
		return (strings.HasPrefix(l, "ETHTOOL_OPTS") || strings.HasPrefix(l, "ETHTOOL_OPTIONS")) && setsChannels(l)
	})

	out := map[string]string{}
	if len(hits) == 0 {
		return out
	}
	names := map[string]bool{}
	for _, d := range e.glob("/sys/class/net/*") {
		names[path.Base(d)] = true
	}
	for _, h := range hits {
		named := false
		for name := range names {
			if mentions(h.data, name) {
				named = true
				if out[name] == "" {
					out[name] = h.file
				}
			}
		}
		if !named {
			for name := range names {
				if out[name] == "" {
					out[name] = h.file
				}
			}
		}
	}
	return out
}

// setsChannels says whether a line passes ethtool's -L (--set-channels).
func setsChannels(l string) bool {
	for _, w := range strings.FieldsFunc(l, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '"' || r == '\'' || r == ';' || r == '=' || r == '`' || r == '('
	}) {
		if w == "-L" || w == "--set-channels" {
			return true
		}
	}
	return false
}

// mentions says whether a file names a device (as a whole word).
func mentions(data, name string) bool {
	for i := 0; ; {
		j := strings.Index(data[i:], name)
		if j < 0 {
			return false
		}
		j += i
		before, after := byte(' '), byte(' ')
		if j > 0 {
			before = data[j-1]
		}
		if k := j + len(name); k < len(data) {
			after = data[k]
		}
		if !isNameByte(before) && !isNameByte(after) {
			return true
		}
		i = j + 1
	}
}

func isNameByte(c byte) bool {
	return c == '.' || c == '-' || c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// walk lists the regular files below a directory.
func (e *Env) walk(dir string) []string {
	var out []string
	_ = filepath.WalkDir(e.P(dir), func(p string, d os.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			out = append(out, e.unP(p))
		}
		return nil
	})
	return out
}

// planHash plans UDP hashing on ports where the driver hashes on IPs only
// and changes it with a register write.
func (e *Env) planHash(it *nicItem, ns *NICState) {
	n := it.NIC
	sd := false
	for _, fl := range []hw.Flow{hw.FlowUDP4, hw.FlowUDP6} {
		bits, ok := n.Hash[fl.String()]
		if !ok {
			continue
		}
		ip := &itemPlan{Key: fl.String(), Live: hw.HashLetters(bits)}
		switch {
		case bits == hw.HashIPs && slices.Contains(hashDrivers, n.Driver) && !n.VF:
			ip.Want = hw.HashLetters(hw.HashIPsPorts)
		case bits == hw.HashIPs:
			sd = true
			continue
		case bits == hw.HashIPsPorts:
		default:
			ip.Note = "kept"
		}
		if ns != nil && ns.Hash[ip.Key] != nil && ns.Hash[ip.Key].Written == ip.Live && ip.Want == "" {
			ip.Note = "was " + hashWords(ns.Hash[ip.Key].Orig)
		}
		it.Hash = append(it.Hash, ip)
	}
	switch {
	case sd && n.VF:
		it.HashNote = "UDP hashed on IPs only (a VF: the host's setting)"
	case sd:
		it.HashNote = "UDP hashed on IPs only (" + n.Driver + ": left as it is)"
	}
}

func hashWords(letters string) string {
	switch letters {
	case "sd":
		return "IPs only"
	case "sdfn":
		return "IPs and ports"
	}
	return letters
}

// planIRQs plans the interrupts' CPUs and XPS from the placement.
func (e *Env) planIRQs(np *nicPlan, it *nicItem) {
	n := it.NIC
	switch it.keep {
	case "foreign":
		it.IRQNote = fmt.Sprintf("placed by someone else (%s): kept; 'x-ui tune apply --take-irqs' hands them to x-ui", it.example)
	case "managed":
		it.IRQNote = "managed by the kernel: kept"
	case "irqbalance":
		it.IRQNote = "left to irqbalance, which runs without x-ui's policy"
		switch ib := np.IRQBalance; {
		case ib == nil:
		case ib.Shadow:
			it.IRQNote = "left to irqbalance (" + ib.Note + ")"
		case ib.Script != "" && ib.current:
			it.IRQNote += " ('systemctl restart irqbalance' applies it)"
		case ib.Script != "":
			it.IRQNote += " ('x-ui tune apply' adds it)"
		case ib.Note != "":
			it.IRQNote += " (" + ib.Note + ")"
		}
	case "unknown":
		switch {
		case len(n.IRQs) == 0 && !n.SharedIRQ:
			it.IRQNote = "no queue interrupts found"
		case n.SharedIRQ:
			it.IRQNote = "one interrupt serves every queue"
		default:
			it.IRQNote = "interrupt names not recognised"
		}
	case "readonly":
		it.IRQNote = "not moved (XUI_TUNE_ONLY=net)"
	case "single":
		it.IRQNote = "one queue: left where it is"
	}
	pl := np.place
	if pl == nil {
		it.XPSNote = "no eligible CPU"
		return
	}
	if it.keep == "" {
		rss := map[int]bool{}
		for _, q := range it.rss {
			rss[q] = true
		}
		for _, q := range n.IRQs {
			cpu, ok := pl.CPU[n.Name][q.Queue]
			if !ok {
				continue
			}
			ip := &irqPlan{Key: irqKey(q), IRQ: q.IRQ, Queue: q.Queue, RSS: rss[q.Queue], Live: q.Affinity.List(), CPU: cpu, Owner: pl.Owner[n.Name][q.Queue]}
			if !q.Affinity.Equal(hw.CPUSet{cpu}) {
				ip.Want = strconv.Itoa(cpu)
			}
			it.IRQs = append(it.IRQs, ip)
		}
	}
	switch {
	case n.TCs:
		it.XPSNote = "traffic classes are set: XPS left to them"
		return
	case n.TxQueues < 2:
		it.XPSNote = "one transmit queue"
		return
	case it.keep == "foreign" || it.keep == "irqbalance":
		it.XPSNote = "kept with the interrupts"
		return
	}
	for q := 0; q < n.TxQueues; q++ {
		live, ok := n.XPS[q]
		if !ok {
			continue
		}
		want := pl.XPS[n.Name][q]
		ip := &itemPlan{Key: fmt.Sprintf("tx-%d", q), Path: fmt.Sprintf("/sys/class/net/%s/queues/tx-%d/xps_cpus", n.Name, q), Live: cpuText(live)}
		if !live.Equal(want) {
			ip.Want = cpuText(want)
		}
		it.XPS = append(it.XPS, ip)
	}
}

// planRPS plans RPS and RFS on a single-queue NIC, and takes x-ui's back
// from one that has more queues now.
func (e *Env) planRPS(np *nicPlan, it *nicItem, ns *NICState) {
	n := it.NIC
	base := "/sys/class/net/" + n.Name + "/queues/"
	if n.RxQueues != 1 {
		it.RPSNote = "off (multi-queue)"
		if ns == nil {
			return
		}
		for _, k := range sortedStrings(ns.RPS) {
			ks := ns.RPS[k]
			if ks.Written == "" {
				continue
			}
			live := e.rpsLive(base + k)
			ip := &itemPlan{Key: k, Path: base + k, Live: live}
			if live == ks.Written && ks.Orig != ks.Written {
				ip.Want = ks.Orig
				ip.Note = "x-ui's RPS taken back (multi-queue now)"
			}
			if live != "" {
				it.RPS = append(it.RPS, ip)
			}
		}
		return
	}
	el := np.Eligible
	if len(el) < 2 {
		it.RPSNote = "off (one CPU)"
		return
	}
	cpus := el
	if n.Node >= 0 && np.topo != nil {
		for _, nd := range np.topo.Nodes {
			if nd.ID == n.Node {
				if x := el.And(nd.CPUs); len(x) >= 2 {
					cpus = x
				}
			}
		}
	}
	for _, k := range []string{"rx-0/rps_cpus", "rx-0/rps_flow_cnt"} {
		if !e.exists(base + k) {
			continue
		}
		live := e.rpsLive(base + k)
		ip := &itemPlan{Key: k, Path: base + k, Live: live}
		want := cpuText(cpus)
		zero := live == "-"
		if k == "rx-0/rps_flow_cnt" {
			want, zero = fmt.Sprint(np.rpsF), live == "0"
		}
		ours := ns != nil && ns.RPS[k] != nil && (ns.RPS[k].Written == live || ns.RPS[k].Pending == live)
		switch {
		case live == want:
		case zero || ours:
			ip.Want = want
		default:
			ip.Note = "set by someone else: kept"
		}
		it.RPS = append(it.RPS, ip)
	}
	it.RPSNote = "over CPUs " + cpus.List()
}

// rpsLive reads rps_cpus as a CPU list ("-" empty) or rps_flow_cnt.
func (e *Env) rpsLive(p string) string {
	s := e.readTrim(p)
	if strings.HasSuffix(p, "_cpus") {
		m, err := hw.ParseMask(s)
		if err != nil {
			return ""
		}
		return cpuText(m)
	}
	return s
}

func sortedStrings[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// nicUnitFor is x-ui-nic.service while a raise waits for the boot, else "".
func (e *Env) nicUnitFor(np *nicPlan, st *State) string {
	want := false
	for _, it := range np.NICs {
		if it.Queues.Want > 0 && (st.NICs[it.Key] == nil || st.NICs[it.Key].Channels == nil || st.NICs[it.Key].Channels.Failed == "") {
			want = true
		}
	}
	// NICs not visible now keep their raise.
	for k, ns := range st.NICs {
		if np.item(k) == nil && ns.Channels != nil && ns.Channels.Want > 0 && ns.Channels.Failed == "" {
			want = true
		}
	}
	if !want {
		return ""
	}
	return renderNICUnit(e.Bin)
}

func (np *nicPlan) item(key string) *nicItem {
	for _, it := range np.NICs {
		if it.Key == key {
			return it
		}
	}
	return nil
}

// renderNICUnit is x-ui-nic.service: the queue raises, before x-ui starts.
func renderNICUnit(bin string) string {
	return Header + `[Unit]
Description=x-ui NIC queues (raised before x-ui starts)
After=network-online.target
Wants=network-online.target
Before=x-ui.service
ConditionVirtualization=!container
ConditionPathExists=` + StateFile + `

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=-` + bin + ` tune nic --boot
TimeoutStartSec=600

[Install]
WantedBy=multi-user.target
`
}
