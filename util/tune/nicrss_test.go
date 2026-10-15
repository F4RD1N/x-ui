//go:build linux

package tune

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/util/hw"
	"github.com/mhsanaei/3x-ui/v2/util/hw/hwtest"
)

// bond66 is 162.249.124.66: two E5-2699 v4 (22 cores of 2 threads each,
// siblings n and n+44) and an 802.3ad bond over two 82599 ports (ixgbe, 16
// queues each, tables of 128).
func bond66() hwtest.Machine {
	m := hwtest.Bond()
	m.Packages, m.CoresPerPackage, m.Numbering, m.MemGiB = 2, 22, "linear", 256
	m.Model = "Intel(R) Xeon(R) CPU E5-2699 v4 @ 2.20GHz"
	return m
}

// epyc145 is 89.41.180.145: two EPYC of 64 cores of 2 threads each
// (siblings n and n+128) and one mlx5 port with 63 queues and a table of
// 512.
func epyc145() hwtest.Machine {
	m := hwtest.EPYC(1)
	m.CoresPerPackage = 64
	m.NICs[0].TableSize, m.NICs[0].SpeedMbps = 512, 25000
	return m
}

// panelSplit is the panel's split of n instances of size CPUs each, in
// name order.
func panelSplit(t *testing.T, b *hwtest.Built, n, size int) []string {
	t.Helper()
	topo, err := hw.ReadTopology(b.FS())
	if err != nil {
		t.Fatal(err)
	}
	var reqs []hw.CPURequest
	for i := 1; i <= n; i++ {
		reqs = append(reqs, hw.CPURequest{Name: fmt.Sprintf("xray-%d", i), CPUs: size})
	}
	natural := func(a, b string) bool { return len(a) < len(b) || len(a) == len(b) && a < b }
	got := hw.SplitCPUs(topo, b.Allowed, hw.UplinkNode(b.FS()), reqs, natural)
	var sets []string
	for _, r := range reqs {
		sets = append(sets, hw.NewCPUSet(got[r.Name]...).List())
	}
	return sets
}

// tableShares sums the live tables' entries by the instance (or the free
// CPUs, "") whose CPU each queue's interrupt is on.
func tableShares(t *testing.T, e *Env, b *hwtest.Built, sets []string, nics ...string) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, nic := range nics {
		for q, c := range tableUse(b.Eth.Devs[nic].Table) {
			cpu, _ := hw.ParseList(queueCPU(t, e, nic, q))
			owner := ""
			for i, s := range sets {
				if set, _ := hw.ParseList(s); len(cpu) == 1 && set.Has(cpu[0]) {
					owner = fmt.Sprintf("xray-%d", i+1)
				}
			}
			out[owner] += c
		}
	}
	return out
}

func spread(shares map[string]int, n int) (lo, hi int) {
	lo = 1 << 30
	for i := 1; i <= n; i++ {
		c := shares[fmt.Sprintf("xray-%d", i)]
		lo, hi = min(lo, c), max(hi, c)
	}
	return lo, hi
}

func tableState(t *testing.T, e *Env, key string) *TableState {
	t.Helper()
	st, _, err := e.loadState()
	if err != nil || st.NICs[key] == nil {
		t.Fatalf("state: %v", err)
	}
	return st.NICs[key].Table
}

// .66: 20 instances of 4 CPUs, 8 free, two NICs of 16 RSS queues. Eight
// instances hold two RSS queues, twelve one, the free CPUs four: weighted,
// every instance gets the same share of both tables within one entry per
// NIC, and the free CPUs keep their 8 entries a queue. The dry run shows the
// weights; a second apply and "tune nic" change nothing.
func TestNICRSSWeights66(t *testing.T) {
	e, b := onHW(t, bond66())
	sets := panelSplit(t, b, 20, 4)
	instances(t, b, b.Allowed.List(), sets...)
	var out bytes.Buffer
	e.Out = &out
	if _, err := e.Apply(ApplyOptions{DryRun: true}, "test"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "RSS table   128 entries, even over queues 0-15 -> weighted for the instance split: 5-6 entries per queue at 2 CPUs/queue (8 queues), 11 at 4 CPUs/queue (6 queues), 8 on the free CPUs (2 queues)") {
		t.Errorf("dry run:\n%s", out.String())
	}
	if len(calls(b, "SetIndir")) != 0 {
		t.Fatal("the dry run wrote a table")
	}

	r := mustApply(t, e, ApplyOptions{Auto: true})
	if !slices.Contains(r.Changed, "eno1: RSS table weighted for the instance split: 5-6 entries per queue at 2 CPUs/queue (8 queues), 11 at 4 CPUs/queue (6 queues), 8 on the free CPUs (2 queues)") {
		t.Errorf("changes %v", r.Changed)
	}
	for _, nic := range []string{"eno1", "eno2"} {
		d := b.Eth.Devs[nic]
		if use := tableUse(d.Table); !d.Configured || len(d.Table) != 128 || len(use) != 16 || d.Resets != 0 {
			t.Errorf("%s: table %v, %d resets", nic, use, d.Resets)
		}
	}
	sh := tableShares(t, e, b, sets, "eno1", "eno2")
	lo, hi := spread(sh, 20)
	if hi-lo > 2 || lo < 11 || hi > 12 || sh[""] != 4*8 {
		t.Errorf("entries per instance %d-%d, free CPUs %d: %v", lo, hi, sh[""], sh)
	}
	if ks := tableState(t, e, "0000:82:00.0"); ks == nil || ks.Written != hw.TableSum(b.Eth.Devs["eno1"].Table) || ks.Pending != "" {
		t.Errorf("state %+v", ks)
	}

	// Again: the placement does not follow the weights, nothing moves.
	b.Eth.Calls = nil
	if r := mustApply(t, e, ApplyOptions{Auto: true}); len(r.Changed) != 0 {
		t.Errorf("second apply: %v", r.Changed)
	}
	if r, err := e.RunNIC(NICOptions{}); err != nil || len(r.Changed) != 0 {
		t.Errorf("tune nic: %v %v", r.Changed, err)
	}
	if c := calls(b, "Set"); len(c) != 0 {
		t.Errorf("calls %v", c)
	}
	if d, _ := e.Status(false); len(d) != 0 {
		t.Errorf("drift: %v", d)
	}
	if got := statusText(t, e); !strings.Contains(got, "RSS table   128 entries weighted for the instance split: 5-6 entries per queue at 2 CPUs/queue (8 queues), 11 at 4 CPUs/queue (6 queues), 8 on the free CPUs (2 queues)") {
		t.Errorf("status:\n%s", got)
	}
	out.Reset()
	e.Out = &out
	if _, err := e.Status(true); err != nil {
		t.Fatal(err)
	}
	var js struct {
		NICs struct {
			NICs []struct {
				RSS *rssPlan `json:"rss_weights"`
			} `json:"nics"`
		} `json:"nics"`
	}
	if err := json.Unmarshal(out.Bytes(), &js); err != nil || len(js.NICs.NICs) != 2 || js.NICs.NICs[0].RSS == nil || len(js.NICs.NICs[0].RSS.Queues) != 16 {
		t.Fatalf("json: %v", err)
	}
	for _, rq := range js.NICs.NICs[0].RSS.Queues {
		if rq.Entries != rq.Live || rq.Weight.CPUs != 4 && rq.Weight.CPUs != 8 || rq.Weight.Unit == "" && rq.Entries != 8 || rq.Entries*rq.Weight.Queues < 5*rq.Weight.CPUs/2 {
			t.Errorf("json queue %+v", rq)
		}
	}
}

// The EPYC servers: 25 instances of 10 CPUs, 6 free, one mlx5 of 63 RSS
// queues: three against two queues an instance, weighted to the same share
// within one entry. An even table laid out otherwise (queues 10-17 with the
// extra entry) is weighted alike, and stays put too.
func TestNICRSSWeightsEPYC(t *testing.T) {
	t.Run("default", func(t *testing.T) { testRSSWeightsEPYC(t, epyc145()) })
	t.Run("rotated", func(t *testing.T) {
		m := epyc145()
		m.NICs[0].Table, m.NICs[0].Configured = hw.DefaultTable(512, 63), true
		for i := range m.NICs[0].Table {
			m.NICs[0].Table[i] = (m.NICs[0].Table[i] + 10) % 63
		}
		testRSSWeightsEPYC(t, m)
	})
}

func testRSSWeightsEPYC(t *testing.T, m hwtest.Machine) {
	e, b := onHW(t, m)
	sets := panelSplit(t, b, 25, 10)
	instances(t, b, b.Allowed.List(), sets...)
	mustApply(t, e, ApplyOptions{Auto: true})
	np := nicPlanOf(t, e)
	held := map[int]int{}
	for i := range sets {
		held[np.place.Units["enp65s0f0np0"][fmt.Sprintf("xray-%d", i+1)][0]]++
	}
	if held[2] == 0 || held[3] == 0 {
		t.Fatalf("RSS queues per instance: %v", held)
	}
	sh := tableShares(t, e, b, sets, "enp65s0f0np0")
	lo, hi := spread(sh, 25)
	if hi-lo > 1 || lo < 512*10/256-1 {
		t.Errorf("entries per instance %d-%d: %v", lo, hi, sh)
	}
	if d := b.Eth.Devs["enp65s0f0np0"]; len(tableUse(d.Table)) != 63 || d.Resets != 0 {
		t.Errorf("table over %d queues, %d resets", len(tableUse(d.Table)), d.Resets)
	}
	b.Eth.Calls = nil
	if r := mustApply(t, e, ApplyOptions{Auto: true}); len(r.Changed) != 0 || len(calls(b, "Set")) != 0 {
		t.Errorf("second apply: %v %v", r.Changed, b.Eth.Calls)
	}
}

// A table someone else set stays, and so does x-ui's once someone changed
// it: revert leaves it too.
func TestNICRSSTableOthers(t *testing.T) {
	m := bond66()
	admin := hw.DefaultTable(128, 16)
	admin[0], admin[1] = 3, 3
	m.NICs[1].Table, m.NICs[1].Configured = admin, true
	e, b := onHW(t, m)
	sets := panelSplit(t, b, 20, 4)
	instances(t, b, b.Allowed.List(), sets...)
	mustApply(t, e, ApplyOptions{Auto: true})
	if !slices.Equal(b.Eth.Devs["eno2"].Table, admin) || slices.Contains(b.Eth.Calls, "SetIndir eno2 128") {
		t.Error("someone else's table changed")
	}
	if !b.Eth.Devs["eno1"].Configured {
		t.Error("eno1 not weighted")
	}
	if got := statusText(t, e); !strings.Contains(got, "RSS table   128 entries over 16 queues, uneven (set by someone): kept") {
		t.Errorf("status:\n%s", got)
	}

	// Someone changes x-ui's table on eno1.
	mine := slices.Clone(b.Eth.Devs["eno1"].Table)
	mine[0] = mine[5]
	b.Eth.SetIndir("eno1", mine)
	b.Eth.Calls = nil
	instances(t, b, b.Allowed.List(), sets[0])
	if r, _ := e.RunNIC(NICOptions{}); strings.Contains(strings.Join(r.Changed, "\n"), "RSS table") || len(calls(b, "SetIndir")) != 0 {
		t.Errorf("tune nic: %v %v", r.Changed, calls(b, "SetIndir"))
	}
	rv, err := e.Revert(false, false)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(rv.Problems, "eno1 RSS table left as it is: changed since x-ui weighted it") || len(calls(b, "SetIndir")) != 0 {
		t.Errorf("revert: %v %v", rv.Problems, b.Eth.Calls)
	}
}

// x-ui's table is made even again when weighting is no longer called for:
// equal shares (one instance), no split (no instances.json).
func TestNICRSSTableEvenAgain(t *testing.T) {
	for _, c := range []struct {
		name, why string
		mod       func(b *hwtest.Built, sets []string)
	}{
		{"equal shares", "the instances' RSS queues weigh the same", func(b *hwtest.Built, sets []string) {
			instances(t, b, b.Allowed.List(), b.Allowed.List())
		}},
		{"no split", "no usable instance split", func(b *hwtest.Built, sets []string) {
			b.WriteFile("/usr/local/x-ui/bin/"+hw.InstancesFile, "")
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e, b := onHW(t, bond66())
			sets := panelSplit(t, b, 20, 4)
			instances(t, b, b.Allowed.List(), sets...)
			mustApply(t, e, ApplyOptions{Auto: true})
			if !b.Eth.Devs["eno1"].Configured || tableState(t, e, "0000:82:00.0") == nil {
				t.Fatal("not weighted")
			}
			c.mod(b, sets)
			if got := statusText(t, e); !strings.Contains(got, "RSS table   128 entries weighted by x-ui, no longer called for ("+c.why+"): 'x-ui tune apply' makes it even again") {
				t.Errorf("status:\n%s", got)
			}
			if d, _ := e.Status(false); !slices.Contains(d, "NIC eno1 RSS table") {
				t.Errorf("drift %v", d)
			}
			b.Eth.Calls = nil
			r, err := e.RunNIC(NICOptions{})
			if err != nil || !slices.Contains(r.Changed, "eno1: RSS table even again ("+c.why+")") {
				t.Errorf("tune nic: %v %v", r.Changed, err)
			}
			for _, nic := range []string{"eno1", "eno2"} {
				if d := b.Eth.Devs[nic]; d.Configured || !hw.DefaultForm(d.Table, 16) {
					t.Errorf("%s: table %v", nic, d.Table[:20])
				}
			}
			if !slices.Equal(calls(b, "SetIndir"), []string{"SetIndir eno1 default", "SetIndir eno2 default"}) {
				t.Errorf("calls %v", b.Eth.Calls)
			}
			if ks := tableState(t, e, "0000:82:00.0"); ks != nil {
				t.Errorf("state %+v", ks)
			}
			if r, _ := e.RunNIC(NICOptions{}); len(r.Changed) != 0 {
				t.Errorf("again: %v", r.Changed)
			}
			if got := statusText(t, e); !strings.Contains(got, "RSS table   128 entries, even over queues 0-15: kept") {
				t.Errorf("status:\n%s", got)
			}
		})
	}
}

// Revert makes x-ui's table even: on an 82599 with 56 queues of which its
// table can address 16, written out (a default over 56 is refused).
func TestNICRSSRevert(t *testing.T) {
	e, b := onHW(t, hwtest.Production())
	instances(t, b, "0-55", prodAuto...)
	mustApply(t, e, ApplyOptions{Auto: true})
	if !b.Eth.Devs["eno1"].Configured || hw.EvenOver(b.Eth.Devs["eno1"].Table, 16) {
		t.Fatal("not weighted")
	}
	dry, err := e.Revert(false, true)
	if err != nil || !slices.Contains(dry.Changed, "would make eno1's weighted RSS table even over queues 0-15") || !b.Eth.Devs["eno1"].Configured {
		t.Errorf("dry revert: %v %v", dry.Changed, err)
	}
	rv, err := e.Revert(false, false)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(rv.Changed, "eno1 RSS table: weighted -> even over queues 0-15") || !slices.Equal(b.Eth.Devs["eno1"].Table, hw.DefaultTable(128, 16)) {
		t.Errorf("revert: %v %v", rv.Changed, rv.Problems)
	}
	if !slices.Equal(calls(b, "SetIndir"), []string{"SetIndir eno1 128", "SetIndir eno1 128"}) {
		t.Errorf("calls %v", calls(b, "SetIndir"))
	}
}

// A raise with x-ui's table set: it is made even first (a driver that
// refuses a queue change while a table is set lets it through), and the new
// queues are weighted after. When that fails, the table is still taken for
// the default after the raise, so RSS is seen to use the new queues.
func TestNICRSSRaise(t *testing.T) {
	m := hwtest.Bond()
	for i := range m.NICs {
		m.NICs[i].Channels.Combined = 8
	}
	setup := func(t *testing.T) (*Env, *hwtest.Built) {
		e, b := onHW(t, m)
		instances(t, b, "0-55", prodAuto...)
		mustApply(t, e, ApplyOptions{Auto: true})
		for _, nic := range []string{"eno1", "eno2"} {
			if d := b.Eth.Devs[nic]; !d.Configured || len(tableUse(d.Table)) != 8 {
				t.Fatalf("%s not weighted over 8 queues", nic)
			}
			b.Eth.Devs[nic].TableLock = true
		}
		b.Eth.Calls = nil
		return e, b
	}
	check := func(t *testing.T, e *Env, b *hwtest.Built, r *Result) {
		t.Helper()
		for _, nic := range []string{"eno1", "eno2"} {
			d := b.Eth.Devs[nic]
			if d.Channels.Combined != 14 || !d.Configured || len(tableUse(d.Table)) != 14 || hw.EvenOver(d.Table, 14) {
				t.Errorf("%s: %d queues, table over %d (%v %v)", nic, d.Channels.Combined, len(tableUse(d.Table)), r.Changed, r.Problems)
			}
		}
		if cs := chanState(t, e, "0000:82:00.0"); cs.Failed != "" || cs.RSSCap != 0 || cs.Want != 14 {
			t.Errorf("state %+v", cs)
		}
		if ks := tableState(t, e, "0000:82:00.0"); ks == nil || ks.Written != hw.TableSum(b.Eth.Devs["eno1"].Table) {
			t.Errorf("table state %+v", ks)
		}
		if r, _ := e.RunNIC(NICOptions{Boot: true}); len(r.Changed) != 0 {
			t.Errorf("next boot: %v", r.Changed)
		}
	}

	e, b := setup(t)
	r, err := e.RunNIC(NICOptions{Boot: true})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"SetIndir eno1 default", "SetChannels eno1 rx=0 tx=0 other=1 combined=14", "SetIndir eno1 128"}
	if got := slices.DeleteFunc(slices.Clone(b.Eth.Calls), func(c string) bool {
		return !strings.HasPrefix(c, "Set") || !strings.Contains(c, "eno1")
	}); !slices.Equal(got, want) {
		t.Errorf("calls %v", got)
	}
	check(t, e, b, r)

	// The table cannot be made even before the raise (and the card lets a
	// set table through): after the raise it is still taken for x-ui's.
	e, b = setup(t)
	for _, nic := range []string{"eno1", "eno2"} {
		b.Eth.Devs[nic].TableLock = false
		b.Eth.Fail["SetIndir "+nic] = fmt.Errorf("busy: %w", hw.ErrBusy)
	}
	b.Eth.DuringReset = func(dev string) { delete(b.Eth.Fail, "SetIndir "+dev) }
	r, err = e.RunNIC(NICOptions{Boot: true})
	if err != nil || !strings.Contains(strings.Join(r.Problems, "\n"), "eno1: RSS table not made even before the queue raise: device busy") {
		t.Fatalf("problems %v %v", r.Problems, err)
	}
	check(t, e, b, r)

	// The raises do not happen (the cards are busy): the tables made even
	// for them are weighted again in the same run.
	e, b = setup(t)
	for _, nic := range []string{"eno1", "eno2"} {
		b.Eth.Fail["SetChannels "+nic] = fmt.Errorf("busy: %w", hw.ErrBusy)
	}
	r, err = e.RunNIC(NICOptions{Boot: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, nic := range []string{"eno1", "eno2"} {
		d := b.Eth.Devs[nic]
		if d.Channels.Combined != 8 || !d.Configured || hw.EvenOver(d.Table, 8) || !slices.Equal(calls(b, "SetIndir "+nic), []string{"SetIndir " + nic + " default", "SetIndir " + nic + " 128"}) {
			t.Errorf("%s: %d queues, table %v, calls %v (%v %v)", nic, d.Channels.Combined, tableUse(d.Table), b.Eth.Calls, r.Changed, r.Problems)
		}
	}
	if ks := tableState(t, e, "0000:82:00.0"); ks == nil || ks.Written != hw.TableSum(b.Eth.Devs["eno1"].Table) {
		t.Errorf("table state %+v", ks)
	}
}

// deafIndir takes RSS tables without applying them.
type deafIndir struct{ hw.Ethtool }

func (deafIndir) SetIndir(string, []uint32) error { return nil }

// A table that cannot be written: the problem is reported, the state does
// not take it for x-ui's, and the next run tries again. A driver that takes
// it without applying it is caught by reading it back.
func TestNICRSSWriteFails(t *testing.T) {
	e, b := onHW(t, bond66())
	sets := panelSplit(t, b, 20, 4)
	instances(t, b, b.Allowed.List(), sets...)
	b.Eth.Fail["SetIndir eno1"] = fmt.Errorf("busy: %w", hw.ErrBusy)
	r := mustApply(t, e, ApplyOptions{Auto: true})
	if !slices.Contains(r.Problems, "eno1: RSS table not weighted: device busy") || b.Eth.Devs["eno1"].Configured || !b.Eth.Devs["eno2"].Configured {
		t.Errorf("apply: %v", r.Problems)
	}
	if ks := tableState(t, e, "0000:82:00.0"); ks != nil {
		t.Errorf("state %+v", ks)
	}
	if d, _ := e.Status(false); !slices.Contains(d, "NIC eno1 RSS table") || slices.Contains(d, "NIC eno2 RSS table") {
		t.Errorf("drift %v", d)
	}
	delete(b.Eth.Fail, "SetIndir eno1")
	if r, _ := e.RunNIC(NICOptions{}); len(r.Problems) != 0 || !b.Eth.Devs["eno1"].Configured || tableState(t, e, "0000:82:00.0") == nil {
		t.Errorf("again: %v %v", r.Changed, r.Problems)
	}

	// Made even again (one instance, equal shares), refused: still x-ui's,
	// tried again next time.
	instances(t, b, b.Allowed.List(), b.Allowed.List())
	b.Eth.Fail["SetIndir eno1"] = fmt.Errorf("busy: %w", hw.ErrBusy)
	if r, _ := e.RunNIC(NICOptions{}); !slices.Contains(r.Problems, "eno1: RSS table not made even: device busy") || tableState(t, e, "0000:82:00.0") == nil {
		t.Errorf("even: %v %v", r.Changed, r.Problems)
	}
	delete(b.Eth.Fail, "SetIndir eno1")
	if r, _ := e.RunNIC(NICOptions{}); !slices.Contains(r.Changed, "eno1: RSS table even again (the instances' RSS queues weigh the same)") || b.Eth.Devs["eno1"].Configured {
		t.Errorf("even again: %v %v", r.Changed, r.Problems)
	}

	e, b = onHW(t, bond66())
	instances(t, b, b.Allowed.List(), sets...)
	e.Eth = deafIndir{e.Eth}
	r = mustApply(t, e, ApplyOptions{Auto: true})
	if !slices.Contains(r.Problems, "eno1: RSS table not weighted: the driver did not take it") || tableState(t, e, "0000:82:00.0") != nil || e.exists(TablesFile) {
		t.Errorf("deaf: %v", r.Problems)
	}
}

// Going back to an x-ui from before weighted tables drops their fingerprints
// from the state; TablesFile keeps them, so once this one is back its
// tables are its own again: placed by index (nothing moves), and made even
// by revert. A table the driver reset meanwhile needs no undoing.
func TestNICRSSRollback(t *testing.T) {
	e, b := onHW(t, bond66())
	sets := panelSplit(t, b, 20, 4)
	instances(t, b, b.Allowed.List(), sets...)
	mustApply(t, e, ApplyOptions{Auto: true})
	var tables map[string]TableState
	if err := json.Unmarshal([]byte(e.readTrim(TablesFile)), &tables); err != nil || len(tables) != 2 ||
		tables["0000:82:00.1"] != (TableState{Written: hw.TableSum(b.Eth.Devs["eno2"].Table), Rings: 16}) {
		t.Fatalf("%s: %v %v", TablesFile, tables, err)
	}
	var raw map[string]any
	json.Unmarshal([]byte(e.readTrim(StateFile)), &raw)
	for _, ns := range raw["nics"].(map[string]any) {
		delete(ns.(map[string]any), "rss_table")
	}
	old, _ := json.Marshal(raw)
	writeT(t, e.Root, StateFile, string(old))

	b.Eth.Calls = nil
	if r, err := e.RunNIC(NICOptions{}); err != nil || len(r.Changed) != 0 || len(calls(b, "Set")) != 0 {
		t.Errorf("tune nic: %v %v %v", r.Changed, b.Eth.Calls, err)
	}
	if ks := tableState(t, e, "0000:82:00.0"); ks == nil || ks.Written != hw.TableSum(b.Eth.Devs["eno1"].Table) || ks.Rings != 16 {
		t.Errorf("state %+v", ks)
	}
	if got := statusText(t, e); !strings.Contains(got, "RSS table   128 entries weighted for the instance split") {
		t.Errorf("status:\n%s", got)
	}

	// The driver reset eno1's table (a reinit): revert leaves it, no problem.
	b.Eth.SetIndir("eno1", nil)
	b.Eth.Calls = nil
	rv, err := e.Revert(false, false)
	if err != nil || len(rv.Problems) != 0 || !slices.Contains(rv.Changed, "eno2 RSS table: weighted -> even over queues 0-15") {
		t.Errorf("revert: %v %v %v", rv.Changed, rv.Problems, err)
	}
	if !slices.Equal(calls(b, "SetIndir"), []string{"SetIndir eno2 default"}) || e.exists(TablesFile) {
		t.Errorf("calls %v", calls(b, "SetIndir"))
	}
}

// Queues added while x-ui's table is set (an admin's "ethtool -L"), which
// mlx5 keeps: the table is made even over all of them, the driver's
// default, and weighted over them the next time.
func TestNICRSSMoreQueues(t *testing.T) {
	m := epyc145()
	m.NICs[0].Channels.Combined = 32
	e, b := onHW(t, m)
	sets := panelSplit(t, b, 25, 10)
	instances(t, b, b.Allowed.List(), sets...)
	mustApply(t, e, ApplyOptions{Auto: true})
	nic := "enp65s0f0np0"
	d := b.Eth.Devs[nic]
	if !d.Configured || len(tableUse(d.Table)) != 32 {
		t.Fatalf("not weighted over 32 queues: %v", tableUse(d.Table))
	}
	c := d.Channels
	c.Combined = 63
	if err := b.Eth.SetChannels(nic, c); err != nil || len(tableUse(d.Table)) != 32 {
		t.Fatal(err)
	}
	if got := statusText(t, e); !strings.Contains(got, "63 of 63: kept (RSS uses 32: its table)") ||
		!strings.Contains(got, "RSS table   512 entries weighted by x-ui, no longer called for (the NIC has more queues than when x-ui weighted it)") {
		t.Errorf("status:\n%s", got)
	}
	b.Eth.Calls = nil
	r, err := e.RunNIC(NICOptions{})
	if err != nil || !slices.Contains(r.Changed, nic+": RSS table even again (the NIC has more queues than when x-ui weighted it)") ||
		d.Configured || !hw.DefaultForm(d.Table, 63) || !slices.Equal(calls(b, "SetIndir"), []string{"SetIndir " + nic + " default"}) {
		t.Errorf("tune nic: %v %v %v", r.Changed, b.Eth.Calls, err)
	}
	if r, _ := e.RunNIC(NICOptions{}); !strings.Contains(strings.Join(r.Changed, "\n"), nic+": RSS table weighted") || !d.Configured || len(tableUse(d.Table)) != 63 {
		t.Errorf("weighted over 63: %v %v", r.Changed, tableUse(d.Table))
	}
	if r, _ := e.RunNIC(NICOptions{}); len(r.Changed) != 0 {
		t.Errorf("again: %v", r.Changed)
	}
}

// A run killed between writing the table and saving the state: the next
// one finds its pending table live and takes it for x-ui's; a pending table
// that never got written is forgotten. An older state without the table
// gets it weighted.
func TestNICRSSPending(t *testing.T) {
	e, b := onHW(t, bond66())
	sets := panelSplit(t, b, 20, 4)
	instances(t, b, b.Allowed.List(), sets...)
	mustApply(t, e, ApplyOptions{Auto: true})
	weighted := slices.Clone(b.Eth.Devs["eno1"].Table)
	st, _, _ := e.loadState()
	ks := st.NICs["0000:82:00.0"].Table
	ks.Pending, ks.Written = ks.Written, ""
	if err := e.saveState(st, nil); err != nil {
		t.Fatal(err)
	}
	b.Eth.Calls = nil
	if r, _ := e.RunNIC(NICOptions{}); len(r.Changed) != 0 || len(calls(b, "SetIndir")) != 0 {
		t.Errorf("settled: %v %v", r.Changed, b.Eth.Calls)
	}
	if ks := tableState(t, e, "0000:82:00.0"); ks == nil || ks.Written != hw.TableSum(weighted) || ks.Pending != "" {
		t.Errorf("state %+v", ks)
	}

	// Pending, not written: the table is the driver's default again.
	st, _, _ = e.loadState()
	st.NICs["0000:82:00.0"].Table = &TableState{Pending: hw.TableSum(weighted)}
	e.saveState(st, nil)
	b.Eth.SetIndir("eno1", nil)
	r, _ := e.RunNIC(NICOptions{})
	if !slices.Equal(b.Eth.Devs["eno1"].Table, weighted) || !strings.Contains(strings.Join(r.Changed, "\n"), "eno1: RSS table weighted") {
		t.Errorf("not weighted again: %v", r.Changed)
	}

	// The write ahead: the table about to be written is marked first.
	b.Eth.SetIndir("eno1", nil)
	st, _, _ = e.loadState()
	st.NICs["0000:82:00.0"].Table = nil
	np := nicPlanOf(t, e)
	if !markPending(st, np) || st.NICs["0000:82:00.0"].Table.Pending != hw.TableSum(weighted) || st.NICs["0000:82:00.0"].Table.Rings != 16 ||
		st.NICs["0000:82:00.1"].Table.Pending != "" {
		t.Errorf("marks %+v %+v", st.NICs["0000:82:00.0"].Table, st.NICs["0000:82:00.1"].Table)
	}

	// The state of an x-ui before weighted tables.
	data := e.readTrim(StateFile)
	var raw map[string]any
	json.Unmarshal([]byte(data), &raw)
	for _, ns := range raw["nics"].(map[string]any) {
		delete(ns.(map[string]any), "rss_table")
	}
	old, _ := json.Marshal(raw)
	writeT(t, e.Root, StateFile, string(old))
	for _, nic := range []string{"eno1", "eno2"} {
		b.Eth.SetIndir(nic, nil)
	}
	if r, err := e.RunNIC(NICOptions{}); err != nil || len(r.Changed) != 2 || !slices.Equal(b.Eth.Devs["eno1"].Table, weighted) || tableState(t, e, "0000:82:00.1") == nil {
		t.Errorf("old state: %v %v", r.Changed, err)
	}
}

// The weighted table and fq on the uplinks together, on .66 with the
// kernel's pfifo_fast under both ports: one apply writes both, the state
// keeps both, a second run changes nothing. A run killed after the table
// and before the replace leaves both marked: the next one takes the table
// for x-ui's and puts the root in, once. Revert undoes both. A queue raise
// at boot makes the table even, weights it again over the new queues and
// makes x-ui's root again, so they run fq too.
func TestNICRSSWithQdisc(t *testing.T) {
	e, b, tc := withTC(t, bond66(), "pfifo_fast", "eno1", "eno2")
	tc.roots["bond0"] = &fakeRoot{kind: "noqueue", handle: "0:"}
	sets := panelSplit(t, b, 20, 4)
	instances(t, b, b.Allowed.List(), sets...)
	r := mustApply(t, e, ApplyOptions{Auto: true})
	for _, nic := range []string{"eno1", "eno2"} {
		if !slices.ContainsFunc(r.Changed, func(c string) bool { return strings.HasPrefix(c, nic+": RSS table weighted for the instance split") }) ||
			!slices.Contains(r.Changed, nic+": root qdisc mq, pfifo_fast on 16 queues -> mq, fq on 16 queues") {
			t.Errorf("%s: apply %v %v", nic, r.Changed, r.Problems)
		}
		if d := b.Eth.Devs[nic]; !d.Configured || hw.EvenOver(d.Table, 16) || d.Resets != 0 {
			t.Errorf("%s: table %v, %d resets", nic, tableUse(d.Table), d.Resets)
		}
	}
	for _, k := range []string{"0000:82:00.0", "0000:82:00.1"} {
		if ks, qs := tableState(t, e, k), qdiscState(t, e, k); ks == nil || ks.Written == "" || qs == nil || qs.Kind != "mq" || qs.Handle == "" {
			t.Errorf("%s: state %+v %+v", k, ks, qs)
		}
	}
	b.Eth.Calls, tc.calls = nil, nil
	if r := mustApply(t, e, ApplyOptions{Auto: true}); len(r.Changed) != 0 {
		t.Errorf("second apply: %v", r.Changed)
	}
	if r, err := e.RunNIC(NICOptions{}); err != nil || len(r.Changed)+len(r.Problems) != 0 {
		t.Errorf("tune nic: %v %v", r, err)
	}
	if c := calls(b, "Set"); len(c) != 0 || len(tc.calls) != 0 {
		t.Errorf("calls %v %v", c, tc.calls)
	}
	if d, _ := e.Status(false); len(d) != 0 {
		t.Errorf("drift: %v", d)
	}

	// Killed between the two writes.
	weighted := slices.Clone(b.Eth.Devs["eno1"].Table)
	b.Eth.SetIndir("eno1", nil)
	tc.up("eno1", "pfifo_fast")
	st, _, _ := e.loadState()
	st.NICs["0000:82:00.0"].Table, st.NICs["0000:82:00.0"].Qdisc = nil, nil
	e.saveState(st, nil)
	type killed struct{}
	onDisk := ""
	run := e.Run
	e.Run = func(d time.Duration, name string, args ...string) (string, error) {
		if name == "tc" && args[0] == "qdisc" {
			onDisk, _ = e.read(StateFile)
			panic(killed{})
		}
		return run(d, name, args...)
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
	if !slices.Equal(b.Eth.Devs["eno1"].Table, weighted) || !strings.Contains(onDisk, `"pending": "mq"`) || !strings.Contains(onDisk, `"pending": "`+hw.TableSum(weighted)+`"`) {
		t.Fatalf("not both marked before the writes:\n%s", onDisk)
	}
	writeT(t, e.Root, StateFile, onDisk)
	b.Eth.Calls, tc.calls = nil, nil
	r, err := e.RunNIC(NICOptions{})
	if err != nil || !slices.Equal(r.Changed, []string{"eno1: root qdisc mq, pfifo_fast on 16 queues -> mq, fq on 16 queues"}) || len(r.Problems) != 0 ||
		len(calls(b, "SetIndir")) != 0 || !slices.Equal(tc.calls, []string{"qdisc replace dev eno1 root mq"}) {
		t.Errorf("the run after: %v %v %v %v", r, err, b.Eth.Calls, tc.calls)
	}
	if ks, qs := tableState(t, e, "0000:82:00.0"), qdiscState(t, e, "0000:82:00.0"); ks == nil || ks.Written != hw.TableSum(weighted) || ks.Pending != "" ||
		qs == nil || qs.Orig != "mq, pfifo_fast on 16 queues" || qs.Handle == "" || qs.Pending != "" {
		t.Errorf("state after: %+v %+v", ks, qs)
	}

	rv, err := e.Revert(false, false)
	if err != nil || len(rv.Problems) != 0 {
		t.Fatalf("revert: %v %v", rv.Problems, err)
	}
	for _, nic := range []string{"eno1", "eno2"} {
		if !slices.Contains(rv.Changed, nic+" RSS table: weighted -> even over queues 0-15") ||
			!slices.ContainsFunc(rv.Changed, func(c string) bool { return strings.HasPrefix(c, nic+" root qdisc: mq, fq on 16 queues -> ") }) {
			t.Errorf("%s: revert %v", nic, rv.Changed)
		}
		if !hw.EvenOver(b.Eth.Devs[nic].Table, 16) || tc.roots[nic].handle != "0:" {
			t.Errorf("%s after revert: table %v, root %s", nic, tableUse(b.Eth.Devs[nic].Table), tc.text(t, nic))
		}
	}

	// A raise at boot.
	m := hwtest.Bond()
	for i := range m.NICs {
		m.NICs[i].Channels.Combined = 8
	}
	e, b, tc = withTC(t, m, "pfifo_fast", "eno1", "eno2")
	instances(t, b, "0-55", prodAuto...)
	mustApply(t, e, ApplyOptions{Auto: true})
	b.Eth.Calls, tc.calls = nil, nil
	r, err = e.RunNIC(NICOptions{Boot: true})
	if err != nil || len(r.Problems) != 0 {
		t.Fatalf("raise: %v %v", r.Problems, err)
	}
	for _, nic := range []string{"eno1", "eno2"} {
		d := b.Eth.Devs[nic]
		if d.Channels.Combined != 14 || !d.Configured || len(tableUse(d.Table)) != 14 || hw.EvenOver(d.Table, 14) ||
			!slices.Equal(calls(b, "SetIndir "+nic), []string{"SetIndir " + nic + " default", "SetIndir " + nic + " 128"}) {
			t.Errorf("%s: %d queues, table %v, calls %v", nic, d.Channels.Combined, tableUse(d.Table), b.Eth.Calls)
		}
		if got := tc.text(t, nic); !strings.HasSuffix(got, ", fq on 14 queues") || tc.roots[nic].handle == "0:" ||
			!slices.Contains(r.Changed, nic+": root qdisc mq, fq on 8 queues, pfifo_fast on 6 -> mq, fq on 14 queues") {
			t.Errorf("%s: root %s, changes %v", nic, got, r.Changed)
		}
	}
	if ks, qs := tableState(t, e, "0000:82:00.0"), qdiscState(t, e, "0000:82:00.0"); ks == nil || ks.Written != hw.TableSum(b.Eth.Devs["eno1"].Table) ||
		qs == nil || qs.Handle != tc.roots["eno1"].handle {
		t.Errorf("state after the raise: %+v %+v", ks, qs)
	}
	if r, _ := e.RunNIC(NICOptions{Boot: true}); len(r.Changed) != 0 {
		t.Errorf("next boot: %v", r.Changed)
	}
	if d, _ := e.Status(false); len(d) != 0 {
		t.Errorf("drift after the raise: %v", d)
	}
}
