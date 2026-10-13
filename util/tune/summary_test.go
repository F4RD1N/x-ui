//go:build linux

package tune

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// The installer's "Configured:" lines: what x-ui set, and whose a value is
// when another file sets it.
func TestSummary(t *testing.T) {
	m := machine{mem: 126877696 * KiB, cpus: 56, conntrack: true, files: map[string]string{
		"/etc/sysctl.d/90-edge-proxy.conf": "net.netfilter.nf_conntrack_max = 8388608\n",
	}}
	m.memTotal = m.mem
	e := m.build(t)
	if got := e.summary(); !slices.Equal(got, []string{"Tuning: not applied ('x-ui tune apply' applies it)"}) {
		t.Errorf("before apply: %q", got)
	}
	mustApply(t, e, ApplyOptions{})
	before, state := snapshot(t, e), e.readTrim(StateFile)
	e.Ran = nil
	want := []string{
		"Open files: 2097152 per process (x-ui and its cores)",
		"Conntrack: max 8388608 (kept: /etc/sysctl.d/90-edge-proxy.conf)",
		"Backlog: somaxconn 65535, netdev_max_backlog 16384, tcp_max_syn_backlog 65536",
		"Congestion control: bbr with fq",
		"NIC: no default route",
	}
	if got := e.summary(); !slices.Equal(got, want) {
		t.Errorf("summary:\n%s", strings.Join(got, "\n"))
	}
	if d := diffSnap(before, snapshot(t, e)); len(d) > 0 || e.readTrim(StateFile) != state || len(e.Ran) != 0 {
		t.Errorf("summary wrote or ran something: %v %v", d, e.Ran)
	}

	// Through the environment, as "x-ui diag --summary" calls it.
	facts, _ := json.Marshal(e.Facts)
	t.Setenv("XUI_TUNE_ROOT", e.Root)
	t.Setenv("XUI_TUNE_FACTS", string(facts))
	if got := Summary(); !slices.Equal(got, want) {
		t.Errorf("Summary():\n%s", strings.Join(got, "\n"))
	}

	if _, err := e.Revert(false, false); err != nil {
		t.Fatal(err)
	}
	if got := e.summary(); !slices.Equal(got, []string{"Tuning: off ('x-ui tune apply' turns it on)"}) {
		t.Errorf("after revert: %q", got)
	}

	// No conntrack line without the module; a small machine keeps the
	// unit's limit.
	e = machine{mem: 2 * GiB, cpus: 2}.build(t)
	mustApply(t, e, ApplyOptions{})
	got := e.summary()
	if len(got) != 4 || got[0] != "Open files: 1048576 per process (x-ui and its cores)" || !strings.HasPrefix(got[1], "Backlog: somaxconn 16384,") {
		t.Errorf("small machine: %q", got)
	}
}
