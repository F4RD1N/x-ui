//go:build linux

package tune

import (
	"fmt"
	"io"
	"strings"
)

// Summary is what the installer prints under "Configured:" about server
// tuning, one line per setting, from the state file, the plan and the live
// values. It only reads: no lock, no writes, no service manager.
func Summary() []string {
	e, err := NewEnv()
	if err != nil {
		return nil
	}
	e.Out = io.Discard
	return e.summary()
}

func (e *Env) summary() []string {
	st, had, err := e.loadState()
	switch {
	case err == nil && st.Disabled:
		return []string{"Tuning: off ('x-ui tune apply' turns it on)"}
	case err == nil && !had:
		return []string{"Tuning: not applied ('x-ui tune apply' applies it)"}
	}
	f := e.gatherFacts()
	p := e.plan(f, st)
	keys := map[string]*KeyPlan{}
	for _, k := range p.Keys {
		keys[k.Key] = k
	}
	var out []string
	if f.Init == "systemd" || f.Init == "openrc" {
		n := p.DropInNoFile
		if n == 0 {
			n = p.baseNoFile
		}
		if n > 0 {
			out = append(out, fmt.Sprintf("Open files: %d per process (x-ui and its cores)", n))
		}
	}
	// Only when the module is loaded; a value another file sets at least as
	// high is that file's, not x-ui's.
	if k := keys["net.netfilter.nf_conntrack_max"]; k != nil && k.Live != "" {
		line := "Conntrack: max " + k.Live
		if k.OthersFile != "" && i64(k.Others) >= k.T.Num {
			line += " (kept: " + k.OthersFile + ")"
		}
		out = append(out, line)
	}
	var backlog []string
	for _, key := range []string{"net.core.somaxconn", "net.core.netdev_max_backlog", "net.ipv4.tcp_max_syn_backlog"} {
		if k := keys[key]; k != nil && k.Live != "" {
			backlog = append(backlog, key[strings.LastIndex(key, ".")+1:]+" "+k.Live)
		}
	}
	if len(backlog) > 0 {
		out = append(out, "Backlog: "+strings.Join(backlog, ", "))
	}
	if cc := normValue(e.readTrim(sysctlPath("net.ipv4.tcp_congestion_control"))); cc != "" {
		line := "Congestion control: " + cc
		if q := normValue(e.readTrim(sysctlPath("net.core.default_qdisc"))); q != "" {
			line += " with " + q
		}
		out = append(out, line)
	}
	return append(out, e.planNICs(f, st, nicOpts{}).summary()...)
}
