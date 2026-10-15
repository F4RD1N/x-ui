//go:build linux

package tune

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

// CPU performance mode. Where the OS sets the CPU clock (cpufreq), the
// "performance" governor keeps the cores at full clock instead of ramping up
// after a burst of packets has already queued, and idle states that take more
// than 10 µs to wake from are turned off, so a core does not sleep through the
// start of a burst. On a dual EPYC whose BIOS left the clock to the OS this
// took the average clock under load from 2.7 to 3.0 GHz, cut xray's CPU per
// Gb/s by 7% and the NIC's dropped packets by most (2026-10).
//
// Both are live kernel values, gone at reboot: every apply sets them, the boot
// apply included, and revert puts back each value x-ui changed. A machine
// whose BIOS or hypervisor sets the clock has no cpufreq and is left alone; so
// is one where a tool or the admin decided (tuned, cpupower,
// power-profiles-daemon, the kernel command line, idle states already turned
// off by someone).

const (
	cpuDir = "/sys/devices/system/cpu"
	// cpuIdleMaxWake is the slowest wake-up (µs) an idle state may have and
	// stay on: C1 and C1E stay, C2/C3/C6 go.
	cpuIdleMaxWake = 10
)

// cpuTools set the governor or idle states themselves: when one is enabled,
// x-ui leaves both to it.
var cpuTools = []string{"tuned", "cpupower", "power-profiles-daemon", "tlp", "auto-cpufreq", "cpufrequtils"}

// cpuWrite is one value x-ui sets: State's key (cpufreq/policyN or
// cpuN/stateM), the file, its live value and the value wanted.
type cpuWrite struct {
	Key, Path, Live, Want string
}

// cpuPlan is what the CPU part of an apply does.
type cpuPlan struct {
	Governor []cpuWrite
	Idle     []cpuWrite
	GovNote  string // the governor's state when nothing is written
	IdleNote string
	idleOff  map[string]string // stateM -> "C6 (133 µs)": the states x-ui keeps off
}

func cpuKeyPath(key string) string {
	if pol, ok := strings.CutPrefix(key, "cpufreq/"); ok {
		return cpuDir + "/cpufreq/" + pol + "/scaling_governor"
	}
	cpu, state, _ := strings.Cut(key, "/")
	return cpuDir + "/" + cpu + "/cpuidle/" + state + "/disable"
}

// cpuTool names a tool or setting that decides the clock or idle states, ""
// when none does.
func (e *Env) cpuTool(f *Facts) string {
	cmdline := " " + e.readTrim("/proc/cmdline") + " "
	for _, a := range []string{"cpufreq.default_governor=", "idle=", "processor.max_cstate=", "intel_idle.max_cstate=", "cpuidle.off="} {
		if strings.Contains(cmdline, " "+a) {
			return "the kernel command line (" + strings.TrimSuffix(a, "=") + ")"
		}
	}
	if strings.Contains(e.readTrim("/etc/default/cpufrequtils"), "GOVERNOR=") {
		return "/etc/default/cpufrequtils"
	}
	// Enabled at boot: read from the unit links, so status and the
	// installer's summary run no command.
	for _, u := range cpuTools {
		if len(e.glob("/etc/systemd/system/*.wants/"+u+".service")) > 0 {
			return u
		}
	}
	return ""
}

func (e *Env) planCPU(f *Facts, st *State) *cpuPlan {
	p := &cpuPlan{idleOff: map[string]string{}}
	if f.Container() || e.OnlyNet {
		p.GovNote, p.IdleNote = "container: kept by the host", "container: kept by the host"
		return p
	}
	if tool := e.cpuTool(f); tool != "" {
		p.GovNote, p.IdleNote = "kept: set by "+tool, "kept: set by "+tool
		return p
	}

	// The governor, per cpufreq policy.
	pols := e.glob(cpuDir + "/cpufreq/policy[0-9]*/scaling_governor")
	sort.Strings(pols)
	perf := 0
	for _, g := range pols {
		dir := path.Dir(g)
		key := "cpufreq/" + path.Base(dir)
		live := e.readTrim(g)
		if live == "performance" {
			perf++
			continue
		}
		if !strings.Contains(" "+e.readTrim(dir+"/scaling_available_governors")+" ", " performance ") {
			p.GovNote = live + ": the driver has no performance governor"
			continue
		}
		if ks := st.CPU[key]; ks != nil && ks.Orig != "" && live != ks.Orig {
			// Neither x-ui's value nor what the kernel starts with: someone
			// chose it since.
			p.GovNote = "kept: " + live + " (changed since x-ui set performance)"
			continue
		}
		if e.writable(g) != nil {
			p.GovNote = live + ": " + e.roNote(f)
			continue
		}
		p.Governor = append(p.Governor, cpuWrite{Key: key, Path: g, Live: live, Want: "performance"})
	}
	switch {
	case len(pols) == 0:
		p.GovNote = "the BIOS or the hypervisor sets the clock"
	case len(p.Governor) == 0 && p.GovNote == "":
		p.GovNote = fmt.Sprintf("performance on %d clock policies", perf)
	}

	// Idle states slower than cpuIdleMaxWake to wake from, per CPU.
	states := e.glob(cpuDir + "/cpu[0-9]*/cpuidle/state[0-9]*/disable")
	sort.Strings(states)
	if len(states) == 0 {
		p.IdleNote = "the BIOS or the hypervisor sets them"
		return p
	}
	var deep []cpuWrite
	var others []string
	for _, d := range states {
		dir := path.Dir(d)
		lat := atoi64(e.readTrim(dir + "/latency"))
		if lat <= cpuIdleMaxWake {
			continue
		}
		cpu := path.Base(path.Dir(path.Dir(dir)))
		state := path.Base(dir)
		key := cpu + "/" + state
		live := e.readTrim(d)
		ks := st.CPU[key]
		if live != "0" {
			if ks == nil {
				// Turned off by someone else: they decide the idle states.
				if !containsStr(others, state) {
					others = append(others, state+" ("+e.readTrim(dir+"/name")+")")
				}
			}
			continue
		}
		p.idleOff[state] = fmt.Sprintf("%s (%d µs)", e.readTrim(dir+"/name"), lat)
		deep = append(deep, cpuWrite{Key: key, Path: d, Live: live, Want: "1"})
	}
	switch {
	case len(others) > 0:
		p.IdleNote = "kept: " + strings.Join(others, ", ") + " turned off by someone else"
		p.idleOff = map[string]string{}
	case len(deep) > 0 && e.writable(deep[0].Path) != nil:
		p.IdleNote = e.roNote(f)
		p.idleOff = map[string]string{}
	default:
		p.Idle = deep
	}
	if p.IdleNote == "" {
		var off []string
		for k := range st.CPU {
			if !strings.HasPrefix(k, "cpufreq/") {
				off = append(off, k)
			}
		}
		if len(p.Idle) == 0 && len(off) == 0 {
			p.IdleNote = "none slower than 10 µs to wake"
		} else if len(p.Idle) == 0 {
			p.IdleNote = fmt.Sprintf("slower than 10 µs to wake: off on %d CPU states (x-ui)", len(off))
		}
	}
	return p
}

func containsStr(list []string, prefix string) bool {
	for _, s := range list {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

// applyCPU writes the plan and records what it changed.
func (e *Env) applyCPU(f *Facts, st *State, r *Result) {
	p := e.planCPU(f, st)
	if len(p.Governor)+len(p.Idle) == 0 {
		return
	}
	if st.CPU == nil {
		st.CPU = map[string]*KeyState{}
	}
	write := func(ws []cpuWrite) (n int, from []string, fail string) {
		for _, w := range ws {
			if err := e.writeKernel(w.Path, w.Want); err != nil {
				_, fail = errState(err, f)
				continue
			}
			ks := st.CPU[w.Key]
			if ks == nil {
				ks = &KeyState{Orig: w.Live}
				st.CPU[w.Key] = ks
			}
			ks.Written = w.Want
			if !containsStr(from, w.Live) {
				from = append(from, w.Live)
			}
			n++
		}
		return n, from, fail
	}
	if n, from, fail := write(p.Governor); n > 0 {
		r.change("cpu clock: %s -> performance on %d policies", strings.Join(from, ", "), n)
	} else if fail != "" {
		r.problem("cpu clock: %s", fail)
	}
	if n, _, fail := write(p.Idle); n > 0 {
		var names []string
		for _, v := range p.idleOff {
			names = append(names, v)
		}
		sort.Strings(names)
		r.change("cpu idle states slower than 10 µs to wake turned off: %s (%d CPU states)", strings.Join(names, ", "), n)
	} else if fail != "" {
		r.problem("cpu idle states: %s", fail)
	}
}

// revertCPU puts back each value x-ui changed that is still x-ui's.
func (e *Env) revertCPU(f *Facts, st *State, r *Result) {
	if len(st.CPU) == 0 {
		return
	}
	gov, idle, left := 0, 0, 0
	for key, ks := range st.CPU {
		p := cpuKeyPath(key)
		if e.readTrim(p) != ks.Written || ks.Orig == "" {
			left++
			continue
		}
		if err := e.writeKernel(p, ks.Orig); err != nil {
			left++
			continue
		}
		if strings.HasPrefix(key, "cpufreq/") {
			gov++
		} else {
			idle++
		}
	}
	if gov > 0 {
		r.change("cpu clock: governor put back on %d policies", gov)
	}
	if idle > 0 {
		r.change("cpu idle states: turned back on (%d CPU states)", idle)
	}
	if left > 0 {
		r.problem("cpu: %d values left as they are (changed since x-ui set them, or gone)", left)
	}
}

// cpuInfo is the CPU part of "x-ui tune status".
func (e *Env) cpuInfo(f *Facts, st *State) []string {
	p := e.planCPU(f, st)
	gov := p.GovNote
	if len(p.Governor) > 0 {
		gov = fmt.Sprintf("%d policies would go to performance (now %s)", len(p.Governor), p.Governor[0].Live)
	} else if n := countPrefix(st.CPU, "cpufreq/"); n > 0 && strings.HasPrefix(gov, "performance") {
		gov += " (x-ui)"
	}
	idle := p.IdleNote
	if len(p.Idle) > 0 {
		var names []string
		for _, v := range p.idleOff {
			names = append(names, v)
		}
		sort.Strings(names)
		idle = fmt.Sprintf("would turn off %s (%d CPU states)", strings.Join(names, ", "), len(p.Idle))
	}
	return []string{"cpu clock: " + gov, "cpu idle states: " + idle}
}

func countPrefix(m map[string]*KeyState, prefix string) int {
	n := 0
	for k := range m {
		if strings.HasPrefix(k, prefix) {
			n++
		}
	}
	return n
}
