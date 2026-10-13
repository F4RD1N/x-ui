//go:build linux

package tune

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
)

// drift lists what an apply would still change.
func (e *Env) drift(p *Plan) []string {
	var d []string
	for _, k := range p.Keys {
		if k.Want != "" {
			d = append(d, k.Key)
		}
	}
	if p.Hash != nil && p.Hash.Want != "" {
		d = append(d, "nf_conntrack hashsize")
	}
	files := map[string]string{
		SysctlFile:      renderSysctl(p.Keys),
		ModulesLoadFile: p.ModulesLoad,
		ModprobeFile:    p.Modprobe,
	}
	switch {
	case e.OnlyNet: // the service is not this test's business
	case p.Facts.Init == "systemd":
		files[DropInFile] = p.DropIn
	case p.Facts.Init == "openrc":
		files[OpenRCConfFile] = p.ConfD
	}
	for path, want := range files {
		have, err := e.read(path)
		if err != nil {
			have = ""
		}
		if want == "" && !e.isOurs(path) {
			continue
		}
		if have != want {
			d = append(d, path)
		}
	}
	sort.Strings(d)
	return d
}

func (e *Env) osName() string {
	for _, l := range strings.Split(e.readTrim("/etc/os-release"), "\n") {
		if v, ok := strings.CutPrefix(l, "PRETTY_NAME="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return "unknown OS"
}

func gib(b int64) string { return fmt.Sprintf("%.1f GiB", float64(b)/float64(GiB)) }

// Status prints what x-ui tune would do and how the machine is doing. It
// returns the drift (empty when everything is applied).
func (e *Env) Status(asJSON bool) ([]string, error) {
	st, had, err := e.loadState()
	if err != nil {
		return nil, err
	}
	f := e.gatherFacts()
	p := e.plan(f, st)
	d := e.drift(p)
	if st.Disabled {
		d = nil
	}
	svc := e.serviceInfo(f)
	health := e.health(f)
	if asJSON {
		out := map[string]any{
			"state":    stateWord(st, had),
			"os":       e.osName(),
			"plan":     p,
			"drift":    d,
			"process":  svc,
			"health":   health,
			"timesync": e.timeInfo(f),
			"swap":     strings.Split(strings.TrimSpace(e.readTrim("/proc/swaps")), "\n")[1:],
		}
		if ok, why := e.swapEligible(f, st); !ok && why != "" {
			out["swapfile"] = why
		}
		enc := json.NewEncoder(e.Out)
		enc.SetIndent("", "  ")
		return d, enc.Encode(out)
	}
	e.printf("x-ui tune: %s\n", stateWord(st, had))
	e.printPlan(p, st, false)
	e.printf("\nService:\n")
	for _, l := range svc {
		e.printf("  %s\n", l)
	}
	e.printf("\nHost:\n")
	e.printf("  time sync: %s\n", e.timeInfo(f))
	if swaps := strings.Split(strings.TrimSpace(e.readTrim("/proc/swaps")), "\n"); len(swaps) > 1 {
		e.printf("  swap: %s\n", strings.Join(swaps[1:], "; "))
	} else if ok, why := e.swapEligible(f, st); !ok && why != "" {
		e.printf("  swap: none (%s)\n", why)
	} else {
		e.printf("  swap: none\n")
	}
	e.printf("\nHealth:\n")
	for _, l := range health {
		e.printf("  %s\n", l)
	}
	if len(d) > 0 {
		e.printf("\nNot applied yet: %s (run: x-ui tune apply)\n", strings.Join(d, ", "))
	}
	return d, nil
}

func stateWord(st *State, had bool) string {
	switch {
	case st.Disabled:
		return "disabled (x-ui tune apply turns it back on)"
	case had:
		return "applied"
	}
	return "not applied"
}

func (e *Env) printPlan(p *Plan, st *State, dry bool) {
	f := p.Facts
	virt := f.Virt
	if virt == "" {
		virt = "no container"
	}
	init := f.Init
	if init == "" {
		init = "no init system"
	}
	e.printf("Machine: %s, kernel %s, %s, %s, %s RAM (sized as %g GiB), %d CPUs\n",
		e.osName(), f.Kernel, init, virt, gib(f.MemBytes), f.G, f.CPUs)
	for _, n := range f.NICs {
		e.printf("  NIC %s: %s, %d Mb/s, %d rx queues\n", n.Name, n.Driver, n.Speed, n.RxQueues)
	}
	tw := tabwriter.NewWriter(e.Out, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "\nKEY\tLIVE\tTARGET\tSTATE")
	for _, k := range p.Keys {
		state := k.State
		if k.Note != "" {
			state += ": " + k.Note
		}
		if dry && k.Want != "" {
			state += " -> " + k.Want
		}
		if k.Persist != "" {
			state += " [99-x-ui.conf]"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", k.Key, k.Live, k.Target, state)
	}
	if h := p.Hash; h != nil {
		state := h.State
		if h.Note != "" {
			state += ": " + h.Note
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", h.Key, h.Live, h.Target, state)
	}
	tw.Flush()
	if f.Init == "systemd" || f.Init == "openrc" {
		e.printf("\nService targets: open files %d, GOMEMLIMIT %s, GOGC %s\n",
			p.Svc.NoFile, p.Svc.GoMemLimit, orDefault(p.Svc.GoGC, "default"))
		if p.GoMemFrom != "" {
			e.printf("  GOMEMLIMIT is set in %s: kept\n", p.GoMemFrom)
		}
		if p.GoGCFrom != "" {
			e.printf("  GOGC is set in %s: kept\n", p.GoGCFrom)
		}
		for _, o := range p.Unit.overrides() {
			e.printf("  overridden by: %s\n", o)
		}
	}
	if dry {
		e.printf("\nDry run: nothing was changed.\n")
	}
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// serviceInfo describes the running service: its limits as systemd has them
// and as each process actually has them.
func (e *Env) serviceInfo(f *Facts) []string {
	if f.Init != "systemd" {
		return []string{"not a systemd host"}
	}
	out, err := e.run("systemctl", "show", "x-ui", "-p", "LimitNOFILE", "-p", "TasksMax", "-p", "KillMode",
		"-p", "OOMScoreAdjust", "-p", "Environment", "-p", "ActiveState", "-p", "ControlGroup")
	if err != nil {
		return []string{"x-ui.service: unknown"}
	}
	props := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			props[k] = v
		}
	}
	lines := []string{fmt.Sprintf("x-ui.service %s: LimitNOFILE %s, TasksMax %s, KillMode %s, OOMScoreAdjust %s",
		props["ActiveState"], props["LimitNOFILE"], props["TasksMax"], props["KillMode"], props["OOMScoreAdjust"])}
	var env []string
	for _, kv := range strings.Fields(props["Environment"]) {
		if strings.HasPrefix(kv, "GOMEMLIMIT=") || strings.HasPrefix(kv, "GOGC=") {
			env = append(env, kv)
		}
	}
	if len(env) > 0 {
		lines = append(lines, "environment: "+strings.Join(env, " "))
	}
	if cg := props["ControlGroup"]; cg != "" {
		data, _ := os.ReadFile(filepath.Join("/sys/fs/cgroup", cg, "cgroup.procs"))
		for _, s := range strings.Fields(string(data)) {
			comm := strings.TrimSpace(e.readTrim("/proc/" + s + "/comm"))
			lim := strings.TrimSpace(limitsLine(e.readTrim("/proc/"+s+"/limits"), "Max open files"))
			oom := e.readTrim("/proc/" + s + "/oom_score_adj")
			lines = append(lines, fmt.Sprintf("pid %s %s: open files %s, oom_score_adj %s", s, comm, lim, oom))
		}
	}
	return lines
}

func limitsLine(s, name string) string {
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, name) {
			fs := strings.Fields(strings.TrimPrefix(l, name))
			if len(fs) >= 2 {
				return fs[0] + "/" + fs[1]
			}
		}
	}
	return "?"
}

func (e *Env) timeInfo(f *Facts) string {
	if f.Container() {
		return "container: kept by the host"
	}
	if f.Init != "systemd" {
		return "unknown"
	}
	s := "not synchronized"
	if out, err := e.run("timedatectl", "show", "-p", "NTPSynchronized", "--value"); err == nil && out == "yes" {
		s = "synchronized"
	}
	if e.have("chronyc") {
		if out, err := e.run("chronyc", "tracking"); err == nil {
			for _, l := range strings.Split(out, "\n") {
				if strings.HasPrefix(l, "System time") {
					s += " (chrony: " + strings.TrimSpace(strings.SplitN(l, ":", 2)[1]) + ")"
				}
			}
		}
	}
	return s
}

// health reads the counters that show whether the limits are being hit.
func (e *Env) health(f *Facts) []string {
	var out []string
	ext := netstat(e.readTrim("/proc/net/netstat"), "TcpExt")
	out = append(out, fmt.Sprintf("listen queue overflows %d, listen drops %d, aborts on memory %d (since boot)",
		ext["ListenOverflows"], ext["ListenDrops"], ext["TCPAbortOnMemory"]))
	sock := e.readTrim("/proc/net/sockstat")
	for _, l := range strings.Split(sock, "\n") {
		if !strings.HasPrefix(l, "TCP:") {
			continue
		}
		fs := strings.Fields(l)
		vals := map[string]int64{}
		for i := 1; i+1 < len(fs); i += 2 {
			vals[fs[i]] = atoi64(fs[i+1])
		}
		orph := atoi64(e.readTrim("/proc/sys/net/ipv4/tcp_max_orphans"))
		tm := strings.Fields(e.readTrim("/proc/sys/net/ipv4/tcp_mem"))
		line := fmt.Sprintf("TCP sockets %d, orphans %d of %d, time-wait %d", vals["inuse"], vals["orphan"], orph, vals["tw"])
		if len(tm) == 3 {
			line += fmt.Sprintf(", memory %d of %s pages before pressure", vals["mem"], tm[1])
			if vals["mem"] > atoi64(tm[1]) {
				line += " (UNDER PRESSURE)"
			}
		}
		out = append(out, line)
	}
	if c := e.readTrim("/proc/sys/net/netfilter/nf_conntrack_count"); c != "" {
		out = append(out, fmt.Sprintf("conntrack %s of %s", c, e.readTrim("/proc/sys/net/netfilter/nf_conntrack_max")))
	}
	var squeeze int64
	for _, l := range strings.Split(e.readTrim("/proc/net/softnet_stat"), "\n") {
		fs := strings.Fields(l)
		if len(fs) >= 3 {
			n, _ := strconv.ParseInt(fs[2], 16, 64)
			squeeze += n
		}
	}
	out = append(out, fmt.Sprintf("softirq time squeezes %d", squeeze))
	var inRange []string
	for _, p := range f.Listeners {
		if int64(p) >= f.PortLo && int64(p) <= f.PortHi && !f.Reserved[p] {
			inRange = append(inRange, strconv.Itoa(p))
		}
	}
	if len(inRange) > 0 {
		out = append(out, "listening ports inside the ephemeral range and not reserved: "+strings.Join(inRange, ","))
	}
	if e.readTrim("/proc/sys/vm/overcommit_memory") == "2" {
		out = append(out, "WARNING: vm.overcommit_memory is 2, which breaks Go programs")
	}
	return out
}

func netstat(s, prefix string) map[string]int64 {
	out := map[string]int64{}
	lines := strings.Split(s, "\n")
	for i := 0; i+1 < len(lines); i++ {
		if !strings.HasPrefix(lines[i], prefix+":") || !strings.HasPrefix(lines[i+1], prefix+":") {
			continue
		}
		names, vals := strings.Fields(lines[i]), strings.Fields(lines[i+1])
		for j := 1; j < len(names) && j < len(vals); j++ {
			out[names[j]] = atoi64(vals[j])
		}
		break
	}
	return out
}
