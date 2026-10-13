//go:build linux

package tune

import (
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"
)

// irqbalance is never installed, enabled, disabled or stopped by x-ui. When
// it is installed and x-ui places a NIC's interrupts, x-ui gives it a policy
// script that bans those NICs (by PCI function, so renumbered interrupts
// stay banned), through its own environment file and a drop-in; irqbalance
// keeps balancing every other device. Where an admin set IRQBALANCE_ARGS,
// or the unit does not pass it, x-ui writes nothing and says what to add.
// While irqbalance runs without the policy, x-ui leaves the NICs'
// interrupts (and XPS) to it.

// irqbalance is irqbalance as x-ui finds it, and what x-ui would write.
type irqbalance struct {
	Unit     string   `json:"unit,omitempty"` // its unit file; "" not installed
	Running  bool     `json:"running"`
	Ours     bool     `json:"policy"`             // running with x-ui's policy script
	Banned   []string `json:"banned,omitempty"`   // the PCI functions x-ui's script bans now
	Conflict string   `json:"conflict,omitempty"` // a file that sets IRQBALANCE_ARGS otherwise
	Note     string   `json:"note,omitempty"`

	DropIn, Env, Script string // x-ui's files as they should be; "" none
	nics                []string
}

// irqbalanceRunning finds an irqbalance process and says whether it runs
// with x-ui's policy script.
func (e *Env) irqbalanceRunning() (running, ours bool) {
	for _, d := range e.glob("/proc/[0-9]*") {
		if e.readTrim(d+"/comm") != "irqbalance" {
			continue
		}
		running = true
		data, _ := e.read(d + "/cmdline")
		args := strings.Split(strings.TrimRight(data, "\x00"), "\x00")
		for i, a := range args {
			next := ""
			if i+1 < len(args) {
				next = args[i+1]
			}
			switch {
			case a == "--policyscript="+IRQBalanceScript, a == "-l"+IRQBalanceScript,
				(a == "--policyscript" || a == "-l") && next == IRQBalanceScript:
				ours = true
			}
		}
	}
	return running, ours
}

func (e *Env) irqbalanceUnit() string {
	for _, d := range unitDirs {
		if f := d + "/irqbalance.service"; e.exists(f) {
			return f
		}
	}
	return ""
}

// irqbalancePlan reads irqbalance's state and works out x-ui's files for
// the NICs whose interrupts x-ui would place.
func (e *Env) irqbalancePlan(np *nicPlan, st *State, o nicOpts) *irqbalance {
	ib := &irqbalance{Unit: e.irqbalanceUnit()}
	ib.Running, ib.Ours = e.irqbalanceRunning()
	if s, err := e.read(IRQBalanceScript); err == nil && e.isOurs(IRQBalanceScript) {
		ib.Banned = scriptPCIs(s)
	}
	var pcis []string
	for _, it := range np.NICs {
		if it.keep == "" && it.Key == it.NIC.PCI {
			pcis = append(pcis, it.NIC.PCI)
			ib.nics = append(ib.nics, it.NIC.Name)
		}
	}
	if ib.Unit == "" || len(pcis) == 0 || e.OnlyNet {
		return ib
	}
	names := strings.Join(ib.nics, ", ")
	v := e.readUnitNamed("irqbalance.service", IRQBalanceDropIn)
	cmd := v.execStart()
	if !strings.Contains(cmd, "$IRQBALANCE_ARGS") && !strings.Contains(cmd, "${IRQBALANCE_ARGS}") {
		ib.Note = fmt.Sprintf("its unit does not pass $IRQBALANCE_ARGS: add --policyscript=%s to its ExecStart to let x-ui place %s's interrupts", IRQBalanceScript, names)
		return ib
	}
	val, file := e.envValue(v, "IRQBALANCE_ARGS")
	if strings.TrimSpace(val) != "" {
		if !strings.Contains(val, IRQBalanceScript) {
			ib.Conflict = file
			ib.Note = fmt.Sprintf("IRQBALANCE_ARGS is set in %s; add --policyscript=%s there to let x-ui place %s's interrupts", file, IRQBalanceScript, names)
		}
		return ib
	}
	ib.Script = renderPolicyScript(pcis)
	ib.Env = Header + `IRQBALANCE_ARGS="--policyscript=` + IRQBalanceScript + "\"\n"
	ib.DropIn = Header + "[Service]\nEnvironmentFile=-" + IRQBalanceEnv + "\n"
	return ib
}

// renderPolicyScript bans the NICs' PCI functions; irqbalance calls it with
// the device's sysfs path and the interrupt.
func renderPolicyScript(pcis []string) string {
	pcis = slices.Clone(pcis)
	slices.Sort(pcis)
	return "#!/bin/sh\n" + Header +
		"# irqbalance runs this for every interrupt with the device's sysfs path and the IRQ.\n" +
		"# x-ui places these NICs' interrupts itself; irqbalance keeps balancing all others.\n" +
		"case \"${1##*/}\" in\n" + strings.Join(pcis, "|") + ") echo ban=true ;;\nesac\nexit 0\n"
}

// scriptPCIs reads back the PCI functions a policy script bans.
func scriptPCIs(s string) []string {
	for _, l := range strings.Split(s, "\n") {
		if pat, ok := strings.CutSuffix(strings.TrimSpace(l), ") echo ban=true ;;"); ok {
			return strings.Split(pat, "|")
		}
	}
	return nil
}

// envValue is a variable's value as a unit's Environment= and
// EnvironmentFile= lines leave it (a file's value wins over Environment=,
// later ones over earlier ones), and where it is set; "" when unset.
func (e *Env) envValue(v *unitView, name string) (val, file string) {
	var envVal, envFile, fileVal, fileFile string
	for _, l := range append(append([]unitLine{}, v.Before...), v.After...) {
		switch l.Key {
		case "Environment":
			for _, w := range shellWords(l.Value) {
				if k, x, ok := strings.Cut(w, "="); ok && k == name {
					envVal, envFile = x, l.File
				}
			}
		case "EnvironmentFile":
			f := strings.TrimPrefix(l.Value, "-")
			if !strings.HasPrefix(f, "/") {
				continue
			}
			data, err := e.read(f)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(data, "\n") {
				line = strings.TrimPrefix(strings.TrimSpace(line), "export ")
				if k, x, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == name {
					fileVal, fileFile = unquote(strings.TrimSpace(x)), f
				}
			}
		}
	}
	if fileFile != "" {
		return fileVal, fileFile
	}
	return envVal, envFile
}

// shellWords splits an Environment= value: words separated by spaces, with
// double or single quotes around a word or its value.
func shellWords(s string) []string {
	var out []string
	var b strings.Builder
	quote := byte(0)
	in := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0 && c == quote:
			quote = 0
		case quote != 0:
			b.WriteByte(c)
		case c == '"' || c == '\'':
			quote, in = c, true
		case c == ' ' || c == '\t':
			if in {
				out = append(out, b.String())
				b.Reset()
				in = false
			}
		default:
			b.WriteByte(c)
			in = true
		}
	}
	if in {
		out = append(out, b.String())
	}
	return out
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	if u, err := strconv.Unquote(s); err == nil {
		return u
	}
	return s
}

// applyIRQBalance writes (or removes) x-ui's irqbalance files and restarts
// irqbalance when they changed, before any interrupt is moved. It reports
// whether irqbalance was restarted.
func (e *Env) applyIRQBalance(np *nicPlan, st *State, r *Result) bool {
	ib := np.IRQBalance
	if ib == nil || e.OnlyNet {
		return false
	}
	changed := false
	for _, f := range []struct {
		path, data string
		mode       uint32
	}{{IRQBalanceScript, ib.Script, 0o755}, {IRQBalanceEnv, ib.Env, 0o644}, {IRQBalanceDropIn, ib.DropIn, 0o644}} {
		if f.data == "" {
			if e.ownFile(f.path, "", r) {
				changed = true
			}
			continue
		}
		wrote, err := e.writeFile(f.path, []byte(f.data), osMode(f.mode))
		if err != nil {
			r.problem("write %s: %v", f.path, err)
			continue
		}
		changed = changed || wrote
	}
	st.IRQBalancePolicy = ib.DropIn != ""
	if !changed {
		return false
	}
	if _, err := e.run("systemctl", "daemon-reload"); err != nil && !e.fake() {
		r.problem("systemctl daemon-reload: %v", err)
	}
	if _, err := e.run("systemctl", "try-restart", "irqbalance"); err != nil && !e.fake() {
		r.problem("systemctl try-restart irqbalance: %v", err)
	}
	if ib.DropIn != "" {
		r.change("irqbalance: %s's interrupts banned for it (%s); it keeps balancing all others", strings.Join(ib.nics, ", "), path.Base(IRQBalanceDropIn))
	} else {
		r.change("irqbalance: x-ui's policy removed")
	}
	return true
}

// irqbalanceText is irqbalance's line in the status.
func (ib *irqbalance) text() string {
	if ib == nil {
		return ""
	}
	var s string
	switch {
	case ib.Unit == "" && !ib.Running:
		return "not installed"
	case ib.Running && ib.Ours:
		s = "running with x-ui's policy"
	case ib.Running:
		s = "running"
	default:
		s = "installed, not running"
	}
	if len(ib.Banned) > 0 && ib.DropIn != "" {
		s += fmt.Sprintf("; %s banned for it (%s)", strings.Join(ib.nics, ", "), path.Base(IRQBalanceDropIn))
	} else if ib.DropIn != "" {
		s += "; 'x-ui tune apply' bans " + strings.Join(ib.nics, ", ") + " for it"
	}
	if ib.Note != "" {
		s += "; " + ib.Note
	}
	return s
}
