//go:build linux

package tune

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// ApplyOptions select how much an apply does.
type ApplyOptions struct {
	DryRun bool // print the plan, change nothing
	Auto   bool // respect the disabled flag (installer, update)
	Boot   bool // sysctls, conntrack and modules only (the unit's ExecStartPre)
	Quiet  bool
	// Host also sets up the host services (time sync, irqbalance, swap)
	// with Auto: the installer passes it on a fresh install, never on an
	// update. A manual apply always does them.
	Host bool
}

// Result summarises an apply or revert.
type Result struct {
	Changed  []string // what changed
	Problems []string // what could not be done (never fatal)
	Restart  bool     // the service must restart for a change to take effect
	Disabled bool     // tuning is disabled; nothing was done
}

func (r *Result) change(format string, a ...any) {
	r.Changed = append(r.Changed, fmt.Sprintf(format, a...))
}
func (r *Result) problem(format string, a ...any) {
	r.Problems = append(r.Problems, fmt.Sprintf(format, a...))
}

// Apply tunes the machine.
func (e *Env) Apply(o ApplyOptions, version string) (*Result, error) {
	wait := 60 * time.Second
	if o.Boot {
		wait = 3 * time.Second
	}
	unlock, err := e.lock(wait)
	if err != nil {
		return nil, err
	}
	defer unlock()

	r := &Result{}
	st, had, err := e.loadState()
	if err != nil {
		// A damaged state file must not stop the service from starting. It
		// is kept for inspection; revert then falls back to file headers.
		r.problem("state: %v (kept as state.json.bad)", err)
		if !o.DryRun {
			_ = e.move(StateFile, StateFile+".bad")
		}
	}
	before := stateSnapshot(st)
	if (o.Auto || o.Boot) && st.Disabled {
		r.Disabled = true
		return r, nil
	}
	if !o.Auto && !o.Boot {
		st.Disabled = false
	}
	st.XUI = version

	unitChanged := false
	if !o.Boot && !o.DryRun {
		unitChanged = e.migrateLegacy(st, r)
	}

	f := e.gatherFacts()
	if !o.DryRun && f.BBR == "module" && !f.Container() {
		// Load BBR now; the sysctl write would also auto-load it, but only
		// a loaded module shows in tcp_available_congestion_control.
		if _, err := e.run("modprobe", "tcp_bbr"); err == nil {
			f.BBR = "available"
		}
		if f.FQModule {
			_, _ = e.run("modprobe", "sch_fq")
		}
	}
	p := e.plan(f, st)
	if o.DryRun {
		e.printPlan(p, st, true)
		return r, nil
	}

	ro := 0
	for _, k := range p.Keys {
		if k.State == "read-only" {
			ro++
		}
	}
	if ro > 0 {
		r.problem("%d kernel settings are %s; 'x-ui tune status' lists them", ro, e.roNote(f))
	}

	// Live sysctl values.
	for _, k := range p.Keys {
		if k.Want == "" {
			continue
		}
		if err := e.writeKernel(sysctlPath(k.Key), k.Want); err != nil {
			k.State, k.Note = errState(err, f)
			k.Persist = "" // the kernel will not take it at boot either
			r.problem("%s: %s", k.Key, k.Note)
			continue
		}
		ks := st.Keys[k.Key]
		if ks == nil {
			ks = &KeyState{}
			st.Keys[k.Key] = ks
		}
		if k.HandBack {
			// Another file's value: nothing of x-ui's left for revert.
			ks.Written, ks.Orig = "", ""
			r.change("%s: %s -> %s (%s)", k.Key, k.Live, k.Want, k.Note)
			continue
		}
		if ks.Written == "" && ks.Orig == "" {
			ks.Orig = k.Live
		}
		ks.Written = k.Want
		r.change("%s: %s -> %s", k.Key, k.Live, k.Want)
	}

	// x-ui's sysctl file.
	for _, k := range p.Keys {
		ks := st.Keys[k.Key]
		if k.Persist != "" {
			if ks == nil {
				ks = &KeyState{}
				st.Keys[k.Key] = ks
			}
			ks.File = k.Persist
		} else if ks != nil {
			ks.File = ""
		}
		if ks != nil && ks.File == "" && ks.Written == "" {
			delete(st.Keys, k.Key)
		}
	}
	e.ownFile(SysctlFile, renderSysctl(p.Keys), r)
	e.ownFile(OldSysctlFile, "", r) // only when it is x-ui's
	e.ownFile(ModulesLoadFile, p.ModulesLoad, r)
	e.ownFile(ModprobeFile, p.Modprobe, r)

	if h := p.Hash; h != nil && h.Want != "" {
		if err := e.writeKernel(hashsizePath, h.Want); err != nil {
			_, note := errState(err, f)
			r.problem("conntrack hashsize: %s", note)
		} else {
			if st.Hashsize == nil {
				st.Hashsize = &KeyState{Orig: h.Live}
			}
			st.Hashsize.Written = h.Want
			r.change("conntrack hashsize: %s -> %s", h.Live, h.Want)
		}
	}

	if !o.Boot {
		// fs.nr_open is raised above first; if that did not work, the limit
		// must not be above what it is, or the service would not start.
		if p.Facts.Init != "" {
			p.capNoFile(atoi64(e.readTrim("/proc/sys/fs/nr_open")), e.Bin)
		}
		switch f.Init {
		case "systemd":
			if e.ownFile(DropInFile, p.DropIn, r) {
				unitChanged = true
				r.Restart = true
			}
			if unitChanged {
				if _, err := e.run("systemctl", "daemon-reload"); err != nil && !e.fake() {
					r.problem("systemctl daemon-reload: %v", err)
				}
			}
			e.raiseNoFile(p.Svc.NoFile, r)
		case "openrc":
			if e.ownFile(OpenRCConfFile, p.ConfD, r) {
				r.Restart = true
			}
		}
		// Host services change the machine beyond x-ui's own needs: an
		// update (Auto alone) leaves them to the admin.
		if !o.Auto || o.Host {
			e.services(f, st, r)
		}
	}

	if !had || !bytesEqual(before, stateSnapshot(st)) {
		if err := e.saveState(st, nil); err != nil {
			return r, fmt.Errorf("saving %s: %w", StateFile, err)
		}
	}
	return r, nil
}

func bytesEqual(a, b []byte) bool { return string(a) == string(b) }

// ownFile writes (or, for "", removes) one of x-ui's files. It reports
// whether anything changed.
func (e *Env) ownFile(path, content string, r *Result) bool {
	if content == "" {
		if !e.isOurs(path) {
			return false
		}
		ok, err := e.remove(path)
		if err != nil {
			r.problem("remove %s: %v", path, err)
		}
		if ok {
			r.change("removed %s", path)
		}
		return ok
	}
	changed, err := e.writeFile(path, []byte(content), 0o644)
	if err != nil {
		r.problem("write %s: %v", path, err)
		return false
	}
	if changed {
		r.change("wrote %s", path)
	}
	return changed
}

// isOurs says whether a file starts with x-ui tune's header.
func (e *Env) isOurs(path string) bool {
	data, err := e.read(path)
	return err == nil && strings.HasPrefix(data, Header[:40])
}

// migrateLegacy moves aside files an older x-ui wrote for the same purpose:
// x-ui.sh's BBR file, and the x-ui-cdn fork's limits drop-in (which sorts
// after x-ui's and would cap LimitNOFILE). Revert puts them back.
func (e *Env) migrateLegacy(st *State, r *Result) (unitChanged bool) {
	files := []string{}
	if e.exists(LegacyBBRFile) {
		files = append(files, LegacyBBRFile)
	}
	legacyDropIns := e.readUnit().Legacy
	files = append(files, legacyDropIns...)
	for _, from := range files {
		to := BackupDir + from
		if err := e.move(from, to); err != nil {
			r.problem("move aside %s: %v", from, err)
			continue
		}
		st.Moved = append(st.Moved, Moved{From: from, To: to})
		r.change("moved %s to %s", from, to)
		if strings.HasPrefix(from, DropInDir) {
			unitChanged = true
		}
	}
	return unitChanged
}

// raiseNoFile raises the open-file limit of the running panel and cores, so
// a higher limit works before the next restart. It never lowers one.
func (e *Env) raiseNoFile(n int64, r *Result) {
	if e.fake() || n <= 0 {
		return
	}
	cg, err := e.run("systemctl", "show", "-p", "ControlGroup", "--value", "x-ui")
	if err != nil || cg == "" {
		return
	}
	data, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", cg, "cgroup.procs"))
	if err != nil {
		return
	}
	raised := 0
	for _, s := range strings.Fields(string(data)) {
		pid := int(atoi64(s))
		var cur unix.Rlimit
		if pid <= 0 || unix.Prlimit(pid, unix.RLIMIT_NOFILE, nil, &cur) != nil {
			continue
		}
		if int64(cur.Max) >= n {
			continue
		}
		nl := unix.Rlimit{Cur: uint64(n), Max: uint64(n)}
		if err := unix.Prlimit(pid, unix.RLIMIT_NOFILE, &nl, nil); err == nil {
			raised++
		}
	}
	if raised > 0 {
		r.change("raised the open-file limit of %d running x-ui processes to %d", raised, n)
	}
}

// Revert undoes everything x-ui tune did, as exactly as it can, and turns
// automatic tuning off.
func (e *Env) Revert(purge, dry bool) (*Result, error) {
	unlock, err := e.lock(60 * time.Second)
	if err != nil {
		return nil, err
	}
	defer unlock()
	r := &Result{}
	st, had, err := e.loadState()
	if err != nil {
		r.problem("state: %v", err)
	}
	if !had {
		r.problem("no state file: x-ui's files are removed, but earlier live values are unknown (a reboot restores the defaults)")
	}
	f := e.gatherFacts()
	if dry {
		for _, p := range ownFiles {
			if e.isOurs(p) {
				r.change("would remove %s", p)
			}
		}
		for _, m := range st.Moved {
			r.change("would restore %s", m.From)
		}
		for k, ks := range st.Keys {
			if ks.Written != "" {
				r.change("would restore %s to %s if it is still %s", k, ks.Orig, ks.Written)
			}
		}
		return r, nil
	}

	unitChanged := false
	for _, p := range ownFiles {
		if e.ownFile(p, "", r) && p == DropInFile {
			unitChanged = true
		}
	}
	for i := len(st.Moved) - 1; i >= 0; i-- {
		m := st.Moved[i]
		if e.exists(m.From) {
			r.problem("not restoring %s: a file of that name exists again", m.From)
			continue
		}
		if err := e.move(m.To, m.From); err != nil {
			r.problem("restore %s: %v", m.From, err)
			continue
		}
		r.change("restored %s", m.From)
		if strings.HasPrefix(m.From, DropInDir) {
			unitChanged = true
		}
	}
	for k, ks := range st.Keys {
		if ks.Written == "" {
			continue
		}
		p := sysctlPath(k)
		live := normValue(e.readTrim(p))
		if live != ks.Written {
			r.problem("%s left at %s: changed since x-ui set %s", k, live, ks.Written)
			continue
		}
		if err := e.writeKernel(p, ks.Orig); err != nil {
			_, note := errState(err, f)
			r.problem("%s: %s", k, note)
			continue
		}
		r.change("%s: %s -> %s", k, live, ks.Orig)
	}
	if h := st.Hashsize; h != nil && h.Written != "" {
		live := e.readTrim(hashsizePath)
		if live == h.Written {
			if err := e.writeKernel(hashsizePath, h.Orig); err != nil {
				_, note := errState(err, f)
				r.problem("conntrack hashsize: %s", note)
			} else {
				r.change("conntrack hashsize: %s -> %s", live, h.Orig)
			}
		}
	}
	e.revertServices(f, st, r)
	if unitChanged && f.Init == "systemd" {
		_, _ = e.run("systemctl", "daemon-reload")
		r.Restart = true
	}

	ns := newState()
	ns.Disabled = true
	ns.XUI = st.XUI
	if purge {
		if err := os.RemoveAll(e.P(StateDir)); err != nil {
			r.problem("remove %s: %v", StateDir, err)
		}
		_ = os.Remove(e.P("/var/lib/x-ui")) // only when empty
	} else if err := e.saveState(ns, nil); err != nil {
		return r, err
	}
	return r, nil
}

var errNotRoot = errors.New("x-ui tune must run as root")

// ownFiles are the files revert removes when they carry x-ui's header.
var ownFiles = []string{SysctlFile, OldSysctlFile, DropInFile, ModulesLoadFile, ModprobeFile, OpenRCConfFile}
