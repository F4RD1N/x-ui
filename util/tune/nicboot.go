//go:build linux

package tune

import (
	"time"
)

// NICOptions are "x-ui tune nic"'s: x-ui runs it itself, when the panel
// starts and when the instance split changes (with the panel's
// instances.json), and at boot from x-ui-nic.service (--boot).
type NICOptions struct {
	Boot      bool   // raise the pending queue counts first
	Instances string // instances.json; "" the one next to the binary
}

// RunNIC re-applies the NICs' kernel state (UDP hashing, interrupt CPUs,
// XPS, RPS) by the current instance split, for the NICs an apply recorded
// and that this network namespace sees. It writes no file but the state
// and runs no service manager command, and does nothing at all in a
// container, before the first apply, or after a revert. With Boot, it first
// raises the queue counts that wait for the boot, unless x-ui already runs
// or the root file system is on the network.
func (e *Env) RunNIC(o NICOptions) (*Result, error) {
	r := &Result{}
	wait := 3 * time.Second
	var deadline time.Time
	if o.Boot {
		wait = 30 * time.Second
		deadline = e.clock().Now().Add(540 * time.Second) // the unit allows 600
	}
	unlock, err := e.lock(wait)
	if err != nil {
		r.problem("skipped: %v", err)
		return r, nil
	}
	defer unlock()
	f := e.gatherFacts()
	if f.Container() {
		return r, nil
	}
	st, had, err := e.loadState()
	if err != nil || !had || st.Disabled || len(st.NICs) == 0 {
		return r, nil
	}
	before := stateSnapshot(st)
	e.endAttempts(st, r)
	only := map[string]bool{}
	for k := range st.NICs {
		if e.nicNameOf(k) != "" {
			only[k] = true
		}
	}
	if len(only) > 0 {
		no := nicOpts{Instances: o.Instances, Only: only}
		np := e.planNICs(f, st, no)
		if o.Boot && np.Skip == "" {
			if why := e.nicBootGuard(); why != "" {
				if stateWantsUnit(st) {
					r.problem("queues not raised: %s", why)
				}
			} else if e.raisePending(st, np, true, deadline, r) {
				np = e.planNICs(f, st, no)
			}
		}
		if np.Skip == "" && !e.stopped {
			e.applyNICKernel(f, st, np, no, r)
		}
	}
	if !bytesEqual(before, stateSnapshot(st)) {
		if err := e.saveState(st, nil); err != nil {
			return r, err
		}
	}
	return r, nil
}
