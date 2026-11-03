package main

import "time"

// restoreSignalGate is owned by the signal-loop goroutine. It keeps at most one
// pending retry for a signal kind, without sleeping in the signal loop or
// sending synthetic OS signals. Shutdown signals remain selectable while a
// restore refuses admission.
type restoreSignalGate struct {
	ready  <-chan time.Time
	cancel func()
	after  func() (<-chan time.Time, func())
}

func newRestoreSignalGate(delay time.Duration) *restoreSignalGate {
	return &restoreSignalGate{after: func() (<-chan time.Time, func()) {
		timer := time.NewTimer(delay)
		return timer.C, func() { timer.Stop() }
	}}
}

func (g *restoreSignalGate) Ready() <-chan time.Time { return g.ready }

func (g *restoreSignalGate) Clear() {
	if g.cancel != nil {
		g.cancel()
	}
	g.ready, g.cancel = nil, nil
}

// Run holds mutation admission across the complete lifecycle callback. If the
// restore owns admission, repeated requests coalesce into one future retry.
func (g *restoreSignalGate) Run(admit func() (func(), bool), reload func()) bool {
	release, ok := admit()
	if !ok {
		if g.ready == nil {
			g.ready, g.cancel = g.after()
		}
		return false
	}
	g.Clear()
	defer release()
	reload()
	return true
}
