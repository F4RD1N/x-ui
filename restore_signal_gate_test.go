package main

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
)

func fakeRestoreSignalGate() (*restoreSignalGate, *int, *int) {
	created, cancelled := 0, 0
	gate := &restoreSignalGate{after: func() (<-chan time.Time, func()) {
		created++
		return make(chan time.Time), func() { cancelled++ }
	}}
	return gate, &created, &cancelled
}

func TestRestoreSignalGateCoalescesAndHoldsAdmissionThroughLifecycle(t *testing.T) {
	gate, created, cancelled := fakeRestoreSignalGate()
	denied := func() (func(), bool) { return nil, false }
	calls, held := 0, false
	for range 100 {
		if gate.Run(denied, func() { calls++ }) {
			t.Fatal("reload ran without admission")
		}
	}
	if *created != 1 || gate.Ready() == nil || calls != 0 {
		t.Fatal("requests were not coalesced into one nonblocking pending retry")
	}
	admit := func() (func(), bool) {
		held = true
		return func() { held = false }, true
	}
	if !gate.Run(admit, func() {
		if !held {
			t.Fatal("admission was released before lifecycle work")
		}
		calls++
	}) {
		t.Fatal("reload did not run after admission reopened")
	}
	if held || calls != 1 || *cancelled != 1 || gate.Ready() != nil {
		t.Fatal("reload did not release admission and cancel its pending retry")
	}
}

func TestRestoreSignalGatesKeepCoreAndPanelRequestsIndependent(t *testing.T) {
	panel, panelCreated, _ := fakeRestoreSignalGate()
	core, coreCreated, _ := fakeRestoreSignalGate()
	denied := func() (func(), bool) { return nil, false }
	panelCalls, coreCalls := 0, 0
	panel.Run(denied, func() { panelCalls++ })
	core.Run(denied, func() { coreCalls++ })
	if *panelCreated != 1 || *coreCreated != 1 {
		t.Fatal("separate signal kinds were not independently deferred")
	}
	// Mirrors the signal-loop select: pending maintenance timers must never
	// block the already available shutdown event.
	shutdown := make(chan struct{}, 1)
	shutdown <- struct{}{}
	select {
	case <-shutdown:
	case <-panel.Ready():
		t.Fatal("unexpected panel retry")
	case <-core.Ready():
		t.Fatal("unexpected core retry")
	default:
		t.Fatal("shutdown event was not serviceable")
	}
	allowed := func() (func(), bool) { return func() {}, true }
	panel.Run(allowed, func() { panelCalls++ })
	if panelCalls != 1 || coreCalls != 0 || core.Ready() == nil {
		t.Fatal("panel reload changed the deferred core-only request")
	}
	core.Run(allowed, func() { coreCalls++ })
	if panelCalls != 1 || coreCalls != 1 {
		t.Fatal("core reload did not preserve its own callback")
	}
}

func TestRestoreSignalGateReleasesAdmissionOnPanic(t *testing.T) {
	gate, _, _ := fakeRestoreSignalGate()
	released := false
	func() {
		defer func() { _ = recover() }()
		gate.Run(func() (func(), bool) { return func() { released = true }, true }, func() { panic("fixture") })
	}()
	if !released {
		t.Fatal("lifecycle panic leaked mutation admission")
	}
}

func TestRestoreSignalLifecycleDrainsBeforeExclusivePublication(t *testing.T) {
	gate, _, _ := fakeRestoreSignalGate()
	entered, releaseLifecycle, lifecycleDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	exclusive, releaseRestore, restoreDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var lifecycleOnce, restoreOnce sync.Once
	unblockLifecycle := func() { lifecycleOnce.Do(func() { close(releaseLifecycle) }) }
	unblockRestore := func() { restoreOnce.Do(func() { close(releaseRestore) }) }
	defer unblockLifecycle()
	defer unblockRestore()
	go func() {
		defer close(lifecycleDone)
		gate.Run(database.TryMutation, func() { close(entered); <-releaseLifecycle })
	}()
	waitSignal := func(channel <-chan struct{}, message string) {
		t.Helper()
		select {
		case <-channel:
		case <-time.After(5 * time.Second):
			t.Fatal(message)
		}
	}
	waitSignal(entered, "lifecycle did not acquire admission")
	go func() {
		defer close(restoreDone)
		release := database.BeginRestore()
		defer release()
		close(exclusive)
		<-releaseRestore
	}()
	deadline := time.Now().Add(5 * time.Second)
	for !database.Restoring() {
		if time.Now().After(deadline) {
			t.Fatal("restore did not close admission")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-exclusive:
		t.Fatal("restore published while lifecycle still held admission")
	default:
	}
	deferred, _, _ := fakeRestoreSignalGate()
	var runs atomic.Int32
	if deferred.Run(database.TryMutation, func() { runs.Add(1) }) || runs.Load() != 0 {
		t.Fatal("new reload started during restore")
	}
	unblockLifecycle()
	waitSignal(lifecycleDone, "lifecycle failed to drain")
	waitSignal(exclusive, "restore could not proceed after lifecycle drained")
	unblockRestore()
	waitSignal(restoreDone, "restore failed to release")
	if !deferred.Run(database.TryMutation, func() { runs.Add(1) }) || runs.Load() != 1 {
		t.Fatal("deferred lifecycle did not resume exactly once")
	}
}

func TestRestoreSignalLifecycleCanDrainAnImportWithoutLockInversion(t *testing.T) {
	gate, _, _ := fakeRestoreSignalGate()
	lifecycleEntered, importDone, lifecycleDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	admitted := make(chan bool, 1)
	go func() {
		defer close(lifecycleDone)
		gate.Run(database.TryLifecycle, func() {
			close(lifecycleEntered)
			// Simulate net/http Shutdown waiting for the existing import.
			<-importDone
		})
	}()
	select {
	case <-lifecycleEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("lifecycle did not start")
	}
	go func() {
		defer close(importDone)
		release, ok := database.TryBeginRestore()
		if ok {
			release()
		}
		admitted <- ok
	}()
	select {
	case <-lifecycleDone:
	case <-time.After(5 * time.Second):
		t.Fatal("reload deadlocked while waiting for import to return busy")
	}
	if <-admitted {
		t.Fatal("import was published during server lifecycle")
	}
	if database.LifecycleActive() || database.Restoring() {
		t.Fatal("lifecycle/restore admission leaked")
	}
	endRestore, ok := database.TryBeginRestore()
	if !ok {
		t.Fatal("import did not become admissible after lifecycle finished")
	}
	if gate.Run(database.TryLifecycle, func() { t.Error("lifecycle ran during restore") }) {
		t.Error("restore failed to defer lifecycle")
	}
	endRestore()
	if !gate.Run(database.TryLifecycle, func() {}) {
		t.Fatal("deferred lifecycle did not run after restore")
	}
}
