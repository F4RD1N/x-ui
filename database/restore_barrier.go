package database

import (
	"sync"
	"sync/atomic"
)

var restoreAdmission struct {
	active    atomic.Bool
	lifecycle atomic.Bool
	mu        sync.RWMutex
	begin     sync.Mutex
}

// Restoring reports the short commit/rollback maintenance interval. Parsing and
// core preflight happen before this interval while ordinary traffic continues.
func Restoring() bool { return restoreAdmission.active.Load() }

// LifecycleActive reports a panel/core reload that excludes restore publication.
func LifecycleActive() bool { return restoreAdmission.lifecycle.Load() }

// TryLifecycle reserves restore admission for an entire server lifecycle. It
// never waits on a restore: the signal loop must remain responsive to shutdown.
func TryLifecycle() (func(), bool) {
	if !restoreAdmission.begin.TryLock() {
		return nil, false
	}
	releaseMutation, ok := TryMutation()
	if !ok {
		restoreAdmission.begin.Unlock()
		return nil, false
	}
	restoreAdmission.lifecycle.Store(true)
	return func() {
		restoreAdmission.lifecycle.Store(false)
		releaseMutation()
		restoreAdmission.begin.Unlock()
	}, true
}

// TryMutation admits a complete HTTP, cron or Telegram mutation only when a
// restore is not committing. The release function must be called exactly once.
func TryMutation() (func(), bool) {
	if Restoring() {
		return nil, false
	}
	if !restoreAdmission.mu.TryRLock() {
		return nil, false
	}
	if Restoring() {
		restoreAdmission.mu.RUnlock()
		return nil, false
	}
	return restoreAdmission.mu.RUnlock, true
}

// BeginRestore refuses new mutations, then drains admitted work before the live
// DB is closed. Restore requests themselves must bypass TryMutation.
func beginRestoreLocked() func() {
	restoreAdmission.active.Store(true)
	restoreAdmission.mu.Lock()
	return func() {
		restoreAdmission.active.Store(false)
		restoreAdmission.mu.Unlock()
		restoreAdmission.begin.Unlock()
	}
}

// TryBeginRestore refuses a concurrent lifecycle or restore before draining
// admitted mutations. In particular, an HTTP import must not wait for a reload
// whose Shutdown is itself waiting for that import request to finish.
func TryBeginRestore() (func(), bool) {
	if !restoreAdmission.begin.TryLock() {
		return nil, false
	}
	return beginRestoreLocked(), true
}

// BeginRestore is for callers that can safely wait outside an HTTP lifecycle.
// HTTP restore paths must use TryBeginRestore instead.
func BeginRestore() func() {
	restoreAdmission.begin.Lock()
	return beginRestoreLocked()
}
