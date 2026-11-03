package database

import (
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestRestoreAdmissionDrainsAndRejectsConcurrentMutations(t *testing.T) {
	release, ok := TryMutation()
	if !ok {
		t.Fatal("initial mutation rejected")
	}
	entered := make(chan func(), 1)
	go func() { entered <- BeginRestore() }()
	deadline := time.After(time.Second)
	for !Restoring() {
		select {
		case <-deadline:
			t.Fatal("restore did not close admission")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	start := time.Now()
	if done, ok := TryMutation(); ok {
		done()
		t.Fatal("mutation admitted during restore")
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("mutation blocked instead of being rejected")
	}
	select {
	case <-entered:
		t.Fatal("restore did not drain already admitted mutation")
	default:
	}
	release()
	var finish func()
	select {
	case finish = <-entered:
	case <-time.After(time.Second):
		t.Fatal("restore remained blocked after mutation ended")
	}
	finish()
	if Restoring() {
		t.Fatal("maintenance flag not cleared")
	}
	release, ok = TryMutation()
	if !ok {
		t.Fatal("mutation rejected after restore")
	}
	release()
}

func TestRestoreLifecycleRefusesImportWithoutWaitingForItsOwnShutdown(t *testing.T) {
	release, ok := TryLifecycle()
	if !ok {
		t.Fatal("lifecycle admission failed")
	}
	defer release()
	if !LifecycleActive() || Restoring() {
		t.Fatal("lifecycle state is not distinct from database publication")
	}
	// The lifecycle owns admission and is waiting for an in-flight HTTP import.
	// The import must return busy instead of waiting for that same lifecycle.
	done := make(chan bool, 1)
	go func() {
		finish, admitted := TryBeginRestore()
		if admitted {
			finish()
		}
		done <- admitted
	}()
	select {
	case admitted := <-done:
		if admitted {
			t.Fatal("restore overlapped an admitted lifecycle")
		}
	case <-time.After(time.Second):
		t.Fatal("restore waited for the lifecycle waiting for this import")
	}
}

func TestRestoreAndLifecycleAdmissionAreMutuallyExclusive(t *testing.T) {
	finish, ok := TryBeginRestore()
	if !ok {
		t.Fatal("restore admission failed")
	}
	for _, admit := range []func() (func(), bool){TryLifecycle, TryBeginRestore, TryMutation} {
		if release, accepted := admit(); accepted {
			release()
			finish()
			t.Fatal("overlapping operation admitted during restore")
		}
	}
	finish()
	release, ok := TryLifecycle()
	if !ok {
		t.Fatal("lifecycle did not reopen after restore")
	}
	release()
	if LifecycleActive() {
		t.Fatal("lifecycle flag leaked after release")
	}
	finish, ok = TryBeginRestore()
	if !ok {
		t.Fatal("restore did not reopen after lifecycle")
	}
	finish()
}

func TestPanelDBPublicationIsAtomicAndPrivateInitializationDoesNotPublish(t *testing.T) {
	previous := GetDB()
	defer currentDB.Store(previous)
	first, err := OpenInitializedDB(filepath.Join(t.TempDir(), "first.db"))
	if err != nil {
		t.Fatal(err)
	}
	firstSQL, _ := first.DB()
	defer firstSQL.Close()
	second, err := OpenInitializedDB(filepath.Join(t.TempDir(), "second.db"))
	if err != nil {
		t.Fatal(err)
	}
	secondSQL, _ := second.DB()
	defer secondSQL.Close()
	if GetDB() != previous {
		t.Fatal("private initialization published its database")
	}
	if err := PublishDB(first); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	failures := make(chan bool, 1)
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			_ = PublishDB(first)
			_ = PublishDB(second)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 4000; i++ {
			db := GetDB()
			if db != first && db != second {
				select {
				case failures <- true:
				default:
				}
				return
			}
		}
	}()
	wg.Wait()
	select {
	case <-failures:
		t.Fatal("reader observed a partial or unknown handle")
	default:
	}
	current := GetDB()
	if err := PublishDB(nil); err == nil {
		t.Fatal("nil handle published")
	}
	if GetDB() != current {
		t.Fatal("failed publication changed handle")
	}
}
