package service

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/xray"
)

func TestPortableRestoreTransactionSuccessAndStoppedState(t *testing.T) {
	for _, manual := range []bool{false, true} {
		t.Run(map[bool]string{false: "running", true: "manually-stopped"}[manual], func(t *testing.T) {
			live, candidate, hooks, state := restoreTransactionFixture(t, manual)
			if err := commitPanelRestore(live, candidate, state.next, hooks); err != nil {
				t.Fatal(err)
			}
			data, _ := os.ReadFile(live)
			if string(data) != "candidate database" {
				t.Fatal("candidate was not installed")
			}
			if state.manual != manual || state.running == manual {
				t.Fatal("runtime manual-stop state changed")
			}
			if manual && state.starts != 0 {
				t.Fatal("restore started an intentionally stopped core")
			}
			for _, suffix := range panelDatabaseSuffixes[1:] {
				if _, err := os.Stat(live + suffix); !os.IsNotExist(err) {
					t.Fatal("old SQLite sidecar survived success")
				}
			}
			entries, _ := filepath.Glob(filepath.Join(filepath.Dir(live), ".xui-predecessor-*"))
			if len(entries) != 0 {
				t.Fatal("committed restore retained predecessor")
			}
		})
	}
}

type restoreTransactionState struct {
	running, manual bool
	starts, opens   int
	old, next       *xray.Config
}

func restoreTransactionFixture(t *testing.T, manual bool) (string, string, panelRestoreHooks, *restoreTransactionState) {
	t.Helper()
	dir := t.TempDir()
	live, candidate := filepath.Join(dir, "live.db"), filepath.Join(dir, "candidate.db")
	os.WriteFile(live, []byte("previous database"), 0600)
	os.WriteFile(candidate, []byte("candidate database"), 0600)
	for _, suffix := range panelDatabaseSuffixes[1:] {
		os.WriteFile(live+suffix, []byte("previous "+suffix), 0600)
	}
	state := &restoreTransactionState{running: !manual, manual: manual, old: &xray.Config{}, next: &xray.Config{InboundConfigs: []xray.InboundConfig{{Tag: "candidate"}}}}
	hooks := panelRestoreHooks{
		Running: func() bool { return state.running }, Manual: func() bool { return state.manual }, SetManual: func(v bool) { state.manual = v }, PreviousConfig: func() *xray.Config { return state.old },
		Stop: func() error { state.running = false; return nil }, CloseDB: func() error { return nil }, OpenDB: func(string) error { state.opens++; return nil }, Checkpoint: func() error { return nil },
		Start: func(*xray.Config) error { state.starts++; state.running = true; return nil }, Rename: os.Rename,
	}
	return live, candidate, hooks, state
}

func TestPortableRestoreRollsBackEveryDestructiveBoundary(t *testing.T) {
	for _, failure := range []string{"checkpoint", "stop", "close", "move-main", "move-wal", "move-candidate", "open-candidate", "start-candidate", "publish-candidate"} {
		t.Run(failure, func(t *testing.T) {
			live, candidate, hooks, state := restoreTransactionFixture(t, false)
			injected := false
			fail := func() error { injected = true; return errors.New("injected " + failure) }
			switch failure {
			case "checkpoint":
				hooks.Checkpoint = fail
			case "stop":
				hooks.Stop = func() error {
					if !injected {
						return fail()
					}
					state.running = false
					return nil
				}
			case "close":
				hooks.CloseDB = func() error {
					if !injected {
						return fail()
					}
					return nil
				}
			case "move-main", "move-wal", "move-candidate":
				hooks.Rename = func(old, next string) error {
					if !injected && ((failure == "move-main" && old == live) || (failure == "move-wal" && old == live+"-wal") || (failure == "move-candidate" && old == candidate)) {
						return fail()
					}
					return os.Rename(old, next)
				}
			case "open-candidate":
				hooks.OpenDB = func(path string) error {
					state.opens++
					b, _ := os.ReadFile(path)
					if !injected && bytes.Equal(b, []byte("candidate database")) {
						return fail()
					}
					return nil
				}
			case "publish-candidate":
				hooks.PublishCandidate = fail
			case "start-candidate":
				hooks.Start = func(cfg *xray.Config) error {
					state.starts++
					if !injected && cfg == state.next {
						return fail()
					}
					state.running = true
					return nil
				}
			}
			if err := commitPanelRestore(live, candidate, state.next, hooks); err == nil {
				t.Fatal("failure was ignored")
			}
			if !injected {
				t.Fatal("test did not exercise its failure boundary")
			}
			b, _ := os.ReadFile(live)
			if string(b) != "previous database" {
				t.Fatalf("previous database lost after %s", failure)
			}
			for _, suffix := range panelDatabaseSuffixes[1:] {
				b, _ := os.ReadFile(live + suffix)
				if string(b) != "previous "+suffix {
					t.Fatalf("SQLite sidecar lost after %s: %s", failure, suffix)
				}
			}
			if !state.running || state.manual {
				t.Fatalf("previous runtime was not restored after %s", failure)
			}
		})
	}
}

func TestPortableRestoreRetainsRecoveryDatabaseIfRollbackItselfFails(t *testing.T) {
	live, candidate, hooks, state := restoreTransactionFixture(t, false)
	hooks.Start = func(cfg *xray.Config) error {
		if cfg == state.next {
			return errors.New("candidate startup failure")
		}
		return nil
	}
	hooks.Rename = func(old, next string) error {
		if next == live && strings.Contains(old, ".xui-predecessor-") && filepath.Base(old) == "database.db" {
			return errors.New("injected rollback rename failure")
		}
		return os.Rename(old, next)
	}
	err := commitPanelRestore(live, candidate, state.next, hooks)
	if err == nil || !strings.Contains(err.Error(), "recovery files remain") {
		t.Fatal("rollback failure not reported with recovery location")
	}
	paths, _ := filepath.Glob(filepath.Join(filepath.Dir(live), ".xui-predecessor-*", "database.db"))
	if len(paths) != 1 {
		t.Fatal("predecessor was deleted after failed rollback")
	}
	b, _ := os.ReadFile(paths[0])
	if string(b) != "previous database" {
		t.Fatal("recovery database is not the predecessor")
	}
	if state.manual {
		t.Fatal("original manual flag not restored")
	}
}

func TestPortableRestoreFailureDoesNotStartManuallyStoppedCore(t *testing.T) {
	live, candidate, hooks, state := restoreTransactionFixture(t, true)
	failed := false
	hooks.OpenDB = func(string) error {
		if !failed {
			failed = true
			return errors.New("candidate migration failed")
		}
		return nil
	}
	if err := commitPanelRestore(live, candidate, state.next, hooks); err == nil {
		t.Fatal("open failure ignored")
	}
	if state.starts != 0 || state.running || !state.manual {
		t.Fatal("rollback started a manually stopped core")
	}
	b, _ := os.ReadFile(live)
	if string(b) != "previous database" {
		t.Fatal("rollback did not restore stopped panel database")
	}
}
