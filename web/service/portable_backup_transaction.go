package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mhsanaei/3x-ui/v2/xray"
)

// Narrow hooks make every destructive boundary testable with temporary files;
// production callers hold the core lifecycle lock around the whole transaction.
type panelRestoreHooks struct {
	Running          func() bool
	Manual           func() bool
	SetManual        func(bool)
	PreviousConfig   func() *xray.Config
	Stop             func() error
	CloseDB          func() error
	OpenDB           func(string) error
	OpenCandidate    func(string) error
	PublishCandidate func() error
	Checkpoint       func() error
	Start            func(*xray.Config) error
	Rename           func(string, string) error
}

var panelDatabaseSuffixes = []string{"", "-wal", "-shm", "-journal"}

// A failed rollback must retain newly installed assets as well as the saved
// predecessor, because a candidate database may still occupy the live path.
type panelRestoreRecoveryError struct{ err error }

func (e *panelRestoreRecoveryError) Error() string { return e.err.Error() }
func (e *panelRestoreRecoveryError) Unwrap() error { return e.err }

func commitPanelRestore(live, candidate string, next *xray.Config, hooks panelRestoreHooks) (resultErr error) {
	previousDir, err := os.MkdirTemp(filepath.Dir(live), ".xui-predecessor-")
	if err != nil {
		return err
	}
	previous := filepath.Join(previousDir, "database.db")
	failed := filepath.Join(previousDir, "failed-candidate.db")
	wasRunning, wasManual := hooks.Running(), hooks.Manual()
	oldConfig := hooks.PreviousConfig()
	if err := hooks.Checkpoint(); err != nil {
		_ = os.RemoveAll(previousDir)
		return fmt.Errorf("cannot checkpoint previous database: %w", err)
	}
	hooks.SetManual(true)
	defer hooks.SetManual(wasManual)
	if err := hooks.Stop(); err != nil {
		if wasRunning && !hooks.Running() {
			err = errors.Join(err, hooks.Start(oldConfig))
		}
		_ = os.RemoveAll(previousDir)
		return fmt.Errorf("cannot stop previous core: %w", err)
	}

	moved := make(map[string]bool)
	installed := false
	rollback := func(cause error) error {
		var recovery []error
		if err := hooks.Stop(); err != nil {
			recovery = append(recovery, fmt.Errorf("stop candidate: %w", err))
		}
		if err := hooks.CloseDB(); err != nil {
			recovery = append(recovery, fmt.Errorf("close candidate database: %w", err))
		}
		if installed {
			for _, suffix := range panelDatabaseSuffixes {
				if _, err := os.Lstat(live + suffix); os.IsNotExist(err) {
					continue
				} else if err != nil {
					recovery = append(recovery, err)
					continue
				}
				if err := hooks.Rename(live+suffix, failed+suffix); err != nil {
					recovery = append(recovery, fmt.Errorf("retain failed candidate: %w", err))
				}
			}
		}
		restored := true
		for _, suffix := range panelDatabaseSuffixes {
			if !moved[suffix] {
				continue
			}
			if err := hooks.Rename(previous+suffix, live+suffix); err != nil {
				restored = false
				recovery = append(recovery, fmt.Errorf("restore predecessor: %w", err))
			}
		}
		if restored {
			if err := hooks.OpenDB(live); err != nil {
				recovery = append(recovery, fmt.Errorf("reopen predecessor: %w", err))
			} else if wasRunning {
				if err := hooks.Start(oldConfig); err != nil {
					recovery = append(recovery, fmt.Errorf("restart predecessor: %w", err))
				}
			}
		}
		if len(recovery) != 0 {
			return &panelRestoreRecoveryError{err: fmt.Errorf("restore failed and rollback needs attention; recovery files remain in %s: %w", previousDir, errors.Join(append([]error{cause}, recovery...)...))}
		}
		// Keep the private failed-candidate directory after a failure for
		// diagnosis; the old database is again at its original live path.
		return fmt.Errorf("restore failed; previous database and runtime restored: %w", cause)
	}

	if err := hooks.CloseDB(); err != nil {
		return rollback(fmt.Errorf("close previous database: %w", err))
	}
	for _, suffix := range panelDatabaseSuffixes {
		if _, err := os.Lstat(live + suffix); os.IsNotExist(err) {
			if suffix == "" {
				return rollback(errors.New("previous panel database is missing"))
			}
			continue
		} else if err != nil {
			return rollback(err)
		}
		if err := hooks.Rename(live+suffix, previous+suffix); err != nil {
			return rollback(fmt.Errorf("retain previous database: %w", err))
		}
		moved[suffix] = true
	}
	if err := hooks.Rename(candidate, live); err != nil {
		return rollback(fmt.Errorf("install candidate database: %w", err))
	}
	installed = true
	if err := os.Chmod(live, 0600); err != nil {
		return rollback(err)
	}
	openCandidate := hooks.OpenCandidate
	if openCandidate == nil {
		openCandidate = hooks.OpenDB
	}
	if err := openCandidate(live); err != nil {
		return rollback(fmt.Errorf("open migrated candidate database: %w", err))
	}
	if wasRunning || !wasManual {
		if err := hooks.Start(next); err != nil {
			return rollback(fmt.Errorf("start restored core: %w", err))
		}
	}
	if hooks.PublishCandidate != nil {
		if err := hooks.PublishCandidate(); err != nil {
			return rollback(fmt.Errorf("publish candidate database: %w", err))
		}
	}
	// Only a fully opened DB and successfully started (or intentionally
	// stopped) runtime permit removal of the predecessor.
	if err := os.RemoveAll(previousDir); err != nil {
		// A retained recovery copy is harmless; treating cleanup as failure
		// here would misreport a committed and working restore.
		return nil
	}
	return nil
}
