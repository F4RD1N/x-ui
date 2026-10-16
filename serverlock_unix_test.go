//go:build !windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// A second panel server on the same database folder is refused while the
// first runs, and starts once the first is gone.
func TestLockServer(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "db")
	// A pid left by an earlier, longer one is replaced, not overwritten.
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, ".x-ui.lock"), []byte("999999999\n"), 0o600)
	first, err := lockServer(dir)
	if err != nil || first == nil {
		t.Fatalf("first lock: %v", err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, ".x-ui.lock"))
	if string(b) != strconv.Itoa(os.Getpid())+"\n" {
		t.Fatalf("lock file holds %q, want this pid", b)
	}

	second, err := lockServer(dir)
	if !errors.Is(err, errServerRunning) || second != nil {
		t.Fatalf("second lock: %v, %v; want errServerRunning", second, err)
	}
	if !strings.Contains(err.Error(), "pid "+strconv.Itoa(os.Getpid())) {
		t.Fatalf("message does not name the holder: %v", err)
	}

	first.Close()
	third, err := lockServer(dir)
	if err != nil {
		t.Fatalf("lock after the first is gone: %v", err)
	}
	third.Close()
}

// A folder where no lock can be taken is not someone else's lock.
func TestLockServerNoFolder(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := lockServer(filepath.Join(file, "db"))
	if err == nil || errors.Is(err, errServerRunning) {
		t.Fatalf("got %v, want an error other than errServerRunning", err)
	}
}

// Only a lock someone holds stops the panel.
func TestLockError(t *testing.T) {
	for _, e := range []error{unix.ENOLCK, unix.EOPNOTSUPP, unix.EINTR, unix.EISDIR} {
		if err := lockError(e, "1", "p"); errors.Is(err, errServerRunning) || !errors.Is(err, e) {
			t.Errorf("%v: got %v", e, err)
		}
	}
	err := lockError(unix.EWOULDBLOCK, "42", "/etc/x-ui/.x-ui.lock")
	if !errors.Is(err, errServerRunning) || !strings.Contains(err.Error(), "pid 42") {
		t.Errorf("held: got %v", err)
	}
	if err := lockError(unix.EAGAIN, "", "p"); !errors.Is(err, errServerRunning) {
		t.Errorf("held, no pid: got %v", err)
	}
}

// A second panel exits before it opens the log, which would empty the
// running panel's.
func TestSecondPanelKeepsTheLog(t *testing.T) {
	db, logs := t.TempDir(), t.TempDir()
	first, err := lockServer(db)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	logPath := filepath.Join(logs, "3xui.log")
	const history = "the running panel's history\n"
	if err := os.WriteFile(logPath, []byte(history), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), runPanelEnv+"=1", "XUI_DB_FOLDER="+db, "XUI_LOG_FOLDER="+logs, "XUI_BIN_FOLDER="+t.TempDir())
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 1 || !strings.Contains(string(out), "Not starting: another x-ui panel is running") {
		t.Fatalf("second panel: %v\n%s", err, out)
	}
	if b, _ := os.ReadFile(logPath); string(b) != history {
		t.Fatalf("the running panel's log is now %q", b)
	}
}
