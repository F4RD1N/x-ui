//go:build !windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// A second panel server on the same database folder is refused while the
// first runs, and starts once the first is gone.
func TestLockServer(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "db")
	first, err := lockServer(dir)
	if err != nil || first == nil {
		t.Fatalf("first lock: %v", err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, ".x-ui.lock"))
	if strings.TrimSpace(string(b)) != strconv.Itoa(os.Getpid()) {
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
