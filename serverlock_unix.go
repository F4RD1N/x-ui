//go:build !windows

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// serverLock stays open, and so locked, for as long as the process runs.
var serverLock *os.File

// errServerRunning says another panel server holds the lock.
var errServerRunning = errors.New("another x-ui panel is running")

// lockServer takes the lock one panel server per database folder holds. A
// second x-ui started by hand used to exit because it could not listen on
// the panel's port; a busy port no longer stops the panel, so this lock is
// what keeps a second one from starting cores, jobs and a bot against the
// same database. Only a lock someone holds stops the start: a folder where
// no lock can be taken (read-only, no flock) is no reason to stay down.
func lockServer(dir string) (*os.File, error) {
	if err := os.MkdirAll(dir, fs.ModePerm); err != nil {
		return nil, err
	}
	p := filepath.Join(dir, ".x-ui.lock")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		b, _ := os.ReadFile(p)
		f.Close()
		return nil, lockError(err, strings.TrimSpace(string(b)), p)
	}
	// The pid is only for the message a second one prints.
	if f.Truncate(0) == nil {
		f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0)
	}
	return f, nil
}

// lockError says what a failed flock means: only a lock someone holds is
// errServerRunning; ENOLCK, EOPNOTSUPP and the like are not.
func lockError(err error, pid, path string) error {
	if !errors.Is(err, unix.EWOULDBLOCK) {
		return err
	}
	if pid != "" {
		return fmt.Errorf("%w (pid %s, lock %s)", errServerRunning, pid, path)
	}
	return fmt.Errorf("%w (lock %s)", errServerRunning, path)
}
