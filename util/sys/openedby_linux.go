//go:build linux

package sys

import (
	"os"
	"path/filepath"
	"strconv"
)

// OpenedBy returns the id of another process that has the file at path
// open, or 0 when none has (or /proc cannot tell).
func OpenedBy(path string) int {
	want, err := filepath.Abs(path)
	if err != nil {
		return 0
	}
	if real, err := filepath.EvalSymlinks(want); err == nil {
		want = real
	}
	procs, _ := os.ReadDir("/proc")
	self := os.Getpid()
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil || pid == self {
			continue
		}
		fdDir := filepath.Join("/proc", p.Name(), "fd")
		fds, _ := os.ReadDir(fdDir)
		for _, fd := range fds {
			if target, err := os.Readlink(filepath.Join(fdDir, fd.Name())); err == nil && target == want {
				return pid
			}
		}
	}
	return 0
}
