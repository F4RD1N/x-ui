//go:build unix

package conf

import (
	"os"

	"golang.org/x/sys/unix"
)

// A raced FIFO must not block configuration loading. The final component may
// not be a symlink, and fstat/SameFile in the caller verifies the opened inode.
func openOpenVPNProofFile(name string) (*os.File, error) {
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}
