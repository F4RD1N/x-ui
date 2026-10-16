package service

import "golang.org/x/sys/unix"

// probeSocketMark sets the mark on a throwaway socket, as the core will on
// each of its own: it takes CAP_NET_ADMIN (or CAP_NET_RAW on newer kernels),
// which a container usually lacks.
func probeSocketMark() (bool, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return false, err
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, directMark); err != nil {
		return false, err
	}
	return true, nil
}
