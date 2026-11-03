//go:build linux || darwin

package openvpn

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// setNotSentLowat sets TCP_NOTSENT_LOWAT on the socket rc to n bytes.
func setNotSentLowat(rc syscall.RawConn, n int) error {
	var serr error
	if err := rc.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, n)
	}); err != nil {
		return err
	}
	return serr
}
