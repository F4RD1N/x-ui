//go:build linux

package internet

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// setBindAddressNoPort lets a socket bound to a source address leave the
// choice of its port to connect(), which may reuse a port for different
// destinations. Without it bind() takes a port of the address for good, and
// the address runs out after ~64k connections whatever their destinations.
func setBindAddressNoPort(fd uintptr) error {
	return syscall.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BIND_ADDRESS_NO_PORT, 1)
}
