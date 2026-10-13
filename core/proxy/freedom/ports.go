package freedom

import (
	"errors"
	"syscall"
)

// outOfLocalPorts reports whether a dial failed for want of a local port or
// address: the source address has no free port left, or is not on the host.
func outOfLocalPorts(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE) || errors.Is(err, syscall.EADDRNOTAVAIL)
}
