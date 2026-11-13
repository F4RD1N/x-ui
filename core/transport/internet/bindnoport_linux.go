package internet

import "golang.org/x/sys/unix"

// setBindAddressNoPort leaves the choice of the local port to connect(), so a
// socket bound to an address shares ports with others going elsewhere.
func setBindAddressNoPort(fd uintptr) error {
	return unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_BIND_ADDRESS_NO_PORT, 1)
}
