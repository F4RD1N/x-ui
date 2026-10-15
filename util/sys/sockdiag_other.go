//go:build !linux

package sys

import "errors"

// LocalEndpoint is the local side of a TCP connection.
type LocalEndpoint struct {
	IP   string
	Port int
}

// CountEstablishedTCP is only implemented on Linux.
func CountEstablishedTCP(ports []int) (map[LocalEndpoint]int, error) {
	return nil, errors.New("not supported on this platform")
}

// UDPSockets is only implemented on Linux.
func UDPSockets(fn func(LocalEndpoint)) error {
	return errors.New("not supported on this platform")
}

// TCPSocket is a TCP socket on a local port.
type TCPSocket struct {
	Local     LocalEndpoint
	Listening bool
	State     int
	Inode     uint32
}

// PortTCPSockets is only implemented on Linux.
func PortTCPSockets(port int) ([]TCPSocket, error) {
	return nil, errors.New("not supported on this platform")
}

// PortTCPListeners is only implemented on Linux.
func PortTCPListeners(port int) ([]TCPSocket, error) {
	return nil, errors.New("not supported on this platform")
}

// DestroyTCP is only implemented on Linux.
func DestroyTCP(s TCPSocket) error {
	return errors.New("not supported on this platform")
}

// Owner cannot tell on this system: it always returns 0 and "".
func (s TCPSocket) Owner() (pid int, name string) { return 0, "" }
