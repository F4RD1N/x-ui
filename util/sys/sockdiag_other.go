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
