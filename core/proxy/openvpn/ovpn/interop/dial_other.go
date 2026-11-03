//go:build !linux

package interop

import (
	"context"
	"errors"
	"net"
)

var errNotLinux = errors.New("interop: the harness needs Linux network namespaces")

// Dial is only available on Linux.
func Dial(ctx context.Context, network, address string) (net.Conn, error) {
	return nil, errNotLinux
}

// InNamespace is only available on Linux.
func InNamespace(ns string, fn func() error) error { return errNotLinux }
