//go:build linux

package interop

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// Dial opens a connection to address (an IP literal and port) from inside
// ClientNamespace. It has the shape of client.DialFunc, and it is how a
// client under test must reach the harness: the host's own firewall may drop
// host traffic to private addresses (the build box drops all host IPv4
// output to 10.0.0.0/8), so the socket is created in the namespace and then
// used from any goroutine; a socket stays in the namespace it was made in.
func Dial(ctx context.Context, network, address string) (net.Conn, error) {
	// A literal address keeps the dial on this goroutine: no resolver, no
	// parallel dials creating sockets on other threads.
	if _, err := netip.ParseAddrPort(address); err != nil {
		return nil, fmt.Errorf("interop: dial %s %q: want ip:port: %w", network, address, err)
	}
	var conn net.Conn
	err := InNamespace(ClientNamespace, func() error {
		var d net.Dialer
		c, err := d.DialContext(ctx, network, address)
		conn = c
		return err
	})
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// InNamespace runs fn on an OS thread switched into the named network
// namespace (/run/netns/ns). Sockets fn creates belong to ns for good. fn
// must not create sockets from other goroutines.
func InNamespace(ns string, fn func() error) error {
	target, err := os.Open("/run/netns/" + ns)
	if err != nil {
		return fmt.Errorf("interop: network namespace %s: %w (is the harness up?)", ns, err)
	}
	defer target.Close()
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		orig, err := os.Open("/proc/thread-self/ns/net")
		if err != nil {
			runtime.UnlockOSThread()
			errc <- fmt.Errorf("interop: own network namespace: %w", err)
			return
		}
		defer orig.Close()
		if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
			runtime.UnlockOSThread()
			errc <- fmt.Errorf("interop: entering network namespace %s: %w", ns, err)
			return
		}
		ferr := fn()
		// Only a thread back in its own namespace returns to the pool; one
		// that cannot switch back stays locked and dies with this goroutine.
		if unix.Setns(int(orig.Fd()), unix.CLONE_NEWNET) == nil {
			runtime.UnlockOSThread()
		}
		errc <- ferr
	}()
	return <-errc
}
