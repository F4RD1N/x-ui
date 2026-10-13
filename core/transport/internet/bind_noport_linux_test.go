package internet_test

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"testing"

	"github.com/xtls/xray-core/common/net"
	. "github.com/xtls/xray-core/transport/internet"
	"golang.org/x/sys/unix"
)

func bindNoPort(t *testing.T, c net.Conn) int {
	t.Helper()
	raw, err := c.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	v := -1
	raw.Control(func(fd uintptr) {
		v, err = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BIND_ADDRESS_NO_PORT)
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestSourceAddressLeavesPortToConnect(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	dest := net.TCPDestination(net.LocalHostIP, net.Port(l.Addr().(*net.TCPAddr).Port))
	var d DefaultSystemDialer

	c, err := d.Dial(context.Background(), net.LocalHostIP, dest, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if v := bindNoPort(t, c); v != 1 {
		t.Fatalf("with a source address IP_BIND_ADDRESS_NO_PORT = %d, want 1", v)
	}

	c2, err := d.Dial(context.Background(), nil, dest, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if v := bindNoPort(t, c2); v != 0 {
		t.Fatalf("without a source address IP_BIND_ADDRESS_NO_PORT = %d, want 0", v)
	}
}

// With a source address, connections to different destinations share the
// address's ports: 3 destinations x 10 connections fit in 10 local ports.
// Runs in a network namespace of its own (needs root).
func TestSourceAddressSharesPorts(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root for a network namespace")
	}
	done := make(chan error, 1)
	go func() {
		// The thread stays locked, so it ends with the goroutine and the
		// namespace never reaches other goroutines.
		runtime.LockOSThread()
		done <- sharesPorts()
	}()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func sharesPorts() error {
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("unshare: %w", err)
	}
	// /proc/sys/net shows the namespace of the thread that opens it.
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_local_port_range", []byte("40000 40009"), 0); err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	ifr.SetUint16(unix.IFF_UP | unix.IFF_LOOPBACK | unix.IFF_RUNNING)
	err = unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
	unix.Close(fd)
	if err != nil {
		return fmt.Errorf("lo up: %w", err)
	}

	var d DefaultSystemDialer
	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	for _, port := range []int{20001, 20002, 20003} {
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			return err
		}
		defer l.Close()
		dest := net.TCPDestination(net.LocalHostIP, net.Port(port))
		for i := 0; i < 10; i++ {
			c, err := d.Dial(context.Background(), net.LocalHostIP, dest, nil)
			if err != nil {
				return fmt.Errorf("connection %d to port %d: %w", i+1, port, err)
			}
			conns = append(conns, c)
		}
	}
	if len(conns) != 30 {
		return fmt.Errorf("%d connections, want 30", len(conns))
	}
	return nil
}

func TestUDPFromSourceAddressBindsIt(t *testing.T) {
	var d DefaultSystemDialer
	c, err := d.Dial(context.Background(), net.LocalHostIP, net.UDPDestination(net.LocalHostIP, 53), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	la := c.(*PacketConnWrapper).PacketConn.LocalAddr().(*net.UDPAddr)
	if !la.IP.Equal(net.LocalHostIP.IP()) {
		t.Fatalf("UDP socket bound to %v, want 127.0.0.1 (its own port pool, not the wildcard one)", la.IP)
	}
}
