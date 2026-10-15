//go:build linux

package sys

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// freeTCPPort returns a port nothing listens on.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// canListen says whether a server could listen on port at all addresses.
func canListen(port int) bool {
	l, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return false
	}
	l.Close()
	return true
}

// dialFrom connects a raw socket of family from local:port (port 0: the
// kernel picks one, as for an outgoing connection) to to, and returns it
// with its local port and a function that closes it once.
func dialFrom(t *testing.T, family int, local string, port int, to *net.TCPAddr) (int, int, func()) {
	t.Helper()
	fd, err := unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	closeFD := func() { once.Do(func() { unix.Close(fd) }) }
	t.Cleanup(closeFD)
	// A read on a connection left open fails after a while, not never.
	tv := unix.NsecToTimeval(int64(2 * time.Second))
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		t.Fatal(err)
	}
	addr := func(ip string, port int) unix.Sockaddr {
		if family == unix.AF_INET {
			sa := &unix.SockaddrInet4{Port: port}
			copy(sa.Addr[:], net.ParseIP(ip).To4())
			return sa
		}
		sa := &unix.SockaddrInet6{Port: port}
		copy(sa.Addr[:], net.ParseIP(ip).To16())
		return sa
	}
	if port != 0 {
		if err := unix.Bind(fd, addr(local, port)); err != nil {
			t.Fatal(err)
		}
	}
	remote := to.IP.String()
	if family == unix.AF_INET6 && to.IP.To4() != nil {
		remote = "::ffff:" + remote
	}
	if err := unix.Connect(fd, addr(remote, to.Port)); err != nil {
		t.Fatal(err)
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	switch a := sa.(type) {
	case *unix.SockaddrInet4:
		port = a.Port
	case *unix.SockaddrInet6:
		port = a.Port
	}
	return fd, port, closeFD
}

// server listens on addr and accepts connections, which it keeps open.
func server(t *testing.T, addr string) *net.TCPAddr {
	t.Helper()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skip("cannot listen on", addr, err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		var conns []net.Conn
		defer func() {
			for _, c := range conns {
				c.Close()
			}
		}()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			conns = append(conns, c)
		}
	}()
	return l.Addr().(*net.TCPAddr)
}

// An outgoing connection whose local port is a port a server wants keeps
// the server from listening there. DestroyTCP closes it, for IPv4, IPv6
// and an IPv6 socket on an IPv4 connection, whether the kernel picked the
// port or the program bound it; its program sees the connection aborted.
func TestDestroyTCPFreesThePort(t *testing.T) {
	inOwnNetns(t)
	v4 := server(t, "127.0.0.1:0")
	for _, c := range []struct {
		name   string
		family int
		local  string
		bind   bool
		to     *net.TCPAddr
		wantIP string
	}{
		{"ipv4, port from the kernel", unix.AF_INET, "127.0.0.1", false, v4, "127.0.0.1"},
		{"ipv4, bound port", unix.AF_INET, "127.0.0.1", true, v4, "127.0.0.1"},
		{"v4-mapped, port from the kernel", unix.AF_INET6, "::ffff:127.0.0.1", false, v4, "127.0.0.1"},
		{"v4-mapped, bound port", unix.AF_INET6, "::ffff:127.0.0.1", true, v4, "127.0.0.1"},
		{"ipv6", unix.AF_INET6, "::1", true, nil, "::1"},
	} {
		t.Run(c.name, func(t *testing.T) {
			to := c.to
			if to == nil {
				to = server(t, "[::1]:0")
			}
			port := 0
			if c.bind {
				port = freeTCPPort(t)
			}
			fd, port, closeFD := dialFrom(t, c.family, c.local, port, to)
			if canListen(port) {
				t.Fatalf("a server could listen on %d next to the connection", port)
			}
			socks, err := PortTCPSockets(port)
			if err != nil {
				t.Fatal(err)
			}
			if len(socks) != 1 || socks[0].Listening || socks[0].Local.IP != c.wantIP || socks[0].State != tcpEstablished {
				t.Fatalf("sockets on %d: %+v", port, socks)
			}
			if err := DestroyTCP(socks[0]); err != nil {
				t.Fatal(err)
			}
			if _, err := unix.Read(fd, make([]byte, 1)); !errors.Is(err, unix.ECONNABORTED) {
				t.Errorf("the program read %v, want ECONNABORTED", err)
			}
			// A bound socket keeps its port until its program closes it,
			// as one does after the abort. Only bound now, it is not
			// listed.
			if c.bind {
				if socks := mustSockets(t, port); len(socks) != 0 {
					t.Errorf("aborted bound socket listed: %+v", socks)
				}
				if canListen(port) {
					t.Errorf("port %d free before the program closed its socket", port)
				}
				closeFD()
			}
			if !canListen(port) {
				t.Fatalf("port %d still taken: %+v", port, mustSockets(t, port))
			}
			// It is gone: closing it again is not an error.
			if err := DestroyTCP(socks[0]); err != nil {
				t.Errorf("destroying a closed socket: %v", err)
			}
		})
	}
}

func mustSockets(t *testing.T, port int) []TCPSocket {
	t.Helper()
	s, err := PortTCPSockets(port)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A connection its program closed first waits in time-wait, which holds
// the port too; DestroyTCP drops it.
func TestDestroyTCPTimeWait(t *testing.T) {
	inOwnNetns(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		if c, err := l.Accept(); err == nil {
			accepted <- c
		}
	}()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port := c.LocalAddr().(*net.TCPAddr).Port
	peer := <-accepted
	c.Close()
	time.Sleep(50 * time.Millisecond)
	peer.Close()
	var tw []TCPSocket
	for i := 0; i < 50 && len(tw) == 0; i++ {
		time.Sleep(20 * time.Millisecond)
		for _, s := range mustSockets(t, port) {
			if s.State == 6 {
				tw = append(tw, s)
			}
		}
	}
	if len(tw) != 1 || tw[0].Inode != 0 {
		t.Fatalf("time-wait socket on %d: %+v", port, mustSockets(t, port))
	}
	if canListen(port) {
		t.Fatal("time-wait did not hold the port")
	}
	if err := DestroyTCP(tw[0]); err != nil {
		t.Fatal(err)
	}
	if !canListen(port) {
		t.Fatalf("port %d still taken: %+v", port, mustSockets(t, port))
	}
}

// A listener is listed as one, with its program. A socket that went away
// is named by its addresses and its cookie: destroying it after a listener
// took its address leaves the listener alone.
func TestDestroyTCPNeverTakesAListener(t *testing.T) {
	inOwnNetns(t)
	to := server(t, "127.0.0.1:0")
	port := freeTCPPort(t)
	_, _, closeFD := dialFrom(t, unix.AF_INET, "127.0.0.1", port, to)
	socks := mustSockets(t, port)
	if len(socks) != 1 {
		t.Fatalf("sockets on %d: %+v", port, socks)
	}
	stale := socks[0]
	if err := DestroyTCP(stale); err != nil {
		t.Fatal(err)
	}
	closeFD()

	l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	socks = mustSockets(t, port)
	if len(socks) != 1 || !socks[0].Listening || socks[0].Inode == 0 {
		t.Fatalf("listener on %d: %+v", port, socks)
	}
	if pid, name := socks[0].Owner(); pid != os.Getpid() || name == "" {
		t.Errorf("owner of the listener: %d %q, want %d", pid, name, os.Getpid())
	}

	if err := DestroyTCP(stale); err != nil {
		t.Fatal(err)
	}
	go func() {
		if c, err := l.Accept(); err == nil {
			c.Close()
		}
	}()
	c, err := net.DialTimeout("tcp", l.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("the listener was closed: %v", err)
	}
	c.Close()
}

// A socket only bound to a port is not listed: listing those would have
// the kernel walk a busy listener's connections with their bucket locked.
// PortTCPListeners lists the listeners alone.
func TestPortTCPSocketsLeavesOutBoundSockets(t *testing.T) {
	port := freeTCPPort(t)
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	if socks := mustSockets(t, port); len(socks) != 0 {
		t.Fatalf("bound socket listed: %+v", socks)
	}

	to := server(t, "127.0.0.2:"+strconv.Itoa(port))
	c, err := net.Dial("tcp", to.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	time.Sleep(50 * time.Millisecond) // accepted
	socks := mustSockets(t, port)
	if len(socks) != 2 {
		t.Fatalf("listener and its connection on %d: %+v", port, socks)
	}
	ls, err := PortTCPListeners(port)
	if err != nil {
		t.Fatal(err)
	}
	if len(ls) != 1 || !ls[0].Listening || ls[0].Local.IP != "127.0.0.2" || ls[0].Inode == 0 {
		t.Fatalf("listeners on %d: %+v", port, ls)
	}
}

// Owner reads the descriptors of the programs with fewer first: a core's
// hundreds of thousands come last.
func TestProcsByFDs(t *testing.T) {
	if fi, err := os.Stat("/proc/self/fd"); err != nil || fi.Size() == 0 {
		t.Skip("this kernel does not count a process's descriptors")
	}
	// This test holds many descriptors, a program started after it few.
	for i := 0; i < 2000; i++ {
		f, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
	}
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skip("cannot start sleep:", err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()
	ids := procsByFDs()
	small, big := slices.Index(ids, cmd.Process.Pid), slices.Index(ids, os.Getpid())
	if small < 0 || big < 0 || small > big {
		t.Fatalf("sleep (pid %d) at %d, the test (pid %d) at %d", cmd.Process.Pid, small, os.Getpid(), big)
	}
}
