//go:build linux

package sys

import (
	"net"
	"testing"
	"time"

	// HostProc is linked from gopsutil; the package must be in the binary.
	_ "github.com/shirou/gopsutil/v4/net"
)

// listen opens a listener on loopback and n client connections to it.
func listen(t *testing.T, n int) (int, func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var conns []net.Conn
	accepted := make(chan net.Conn, n)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	for i := 0; i < n; i++ {
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	for i := 0; i < n; i++ {
		select {
		case c := <-accepted:
			conns = append(conns, c)
		case <-time.After(5 * time.Second):
			t.Fatal("accept timeout")
		}
	}
	return l.Addr().(*net.TCPAddr).Port, func() {
		for _, c := range conns {
			c.Close()
		}
		l.Close()
	}
}

func TestCountEstablishedTCP(t *testing.T) {
	p1, c1 := listen(t, 7)
	defer c1()
	p2, c2 := listen(t, 3)
	defer c2()
	p3, c3 := listen(t, 2) // not asked for
	defer c3()

	got, err := CountEstablishedTCP([]int{p1, p2})
	if err != nil {
		t.Fatal(err)
	}
	if n := got[LocalEndpoint{IP: "127.0.0.1", Port: p1}]; n != 7 {
		t.Fatalf("port %d: %d (%v)", p1, n, got)
	}
	if n := got[LocalEndpoint{IP: "127.0.0.1", Port: p2}]; n != 3 {
		t.Fatalf("port %d: %d (%v)", p2, n, got)
	}
	for ep := range got {
		if ep.Port == p3 {
			t.Fatalf("unrequested port counted: %v", got)
		}
		// The client ends have ephemeral local ports, which must not count.
		if ep.Port != p1 && ep.Port != p2 {
			t.Fatalf("stray endpoint: %v", ep)
		}
	}
	if got, err := CountEstablishedTCP(nil); err != nil || len(got) != 0 {
		t.Fatalf("no ports: %v %v", got, err)
	}
}

func TestCountEstablishedTCPManyPorts(t *testing.T) {
	// More scattered ports than the filter takes as ranges: it falls back to
	// one wide range and the exact filtering happens in Go.
	p1, c1 := listen(t, 4)
	defer c1()
	ports := []int{p1}
	for i := 0; i < 3*maxPortRanges; i++ {
		ports = append(ports, 1000+i*7)
	}
	got, err := CountEstablishedTCP(ports)
	if err != nil {
		t.Fatal(err)
	}
	if n := got[LocalEndpoint{IP: "127.0.0.1", Port: p1}]; n != 4 {
		t.Fatalf("port %d: %d (%v)", p1, n, got)
	}
}

func TestCountEstablishedTCPv6(t *testing.T) {
	l, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback")
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
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	time.Sleep(50 * time.Millisecond)
	port := l.Addr().(*net.TCPAddr).Port
	got, err := CountEstablishedTCP([]int{port})
	if err != nil {
		t.Fatal(err)
	}
	if n := got[LocalEndpoint{IP: "::1", Port: port}]; n != 1 {
		t.Fatalf("v6: %v", got)
	}
}

func TestPortFilterLayout(t *testing.T) {
	// 3 ranges: 2 full blocks of 20 bytes and a last one of 16.
	bc := portFilter([]int{80, 81, 82, 443, 8443})
	if len(bc) != 20+20+16 {
		t.Fatalf("length %d", len(bc))
	}
	if portFilter([]int{0, 70000}) != nil {
		t.Fatal("invalid ports gave a filter")
	}
}

func TestSockstatCounts(t *testing.T) {
	_, c := listen(t, 2)
	defer c()
	tcp, _, err := sockstatCounts()
	if err != nil {
		t.Fatal(err)
	}
	if tcp < 5 { // a listener and four connection ends at least
		t.Fatalf("tcp sockets: %d", tcp)
	}
	n, err := GetTCPCount()
	if err != nil || n < 5 {
		t.Fatalf("GetTCPCount: %d %v", n, err)
	}
}

func TestKernelAppliesPortFilter(t *testing.T) {
	p1, c1 := listen(t, 3)
	defer c1()
	p2, c2 := listen(t, 2)
	defer c2()
	p3, c3 := listen(t, 2)
	defer c3()
	_ = p3
	// Called without the Go-side check: everything delivered must already
	// match, which proves the kernel ran the filter (an EINVAL here would
	// mean it refused it).
	seen := map[int]int{}
	err := dumpTCP(2 /* AF_INET */, portFilter([]int{p1, p2}), func(ep LocalEndpoint) { seen[ep.Port]++ })
	if err != nil {
		t.Fatalf("kernel refused the filter: %v", err)
	}
	if seen[p1] != 3 || seen[p2] != 2 || len(seen) != 2 {
		t.Fatalf("filtered dump: %v (want %d:3 %d:2)", seen, p1, p2)
	}
	// The single-range form used for many ports.
	lo, hi := p1, p2
	if lo > hi {
		lo, hi = hi, lo
	}
	seen = map[int]int{}
	if err := dumpTCP(2, portFilter([]int{lo, hi}), func(ep LocalEndpoint) { seen[ep.Port]++ }); err != nil {
		t.Fatal(err)
	}
	for port := range seen {
		if port != p1 && port != p2 {
			t.Fatalf("port %d passed the filter", port)
		}
	}
}

func TestUDPSockets(t *testing.T) {
	wild, err := net.ListenPacket("udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer wild.Close()
	lo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lo.Close()
	wildPort := wild.LocalAddr().(*net.UDPAddr).Port
	loPort := lo.LocalAddr().(*net.UDPAddr).Port
	found := map[LocalEndpoint]bool{}
	if err := UDPSockets(func(ep LocalEndpoint) { found[ep] = true }); err != nil {
		t.Fatal(err)
	}
	if !found[LocalEndpoint{IP: "", Port: wildPort}] {
		t.Errorf("the wildcard socket on port %d was not reported as IP \"\"", wildPort)
	}
	if !found[LocalEndpoint{IP: "127.0.0.1", Port: loPort}] {
		t.Errorf("the socket on 127.0.0.1:%d was not reported", loPort)
	}
}
