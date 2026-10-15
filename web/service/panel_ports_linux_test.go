//go:build linux

package service

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/util/sys"
	"github.com/mhsanaei/3x-ui/v2/util/tune"
)

// The GOMEMLIMIT "x-ui tune" writes into the unit is one the panel can split
// among its cores.
func TestTuneGoMemLimitParses(t *testing.T) {
	for _, gib := range []float64{1, 2, 8, 16, 128} {
		f := &tune.Facts{MemBytes: int64(gib * float64(tune.GiB)), PageSize: 4096, G: gib}
		f.MemTotal = f.MemBytes
		f.TCPMemMax = f.MemBytes / 4096 * 3 / 32
		v := tune.ServiceTargets(f).GoMemLimit
		n := parseGoMemLimit(v)
		if n <= 0 || n%(1<<20) != 0 || n < 256<<20 || n > f.MemBytes {
			t.Fatalf("%g GiB: %q parses to %d", gib, v, n)
		}
	}
}

// ownNetns skips a test that closes sockets unless it runs in the tests'
// own network namespace.
func ownNetns(t *testing.T) {
	t.Helper()
	if os.Getenv(ownNetnsEnv) != "1" {
		t.Skip("closes sockets: runs only as root, in a network namespace of its own")
	}
}

// fakeReservedPorts points the reservations at a file of the test's, with
// the panel's database and state file in a folder of its own.
func fakeReservedPorts(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XUI_DB_FOLDER", dir)
	if err := database.InitDB(filepath.Join(dir, "x-ui.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.CloseDB() })
	sysctl := filepath.Join(dir, "ip_local_reserved_ports")
	os.WriteFile(sysctl, []byte("\n"), 0o644)
	old := reservedPortsPath
	reservedPortsPath = sysctl
	t.Cleanup(func() { reservedPortsPath = old })
	return sysctl
}

// holdPort opens an outgoing connection from from:port to a server of its
// own, as a busy core's connection takes a port of the ephemeral range.
// Its program is slow: after the connection fails it waits a moment before
// it closes it, and the channel then gets the error it saw.
func holdPort(t *testing.T, from string, port int) <-chan error {
	t.Helper()
	srv, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	go func() {
		var conns []net.Conn
		defer func() {
			for _, c := range conns {
				c.Close()
			}
		}()
		for {
			c, err := srv.Accept()
			if err != nil {
				return
			}
			conns = append(conns, c)
		}
	}()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(from), Port: port}}
	c, err := d.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	done := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 1))
		time.Sleep(300 * time.Millisecond)
		c.Close()
		done <- err
	}()
	return done
}

// listenOn listens on addr and accepts connections, as another program's
// server.
func listenOn(t *testing.T, addr string) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return l
}

func aborted(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if !errors.Is(err, syscall.ECONNABORTED) {
			t.Errorf("the connection on the port saw %v, want it aborted", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("the connection on the port is still open")
	}
}

func stillOpen(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		t.Errorf("the connection on the port was closed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
}

// A port the panel moves to that outgoing connections hold is reserved and
// freed: the connections are closed and the move is accepted. A listener
// keeps its port: the move is refused, naming the program, and nothing is
// closed or reserved. Sockets on other addresses are left alone.
func TestServerPortHeldByConnections(t *testing.T) {
	ownNetns(t)
	sysctl := fakeReservedPorts(t)
	var ss SettingService
	if err := ss.SetPort(freeTCPPort(t)); err != nil {
		t.Fatal(err)
	}

	port := freeTCPPort(t)
	done := holdPort(t, "127.0.0.1", port)
	if err := ss.checkServerPorts("", port, false, "", 0); err != nil {
		t.Fatalf("port held only by a connection: %v", err)
	}
	aborted(t, done)
	if got, _ := os.ReadFile(sysctl); !parsePortList(string(got))[port] {
		t.Errorf("port %d not reserved: %q", port, got)
	}

	// Another program listens on 127.0.0.1; a connection has the port
	// at 127.0.0.2.
	port = freeTCPPort(t)
	l := listenOn(t, "127.0.0.1:"+strconv.Itoa(port))
	done = holdPort(t, "127.0.0.2", port)
	err := ss.checkServerPorts("", port, false, "", 0)
	if err == nil || !strings.Contains(err.Error(), "listens on it") || !strings.Contains(err.Error(), "pid "+strconv.Itoa(os.Getpid())) {
		t.Fatalf("port with a listener: %v", err)
	}
	stillOpen(t, done)
	if got, _ := os.ReadFile(sysctl); parsePortList(string(got))[port] {
		t.Errorf("refused port %d reserved: %q", port, got)
	}
	// On 127.0.0.2 only the connection is in the way.
	if err := ss.checkServerPorts("127.0.0.2", port, false, "", 0); err != nil {
		t.Fatalf("127.0.0.2, next to a listener on 127.0.0.1: %v", err)
	}
	aborted(t, done)
	if c, err := net.DialTimeout("tcp", l.Addr().String(), time.Second); err != nil {
		t.Errorf("the other program's listener was closed: %v", err)
	} else {
		c.Close()
	}
}

// kernelPorts points the reservations at the kernel's own list and narrows
// the ephemeral range to port alone, so that every outgoing connection
// takes it until it is reserved. Both are the test namespace's: the test
// is skipped in the host's. They are put back afterwards.
func kernelPorts(t *testing.T, port int) {
	t.Helper()
	self, _ := os.Readlink("/proc/self/ns/net")
	host, err := os.Readlink("/proc/1/ns/net")
	if err != nil || self == host {
		t.Skip("writes the kernel's port settings: runs only in a network namespace of its own")
	}
	const rangePath = "/proc/sys/net/ipv4/ip_local_port_range"
	const reservedPath = "/proc/sys/net/ipv4/ip_local_reserved_ports"
	oldRange, err := os.ReadFile(rangePath)
	if err != nil {
		t.Fatal(err)
	}
	oldReserved, _ := os.ReadFile(reservedPath)
	old := reservedPortsPath
	reservedPortsPath = reservedPath
	t.Cleanup(func() {
		reservedPortsPath = old
		os.WriteFile(reservedPath, oldReserved, 0o644)
		os.WriteFile(rangePath, oldRange, 0o644)
	})
	p := strconv.Itoa(port)
	if err := os.WriteFile(rangePath, []byte(p+" "+p), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A busy core keeps opening connections while the port is got ready: the
// ones it opened until the port was reserved are closed too, and the move
// is accepted.
func TestServerPortHeldByNewConnections(t *testing.T) {
	ownNetns(t)
	fakeReservedPorts(t)
	var ss SettingService
	if err := ss.SetPort(freeTCPPort(t)); err != nil {
		t.Fatal(err)
	}
	to := listenOn(t, ":0").Addr().(*net.TCPAddr).Port
	for round := 0; round < 3; round++ {
		t.Run(strconv.Itoa(round), func(t *testing.T) {
			port := freeTCPPort(t)
			kernelPorts(t, port)
			stop, stopped := make(chan struct{}), make(chan struct{})
			opened := make(chan struct{}, 1)
			go func() {
				defer close(stopped)
				var conns []net.Conn
				defer func() {
					for _, c := range conns {
						c.Close()
					}
				}()
				// Each to another address of the loopback: a port the
				// kernel hands out takes one connection per peer.
				for i := 0; ; i++ {
					select {
					case <-stop:
						return
					default:
					}
					addr := net.JoinHostPort(net.IPv4(127, 1, byte(i>>8), byte(i)).String(), strconv.Itoa(to))
					if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
						conns = append(conns, c)
						if len(conns) == 20 {
							opened <- struct{}{}
						}
					}
				}
			}()
			t.Cleanup(func() {
				close(stop)
				<-stopped
			})
			select {
			case <-opened:
			case <-time.After(5 * time.Second):
				t.Fatal("no connections from the port")
			}
			if err := ss.checkServerPorts("", port, false, "", 0); err != nil {
				t.Fatalf("port held only by connections: %v", err)
			}
		})
	}
}

// A socket only bound to the port is no connection: nothing is closed, and
// the port cannot be used while its program has it.
func TestServerPortHeldByBoundSocket(t *testing.T) {
	ownNetns(t)
	fakeReservedPorts(t)
	var ss SettingService
	if err := ss.SetPort(freeTCPPort(t)); err != nil {
		t.Fatal(err)
	}
	port := freeTCPPort(t)
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	old := closeSocket
	defer func() { closeSocket = old }()
	closeSocket = func(s sys.TCPSocket) error {
		t.Errorf("closed %+v", s)
		return nil
	}
	err = ss.checkServerPorts("", port, false, "", 0)
	if err == nil || !strings.Contains(err.Error(), "address already in use") {
		t.Fatalf("port of a bound socket: %v", err)
	}
}

// ListenServer listens on a port connections hold, closing them; another
// program's listener keeps its port.
func TestListenServerFreesPort(t *testing.T) {
	ownNetns(t)
	fakeReservedPorts(t)
	port := freeTCPPort(t)
	done := holdPort(t, "127.0.0.1", port)
	l, err := ListenServer("Web", "", port)
	if err != nil {
		t.Fatalf("port held by a connection: %v", err)
	}
	l.Close()
	aborted(t, done)

	port = freeTCPPort(t)
	listenOn(t, "127.0.0.1:"+strconv.Itoa(port))
	if l, err := ListenServer("Web", "", port); err == nil || !strings.Contains(err.Error(), "listens on it") {
		if l != nil {
			l.Close()
		}
		t.Fatalf("port of another program's listener: %v", err)
	}
}

// Before a restart, a server that keeps its address is not checked: its
// own port and the connections on it are left as they are. A move is
// checked as a save is.
func TestCheckServerMoves(t *testing.T) {
	ownNetns(t)
	fakeReservedPorts(t)
	var ss SettingService
	webPort := freeTCPPort(t)
	ss.SetPort(webPort)
	ss.saveSetting("subEnable", "false")
	current := net.JoinHostPort("", strconv.Itoa(webPort))

	done := holdPort(t, "127.0.0.1", webPort)
	if err := CheckServerMoves(current, ""); err != nil {
		t.Fatalf("nothing moves: %v", err)
	}
	stillOpen(t, done)

	port := freeTCPPort(t)
	ss.SetPort(port)
	done = holdPort(t, "127.0.0.1", port)
	if err := CheckServerMoves(current, ""); err != nil {
		t.Fatalf("move to a port connections hold: %v", err)
	}
	aborted(t, done)

	port = freeTCPPort(t)
	ss.SetPort(port)
	listenOn(t, "127.0.0.1:"+strconv.Itoa(port))
	if err := CheckServerMoves(current, ""); err == nil || !strings.Contains(err.Error(), "Web port") {
		t.Fatalf("move to another program's port: %v", err)
	}

	// The subscription server, turned on, onto a listener's port.
	ss.SetPort(webPort)
	subPort := freeTCPPort(t)
	ss.saveSetting("subEnable", "true")
	ss.saveSetting("subPort", strconv.Itoa(subPort))
	listenOn(t, "127.0.0.1:"+strconv.Itoa(subPort))
	if err := CheckServerMoves(current, ""); err == nil || !strings.Contains(err.Error(), "Sub port") {
		t.Fatalf("subscription server onto another program's port: %v", err)
	}
	// Running there already, it is not checked.
	if err := CheckServerMoves(current, net.JoinHostPort("", strconv.Itoa(subPort))); err != nil {
		t.Fatalf("subscription server stays: %v", err)
	}
}

// A server that keeps its port and changes only its address is checked
// where a probe cannot be, at a save and before the restart alike. Taking
// every address, it is refused where another program listens at one it
// did not have, and the connections there are closed while its own stay.
// A single address must be one the host has.
func TestServerAddressMoves(t *testing.T) {
	ownNetns(t)
	fakeReservedPorts(t)
	var ss SettingService
	ss.saveSetting("subEnable", "false")
	set := func(listen string, port int) {
		t.Helper()
		ss.saveSetting("webListen", listen)
		if err := ss.SetPort(port); err != nil {
			t.Fatal(err)
		}
	}

	// The panel on 127.0.0.2, another program on 127.0.0.1, same port.
	port := listenOn(t, "127.0.0.2:0").Addr().(*net.TCPAddr).Port
	listenOn(t, "127.0.0.1:"+strconv.Itoa(port))
	set("127.0.0.2", port)
	if err := ss.checkServerPorts("", port, false, "", 0); err == nil || !strings.Contains(err.Error(), "listens on it") {
		t.Fatalf("save onto all addresses next to a listener: %v", err)
	}
	set("", port)
	if err := CheckServerMoves(net.JoinHostPort("127.0.0.2", strconv.Itoa(port)), ""); err == nil || !strings.Contains(err.Error(), "listens on it") {
		t.Fatalf("restart onto all addresses next to a listener: %v", err)
	}

	// The panel on all addresses, moving to one the host does not have.
	port = listenOn(t, ":0").Addr().(*net.TCPAddr).Port
	current := net.JoinHostPort("", strconv.Itoa(port))
	set("", port)
	if err := ss.checkServerPorts("203.0.113.9", port, false, "", 0); err == nil || !strings.Contains(err.Error(), "cannot be used") {
		t.Fatalf("save onto an address the host does not have: %v", err)
	}
	set("203.0.113.9", port)
	if err := CheckServerMoves(current, ""); err == nil || !strings.Contains(err.Error(), "cannot be used") {
		t.Fatalf("restart onto an address the host does not have: %v", err)
	}
	set("127.0.0.1", port)
	if err := CheckServerMoves(current, ""); err != nil {
		t.Fatalf("restart onto an address the host has: %v", err)
	}

	// The panel on 127.0.0.3 with a connection of its own; another
	// program's connection has the port at 127.0.0.1.
	panel, err := net.Listen("tcp", "127.0.0.3:0")
	if err != nil {
		t.Fatal(err)
	}
	defer panel.Close()
	port = panel.Addr().(*net.TCPAddr).Port
	client, err := net.Dial("tcp", panel.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	own, err := panel.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer own.Close()
	done := holdPort(t, "127.0.0.1", port)
	set("127.0.0.3", port)
	start := time.Now()
	if err := ss.checkServerPorts("", port, false, "", 0); err != nil {
		t.Fatalf("save onto all addresses, the port held by a connection: %v", err)
	}
	// A probe would fail on the panel's own listener: none is waited for.
	if d := time.Since(start); d > portFreeWait/2 {
		t.Errorf("the save took %v", d)
	}
	aborted(t, done)
	own.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := own.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("the panel's own connection: %v", err)
	}
	if c, err := net.DialTimeout("tcp", panel.Addr().String(), time.Second); err != nil {
		t.Errorf("the panel's listener was closed: %v", err)
	} else {
		c.Close()
	}
}

// After a restart that could not move it, a server listens where it was,
// not where the settings say: a save that sets that port again is no move
// onto someone else's listener.
func TestServerSettingFromWhereItListens(t *testing.T) {
	fakeReservedPorts(t)
	var ss SettingService
	if err := ss.SetPort(freeTCPPort(t)); err != nil {
		t.Fatal(err)
	}
	ss.saveSetting("subEnable", "true")
	ss.saveSetting("subPort", strconv.Itoa(freeTCPPort(t)))
	web := listenOn(t, ":0").Addr().(*net.TCPAddr).Port
	sub := listenOn(t, ":0").Addr().(*net.TCPAddr).Port
	ServerListening("Web", net.JoinHostPort("", strconv.Itoa(web)))
	ServerListening("Sub", net.JoinHostPort("", strconv.Itoa(sub)))
	defer ServerListening("Web", "")
	defer ServerListening("Sub", "")

	if err := ss.CheckWebPort("", web); err != nil {
		t.Errorf("web port set to where the server listens: %v", err)
	}
	webPort, _ := ss.GetPort()
	if err := ss.checkServerPorts("", webPort, true, "", sub); err != nil {
		t.Errorf("sub port set to where the server listens: %v", err)
	}
	// Any other port is checked as ever.
	other := listenOn(t, "127.0.0.1:0").Addr().(*net.TCPAddr).Port
	if err := ss.CheckWebPort("", other); err == nil || !strings.Contains(err.Error(), "listens on it") {
		t.Errorf("web port of another listener: %v", err)
	}
}

// The program that holds a port is looked for once per listener: a web
// server that cannot listen retries every 10 s, and each search may read
// every descriptor on the host.
func TestPortOwnerLookedForOnce(t *testing.T) {
	fakeReservedPorts(t)
	calls := 0
	old := socketOwner
	defer func() { socketOwner = old }()
	socketOwner = func(s sys.TCPSocket) (int, string) {
		calls++
		return old(s)
	}
	for want := 1; want <= 2; want++ {
		port := listenOn(t, "127.0.0.1:0").Addr().(*net.TCPAddr).Port
		for range 3 {
			l, err := ListenServer("Web", "", port)
			if err == nil {
				l.Close()
			}
			if err == nil || !strings.Contains(err.Error(), "pid "+strconv.Itoa(os.Getpid())) {
				t.Fatalf("port of another listener: %v", err)
			}
		}
		if calls != want {
			t.Errorf("listener %d: looked for %d times in all", want, calls)
		}
	}
}
