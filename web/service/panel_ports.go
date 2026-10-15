package service

import (
	"errors"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/common"
	"github.com/mhsanaei/3x-ui/v2/util/sys"
)

// The panel and its subscription server listen next to the cores. A port
// both want is lost by whichever binds last: a core backs off and retries
// for ever, and a server that cannot listen after the restart that applied
// a setting stays down. These checks keep them apart up front.

// panelPortUser names the panel's own server, "panel" or "subscription",
// that listens on port at an address overlapping listen, or returns "".
func panelPortUser(listen string, port int) string {
	var s SettingService
	overlaps := func(other string) bool {
		return wildcardListen(listen) || wildcardListen(other) || listen == other
	}
	if p, err := s.GetPort(); err == nil && p == port {
		if l, _ := s.GetListen(); overlaps(l) {
			return "panel"
		}
	}
	if on, _ := s.GetSubEnable(); on {
		if p, err := s.GetSubPort(); err == nil && p == port {
			if l, _ := s.GetSubListen(); overlaps(l) {
				return "subscription"
			}
		}
	}
	return ""
}

// checkServerPort refuses port for the panel's server what ("Web" or "Sub")
// when an inbound or a sub-inbound has it, or, when probe is set, when
// something on the host holds it now.
func checkServerPort(what, listen string, port int, probe bool) error {
	var inbounds InboundService
	if exist, err := inbounds.checkPortExist(listen, port, 0); err != nil {
		return err
	} else if exist {
		return common.NewErrorf("%s port %d is already used by an inbound", what, port)
	}
	if name, err := subPortUser(listen, port, 0); err != nil {
		return err
	} else if name != "" {
		return common.NewErrorf("%s port %d is already used by a sub-inbound of %s", what, port, name)
	}
	if !probe {
		return nil
	}
	if err := freeServerPort(what, listen, port, ""); err != nil {
		return err
	}
	l, err := net.Listen("tcp", net.JoinHostPort(listen, strconv.Itoa(port)))
	if err != nil {
		return common.NewErrorf("%s port %d cannot be used: %v%s", what, port, err, portHolder(listen, port))
	}
	l.Close()
	return nil
}

// closeSocket closes a connection that holds a port one of the panel's
// servers moves to. The tests replace it outside a network namespace of
// their own, where it would close the host's connections.
var closeSocket = sys.DestroyTCP

// portFreeWait is how long freeServerPort waits for the programs of the
// connections it closed to let go of the port.
var portFreeWait = 3 * time.Second

// freeServerPort gets listen:port ready for the panel's server what. A
// listener there belongs to another program, which has the port: that is
// refused, naming the program. Otherwise the port is reserved first, so no
// new outgoing connection takes it, and the connections that took it as
// their local port already are closed, as "ss -K" does: on a busy server
// any port of the ephemeral range is the local port of some connection,
// and the server could not listen there until it ended, maybe hours later.
// Their programs see an aborted connection. Listeners are never closed.
// Sockets at the address own, when set, are the server's: it listens there
// now, and they are left alone.
func freeServerPort(what, listen string, port int, own string) error {
	theirs := func(socks []sys.TCPSocket) ([]sys.TCPSocket, error) {
		var out []sys.TCPSocket
		for _, s := range socks {
			if own != "" && sameIP(own, s.Local.IP) {
				continue
			}
			if s.Listening {
				return nil, common.NewErrorf("%s port %d is in use: %s listens on it", what, port, ownerName(s))
			}
			out = append(out, s)
		}
		return out, nil
	}
	if _, err := theirs(portSockets(listen, port, true)); err != nil {
		return err
	}
	reservePorts(port)
	// Listed once the port is reserved: a busy core keeps opening
	// connections from it until then.
	held, err := theirs(portSockets(listen, port, false))
	if err != nil {
		return err
	}
	closed := 0
	for _, s := range held {
		if err := closeSocket(s); err != nil {
			logger.Warningf("%s port %d: cannot close the connections on it: %v", what, port, err)
			break
		}
		closed++
	}
	if closed == 0 {
		return nil
	}
	logger.Infof("%s port %d: closed %d connections that held it as their local port", what, port, closed)
	if own != "" {
		return nil // the server's own listener is in the way of a probe
	}
	// A connection whose program bound it to the port keeps the port
	// until the program closes it after the abort.
	addr := net.JoinHostPort(listen, strconv.Itoa(port))
	for deadline := time.Now().Add(portFreeWait); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if l, err := net.Listen("tcp", addr); err == nil {
			l.Close()
			break
		}
	}
	return nil
}

// portSockets lists the TCP sockets on port at an address overlapping
// listen, or none when sock_diag cannot tell; only the listeners when
// listeners is set, which the kernel finds without reading every
// connection.
func portSockets(listen string, port int, listeners bool) []sys.TCPSocket {
	list := sys.PortTCPSockets
	if listeners {
		list = sys.PortTCPListeners
	}
	socks, _ := list(port)
	var out []sys.TCPSocket
	for _, s := range socks {
		if sharesAddress(listen, s.Local.IP) {
			out = append(out, s)
		}
	}
	return out
}

// sharesAddress says whether a socket on the local address ip and a server
// listening on listen overlap: either takes every address, or both have
// the same one.
func sharesAddress(listen, ip string) bool {
	return wildcardListen(listen) || wildcardListen(ip) || sameIP(listen, ip)
}

// sameIP says whether a and b are the same address; an IPv4 address and
// its v4-mapped IPv6 form are.
func sameIP(a, b string) bool {
	x, y := net.ParseIP(a), net.ParseIP(b)
	if x == nil || y == nil {
		return a == b
	}
	return x.Equal(y)
}

// socketOwner finds the program that has a socket open; the tests count
// its calls.
var socketOwner = sys.TCPSocket.Owner

// lastOwner is the program ownerName found last, by its socket's inode.
// Finding one may read every descriptor on the host, and a web server that
// cannot listen meets the same listener on every retry.
var lastOwner struct {
	sync.Mutex
	inode uint32
	name  string
}

// ownerName names the program that has s open, for a message.
func ownerName(s sys.TCPSocket) string {
	lastOwner.Lock()
	defer lastOwner.Unlock()
	if s.Inode == 0 || s.Inode != lastOwner.inode {
		name := "another program"
		if pid, n := socketOwner(s); pid > 0 {
			name = n + " (pid " + strconv.Itoa(pid) + ")"
		}
		lastOwner.inode, lastOwner.name = s.Inode, name
	}
	return lastOwner.name
}

// portHolder says, for a message, what holds listen:port: ", <program>
// listens on it" or ", N sockets hold it", or "" when nothing does.
func portHolder(listen string, port int) string {
	held := portSockets(listen, port, false)
	for _, s := range held {
		if s.Listening {
			return ", " + ownerName(s) + " listens on it"
		}
	}
	if len(held) == 0 {
		return ""
	}
	msg := ", " + strconv.Itoa(len(held)) + " sockets hold it"
	if held[0].Inode != 0 {
		msg += " (" + ownerName(held[0]) + ")"
	}
	return msg
}

// ListenServer opens the listener of the panel's server what on
// listen:port. When the port is taken it is freed as freeServerPort does,
// and tried again; a listener of another program keeps it.
func ListenServer(what, listen string, port int) (net.Listener, error) {
	addr := net.JoinHostPort(listen, strconv.Itoa(port))
	l, err := net.Listen("tcp", addr)
	if !errors.Is(err, syscall.EADDRINUSE) {
		return l, err
	}
	if err := freeServerPort(what, listen, port, ""); err != nil {
		return nil, err
	}
	l, err = net.Listen("tcp", addr)
	if err != nil {
		return nil, common.NewErrorf("%v%s", err, portHolder(listen, port))
	}
	return l, nil
}

// CheckServerMove runs before a restart moves the panel's server what from
// current, the address it listens on now ("" when it does not listen), to
// listen:port. It gets the new port ready as a save of the settings does,
// and fails when the server could not listen there: the restart would
// bring it back without its listener, and the cores it stops with it.
func CheckServerMove(what, current, listen string, port int) error {
	if host, p, err := net.SplitHostPort(current); err == nil {
		if n, _ := strconv.Atoi(p); holdsPort(host, n, listen, port) {
			return checkServerAddress(what, host, listen, port)
		}
	}
	return checkServerPort(what, listen, port, true)
}

// checkServerAddress checks a move of the panel's server what, listening
// on current, to listen on the same port, which a probe cannot: it would
// fail on the server's own socket. A single address must be one the host
// has; the server has the port there already. Taking every address, the
// server takes the port at those it did not listen on, which are got
// ready as a new port is.
func checkServerAddress(what, current, listen string, port int) error {
	switch {
	case sameIP(listen, current), wildcardListen(listen) && wildcardListen(current):
		return nil
	case !wildcardListen(listen):
		l, err := net.Listen("tcp", net.JoinHostPort(listen, "0"))
		if err != nil {
			return common.NewErrorf("%s address %s cannot be used: %v", what, listen, err)
		}
		l.Close()
		return nil
	}
	return freeServerPort(what, listen, port, current)
}

// CheckServerMoves runs CheckServerMove for the web server, listening on
// web now, and the subscription server, on sub, with the addresses in the
// settings.
func CheckServerMoves(web, sub string) error {
	var s SettingService
	listen, err := s.GetListen()
	if err != nil {
		return err
	}
	port, err := s.GetPort()
	if err != nil {
		return err
	}
	if err := CheckServerMove("Web", web, listen, port); err != nil {
		return err
	}
	if on, err := s.GetSubEnable(); err != nil || !on {
		return err
	}
	subListen, err := s.GetSubListen()
	if err != nil {
		return err
	}
	subPort, err := s.GetSubPort()
	if err != nil {
		return err
	}
	return CheckServerMove("Sub", sub, subListen, subPort)
}

// The addresses the panel's servers listen on now, by what. A port saved
// in the settings takes effect at the next restart; until then the old one
// is in use, and addPanelPorts keeps it reserved too. A restart that could
// not move a server leaves it where it was.
var (
	serverAddrsMu sync.Mutex
	serverAddrs   = map[string]string{}
)

// ServerListening records the address, host:port, the panel's server what
// listens on, or "" once it stopped.
func ServerListening(what, addr string) {
	serverAddrsMu.Lock()
	defer serverAddrsMu.Unlock()
	if addr == "" {
		delete(serverAddrs, what)
		return
	}
	serverAddrs[what] = addr
}

// serverAddress is the address the panel's server what listens on in this
// process, or, when it does not, settings: the one in the settings.
func serverAddress(what, settings string) string {
	serverAddrsMu.Lock()
	defer serverAddrsMu.Unlock()
	if addr, ok := serverAddrs[what]; ok {
		return addr
	}
	return settings
}

// holdsPort says whether a server listening on oldListen:oldPort holds
// listen:port itself: the same port at an overlapping address. A probe there
// fails on the server's own socket, so it cannot tell whether anything else
// holds the port; the inbound checks and checkServerAddress still apply.
func holdsPort(oldListen string, oldPort int, listen string, port int) bool {
	return port == oldPort && (wildcardListen(listen) || wildcardListen(oldListen) || listen == oldListen)
}

// checkServerPorts runs checkServerPort for the web and the subscription
// server when the address one of them would listen on changes; a server
// that keeps its address holds its port itself.
func (s *SettingService) checkServerPorts(webListen string, webPort int, subEnable bool, subListen string, subPort int) error {
	if err := s.CheckWebPort(webListen, webPort); err != nil {
		return err
	}
	if !subEnable {
		return nil
	}
	wasOn, _ := s.GetSubEnable()
	oldSubListen, _ := s.GetSubListen()
	oldSubPort, _ := s.GetSubPort()
	if wasOn && subPort == oldSubPort && subListen == oldSubListen {
		return nil
	}
	current := ""
	if wasOn {
		current = net.JoinHostPort(oldSubListen, strconv.Itoa(oldSubPort))
	}
	return checkServerSetting("Sub", serverAddress("Sub", current), subListen, subPort)
}

// CheckWebPort runs checkServerPort for the web server when the address it
// would listen on changes. "x-ui setting -port" runs it too: a panel
// restarted onto a port it cannot listen on comes back without its web
// server.
func (s *SettingService) CheckWebPort(listen string, port int) error {
	oldListen, _ := s.GetListen()
	oldPort, _ := s.GetPort()
	if port == oldPort && listen == oldListen {
		return nil
	}
	return checkServerSetting("Web", serverAddress("Web", net.JoinHostPort(oldListen, strconv.Itoa(oldPort))), listen, port)
}

// checkServerSetting runs checkServerPort for the panel's server what,
// listening on current ("" when it does not), saved to listen on
// listen:port. Where the server is running decides, not the settings: a
// server whose last move failed is still where it was.
func checkServerSetting(what, current, listen string, port int) error {
	host, p, err := net.SplitHostPort(current)
	n, _ := strconv.Atoi(p)
	holds := err == nil && holdsPort(host, n, listen, port)
	if err := checkServerPort(what, listen, port, !holds); err != nil || !holds {
		return err
	}
	return checkServerAddress(what, host, listen, port)
}

// addPanelPorts adds the panel's own web port, and the subscription port
// when that server is on, to the ports kept out of the ephemeral range. Both
// are outside the kernel's default range only by luck (the installer's 60000
// is inside it, and "x-ui tune" widens the range to 10000-65535): an
// outgoing connection holding one while the panel restarts would stop the
// panel from listening.
func (s *XrayService) addPanelPorts(ports map[int]bool) {
	if p, err := s.settingService.GetPort(); err == nil && p > 0 && p <= 65535 {
		ports[p] = true
	}
	if on, err := s.settingService.GetSubEnable(); err == nil && on {
		if p, err := s.settingService.GetSubPort(); err == nil && p > 0 && p <= 65535 {
			ports[p] = true
		}
	}
	serverAddrsMu.Lock()
	defer serverAddrsMu.Unlock()
	for _, addr := range serverAddrs {
		if _, p, err := net.SplitHostPort(addr); err == nil {
			if n, err := strconv.Atoi(p); err == nil && n > 0 && n <= 65535 {
				ports[n] = true
			}
		}
	}
}
