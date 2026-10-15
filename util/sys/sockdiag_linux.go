//go:build linux

package sys

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// LocalEndpoint is the local side of a TCP connection.
type LocalEndpoint struct {
	IP   string // IPv4 in dotted form, IPv6 otherwise; v4-mapped IPv6 is shown as IPv4
	Port int
}

const (
	sockDiagByFamily = 20
	inetDiagReqBC    = 1 // INET_DIAG_REQ_BYTECODE
	bcJmp            = 1
	bcSGE            = 2
	bcSLE            = 3
	tcpEstablished   = 1
	tcpClose         = 7  // an unconnected UDP socket, a TCP socket only bound
	tcpListen        = 10 // a listening TCP socket
	tcpBoundInactive = 13 // a TCP socket only bound, which a kernel from 6.7 on lists
	maxPortRanges    = 32
)

// CountEstablishedTCP counts established TCP connections whose local port is
// one of ports, per local address and port. It asks the kernel through
// sock_diag with a filter on the local port, so with hundreds of thousands of
// connections only the matching ones are read -- unlike /proc/net/tcp, which
// prints every socket as text on each read.
func CountEstablishedTCP(ports []int) (map[LocalEndpoint]int, error) {
	out := map[LocalEndpoint]int{}
	if len(ports) == 0 {
		return out, nil
	}
	want := map[int]bool{}
	for _, p := range ports {
		want[p] = true
	}
	bc := portFilter(ports)
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		err := dumpTCP(family, bc, func(ep LocalEndpoint) {
			if want[ep.Port] {
				out[ep]++
			}
		})
		if errors.Is(err, unix.EINVAL) && bc != nil {
			// A kernel that refuses the filter: read everything.
			err = dumpTCP(family, nil, func(ep LocalEndpoint) {
				if want[ep.Port] {
					out[ep]++
				}
			})
		}
		if err != nil {
			if family == unix.AF_INET6 {
				continue // IPv6 may be disabled
			}
			return nil, err
		}
	}
	return out, nil
}

// portFilter builds inet_diag bytecode that accepts sockets whose local port
// lies in one of the port ranges. Each range is "sport >= lo && sport <= hi",
// then a jump to accept; a failed test falls through to the next range, and
// the last one's failures jump past the end, which rejects. Many scattered
// ports are reduced to their overall range and filtered exactly in Go.
func portFilter(ports []int) []byte {
	sorted := append([]int(nil), ports...)
	sort.Ints(sorted)
	type rng struct{ lo, hi int }
	var ranges []rng
	for _, p := range sorted {
		if p <= 0 || p > 65535 {
			continue
		}
		if n := len(ranges); n > 0 && p <= ranges[n-1].hi+1 {
			if p > ranges[n-1].hi {
				ranges[n-1].hi = p
			}
			continue
		}
		ranges = append(ranges, rng{p, p})
	}
	if len(ranges) == 0 {
		return nil
	}
	if len(ranges) > maxPortRanges {
		ranges = []rng{{ranges[0].lo, ranges[len(ranges)-1].hi}}
	}
	const cmp = 8                  // comparison op plus the op carrying the port
	const block = 20               // GE, LE, JMP
	total := len(ranges)*block - 4 // the last range needs no jump
	bc := make([]byte, 0, total)
	op := func(code, yes uint8, no int) {
		bc = append(bc, code, yes, 0, 0)
		binary.NativeEndian.PutUint16(bc[len(bc)-2:], uint16(no))
	}
	port := func(p int) {
		bc = append(bc, 0, 0, 0, 0)
		binary.NativeEndian.PutUint16(bc[len(bc)-2:], uint16(p))
	}
	for i, r := range ranges {
		start := i * block
		last := i == len(ranges)-1
		next := start + block // where the next range starts
		if last {
			next = total + 4 // past the end: reject
		}
		at := len(bc)
		op(bcSGE, cmp, next-at)
		port(r.lo)
		at = len(bc)
		op(bcSLE, cmp, next-at)
		port(r.hi)
		if !last {
			at = len(bc)
			op(bcJmp, 4, total-at) // to the end: accept
		}
	}
	return bc
}

// UDPSockets calls fn with the local address and port of every UDP socket,
// IPv4 and IPv6. A socket bound to all addresses has IP "".
func UDPSockets(fn func(LocalEndpoint)) error {
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		err := dumpSockets(family, unix.IPPROTO_UDP, ^uint32(0), nil, func(ep LocalEndpoint) {
			if ep.IP == "0.0.0.0" || ep.IP == "::" {
				ep.IP = ""
			}
			fn(ep)
		})
		if err != nil && family == unix.AF_INET {
			return err
		}
	}
	return nil
}

// ListeningPorts lists the local ports of listening TCP sockets and of
// unconnected UDP sockets (bound, waiting for any peer), IPv4 and IPv6. Read
// through sock_diag, it takes milliseconds where /proc/net/udp, on a server
// with tens of thousands of UDP sockets, takes many seconds.
func ListeningPorts() ([]int, error) {
	set := map[int]bool{}
	add := func(ep LocalEndpoint) {
		if ep.Port != 0 {
			set[ep.Port] = true
		}
	}
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		for _, q := range []struct {
			proto  uint8
			states uint32
		}{{unix.IPPROTO_TCP, 1 << tcpListen}, {unix.IPPROTO_UDP, 1 << tcpClose}} {
			if err := dumpSockets(family, q.proto, q.states, nil, add); err != nil && family == unix.AF_INET {
				return nil, err
			}
		}
	}
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out, nil
}

// PortListeners returns the local addresses that listen on a port: TCP
// listeners and unconnected UDP sockets, IPv4 and IPv6, filtered by the
// kernel. A socket bound to all addresses shows as "0.0.0.0" or "::".
func PortListeners(port int) ([]LocalEndpoint, error) {
	var out []LocalEndpoint
	bc := portFilter([]int{port})
	add := func(ep LocalEndpoint) {
		if ep.Port == port {
			out = append(out, ep)
		}
	}
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		for _, q := range []struct {
			proto  uint8
			states uint32
		}{{unix.IPPROTO_TCP, 1 << tcpListen}, {unix.IPPROTO_UDP, 1 << tcpClose}} {
			err := dumpSockets(family, q.proto, q.states, bc, add)
			if errors.Is(err, unix.EINVAL) {
				err = dumpSockets(family, q.proto, q.states, nil, add) // no filter support
			}
			if err != nil && family == unix.AF_INET {
				return nil, err
			}
		}
	}
	return out, nil
}

// TCPSocket is a TCP socket on a local port, as sock_diag lists it.
type TCPSocket struct {
	Local     LocalEndpoint
	Listening bool
	State     int    // the kernel's TCP state: 1 established, 6 time-wait, 10 listen...
	Inode     uint32 // 0 for a socket no program has any more (time-wait)
	family    uint8
	id        [48]byte // inet_diag_sockid, which names it to SOCK_DESTROY
}

// PortTCPSockets lists the TCP sockets whose local port is port, IPv4 and
// IPv6: listeners and connections in every state, time-wait included. A
// socket only bound to the port is left out: to list those, a kernel from
// 6.7 on walks every bound socket with its bucket locked and softirqs off,
// and a listener's bucket holds all the connections it accepted, so a busy
// inbound's new connections would stall meanwhile. An IPv6 socket on an
// IPv4 connection shows its v4-mapped address as IPv4.
func PortTCPSockets(port int) ([]TCPSocket, error) {
	return portTCPSockets(port, ^uint32(0)&^(1<<tcpBoundInactive))
}

// PortTCPListeners lists the TCP listeners on port, as PortTCPSockets
// does. The kernel reads only its table of listeners, not the connections.
func PortTCPListeners(port int) ([]TCPSocket, error) {
	return portTCPSockets(port, 1<<tcpListen)
}

func portTCPSockets(port int, states uint32) ([]TCPSocket, error) {
	var out []TCPSocket
	bc := portFilter([]int{port})
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		var got []TCPSocket
		add := func(msg []byte) {
			// inet_diag_msg: family, state, timer, retrans, id[48], expires,
			// rqueue, wqueue, uid, inode
			if len(msg) < 72 {
				return
			}
			s := TCPSocket{
				Local:     msgLocal(msg),
				Listening: msg[1] == tcpListen,
				State:     int(msg[1]),
				Inode:     binary.NativeEndian.Uint32(msg[68:72]),
				family:    msg[0],
			}
			copy(s.id[:], msg[4:52])
			if s.Local.Port == port {
				got = append(got, s)
			}
		}
		err := dumpDiag(family, unix.IPPROTO_TCP, states, bc, add)
		if errors.Is(err, unix.EINVAL) {
			got = nil
			err = dumpDiag(family, unix.IPPROTO_TCP, states, nil, add) // no filter support
		}
		if err != nil {
			if family == unix.AF_INET6 {
				continue // IPv6 may be disabled
			}
			return nil, err
		}
		out = append(out, got...)
	}
	return out, nil
}

// sockDestroy is SOCK_DESTROY, which closes a socket from outside its program.
const sockDestroy = 21

// DestroyTCP closes s from outside its program, as "ss -K" does: the kernel
// aborts the connection, sends the peer a reset, and the program's next
// call on it fails with ECONNABORTED. A socket in time-wait is dropped. It
// needs CAP_NET_ADMIN and a kernel built with INET_DIAG_DESTROY. A socket
// gone meanwhile is not an error: the kernel finds s by its addresses and
// checks its cookie, so a new socket on the same addresses, a listener
// among them, is never taken for it.
func DestroyTCP(s TCPSocket) error {
	fd, err := diagSocket()
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	req := make([]byte, 16+56)
	binary.NativeEndian.PutUint32(req[0:], uint32(len(req)))
	binary.NativeEndian.PutUint16(req[4:], sockDestroy)
	binary.NativeEndian.PutUint16(req[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	binary.NativeEndian.PutUint32(req[8:], 1)
	req[16] = s.family
	req[17] = unix.IPPROTO_TCP
	binary.NativeEndian.PutUint32(req[20:], ^uint32(0))
	copy(req[24:], s.id[:])
	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if n < 20 || binary.NativeEndian.Uint16(buf[4:]) != unix.NLMSG_ERROR {
			return errors.New("sock_diag: unexpected answer to SOCK_DESTROY")
		}
		switch code := syscall.Errno(-int32(binary.NativeEndian.Uint32(buf[16:]))); code {
		case 0, unix.ENOENT:
			return nil
		default:
			return code
		}
	}
}

// Owner finds the program that has the socket open, by its inode in
// /proc/*/fd: its process id and name, or 0 and "" when none has or /proc
// cannot tell. It may read every descriptor of every process, several
// seconds on a server with a million connections, so it is for error
// messages.
func (s TCPSocket) Owner() (pid int, name string) {
	if s.Inode == 0 {
		return 0, ""
	}
	want := "socket:[" + strconv.FormatUint(uint64(s.Inode), 10) + "]"
	for _, id := range procsByFDs() {
		dir := "/proc/" + strconv.Itoa(id)
		if hasFD(dir+"/fd", want) {
			comm, _ := os.ReadFile(dir + "/comm")
			return id, strings.TrimSpace(string(comm))
		}
	}
	return 0, ""
}

// procsByFDs lists the processes, those with fewer open descriptors first.
// A socket in a server's way is mostly some small program's, and the cores
// hold nearly every descriptor on the host: theirs are read last. A kernel
// from 6.2 on gives the count as the size of /proc/PID/fd; an older one
// gives 0, and the order is /proc's.
func procsByFDs() []int {
	entries, _ := os.ReadDir("/proc")
	type proc struct {
		id  int
		fds int64
	}
	var procs []proc
	for _, e := range entries {
		id, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		p := proc{id: id}
		if fi, err := os.Stat("/proc/" + e.Name() + "/fd"); err == nil {
			p.fds = fi.Size()
		}
		procs = append(procs, p)
	}
	sort.SliceStable(procs, func(i, j int) bool { return procs[i].fds < procs[j].fds })
	ids := make([]int, len(procs))
	for i, p := range procs {
		ids[i] = p.id
	}
	return ids
}

// hasFD says whether a descriptor in dir links to target. Names are read in
// batches: a core has hundreds of thousands.
func hasFD(dir, target string) bool {
	f, err := os.Open(dir)
	if err != nil {
		return false
	}
	defer f.Close()
	for {
		names, err := f.Readdirnames(4096)
		for _, n := range names {
			if l, err := os.Readlink(dir + "/" + n); err == nil && l == target {
				return true
			}
		}
		if err != nil {
			return false
		}
	}
}

func dumpTCP(family uint8, bytecode []byte, fn func(LocalEndpoint)) error {
	return dumpSockets(family, unix.IPPROTO_TCP, 1<<tcpEstablished, bytecode, fn)
}

func dumpSockets(family, proto uint8, states uint32, bytecode []byte, fn func(LocalEndpoint)) error {
	return dumpDiag(family, proto, states, bytecode, func(msg []byte) {
		if len(msg) >= 24 {
			fn(msgLocal(msg))
		}
	})
}

// msgLocal reads the local address and port of an inet_diag_msg: family,
// state, timer, retrans, then inet_diag_sockid: sport, dport (big endian),
// src[16], ...
func msgLocal(msg []byte) LocalEndpoint {
	port := int(binary.BigEndian.Uint16(msg[4:6]))
	var ip net.IP
	if msg[0] == unix.AF_INET {
		ip = net.IP(append([]byte(nil), msg[8:12]...))
	} else {
		ip = net.IP(append([]byte(nil), msg[8:24]...))
	}
	return LocalEndpoint{IP: normIP(ip), Port: port}
}

func diagSocket() (int, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return -1, err
	}
	tv := unix.NsecToTimeval(int64(10 * time.Second))
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 4<<20)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// dumpDiag calls fn with each inet_diag_msg of a sock_diag dump.
func dumpDiag(family, proto uint8, states uint32, bytecode []byte, fn func(msg []byte)) error {
	fd, err := diagSocket()
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	// nlmsghdr + inet_diag_req_v2 (+ bytecode attribute)
	req := make([]byte, 16+56)
	req[16] = family
	req[17] = proto
	binary.NativeEndian.PutUint32(req[20:], states)
	if len(bytecode) > 0 {
		attr := make([]byte, 4+len(bytecode))
		binary.NativeEndian.PutUint16(attr[0:], uint16(len(attr)))
		binary.NativeEndian.PutUint16(attr[2:], inetDiagReqBC)
		copy(attr[4:], bytecode)
		req = append(req, attr...)
		for len(req)%4 != 0 {
			req = append(req, 0)
		}
	}
	binary.NativeEndian.PutUint32(req[0:], uint32(len(req)))
	binary.NativeEndian.PutUint16(req[4:], sockDiagByFamily)
	binary.NativeEndian.PutUint16(req[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(req[8:], 1)
	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}

	buf := make([]byte, 1<<20)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return err
		}
		b := buf[:n]
		for len(b) >= 16 {
			l := int(binary.NativeEndian.Uint32(b[0:]))
			typ := binary.NativeEndian.Uint16(b[4:])
			if l < 16 || l > len(b) {
				return errors.New("sock_diag: truncated message")
			}
			switch typ {
			case unix.NLMSG_DONE:
				return nil
			case unix.NLMSG_ERROR:
				if l >= 20 {
					if code := int32(binary.NativeEndian.Uint32(b[16:])); code != 0 {
						return syscall.Errno(-code)
					}
				}
				return nil
			}
			fn(b[16:l])
			adv := (l + 3) &^ 3
			if adv > len(b) {
				break
			}
			b = b[adv:]
		}
	}
}

func normIP(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// sockstatCounts reads "inuse" and "tw" for a protocol from sockstat files.
func sockstatCounts() (tcp, udp int, err error) {
	read := func(path string) (map[string]map[string]int, error) {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		out := map[string]map[string]int{}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			proto, rest, ok := strings.Cut(sc.Text(), ":")
			if !ok {
				continue
			}
			fields := strings.Fields(rest)
			m := map[string]int{}
			for i := 0; i+1 < len(fields); i += 2 {
				n, err := strconv.Atoi(fields[i+1])
				if err == nil {
					m[fields[i]] = n
				}
			}
			out[proto] = m
		}
		return out, sc.Err()
	}
	root := HostProc()
	v4, err := read(root + "/net/sockstat")
	if err != nil {
		return 0, 0, err
	}
	tcpStat, ok1 := v4["TCP"]
	udpStat, ok2 := v4["UDP"]
	if !ok1 || !ok2 {
		return 0, 0, fmt.Errorf("unexpected %s/net/sockstat", root)
	}
	tcp = tcpStat["inuse"] + tcpStat["tw"]
	udp = udpStat["inuse"]
	if v6, err := read(root + "/net/sockstat6"); err == nil {
		tcp += v6["TCP6"]["inuse"]
		udp += v6["UDP6"]["inuse"]
	}
	return tcp, udp, nil
}
