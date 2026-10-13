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

func dumpTCP(family uint8, bytecode []byte, fn func(LocalEndpoint)) error {
	return dumpSockets(family, unix.IPPROTO_TCP, 1<<tcpEstablished, bytecode, fn)
}

func dumpSockets(family, proto uint8, states uint32, bytecode []byte, fn func(LocalEndpoint)) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	tv := unix.NsecToTimeval(int64(10 * time.Second))
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 4<<20)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}

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
			msg := b[16:l]
			// inet_diag_msg: family, state, timer, retrans, then
			// inet_diag_sockid: sport, dport (big endian), src[16], ...
			if len(msg) >= 24 {
				port := int(binary.BigEndian.Uint16(msg[4:6]))
				var ip net.IP
				if msg[0] == unix.AF_INET {
					ip = net.IP(append([]byte(nil), msg[8:12]...))
				} else {
					ip = net.IP(append([]byte(nil), msg[8:24]...))
				}
				fn(LocalEndpoint{IP: normIP(ip), Port: port})
			}
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
