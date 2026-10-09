//go:build linux

package freedom

import (
	"context"
	"encoding/binary"
	"os"
	"sync"
	"syscall"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/icmpecho"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

// echoSocketTypes are tried in order: the ICMP datagram socket, which the
// kernel demultiplexes by identifier itself and which needs no privilege
// where net.ipv4.ping_group_range admits the process's group; then a raw
// socket (root or CAP_NET_RAW). Tests narrow it to one.
var echoSocketTypes = []int{unix.SOCK_DGRAM, unix.SOCK_RAW}

// echoConn is one flow's ICMP socket of one family.
//
// A datagram socket gets an identifier from the kernel, which rewrites it
// on the way out and delivers to the socket only the replies carrying it. A
// raw socket sees every ICMP message the host receives, so each one is given
// an identifier no other raw echo socket of this process holds, and a socket
// filter passes it only echo replies carrying that identifier.
type echoConn struct {
	ipv6   bool
	raw    bool
	wireID uint16 // raw: the identifier on the wire; datagram: 0, the kernel's
	file   *os.File
	rc     syscall.RawConn
}

func openEchoConn(ctx context.Context, ipv6 bool, bind net.IP, sockopt *internet.SocketConfig) (*echoConn, error) {
	var errs []error
	for _, typ := range echoSocketTypes {
		c, err := newEchoConn(ctx, ipv6, typ, bind, sockopt)
		if err == nil {
			return c, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.New("no ICMP socket could be opened").Base(errors.Combine(errs...))
}

func newEchoConn(ctx context.Context, ipv6 bool, typ int, bind net.IP, sockopt *internet.SocketConfig) (*echoConn, error) {
	family, proto, network := unix.AF_INET, unix.IPPROTO_ICMP, "ip4:icmp"
	if ipv6 {
		family, proto, network = unix.AF_INET6, unix.IPPROTO_ICMPV6, "ip6:ipv6-icmp"
	}
	fd, err := unix.Socket(family, typ|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}
	c := &echoConn{ipv6: ipv6, raw: typ == unix.SOCK_RAW}
	if c.raw {
		id, ok := rawEchoIDs.alloc(ipv6)
		if !ok {
			unix.Close(fd)
			return nil, errors.New("no free ICMP identifier")
		}
		c.wireID = id
		if err := attachEchoFilter(fd, ipv6, id); err != nil {
			rawEchoIDs.release(ipv6, id)
			unix.Close(fd)
			return nil, err
		}
	}
	// The descriptor is non-blocking, so the file is pollable: reads wait in
	// the runtime's poller and Close wakes them.
	c.file = os.NewFile(uintptr(fd), network)
	if c.rc, err = c.file.SyscallConn(); err != nil {
		c.Close()
		return nil, err
	}
	internet.ControlSocket(ctx, network, "", c.rc, sockopt)
	if bind != nil {
		var berr error
		if err := c.rc.Control(func(fd uintptr) {
			berr = unix.Bind(int(fd), echoSockaddr(bind, ipv6))
		}); err == nil {
			err = berr
		}
		if err != nil {
			c.Close()
			return nil, errors.New("failed to bind the ICMP socket to ", bind).Base(err)
		}
	}
	return c, nil
}

// attachEchoFilter makes a raw socket receive only echo replies carrying id.
// A raw IPv4 socket's packets start at the IP header; ICMPv6 ones at the
// ICMPv6 header.
func attachEchoFilter(fd int, ipv6 bool, id uint16) error {
	var prog []bpf.Instruction
	if ipv6 {
		prog = []bpf.Instruction{
			bpf.LoadAbsolute{Off: 0, Size: 1},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: icmpecho.TypeEchoReply6, SkipFalse: 3},
			bpf.LoadAbsolute{Off: 4, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(id), SkipFalse: 1},
			bpf.RetConstant{Val: 0xffffffff},
			bpf.RetConstant{Val: 0},
		}
	} else {
		prog = []bpf.Instruction{
			bpf.LoadMemShift{Off: 0}, // X = IP header length
			bpf.LoadIndirect{Off: 0, Size: 1},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: icmpecho.TypeEchoReply4, SkipFalse: 3},
			bpf.LoadIndirect{Off: 4, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(id), SkipFalse: 1},
			bpf.RetConstant{Val: 0xffffffff},
			bpf.RetConstant{Val: 0},
		}
	}
	raw, err := bpf.Assemble(prog)
	if err != nil {
		return err
	}
	filter := make([]unix.SockFilter, len(raw))
	for i, ins := range raw {
		filter[i] = unix.SockFilter{Code: ins.Op, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
	}
	err = unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	})
	return os.NewSyscallError("setsockopt SO_ATTACH_FILTER", err)
}

func echoSockaddr(ip net.IP, ipv6 bool) unix.Sockaddr {
	if ipv6 {
		sa := &unix.SockaddrInet6{}
		copy(sa.Addr[:], ip.To16())
		return sa
	}
	sa := &unix.SockaddrInet4{}
	copy(sa.Addr[:], ip.To4())
	return sa
}

// write sends one echo request message to ip. It never waits: an echo that
// does not fit the socket buffer is dropped.
func (c *echoConn) write(ip net.IP, msg []byte) error {
	sa := echoSockaddr(ip, c.ipv6)
	var serr error
	if err := c.rc.Write(func(fd uintptr) bool {
		serr = unix.Sendto(int(fd), msg, 0, sa)
		return true
	}); err != nil {
		return err
	}
	return os.NewSyscallError("sendto", serr)
}

// echoReadPool holds receive buffers. One is taken only once the socket is
// readable and returned once the reply is handled, so an idle flow holds
// none.
var echoReadPool = sync.Pool{New: func() any {
	b := make([]byte, 1<<16)
	return &b
}}

// readLoop hands each ICMP message received to deliver, from the IP it came
// from, until the socket is closed. deliver must not keep msg.
func (c *echoConn) readLoop(deliver func(peer net.IP, msg []byte)) {
	for {
		var (
			bp   *[]byte
			n    int
			from unix.Sockaddr
			rerr error
		)
		err := c.rc.Read(func(fd uintptr) bool {
			bp = echoReadPool.Get().(*[]byte)
			for {
				n, from, rerr = unix.Recvfrom(int(fd), *bp, 0)
				if rerr != unix.EINTR {
					break
				}
			}
			if rerr == unix.EAGAIN {
				echoReadPool.Put(bp)
				bp = nil
				return false
			}
			return true
		})
		if err != nil {
			if bp != nil {
				echoReadPool.Put(bp)
			}
			return
		}
		if rerr == nil {
			if peer, msg, ok := c.parse(from, (*bp)[:n]); ok {
				deliver(peer, msg)
			}
		}
		echoReadPool.Put(bp)
	}
}

// parse returns the sender and the ICMP message of a received packet, or
// false for anything that is not an echo reply meant for this socket.
func (c *echoConn) parse(from unix.Sockaddr, b []byte) (net.IP, []byte, bool) {
	var peer net.IP
	switch sa := from.(type) {
	case *unix.SockaddrInet4:
		peer = net.IP(append([]byte(nil), sa.Addr[:]...))
	case *unix.SockaddrInet6:
		peer = net.IP(append([]byte(nil), sa.Addr[:]...))
	default:
		return nil, nil, false
	}
	if !c.raw {
		return peer, b, true
	}
	if !c.ipv6 {
		// A raw IPv4 socket receives the IP header, and its ICMP checksum is
		// not verified by the kernel.
		if len(b) < 20 || b[0]>>4 != 4 {
			return nil, nil, false
		}
		ihl := int(b[0]&0x0f) * 4
		if total := int(binary.BigEndian.Uint16(b[2:4])); total < len(b) {
			b = b[:total]
		}
		if ihl < 20 || len(b) < ihl+icmpecho.HeaderLen {
			return nil, nil, false
		}
		b = b[ihl:]
		if icmpecho.Checksum(b) != 0 {
			return nil, nil, false
		}
	}
	if len(b) < icmpecho.HeaderLen || binary.BigEndian.Uint16(b[4:6]) != c.wireID {
		return nil, nil, false
	}
	return peer, b, true
}

func (c *echoConn) Close() error {
	if c.raw {
		rawEchoIDs.release(c.ipv6, c.wireID)
	}
	if c.file == nil {
		return nil
	}
	return c.file.Close()
}

// echoIDs hands out the identifiers of this process's raw echo sockets, one
// per socket and family, so that no two flows can take each other's replies.
type echoIDs struct {
	mu   sync.Mutex
	used [2]map[uint16]struct{}
}

var rawEchoIDs echoIDs

func (r *echoIDs) alloc(ipv6 bool) (uint16, bool) {
	i := 0
	if ipv6 {
		i = 1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.used[i] == nil {
		r.used[i] = make(map[uint16]struct{})
	}
	start := uint16(dice.Roll(1 << 16))
	for k := 0; k < 1<<16; k++ {
		id := start + uint16(k)
		if _, ok := r.used[i][id]; !ok {
			r.used[i][id] = struct{}{}
			return id, true
		}
	}
	return 0, false
}

func (r *echoIDs) release(ipv6 bool, id uint16) {
	i := 0
	if ipv6 {
		i = 1
	}
	r.mu.Lock()
	delete(r.used[i], id)
	r.mu.Unlock()
}
