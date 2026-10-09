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

// echoRawRcvBuf is the receive buffer asked for a shared raw socket, which
// takes the replies of every flow sharing it.
const echoRawRcvBuf = 1 << 21

// echoConn is one flow's ICMP endpoint of one family.
//
// A datagram socket is the flow's own. The kernel gives it an identifier,
// rewrites it on the way out and delivers to the socket only the replies
// carrying it.
//
// A raw socket is handed a copy of every ICMP message the host receives that
// its filter does not reject, so every raw socket costs the kernel work on
// such packets, whoever sends them. Flows therefore never open raw sockets
// of their own: the flows of one family and one set of socket settings share
// one (echoSocket), however many flows there are. Each flow holds an
// identifier no other flow of this process holds, and the socket's reader
// hands each reply to the flow holding its identifier. The socket is given
// echo replies only, and a flow's source address (sendThrough) goes with each
// echo it sends rather than in a bind.
type echoConn struct {
	ipv6   bool
	wireID uint16 // raw: the identifier on the wire; datagram: 0, the kernel's
	oob    []byte // raw: the source address as IP_PKTINFO / IPV6_PKTINFO
	sock   *echoSocket
	closed bool // raw: guarded by rawEchoSockets.mu
}

// echoSocket is an ICMP socket: a flow's own datagram socket, or a raw
// socket shared by flows.
type echoSocket struct {
	ipv6 bool
	raw  bool
	file *os.File
	rc   syscall.RawConn

	// Shared raw sockets only, guarded by rawEchoSockets.mu.
	key   rawEchoKey
	flows map[uint16]func(peer net.IP, msg []byte)
}

// rawEchoKey tells apart the raw sockets flows cannot share: the family, and
// the outbound's socket settings (mark, interface, ...), which belong to one
// outbound.
type rawEchoKey struct {
	ipv6    bool
	sockopt *internet.SocketConfig
}

// rawEchoSockets holds this process's shared raw sockets. A socket is opened
// for the first flow that needs it and closed when its last flow leaves.
var rawEchoSockets struct {
	mu    sync.RWMutex
	socks map[rawEchoKey]*echoSocket
}

// openEchoConn opens the flow's endpoint of the family. deliver is called,
// from a reader of the socket, with every echo reply that may be the flow's;
// it must not block or keep msg.
func openEchoConn(ctx context.Context, ipv6 bool, bind net.IP, sockopt *internet.SocketConfig, deliver func(peer net.IP, msg []byte)) (*echoConn, error) {
	var errs []error
	for _, typ := range echoSocketTypes {
		var c *echoConn
		var err error
		if typ == unix.SOCK_RAW {
			c, err = joinRawEchoSocket(ctx, ipv6, bind, sockopt, deliver)
		} else {
			c, err = openDatagramEchoConn(ctx, ipv6, bind, sockopt, deliver)
		}
		if err == nil {
			return c, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.New("no ICMP socket could be opened").Base(errors.Combine(errs...))
}

func openDatagramEchoConn(ctx context.Context, ipv6 bool, bind net.IP, sockopt *internet.SocketConfig, deliver func(net.IP, []byte)) (*echoConn, error) {
	s, err := newEchoSocket(ctx, ipv6, unix.SOCK_DGRAM, sockopt)
	if err != nil {
		return nil, err
	}
	if bind != nil {
		var berr error
		err := s.rc.Control(func(fd uintptr) {
			berr = unix.Bind(int(fd), echoSockaddr(bind, ipv6))
		})
		if err == nil {
			err = berr
		}
		if err != nil {
			s.file.Close()
			return nil, errors.New("failed to bind the ICMP socket to ", bind).Base(err)
		}
	}
	go s.readLoop(deliver)
	return &echoConn{ipv6: ipv6, sock: s}, nil
}

// joinRawEchoSocket gives the flow an identifier on the shared raw socket
// for the family and sockopt, opening the socket if no flow holds it.
func joinRawEchoSocket(ctx context.Context, ipv6 bool, bind net.IP, sockopt *internet.SocketConfig, deliver func(net.IP, []byte)) (*echoConn, error) {
	c := &echoConn{ipv6: ipv6}
	if bind != nil {
		c.oob = echoPktinfo(bind, ipv6)
	}
	key := rawEchoKey{ipv6: ipv6, sockopt: sockopt}
	r := &rawEchoSockets
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.socks[key]
	if s == nil {
		var err error
		if s, err = newEchoSocket(ctx, ipv6, unix.SOCK_RAW, sockopt); err != nil {
			return nil, err
		}
		s.key = key
		s.flows = make(map[uint16]func(net.IP, []byte))
		if r.socks == nil {
			r.socks = make(map[rawEchoKey]*echoSocket)
		}
		r.socks[key] = s
		go s.readLoop(s.dispatch)
	}
	id, ok := rawEchoIDs.alloc(ipv6)
	if !ok {
		if len(s.flows) == 0 {
			delete(r.socks, key)
			s.file.Close()
		}
		return nil, errors.New("no free ICMP identifier")
	}
	s.flows[id] = deliver
	c.wireID = id
	c.sock = s
	return c, nil
}

func newEchoSocket(ctx context.Context, ipv6 bool, typ int, sockopt *internet.SocketConfig) (*echoSocket, error) {
	family, proto, network := unix.AF_INET, unix.IPPROTO_ICMP, "ip4:icmp"
	if ipv6 {
		family, proto, network = unix.AF_INET6, unix.IPPROTO_ICMPV6, "ip6:ipv6-icmp"
	}
	fd, err := unix.Socket(family, typ|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}
	s := &echoSocket{ipv6: ipv6, raw: typ == unix.SOCK_RAW}
	if s.raw {
		if err := filterEchoReplies(fd, ipv6); err != nil {
			unix.Close(fd)
			return nil, err
		}
		if unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, echoRawRcvBuf) != nil {
			unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, echoRawRcvBuf)
		}
	}
	// The descriptor is non-blocking, so the file is pollable: reads wait in
	// the runtime's poller and Close wakes them.
	s.file = os.NewFile(uintptr(fd), network)
	if s.rc, err = s.file.SyscallConn(); err != nil {
		s.file.Close()
		return nil, err
	}
	internet.ControlSocket(ctx, network, "", s.rc, sockopt)
	return s, nil
}

// filterEchoReplies makes a raw socket receive echo replies only.
// ICMP_FILTER / ICMPV6_FILTER reject every other type before the kernel
// copies a packet for the socket; a socket filter checks the type again. A
// raw IPv4 socket's packets start at the IP header; ICMPv6 ones at the
// ICMPv6 header.
func filterEchoReplies(fd int, ipv6 bool) error {
	var prog []bpf.Instruction
	if ipv6 {
		var f unix.ICMPv6Filter // a set bit blocks the type
		for i := range f.Data {
			f.Data[i] = ^uint32(0)
		}
		f.Data[icmpecho.TypeEchoReply6>>5] &^= 1 << (icmpecho.TypeEchoReply6 & 31)
		if err := unix.SetsockoptICMPv6Filter(fd, unix.IPPROTO_ICMPV6, unix.ICMPV6_FILTER, &f); err != nil {
			return os.NewSyscallError("setsockopt ICMPV6_FILTER", err)
		}
		prog = []bpf.Instruction{
			bpf.LoadAbsolute{Off: 0, Size: 1},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: icmpecho.TypeEchoReply6, SkipFalse: 1},
			bpf.RetConstant{Val: 0xffffffff},
			bpf.RetConstant{Val: 0},
		}
	} else {
		mask := ^uint32(1 << icmpecho.TypeEchoReply4) // a set bit blocks the type
		if err := unix.SetsockoptInt(fd, unix.SOL_RAW, unix.ICMP_FILTER, int(int32(mask))); err != nil {
			return os.NewSyscallError("setsockopt ICMP_FILTER", err)
		}
		prog = []bpf.Instruction{
			bpf.LoadMemShift{Off: 0}, // X = IP header length
			bpf.LoadIndirect{Off: 0, Size: 1},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: icmpecho.TypeEchoReply4, SkipFalse: 1},
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

// echoPktinfo is the control message that sends a datagram from src. The
// kernel refuses it, as it refuses a bind, when src is not of this host.
func echoPktinfo(src net.IP, ipv6 bool) []byte {
	if ipv6 {
		var info unix.Inet6Pktinfo
		copy(info.Addr[:], src.To16())
		return unix.PktInfo6(&info)
	}
	var info unix.Inet4Pktinfo
	copy(info.Spec_dst[:], src.To4())
	return unix.PktInfo4(&info)
}

// write sends one echo request message to ip. It never waits: an echo that
// does not fit the socket buffer is dropped.
func (c *echoConn) write(ip net.IP, msg []byte) error {
	sa := echoSockaddr(ip, c.ipv6)
	var serr error
	if err := c.sock.rc.Write(func(fd uintptr) bool {
		if c.oob != nil {
			_, serr = unix.SendmsgN(int(fd), msg, c.oob, sa, 0)
		} else {
			serr = unix.Sendto(int(fd), msg, 0, sa)
		}
		return true
	}); err != nil {
		return err
	}
	return os.NewSyscallError("sendto", serr)
}

// echoReadPool holds receive buffers. One is taken only once the socket is
// readable and returned once the reply is handled, so an idle socket holds
// none.
var echoReadPool = sync.Pool{New: func() any {
	b := make([]byte, 1<<16)
	return &b
}}

// readLoop hands each echo reply received to deliver, from the IP it came
// from, until the socket is closed. deliver must not keep msg.
func (s *echoSocket) readLoop(deliver func(peer net.IP, msg []byte)) {
	for {
		var (
			bp   *[]byte
			n    int
			from unix.Sockaddr
			rerr error
		)
		err := s.rc.Read(func(fd uintptr) bool {
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
			if peer, msg, ok := s.parse(from, (*bp)[:n]); ok {
				deliver(peer, msg)
			}
		}
		echoReadPool.Put(bp)
	}
}

// dispatch hands a reply read from a shared raw socket to the flow holding
// its identifier.
func (s *echoSocket) dispatch(peer net.IP, msg []byte) {
	id := binary.BigEndian.Uint16(msg[4:6])
	rawEchoSockets.mu.RLock()
	deliver := s.flows[id]
	rawEchoSockets.mu.RUnlock()
	if deliver != nil {
		deliver(peer, msg)
	}
}

// parse returns the sender and the ICMP message of a received packet, or
// false for anything that cannot be an echo reply.
func (s *echoSocket) parse(from unix.Sockaddr, b []byte) (net.IP, []byte, bool) {
	var peer net.IP
	switch sa := from.(type) {
	case *unix.SockaddrInet4:
		peer = net.IP(append([]byte(nil), sa.Addr[:]...))
	case *unix.SockaddrInet6:
		peer = net.IP(append([]byte(nil), sa.Addr[:]...))
	default:
		return nil, nil, false
	}
	if s.raw && !s.ipv6 {
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
	if len(b) < icmpecho.HeaderLen {
		return nil, nil, false
	}
	return peer, b, true
}

// Close closes a datagram socket, or gives up the flow's identifier on a
// shared raw socket and closes the socket when no flow holds it any more.
// Its reader ends with the socket.
func (c *echoConn) Close() error {
	s := c.sock
	if !s.raw {
		return s.file.Close()
	}
	r := &rawEchoSockets
	r.mu.Lock()
	defer r.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	delete(s.flows, c.wireID)
	rawEchoIDs.release(c.ipv6, c.wireID)
	if len(s.flows) == 0 && r.socks[s.key] == s {
		delete(r.socks, s.key)
		return s.file.Close()
	}
	return nil
}

// echoIDs hands out the identifiers of this process's raw echo flows, one
// per flow and family, so that no two flows can take each other's replies.
// maxEchoFlows keeps all but a few of them free.
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
