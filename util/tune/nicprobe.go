//go:build linux

package tune

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v2/util/hw"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// sysProber reaches the gateway for real: an ICMP echo on a raw socket
// bound to the route's device, or, when the gateway does not answer echo,
// its neighbour entry. That probe first deletes the entry (unless it is a
// static one), then one datagram to the gateway's discard port makes the
// kernel resolve it again: only an answer after the probe started makes it
// reachable. (An entry left from before a queue change says nothing: the
// kernel flushes neighbours only on a carrier drop that link watch sees,
// and many drivers turn the carrier back on within the change.)
type sysProber struct{}

func (sysProber) Pick(routes []hw.Route, deadline time.Time) string {
	for {
		for _, kind := range []string{"icmp", "neigh"} {
			for _, rt := range routes {
				if rt.Gateway == nil {
					continue
				}
				p := fmt.Sprintf("%s %s %s", kind, rt.Dev, rt.Gateway)
				if probeOnce(p, min(3*time.Second, max(time.Until(deadline), time.Second))) == nil {
					return p
				}
			}
		}
		if !time.Now().Before(deadline) {
			return ""
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func (sysProber) Reach(probe string, deadline time.Time) bool {
	for {
		if probeOnce(probe, min(2*time.Second, max(time.Until(deadline), 200*time.Millisecond))) == nil {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(pollEvery)
	}
}

// probeOnce runs "icmp|neigh <dev> <gateway>" once.
func probeOnce(probe string, timeout time.Duration) error {
	f := strings.Fields(probe)
	if len(f) != 3 {
		return errors.New("bad probe")
	}
	gw := net.ParseIP(f[2])
	if gw == nil {
		return errors.New("bad gateway")
	}
	if f[0] == "neigh" {
		return neighReach(f[1], gw, timeout)
	}
	return icmpEcho(f[1], gw, timeout)
}

func sockaddr(dev string, ip net.IP, port int) (unix.Sockaddr, int) {
	if v4 := ip.To4(); v4 != nil {
		sa := &unix.SockaddrInet4{Port: port}
		copy(sa.Addr[:], v4)
		return sa, unix.AF_INET
	}
	sa := &unix.SockaddrInet6{Port: port}
	copy(sa.Addr[:], ip.To16())
	if ip.IsLinkLocalUnicast() {
		if ifi, err := net.InterfaceByName(dev); err == nil {
			sa.ZoneId = uint32(ifi.Index)
		}
	}
	return sa, unix.AF_INET6
}

func icmpChecksum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

// icmpEcho pings the gateway once through the device.
func icmpEcho(dev string, gw net.IP, timeout time.Duration) error {
	sa, fam := sockaddr(dev, gw, 0)
	proto, echo, reply := unix.IPPROTO_ICMP, byte(8), byte(0)
	if fam == unix.AF_INET6 {
		proto, echo, reply = unix.IPPROTO_ICMPV6, 128, 129
	}
	fd, err := unix.Socket(fam, unix.SOCK_RAW|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, dev); err != nil {
		return err
	}
	id, seq := uint16(os.Getpid()), uint16(time.Now().UnixNano()>>10)
	msg := []byte{echo, 0, 0, 0, byte(id >> 8), byte(id), byte(seq >> 8), byte(seq), 'x', '-', 'u', 'i'}
	if fam == unix.AF_INET {
		cs := icmpChecksum(msg)
		msg[2], msg[3] = byte(cs>>8), byte(cs)
	} // the kernel fills ICMPv6's
	if err := unix.Sendto(fd, msg, 0, sa); err != nil {
		return err
	}
	end := time.Now().Add(timeout)
	buf := make([]byte, 2048)
	for {
		left := time.Until(end)
		if left <= 0 {
			return errors.New("no echo reply")
		}
		tv := unix.NsecToTimeval(left.Nanoseconds())
		_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
		n, from, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		b := buf[:n]
		if fam == unix.AF_INET {
			if n < 1 {
				continue
			}
			ihl := int(b[0]&0x0f) * 4
			if n < ihl+8 {
				continue
			}
			b = b[ihl:]
		}
		if len(b) < 8 || b[0] != reply || uint16(b[4])<<8|uint16(b[5]) != id || uint16(b[6])<<8|uint16(b[7]) != seq {
			continue
		}
		switch a := from.(type) {
		case *unix.SockaddrInet4:
			if net.IP(a.Addr[:]).Equal(gw) {
				return nil
			}
		case *unix.SockaddrInet6:
			if net.IP(a.Addr[:]).Equal(gw) {
				return nil
			}
		}
	}
}

// neighReach forgets the gateway's neighbour entry, makes the kernel
// resolve it again and waits for the entry to be reachable.
func neighReach(dev string, gw net.IP, timeout time.Duration) error {
	link, err := netlink.LinkByName(dev)
	if err != nil {
		return err
	}
	sa, fam := sockaddr(dev, gw, 9)
	family := netlink.FAMILY_V4
	if fam == unix.AF_INET6 {
		family = netlink.FAMILY_V6
	}
	if err := neighForget(link.Attrs().Index, family, gw); err != nil {
		return err
	}
	fd, err := unix.Socket(fam, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, dev); err != nil {
		return err
	}
	_ = unix.Sendto(fd, []byte("x-ui"), unix.MSG_DONTWAIT, sa)
	end := time.Now().Add(timeout)
	for {
		neighs, err := netlink.NeighList(link.Attrs().Index, family)
		if err != nil {
			return err
		}
		for _, n := range neighs {
			if n.IP.Equal(gw) && n.State&netlink.NUD_REACHABLE != 0 {
				return nil
			}
		}
		if !time.Now().Before(end) {
			return errors.New("the gateway's neighbour entry is not reachable")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// neighForget deletes the gateway's neighbour entry, so that only a fresh
// answer makes it reachable. A static (permanent or no-ARP) entry is kept:
// it is never reachable, so the probe fails on it as it should.
func neighForget(index, family int, gw net.IP) error {
	neighs, err := netlink.NeighList(index, family)
	if err != nil {
		return err
	}
	for _, n := range neighs {
		if !n.IP.Equal(gw) || n.State&(netlink.NUD_PERMANENT|netlink.NUD_NOARP) != 0 {
			continue
		}
		if err := netlink.NeighDel(&n); err != nil && !errors.Is(err, unix.ENOENT) {
			return err
		}
	}
	return nil
}
