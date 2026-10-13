package sys

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// UDPPortUse is how much of the local port range UDP sockets hold.
type UDPPortUse struct {
	Pool   int            // ports a socket can be given
	Wild   int            // held by sockets on all addresses
	ByIP   map[string]int // held in each address's share: its own sockets plus the wildcard ones
	Shared int            // held in the default address's share: by any socket
}

// Used returns the ports held in the share a core sending from egress draws
// on ("" is the host's default address).
func (u *UDPPortUse) Used(egress string) int {
	if egress == "" {
		return u.Shared
	}
	if n, ok := u.ByIP[egress]; ok {
		return n
	}
	return u.Wild
}

const (
	localPortRangeFile = "/proc/sys/net/ipv4/ip_local_port_range"
	reservedPortsFile  = "/proc/sys/net/ipv4/ip_local_reserved_ports"
)

// ReadUDPPortUse counts the ports of the local port range that the UDP
// sockets list gives hold, per local address.
func ReadUDPPortUse(list func(func(LocalEndpoint)) error) (*UDPPortUse, error) {
	return ReadUDPPortUseAt("", list)
}

// ReadUDPPortUseAt is ReadUDPPortUse with the port range read below root
// ("" is the real system; tests use a fake tree).
func ReadUDPPortUseAt(root string, list func(func(LocalEndpoint)) error) (*UDPPortUse, error) {
	lo, hi, err := localPortRange(filepath.Join(root, localPortRangeFile))
	if err != nil {
		return nil, err
	}
	var reserved map[int]bool
	if b, err := os.ReadFile(filepath.Join(root, reservedPortsFile)); err == nil {
		reserved = parsePorts(string(b))
	}
	pool := 0
	for p := lo; p <= hi; p++ {
		if !reserved[p] {
			pool++
		}
	}
	wild := map[int]bool{}
	all := map[int]bool{}
	byIP := map[string]map[int]bool{}
	err = list(func(ep LocalEndpoint) {
		if ep.Port < lo || ep.Port > hi || reserved[ep.Port] {
			return // not taken from the range
		}
		all[ep.Port] = true
		if ep.IP == "" {
			wild[ep.Port] = true
			return
		}
		m := byIP[ep.IP]
		if m == nil {
			m = map[int]bool{}
			byIP[ep.IP] = m
		}
		m[ep.Port] = true
	})
	if err != nil {
		return nil, err
	}
	u := &UDPPortUse{Pool: pool, Wild: len(wild), Shared: len(all), ByIP: map[string]int{}}
	for ip, ports := range byIP {
		n := len(wild)
		for p := range ports {
			if !wild[p] {
				n++
			}
		}
		u.ByIP[ip] = n
	}
	return u, nil
}

func localPortRange(path string) (int, int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, err
	}
	f := strings.Fields(string(b))
	if len(f) != 2 {
		return 0, 0, errors.New("unexpected ip_local_port_range")
	}
	lo, err1 := strconv.Atoi(f[0])
	hi, err2 := strconv.Atoi(f[1])
	if err1 != nil || err2 != nil || lo < 1 || hi < lo {
		return 0, 0, errors.New("unexpected ip_local_port_range")
	}
	return lo, hi, nil
}

// parsePorts reads a port list ("1,3-5,8") into a set; bad parts are
// skipped.
func parsePorts(s string) map[int]bool {
	out := map[int]bool{}
	for _, part := range strings.Split(strings.TrimSpace(s), ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		a, b, isRange := strings.Cut(part, "-")
		lo, err1 := strconv.Atoi(a)
		hi := lo
		var err2 error
		if isRange {
			hi, err2 = strconv.Atoi(b)
		}
		if err1 != nil || err2 != nil || lo < 1 || hi > 65535 || lo > hi {
			continue
		}
		for p := lo; p <= hi; p++ {
			out[p] = true
		}
	}
	return out
}
