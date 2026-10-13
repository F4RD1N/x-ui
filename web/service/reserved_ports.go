package service

// Inbound ports are kept out of the kernel's ephemeral range.
//
// A busy core opens hundreds of thousands of outgoing connections, and the
// kernel hands their local ports out of net.ipv4.ip_local_port_range --
// often all of 1024-65535. A connection can then sit on an inbound's port
// number, and the next time that core starts it cannot listen there
// ("address already in use"). Listing the inbound ports in
// ip_local_reserved_ports stops that. Other reservations on the machine are
// kept: the panel only adds and removes its own, which it remembers in a
// file next to the database.

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/logger"
)

var (
	reservedPortsPath = "/proc/sys/net/ipv4/ip_local_reserved_ports"
	reservedMu        sync.Mutex
)

func reservedStatePath() string {
	return filepath.Join(config.GetDBFolderPath(), "reserved-ports")
}

// parsePortList reads "1,3-5,8" into a set.
func parsePortList(s string) map[int]bool {
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

// formatPortList writes a set as "1,3-5,8".
func formatPortList(set map[int]bool) string {
	ports := make([]int, 0, len(set))
	for p := range set {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	var parts []string
	for i := 0; i < len(ports); {
		j := i
		for j+1 < len(ports) && ports[j+1] == ports[j]+1 {
			j++
		}
		if i == j {
			parts = append(parts, strconv.Itoa(ports[i]))
		} else {
			parts = append(parts, strconv.Itoa(ports[i])+"-"+strconv.Itoa(ports[j]))
		}
		i = j + 1
	}
	return strings.Join(parts, ",")
}

// mergeReserved replaces the panel's old reservations in current with the
// ports it wants now, leaving everyone else's, and returns the result with
// the ports that are now the panel's own: those it reserved itself. A port
// someone else had reserved before the panel wanted it stays theirs, and
// stays reserved once the panel no longer needs it. A port of the panel's
// that someone else removed is reserved again.
func mergeReserved(current, oldOurs, want map[int]bool) (merged, ours map[int]bool) {
	merged, ours = map[int]bool{}, map[int]bool{}
	for p := range current {
		if !oldOurs[p] || want[p] {
			merged[p] = true
		}
	}
	for p := range want {
		if p < 1 || p > 65535 {
			continue
		}
		if oldOurs[p] || !current[p] {
			ours[p] = true
		}
		merged[p] = true
	}
	return merged, ours
}

// syncReservedPorts makes ports the panel's reservations. It reads the
// kernel's list every time: another program may have changed it.
func syncReservedPorts(ports map[int]bool) {
	reservedMu.Lock()
	defer reservedMu.Unlock()
	cur, err := os.ReadFile(reservedPortsPath)
	if err != nil {
		return // not Linux, or no such sysctl
	}
	old, _ := os.ReadFile(reservedStatePath())
	merged, ours := mergeReserved(parsePortList(string(cur)), parsePortList(string(old)), ports)
	if m := formatPortList(merged); m != strings.TrimSpace(string(cur)) {
		if err := os.WriteFile(reservedPortsPath, []byte(m+"\n"), 0o644); err != nil {
			logger.Warning("reserve inbound ports in ip_local_reserved_ports:", err)
			return
		}
	}
	if o := formatPortList(ours); o != strings.TrimSpace(string(old)) {
		if err := os.WriteFile(reservedStatePath(), []byte(o+"\n"), 0o600); err != nil {
			logger.Warning("remember the reserved inbound ports:", err)
		}
	}
}
