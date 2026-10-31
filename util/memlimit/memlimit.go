// Package memlimit sizes the Go memory limit (GOMEMLIMIT) of the panel and of
// its Xray core from the memory the server has right now.
//
// The limit is worked out again every time the panel or the core starts, so at
// every boot, and is never written anywhere. A server made from a snapshot of
// a smaller one, or resized, gets the limit for the memory it boots with. A
// GOMEMLIMIT in the service's environment is not used: one left over from a
// 1 GB server (449MiB) kept the core of a 24 GB server collecting garbage with
// most of its CPU. To give x-ui less memory, set MemoryMax= in a drop-in
// ("systemctl edit x-ui"; updates rewrite x-ui.service itself): the limit
// follows it.
package memlimit

import (
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
)

const MiB = 1 << 20

// Facts is what the limit is worked out from, in bytes.
type Facts struct {
	MemTotal  int64 // MemTotal in /proc/meminfo; 0 when unknown
	Cgroup    int64 // the smallest memory limit over this process's cgroups; 0 when none
	TCPMemMax int64 // net.ipv4.tcp_mem's ceiling; 0 when not visible (a container's own network namespace)
}

// Usable is the memory x-ui can count on: MemTotal, or a smaller cgroup limit.
func (f Facts) Usable() int64 {
	if f.Cgroup > 0 && (f.MemTotal == 0 || f.Cgroup < f.MemTotal) {
		return f.Cgroup
	}
	return f.MemTotal
}

func (f Facts) String() string {
	gib := func(n int64) string { return strconv.FormatFloat(float64(n)/(1<<30), 'f', 1, 64) + " GiB" }
	if f.Usable() < f.MemTotal {
		return "memory limit " + gib(f.Usable()) + " of " + gib(f.MemTotal) + " RAM"
	}
	return gib(f.MemTotal) + " RAM"
}

// Limit is 3/4 of the usable memory left after the kernel's TCP buffers (their
// ceiling, at most a quarter) and a reserve for the rest of the system (5%, at
// least 256 MiB), in whole MiB and never under 256 MiB: about 440 MiB on a
// 1 GB server, 15 GiB on a 24 GB one. 0 when the memory is unknown.
//
// GOMEMLIMIT is a soft limit: the core still grows past it when it has to,
// but near it the garbage collector runs harder and harder.
func Limit(f Facts) int64 {
	r := f.Usable()
	if r <= 0 {
		return 0
	}
	tcp := float64(f.TCPMemMax)
	if tcp <= 0 {
		// the kernel's default ceiling: about 3/32 of the machine's memory
		tcp = float64(max(f.MemTotal, r)) * 3 / 32
	}
	if f.MemTotal > r {
		// tcp_mem is the whole machine's; this cgroup's share of it
		tcp = tcp * float64(r) / float64(f.MemTotal)
	}
	// tcp_mem set far above the memory (tuning scripts do) would leave
	// nothing: count at most a quarter
	tcp = min(tcp, float64(r)/4)
	reserve := max(int64(256*MiB), r/20)
	lim := int64((float64(r)-tcp-float64(reserve))*0.75) / MiB * MiB
	return max(lim, 256*MiB)
}

// Environ returns env with GOMEMLIMIT set to limit, replacing every value it
// had, and without GOGC=off: that leaves the limit as the only thing that ever
// collects garbage, so panel and core would each grow to the full limit. A
// GOGC with a number is kept. With limit 0 (memory unknown) env is returned as
// it is.
func Environ(env []string, limit int64) []string {
	if limit <= 0 {
		return env
	}
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		if strings.HasPrefix(kv, "GOMEMLIMIT=") {
			continue
		}
		if v, ok := strings.CutPrefix(kv, "GOGC="); ok && GCOff(v) {
			continue
		}
		out = append(out, kv)
	}
	return append(out, fmt.Sprintf("GOMEMLIMIT=%dMiB", limit/MiB))
}

// GCOff tells whether a GOGC value turns the garbage collector off.
func GCOff(gogc string) bool { return strings.EqualFold(gogc, "off") }

// Detect reads the facts of this machine.
func Detect() Facts { return detect("") }

// detect reads the facts below root ("" for this machine's own files).
func detect(root string) Facts {
	read := func(p string) string {
		b, _ := os.ReadFile(root + p)
		return strings.TrimSpace(string(b))
	}
	var f Facts
	for _, l := range strings.Split(read("/proc/meminfo"), "\n") {
		if fs := strings.Fields(l); len(fs) >= 2 && fs[0] == "MemTotal:" {
			kb, _ := strconv.ParseInt(fs[1], 10, 64)
			f.MemTotal = kb * 1024
		}
	}
	if fs := strings.Fields(read("/proc/sys/net/ipv4/tcp_mem")); len(fs) == 3 {
		pages, _ := strconv.ParseInt(fs[2], 10, 64)
		f.TCPMemMax = pages * int64(os.Getpagesize())
	}

	// cgroup v2 ("0::/system.slice/x-ui.service") and v1 ("4:memory:/...")
	// limits of this process's cgroup and all above it. In a container the
	// path may be the host's while /sys/fs/cgroup is the container's own: the
	// walk up ends at the mount itself, which then holds the limit.
	take := func(s string) {
		n, err := strconv.ParseInt(s, 10, 64)
		if err == nil && n > 0 && n < 1<<60 && (f.Cgroup == 0 || n < f.Cgroup) {
			f.Cgroup = n
		}
	}
	walk := func(base, rel, file string) {
		for rel = path.Clean("/" + rel); ; rel = path.Dir(rel) {
			take(read(path.Join(base, rel, file)))
			if rel == "/" {
				return
			}
		}
	}
	for _, l := range strings.Split(read("/proc/self/cgroup"), "\n") {
		fs := strings.SplitN(l, ":", 3)
		if len(fs) != 3 {
			continue
		}
		if fs[0] == "0" && fs[1] == "" {
			walk("/sys/fs/cgroup", fs[2], "memory.max")
		}
		for _, c := range strings.Split(fs[1], ",") {
			if c == "memory" {
				walk("/sys/fs/cgroup/memory", fs[2], "memory.limit_in_bytes")
			}
		}
	}
	return f
}
