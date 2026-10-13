//go:build linux

package tune

import (
	"fmt"
	"math"
	"sort"
)

// Class says how a key's target combines with what is already there.
type Class string

const (
	ClassLimit  Class = "limit"  // raise to at least the target
	ClassWiden  Class = "widen"  // ip_local_port_range: only ever wider
	ClassField  Class = "field"  // tcp_rmem/tcp_wmem: raise the third field
	ClassBits   Class = "bits"   // tcp_fastopen: OR the bits in
	ClassChoice Class = "choice" // set, unless an admin's file chose otherwise
)

// Target is what x-ui wants for one sysctl key.
type Target struct {
	Key   string `json:"key"`
	Class Class  `json:"class"`
	Num   int64  `json:"num,omitempty"` // limit, field, bits; choice when numeric
	Str   string `json:"str,omitempty"` // choice
	Lo    int64  `json:"lo,omitempty"`  // widen
	Hi    int64  `json:"hi,omitempty"`  // widen
	// OnlyFromZero: a choice applied only when the current value is 0
	// (tcp_mtu_probing: 2 is a stronger setting and is kept).
	OnlyFromZero bool `json:"-"`
	// Optional keys may be missing at boot (conntrack); their line in
	// 99-x-ui.conf gets the "-" prefix so systemd-sysctl does not complain.
	Optional bool   `json:"-"`
	Why      string `json:"-"`
}

// Text is the target as written to the sysctl.
func (t *Target) Text() string {
	switch t.Class {
	case ClassWiden:
		return fmt.Sprintf("%d %d", t.Lo, t.Hi)
	case ClassChoice:
		if t.Str != "" {
			return t.Str
		}
		return fmt.Sprint(t.Num)
	case ClassBits:
		return fmt.Sprintf("|%d", t.Num)
	default:
		return fmt.Sprint(t.Num)
	}
}

// Service holds the machine-dependent service settings.
type Service struct {
	NoFile     int64  `json:"nofile"`      // the open-file limit the service should get
	GoMemLimit string `json:"gomemlimit"`  // e.g. "504MiB"
	GoGC       string `json:"gogc"`        // "" leaves Go's default
	Hashsize   int64  `json:"ct_hashsize"` // 0: conntrack does not apply
}

// BaseNoFile is the LimitNOFILE the shipped unit sets.
const BaseNoFile = 1048576

func pow2floor(x float64) int64 {
	if x < 1 {
		return 1
	}
	return int64(1) << uint(math.Floor(math.Log2(x)))
}

func pow2ceil(x float64) int64 {
	if x <= 1 {
		return 1
	}
	p := pow2floor(x)
	if float64(p) < x {
		p <<= 1
	}
	return p
}

func clamp(x, lo, hi int64) int64 {
	if x < lo {
		return lo
	}
	if x > hi {
		return hi
	}
	return x
}

// ServiceTargets computes the service's limits.
func ServiceTargets(f *Facts) Service {
	var s Service
	n := clamp(pow2ceil(16384*f.G), BaseNoFile, 8388608)
	ceil := f.NrOpen
	if f.NrOpenRW && n > ceil {
		ceil = n // fs.nr_open is raised first
	}
	if ceil > 0 && n > ceil {
		n = ceil
	}
	if f.Container() && f.Pid1Hard > 0 && n > f.Pid1Hard {
		n = f.Pid1Hard
	}
	s.NoFile = n

	tcp := float64(f.TCPMemMax * f.PageSize)
	if f.MemTotal > f.MemBytes && f.MemTotal > 0 {
		// A cgroup limit (Docker): tcp_mem is the host's, so take this
		// cgroup's share of it.
		tcp = tcp * float64(f.MemBytes) / float64(f.MemTotal)
	}
	reserve := f.MemBytes / 20
	if reserve < 256*MiB {
		reserve = 256 * MiB
	}
	m := (float64(f.MemBytes) - tcp - float64(reserve)) * 0.75
	lim := int64(m) / MiB
	if lim < 256 {
		lim = 256
	}
	s.GoMemLimit = fmt.Sprintf("%dMiB", lim)
	if f.G >= 4 {
		s.GoGC = "150"
	}
	if f.Conntrack {
		s.Hashsize = conntrackMax(f) / 2
	}
	return s
}

func conntrackMax(f *Facts) int64 {
	return clamp(pow2ceil(65536*f.G), 131072, 8388608)
}

// Targets computes every sysctl target for the machine. It is pure: all
// input comes from f.
func Targets(f *Facts) []Target {
	g := f.G
	svc := ServiceTargets(f)
	var t []Target
	add := func(x Target) { t = append(t, x) }

	add(Target{Key: "fs.file-max", Class: ClassLimit, Num: 2 * svc.NoFile,
		Why: "system-wide open files: at least twice the service's limit"})
	add(Target{Key: "fs.nr_open", Class: ClassLimit, Num: svc.NoFile,
		Why: "per-process open-file ceiling, so the service's LimitNOFILE can be set"})
	add(Target{Key: "kernel.pid_max", Class: ClassLimit, Num: 4194304,
		Why: "one xray core per instance, each with hundreds of threads"})

	lo := int64(10000)
	if f.PortLo > lo {
		// Ports between 10000 and the current range that something other
		// than the panel listens on stay outside the range.
		for _, p := range f.Listeners {
			if int64(p) >= lo && int64(p) < f.PortLo && !f.Reserved[p] {
				if q := int64(p) + 1; q > lo {
					lo = q
				}
			}
		}
		if lo%2 == 1 {
			lo++
		}
	}
	add(Target{Key: "net.ipv4.ip_local_port_range", Class: ClassWiden, Lo: lo, Hi: 65535,
		Why: "a larger local port pool for outgoing connections and UDP flows"})
	add(Target{Key: "net.ipv4.tcp_tw_reuse", Class: ClassChoice, Num: 1,
		Why: "reuse TIME_WAIT sockets for new outgoing connections"})
	add(Target{Key: "net.ipv4.tcp_fin_timeout", Class: ClassChoice, Num: 15,
		Why: "free FIN_WAIT_2 sockets of vanished clients sooner"})

	somax := clamp(pow2floor(8192*g), 8192, 65536)
	add(Target{Key: "net.core.somaxconn", Class: ClassLimit, Num: min(somax, 65535),
		Why: "accept queue for reconnect storms (xray uses it as its backlog)"})
	add(Target{Key: "net.ipv4.tcp_max_syn_backlog", Class: ClassLimit, Num: somax,
		Why: "SYN queue, kept in line with somaxconn"})
	add(Target{Key: "net.core.netdev_max_backlog", Class: ClassLimit, Num: clamp(pow2floor(2048*g), 2048, 16384),
		Why: "per-CPU receive backlog for packet bursts"})
	if f.Fast {
		add(Target{Key: "net.core.netdev_budget", Class: ClassLimit, Num: 600,
			Why: "more packets per softirq round on fast NICs or many CPUs"})
		add(Target{Key: "net.core.netdev_budget_usecs", Class: ClassLimit, Num: 4000,
			Why: "more time per softirq round on fast NICs or many CPUs"})
	}
	add(Target{Key: "net.ipv4.tcp_max_tw_buckets", Class: ClassLimit, Num: clamp(pow2floor(16384*g), 65536, 2097152),
		Why: "TIME_WAIT sockets kept before the kernel destroys them early"})
	add(Target{Key: "net.ipv4.tcp_max_orphans", Class: ClassLimit, Num: clamp(pow2floor(8192*g), 32768, 1048576),
		Why: "orphaned sockets before connections are reset"})
	add(Target{Key: "net.core.rmem_max", Class: ClassLimit, Num: 16 * MiB,
		Why: "receive buffer a socket may ask for (QUIC asks about 7 MB)"})
	add(Target{Key: "net.core.wmem_max", Class: ClassLimit, Num: 16 * MiB,
		Why: "send buffer a socket may ask for"})
	buf := min(32*MiB, pow2floor(4*float64(MiB)*g))
	add(Target{Key: "net.ipv4.tcp_rmem", Class: ClassField, Num: buf,
		Why: "TCP receive window for long, fast paths (third field)"})
	add(Target{Key: "net.ipv4.tcp_wmem", Class: ClassField, Num: buf,
		Why: "TCP send window for long, fast paths (third field)"})
	add(Target{Key: "net.ipv4.tcp_notsent_lowat", Class: ClassChoice, Num: 131072,
		Why: "limit unsent data per socket so mux streams do not queue behind bulk"})
	add(Target{Key: "net.ipv4.tcp_slow_start_after_idle", Class: ClassChoice, Num: 0,
		Why: "keep the congestion window of idle long-lived connections"})
	add(Target{Key: "net.ipv4.tcp_mtu_probing", Class: ClassChoice, Num: 1, OnlyFromZero: true,
		Why: "recover from ICMP black holes"})
	add(Target{Key: "net.ipv4.tcp_fastopen", Class: ClassBits, Num: 3,
		Why: "let inbounds that ask for TCP Fast Open use it"})
	if kernelAtLeast(f, 4, 13) && f.BBR != "missing" && f.BBR != "" {
		add(Target{Key: "net.ipv4.tcp_congestion_control", Class: ClassChoice, Str: "bbr",
			Why: "BBR copes with lossy, long-RTT paths"})
		add(Target{Key: "net.core.default_qdisc", Class: ClassChoice, Str: "fq",
			Why: "fq, BBR's pairing (applies to interfaces brought up later)"})
	}
	if !kernelAtLeast(f, 6, 3) {
		add(Target{Key: "net.ipv6.route.max_size", Class: ClassLimit, Num: clamp(pow2floor(16384*g), 65536, 1048576),
			Why: "IPv6 route cache before 6.3 caps new IPv6 destinations"})
	}
	add(Target{Key: "vm.swappiness", Class: ClassChoice, Num: 10,
		Why: "keep the cores' memory in RAM; swap only under pressure"})
	add(Target{Key: "vm.max_map_count", Class: ClassLimit, Num: 262144,
		Why: "memory maps for large Go heaps"})
	if g >= 8 {
		add(Target{Key: "vm.min_free_kbytes", Class: ClassLimit, Num: min(1048576, f.MemBytes/KiB/256),
			Why: "headroom for atomic allocations in the network softirq"})
	}
	if f.Conntrack {
		add(Target{Key: "net.netfilter.nf_conntrack_max", Class: ClassLimit, Num: conntrackMax(f), Optional: true,
			Why: "every proxied connection is tracked twice; a full table blocks new ones"})
		add(Target{Key: "net.netfilter.nf_conntrack_tcp_timeout_established", Class: ClassChoice, Num: 7200, Optional: true,
			Why: "forget dead connections after 2 h instead of 5 days"})
	}
	sort.SliceStable(t, func(i, j int) bool { return t[i].Key < t[j].Key })
	return t
}
