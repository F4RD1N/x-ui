//go:build linux

package tune

import (
	"bufio"
	"math"
	"os"
	"path"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	KiB = int64(1) << 10
	MiB = int64(1) << 20
	GiB = int64(1) << 30
)

// NIC is a network interface backed by a device.
type NIC struct {
	Name     string `json:"name"`
	Driver   string `json:"driver,omitempty"`
	Speed    int    `json:"speed_mbps,omitempty"`
	RxQueues int    `json:"rx_queues"`
}

// Facts is what the tuner detects about the machine.
type Facts struct {
	MemTotal  int64   `json:"mem_total"`
	MemBytes  int64   `json:"mem_bytes"` // R: the smaller of MemTotal and any cgroup limit
	G         float64 `json:"g"`         // R in whole GiB, at least 0.5
	CPUs      int     `json:"cpus"`
	Kernel    string  `json:"kernel"`
	KMajor    int     `json:"-"`
	KMinor    int     `json:"-"`
	Virt      string  `json:"virt"` // container type, "" for none
	Init      string  `json:"init"` // systemd, openrc or ""
	NrOpen    int64   `json:"nr_open"`
	Pid1Hard  int64   `json:"pid1_nofile_hard"`
	PageSize  int64   `json:"page_size"`
	TCPMemMax int64   `json:"tcp_mem_max_pages"`
	NICs      []NIC   `json:"nics,omitempty"`

	PortLo, PortHi int64        `json:"-"`
	Listeners      []int        `json:"-"`
	Reserved       map[int]bool `json:"-"`

	Conntrack  bool   `json:"conntrack"`
	BBR        string `json:"bbr"` // available, module, builtin, missing
	FQModule   bool   `json:"-"`   // sch_fq is a loadable module
	BBRModule  bool   `json:"-"`   // tcp_bbr is a loadable module
	NrOpenRW   bool   `json:"-"`
	Fast       bool   `json:"-"` // C >= 8 or a NIC of 10G or more
	SwapActive bool   `json:"swap_active"`
}

// Container reports whether the machine is a container (any kind).
func (f *Facts) Container() bool { return f.Virt != "" && f.Virt != "none" }

// IsLXC reports a container whose network namespace is its own (LXC, nspawn).
func (f *Facts) IsLXC() bool {
	switch f.Virt {
	case "lxc", "lxc-libvirt", "systemd-nspawn", "openvz":
		return true
	}
	return false
}

func (e *Env) gatherFacts() *Facts {
	f := &Facts{PageSize: int64(os.Getpagesize())}

	// Memory: MemTotal, capped by any cgroup limit (Docker shows the host's
	// RAM in /proc/meminfo).
	f.MemTotal = meminfo(e.readTrim("/proc/meminfo"), "MemTotal")
	f.MemBytes = f.MemTotal
	if lim := e.cgroupMemLimit(); lim > 0 && (f.MemBytes == 0 || lim < f.MemBytes) {
		f.MemBytes = lim
	}

	// CPUs: PID 1's affinity mask, or the cgroup quota when smaller.
	f.CPUs = cpuListCount(statusField(e.readTrim("/proc/1/status"), "Cpus_allowed_list"))
	if f.CPUs == 0 {
		f.CPUs = runtime.NumCPU()
	}
	if q := e.cgroupCPUQuota(); q > 0 && q < f.CPUs {
		f.CPUs = q
	}

	f.Kernel = e.readTrim("/proc/sys/kernel/osrelease")
	f.Init = e.detectInit()
	f.Virt = e.detectVirt()

	if o := e.Facts; o != nil {
		if o.MemBytes > 0 {
			f.MemBytes = o.MemBytes
			if f.MemTotal == 0 || f.MemTotal < o.MemBytes {
				f.MemTotal = o.MemBytes
			}
		}
		if o.CPUs > 0 {
			f.CPUs = o.CPUs
		}
		if o.Kernel != "" {
			f.Kernel = o.Kernel
		}
		if o.Virt != "" {
			f.Virt = o.Virt
		}
		if o.Init != "" {
			f.Init = o.Init
		}
		if o.PageSize > 0 {
			f.PageSize = o.PageSize
		}
	}
	if f.Virt == "none" {
		f.Virt = ""
	}
	if f.Init == "none" {
		f.Init = ""
	}
	f.KMajor, f.KMinor = kernelVersion(f.Kernel)
	f.G = math.Round(float64(f.MemBytes) / float64(GiB))
	if f.G < 0.5 {
		f.G = 0.5
	}

	f.NrOpen = atoi64(e.readTrim("/proc/sys/fs/nr_open"))
	f.NrOpenRW = e.writable("/proc/sys/fs/nr_open") == nil
	f.Pid1Hard = limitsHard(e.readTrim("/proc/1/limits"), "Max open files")
	if fs := strings.Fields(e.readTrim("/proc/sys/net/ipv4/tcp_mem")); len(fs) == 3 {
		f.TCPMemMax = atoi64(fs[2])
	}
	if f.TCPMemMax == 0 && f.PageSize > 0 {
		// Not visible here (a container's own network namespace): assume
		// the kernel's default, about 3/32 of the machine's pages.
		f.TCPMemMax = max(f.MemTotal, f.MemBytes) / f.PageSize * 3 / 32
	}

	f.NICs = e.nics()
	f.Fast = f.CPUs >= 8
	for _, n := range f.NICs {
		if n.Speed >= 10000 {
			f.Fast = true
		}
	}

	if fs := strings.Fields(e.readTrim("/proc/sys/net/ipv4/ip_local_port_range")); len(fs) == 2 {
		f.PortLo, f.PortHi = atoi64(fs[0]), atoi64(fs[1])
	}
	f.Listeners = e.listeners()
	f.Reserved = parsePorts(e.readTrim("/proc/sys/net/ipv4/ip_local_reserved_ports"))

	f.Conntrack = e.conntrackApplies()
	f.BBR, f.BBRModule = e.moduleState("tcp_bbr", "bbr")
	_, f.FQModule = e.moduleState("sch_fq", "")
	f.SwapActive = swapActive(e.readTrim("/proc/swaps"))
	return f
}

func meminfo(s, key string) int64 {
	for _, l := range strings.Split(s, "\n") {
		if k, v, ok := strings.Cut(l, ":"); ok && k == key {
			fs := strings.Fields(v)
			if len(fs) > 0 {
				n := atoi64(fs[0])
				if len(fs) > 1 && fs[1] == "kB" {
					n *= KiB
				}
				return n
			}
		}
	}
	return 0
}

func statusField(s, key string) string {
	for _, l := range strings.Split(s, "\n") {
		if k, v, ok := strings.Cut(l, ":"); ok && k == key {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// cpuListCount counts "0-3,8,10-11".
func cpuListCount(s string) int {
	n := 0
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		a, b, isRange := strings.Cut(part, "-")
		lo, err := strconv.Atoi(a)
		if err != nil {
			return 0
		}
		hi := lo
		if isRange {
			if hi, err = strconv.Atoi(b); err != nil {
				return 0
			}
		}
		if hi >= lo {
			n += hi - lo + 1
		}
	}
	return n
}

// cgroupDirs lists the cgroup v2 directories whose limits apply: this
// process's and the x-ui service's, with all their ancestors.
func (e *Env) cgroupDirs() (v2 []string, v1mem []string) {
	seen := map[string]bool{}
	add := func(list *[]string, base, rel string) {
		for {
			d := path.Join(base, rel)
			if !seen[d] {
				seen[d] = true
				*list = append(*list, d)
			}
			if rel == "/" || rel == "." || rel == "" {
				return
			}
			rel = path.Dir(rel)
		}
	}
	for _, l := range strings.Split(e.readTrim("/proc/self/cgroup"), "\n") {
		fs := strings.SplitN(l, ":", 3)
		if len(fs) != 3 {
			continue
		}
		if fs[0] == "0" && fs[1] == "" {
			add(&v2, "/sys/fs/cgroup", fs[2])
			add(&v2, "/sys/fs/cgroup", "/system.slice/x-ui.service")
		}
		for _, c := range strings.Split(fs[1], ",") {
			if c == "memory" {
				add(&v1mem, "/sys/fs/cgroup/memory", fs[2])
			}
		}
	}
	return v2, v1mem
}

func (e *Env) cgroupMemLimit() int64 {
	v2, v1 := e.cgroupDirs()
	var lim int64
	take := func(s string) {
		n := atoi64(s)
		if n > 0 && n < 1<<60 && (lim == 0 || n < lim) {
			lim = n
		}
	}
	for _, d := range v2 {
		take(e.readTrim(d + "/memory.max"))
	}
	for _, d := range v1 {
		take(e.readTrim(d + "/memory.limit_in_bytes"))
	}
	return lim
}

func (e *Env) cgroupCPUQuota() int {
	v2, _ := e.cgroupDirs()
	best := 0
	for _, d := range v2 {
		fs := strings.Fields(e.readTrim(d + "/cpu.max"))
		if len(fs) != 2 || fs[0] == "max" {
			continue
		}
		q, p := atoi64(fs[0]), atoi64(fs[1])
		if q <= 0 || p <= 0 {
			continue
		}
		n := int((q + p - 1) / p)
		if best == 0 || n < best {
			best = n
		}
	}
	return best
}

func kernelVersion(s string) (int, int) {
	fs := strings.FieldsFunc(s, func(r rune) bool { return r == '.' || r == '-' || r == '+' })
	if len(fs) < 2 {
		return 0, 0
	}
	a, _ := strconv.Atoi(fs[0])
	b, _ := strconv.Atoi(fs[1])
	return a, b
}

func kernelAtLeast(f *Facts, major, minor int) bool {
	return f.KMajor > major || (f.KMajor == major && f.KMinor >= minor)
}

func (e *Env) detectInit() string {
	if e.isDir("/run/systemd/system") {
		return "systemd"
	}
	if e.exists("/run/openrc") {
		return "openrc"
	}
	return ""
}

func (e *Env) detectVirt() string {
	if !e.fake() {
		if out, _ := e.Run(5*time.Second, "systemd-detect-virt", "-c"); out != "" && !strings.Contains(out, " ") {
			if out == "none" {
				return ""
			}
			return out
		}
	}
	if env, err := e.read("/proc/1/environ"); err == nil {
		for _, kv := range strings.Split(env, "\x00") {
			if v, ok := strings.CutPrefix(kv, "container="); ok && v != "" {
				return v
			}
		}
	}
	switch {
	case e.exists("/.dockerenv"):
		return "docker"
	case e.exists("/run/.containerenv"):
		return "podman"
	case e.exists("/proc/vz") && !e.exists("/proc/bc"):
		return "openvz"
	}
	rel := strings.ToLower(e.readTrim("/proc/sys/kernel/osrelease"))
	if strings.Contains(rel, "microsoft") || strings.Contains(rel, "wsl") {
		return "wsl"
	}
	return ""
}

func limitsHard(s, name string) int64 {
	for _, l := range strings.Split(s, "\n") {
		if !strings.HasPrefix(l, name) {
			continue
		}
		fs := strings.Fields(strings.TrimPrefix(l, name))
		if len(fs) >= 2 {
			if fs[1] == "unlimited" {
				return math.MaxInt64
			}
			return atoi64(fs[1])
		}
	}
	return 0
}

func (e *Env) nics() []NIC {
	var out []NIC
	for _, dev := range e.glob("/sys/class/net/*") {
		name := path.Base(dev)
		if !e.exists(dev + "/device") {
			continue
		}
		n := NIC{Name: name}
		if t, err := os.Readlink(e.P(dev + "/device/driver")); err == nil {
			n.Driver = path.Base(t)
		}
		if s, err := strconv.Atoi(e.readTrim(dev + "/speed")); err == nil && s > 0 {
			n.Speed = s
		}
		n.RxQueues = len(e.glob(dev + "/queues/rx-*"))
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// listeners lists local ports with a listening TCP socket or an unconnected
// UDP socket.
func (e *Env) listeners() []int {
	set := map[int]bool{}
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"} {
		tcp := strings.Contains(f, "tcp")
		s, err := e.read(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(strings.NewReader(s))
		sc.Buffer(make([]byte, 64*1024), 1<<20)
		for sc.Scan() {
			fs := strings.Fields(sc.Text())
			if len(fs) < 4 || fs[0] == "sl" {
				continue
			}
			_, lport, ok := strings.Cut(fs[1], ":")
			if !ok {
				continue
			}
			_, rport, _ := strings.Cut(fs[2], ":")
			p, err := strconv.ParseInt(lport, 16, 32)
			if err != nil || p == 0 {
				continue
			}
			if tcp && fs[3] != "0A" {
				continue
			}
			if !tcp && rport != "0000" {
				continue
			}
			set[int(p)] = true
		}
	}
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

func parsePorts(s string) map[int]bool {
	out := map[int]bool{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		a, b, isRange := strings.Cut(part, "-")
		lo, err := strconv.Atoi(a)
		if err != nil {
			continue
		}
		hi := lo
		if isRange {
			if hi, err = strconv.Atoi(b); err != nil {
				continue
			}
		}
		for p := lo; p <= hi && p <= 65535; p++ {
			out[p] = true
		}
	}
	return out
}

// conntrackApplies: the conntrack table is in use or will be (the module is
// loaded at boot, or a firewall that loads it is enabled). x-ui never loads
// the module itself.
func (e *Env) conntrackApplies() bool {
	if e.exists("/proc/sys/net/netfilter/nf_conntrack_max") {
		return true
	}
	for _, dir := range []string{"/etc/modules-load.d", "/run/modules-load.d", "/usr/lib/modules-load.d", "/lib/modules-load.d"} {
		for _, f := range e.glob(dir + "/*.conf") {
			for _, l := range strings.Split(e.readTrim(f), "\n") {
				if strings.TrimSpace(l) == "nf_conntrack" {
					return true
				}
			}
		}
	}
	for _, l := range strings.Split(e.readTrim("/etc/modules"), "\n") {
		if strings.TrimSpace(l) == "nf_conntrack" {
			return true
		}
	}
	if strings.Contains(strings.ReplaceAll(e.readTrim("/etc/ufw/ufw.conf"), " ", ""), "ENABLED=yes") {
		return true
	}
	return e.exists("/etc/systemd/system/multi-user.target.wants/firewalld.service")
}

// moduleState says whether a kernel feature is available now ("available"),
// can be loaded ("module"), is built in ("builtin") or does not exist
// ("missing"), and whether it is a loadable module.
func (e *Env) moduleState(mod, cc string) (string, bool) {
	if cc != "" {
		for _, a := range strings.Fields(e.readTrim("/proc/sys/net/ipv4/tcp_available_congestion_control")) {
			if a == cc {
				return "available", e.isModule(mod)
			}
		}
	}
	rel := e.readTrim("/proc/sys/kernel/osrelease")
	if strings.Contains(e.readTrim("/lib/modules/"+rel+"/modules.builtin"), "/"+mod+".ko") {
		return "builtin", false
	}
	if e.isModule(mod) {
		return "module", true
	}
	return "missing", false
}

func (e *Env) isModule(mod string) bool {
	rel := e.readTrim("/proc/sys/kernel/osrelease")
	if e.exists("/sys/module/" + mod + "/initstate") {
		return true
	}
	return strings.Contains(e.readTrim("/lib/modules/"+rel+"/modules.dep"), "/"+mod+".ko")
}

func swapActive(s string) bool {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return len(lines) > 1
}

func atoi64(s string) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		if u, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64); err == nil {
			if u > math.MaxInt64 {
				return math.MaxInt64
			}
			return int64(u)
		}
		return 0
	}
	return n
}
