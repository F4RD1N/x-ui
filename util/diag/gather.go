//go:build linux

package diag

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/util/hw"
	"github.com/mhsanaei/3x-ui/v2/util/sys"
	"github.com/mhsanaei/3x-ui/v2/util/tune"
)

// env is everything diag reads through: the /sys, /proc and /etc tree, the
// NICs' ethtool settings, the socket scans and the clock. Tests replace each
// part; nothing in it writes.
type env struct {
	fs      hw.FS
	eth     hw.Ethtool
	tcp     func(ports []int) (map[sys.LocalEndpoint]int, error) // nil: no socket scan
	udp     func(func(sys.LocalEndpoint)) error                  // nil: no socket scan
	summary func() []string                                      // the tuning lines (tune.Summary)
	now     func() time.Time
	sleep   func(time.Duration)
	exe     string // the x-ui binary: <its dir>/bin/instances.json when no core says where
	root    bool   // other processes' open files and the cores' configs need root
}

const (
	tuneState       = "/var/lib/x-ui/tune/state.json"
	irqbalancePol   = "/var/lib/x-ui/tune/irqbalance-policy"
	irqbalanceDrop  = "/etc/systemd/system/irqbalance.service.d/90-x-ui.conf"
	needsRoot       = "needs root"
	policyFlag      = "--policyscript"
	xrayBinaryStart = "xray-linux-"
)

// Report is everything "x-ui diag" shows; --json prints it as it is.
type Report struct {
	Time      time.Time         `json:"time"`
	Version   string            `json:"version"`
	Kernel    string            `json:"kernel"`
	Seconds   int               `json:"seconds"`
	Root      bool              `json:"root"`
	Hardware  Hardware          `json:"hardware"`
	NICs      []*NICReport      `json:"nics"`
	NetNotes  []string          `json:"network_notes,omitempty"`
	Sample    *Sample           `json:"sample,omitempty"`
	Instances []*InstanceReport `json:"instances"`
	TCP       TCPReport         `json:"tcp"`
	Warnings  []string          `json:"warnings"`
}

// Hardware is the machine: CPUs, NUMA nodes, memory.
type Hardware struct {
	Sockets        int          `json:"sockets"`
	Cores          int          `json:"cores"`
	CPUs           int          `json:"cpus"`
	ThreadsPerCore int          `json:"threads_per_core"`
	MemBytes       int64        `json:"mem_bytes"`
	Model          string       `json:"model"`
	Virt           string       `json:"virt"` // "" bare metal, else the VM or container kind
	Container      bool         `json:"container"`
	NUMABalancing  string       `json:"numa_balancing"` // "on", "off", "" unknown
	Isolated       hw.CPUSet    `json:"isolated,omitempty"`
	Nodes          []NodeReport `json:"nodes"`
	Note           string       `json:"note,omitempty"`
}

// NodeReport is one NUMA node.
type NodeReport struct {
	ID         int       `json:"id"`
	CPUs       hw.CPUSet `json:"cpus"`
	MemBytes   int64     `json:"mem_bytes"`
	MemoryOnly bool      `json:"memory_only,omitempty"`
}

// NICReport is one NIC under the default routes.
type NICReport struct {
	Name      string            `json:"name"`
	Via       []string          `json:"via"`
	Routes    string            `json:"routes"` // "v4", "v6", "v4+v6"
	Driver    string            `json:"driver"`
	PCI       string            `json:"pci"`
	Vendor    string            `json:"vendor"`
	Device    string            `json:"device"`
	Model     string            `json:"model"`
	Node      int               `json:"node"`
	SpeedMbps int               `json:"speed_mbps"`
	Up        bool              `json:"up"`
	Carrier   bool              `json:"carrier"`
	VF        bool              `json:"vf,omitempty"`
	Channels  *hw.Channels      `json:"channels"`
	Queues    int               `json:"queues"`
	RSS       *RSSReport        `json:"rss"`
	Hash      map[string]string `json:"hash"` // flow -> "sd", "sdfn"
	Offloads  map[string]bool   `json:"offloads"`
	IRQs      []IRQReport       `json:"irqs"`
	OtherIRQs []int             `json:"other_irqs,omitempty"`
	Siblings  []string          `json:"rss_siblings,omitempty"` // cores with RSS interrupts on two threads: "11/39"
	IRQNote   string            `json:"irq_note,omitempty"`
	IRQBal    IRQBalance        `json:"irqbalance"`
	XPS       XPSReport         `json:"xps"`
	RPS       RPSReport         `json:"rps"`
	Managed   bool              `json:"managed_by_x_ui"` // "x-ui tune" manages it
	Notes     []string          `json:"notes,omitempty"`

	nic *hw.NIC
	rss map[int]bool // hashed queues
}

// RSSReport is the RSS indirection table.
type RSSReport struct {
	Size   int       `json:"size"`
	Queues int       `json:"queues"` // distinct queues it uses
	Used   hw.CPUSet `json:"used"`   // the queues, as a list ("0-15")
	Even   bool      `json:"even"`   // spread evenly over queues 0..Queues-1
}

// IRQReport is one queue interrupt.
type IRQReport struct {
	IRQ       int       `json:"irq"`
	Name      string    `json:"name"`
	Queue     int       `json:"queue"`
	Kind      string    `json:"kind"`
	RSS       bool      `json:"rss"` // its queue is in the RSS table
	CPUs      hw.CPUSet `json:"cpus"`
	Effective hw.CPUSet `json:"effective"`
	Owner     string    `json:"owner,omitempty"` // instance on its CPU, "free", or "" without instances
}

// IRQBalance is the irqbalance daemon as it concerns a NIC.
type IRQBalance struct {
	Installed bool `json:"installed"`
	Running   bool `json:"running"`
	Policy    bool `json:"x_ui_policy"` // it runs with x-ui's policy script
	DropIn    bool `json:"drop_in"`     // 90-x-ui.conf gives it the script
	Banned    bool `json:"banned"`      // the script bans this NIC
}

// XPSReport says which queue each CPU sends on, measured against where the
// queues' interrupts are.
type XPSReport struct {
	Available bool              `json:"available"`
	Note      string            `json:"note,omitempty"`
	Queues    int               `json:"queues"` // TX queues
	Set       int               `json:"set"`    // TX queues with CPUs
	Own       int               `json:"own"`    // CPUs sending on a queue served on themselves
	Core      int               `json:"core"`   // ... on their core
	Node      int               `json:"node"`   // ... on their node
	Remote    int               `json:"remote"` // ... on another node
	None      int               `json:"none"`   // CPUs no queue lists
	Map       map[string]string `json:"map,omitempty"`
}

// RPSReport is receive packet steering.
type RPSReport struct {
	Queues  map[string]string `json:"queues,omitempty"` // "rx-0" -> CPUs
	FlowCnt map[string]int    `json:"flow_cnt,omitempty"`
	On      bool              `json:"on"`
}

// InstanceReport is one running xray core.
type InstanceReport struct {
	Name       string    `json:"name"`
	PID        int       `json:"pid"`
	CPUPct     *float64  `json:"cpu_pct"` // of its own CPUs, over the sample; null without one
	CPUs       hw.CPUSet `json:"cpus"`
	Nodes      []int     `json:"nodes"`
	Threads    int       `json:"threads"`
	FDs        int       `json:"fds"` // -1 unknown
	FDLimit    int64     `json:"fd_limit"`
	RSSBytes   int64     `json:"rss_bytes"`
	TCP        int       `json:"tcp"` // established on its inbounds; -1 unknown
	UDP        *UDPUse   `json:"udp"` // null without a socket scan
	NICIRQs    NICIRQs   `json:"nic_irqs"`
	SoftirqPct *float64  `json:"softirq_pct"`
	Config     string    `json:"config,omitempty"`
	Egress     string    `json:"egress,omitempty"`
	Notes      []string  `json:"notes,omitempty"`

	pinned bool   // its CPUs are not all the allowed ones
	ticks  uint64 // utime+stime at the first snapshot
}

// UDPUse is the local ports an instance's UDP sockets draw on.
type UDPUse struct {
	IP   string `json:"ip"` // "" the host's default address
	Used int    `json:"used"`
	Pool int    `json:"pool"`
}

// NICIRQs counts the NIC queue interrupts on an instance's CPUs.
type NICIRQs struct {
	RSS   int     `json:"rss"`
	Other int     `json:"other"`
	Share float64 `json:"share"` // its fair part of the RSS interrupts; 0 unknown
}

// TCPReport is the kernel's socket counters and the limits they run into.
type TCPReport struct {
	InUse           int64   `json:"inuse"`
	InUse6          int64   `json:"inuse6"`
	Orphans         int64   `json:"orphans"`
	MaxOrphans      int64   `json:"max_orphans"`
	TimeWait        int64   `json:"time_wait"`
	MaxTimeWait     int64   `json:"max_time_wait"`
	MemPages        int64   `json:"mem_pages"`
	TCPMem          []int64 `json:"tcp_mem"`
	ListenOverflows uint64  `json:"listen_overflows"`
	ListenDrops     uint64  `json:"listen_drops"`
	AbortOnMemory   uint64  `json:"abort_on_memory"`
	Conntrack       *Gauge  `json:"conntrack"`
	Files           *Gauge  `json:"files"`
	UDPPool         int     `json:"udp_pool,omitempty"`
}

// Gauge is a count against its limit.
type Gauge struct {
	Count int64 `json:"count"`
	Max   int64 `json:"max"`
}

// ctx is one run of diag: the report and what it was built from.
type ctx struct {
	e       *env
	r       *Report
	topo    *hw.Topology
	allowed hw.CPUSet
	owners  map[int][]string // CPU -> instances pinned there
	tuned   map[string]bool  // NICs (PCI or name) "x-ui tune" manages
	disable bool             // tuning turned off
	irqb    IRQBalance
	udp     *sys.UDPPortUse
	a, b    *snap
	file    *hw.Instances // the panel's instances.json
}

// gather reads everything but the sample. scan: count sockets.
func (e *env) gather(version string, scan bool) *ctx {
	c := &ctx{e: e, owners: map[int][]string{}, tuned: map[string]bool{}}
	r := &Report{Time: e.now().UTC().Truncate(time.Second), Version: version, Root: e.root,
		NICs: []*NICReport{}, Instances: []*InstanceReport{}, Warnings: []string{}}
	c.r = r
	r.Kernel = e.fs.ReadTrim("/proc/sys/kernel/osrelease")
	c.hardware()
	c.instances()
	c.readTuneState()
	c.irqbalance()
	c.nics()
	c.instanceIRQs()
	if scan {
		c.sockets()
	}
	c.tcp()
	return c
}

func (c *ctx) hardware() {
	h := &c.r.Hardware
	t, err := hw.ReadTopology(c.e.fs)
	h.Virt, h.Container = c.virt()
	switch c.e.fs.ReadTrim("/proc/sys/kernel/numa_balancing") {
	case "":
	case "0":
		h.NUMABalancing = "off"
	default:
		h.NUMABalancing = "on"
	}
	if err != nil {
		h.Note = "CPU topology: " + err.Error()
		h.Nodes = []NodeReport{}
		return
	}
	c.topo = t
	h.Sockets = t.Sockets()
	h.Cores = len(t.Cores)
	h.CPUs = len(t.Online)
	h.ThreadsPerCore = t.ThreadsPerCore()
	h.MemBytes = t.MemBytes
	h.Model = t.Model
	h.Isolated = t.Isolated
	for _, n := range t.Nodes {
		h.Nodes = append(h.Nodes, NodeReport{ID: n.ID, CPUs: n.CPUs, MemBytes: n.MemBytes, MemoryOnly: len(n.CPUs) == 0})
	}
	c.allowed = t.Online
}

// virt names the virtualisation from files only: a container's marks, then
// the firmware's vendor, the paravirtual clock, the CPU's hypervisor flag.
func (c *ctx) virt() (string, bool) {
	fs := c.e.fs
	if v := fs.ReadTrim("/run/systemd/container"); v != "" {
		return v, true
	}
	if env, err := fs.Read("/proc/1/environ"); err == nil {
		for _, kv := range strings.Split(env, "\x00") {
			if v, ok := strings.CutPrefix(kv, "container="); ok && v != "" {
				return v, true
			}
		}
	}
	switch {
	case fs.Exists("/.dockerenv"):
		return "docker", true
	case fs.Exists("/run/.containerenv"):
		return "podman", true
	case fs.Exists("/proc/vz") && !fs.Exists("/proc/bc"):
		return "openvz", true
	}
	vendor := strings.ToLower(fs.ReadTrim("/sys/class/dmi/id/sys_vendor") + " " + fs.ReadTrim("/sys/class/dmi/id/product_name"))
	for _, v := range []struct{ match, name string }{
		{"qemu", "kvm"}, {"kvm", "kvm"}, {"vmware", "vmware"}, {"xen", "xen"}, {"microsoft", "microsoft"},
		{"amazon ec2", "amazon"}, {"google", "google"}, {"virtualbox", "oracle"}, {"parallels", "parallels"},
	} {
		if strings.Contains(vendor, v.match) {
			return v.name, false
		}
	}
	if t := fs.ReadTrim("/sys/hypervisor/type"); t != "" {
		return t, false
	}
	clock := fs.ReadTrim("/sys/devices/system/clocksource/clocksource0/available_clocksource")
	for _, v := range []struct{ match, name string }{{"kvm-clock", "kvm"}, {"hyperv", "microsoft"}, {"xen", "xen"}} {
		if strings.Contains(clock, v.match) {
			return v.name, false
		}
	}
	for _, l := range strings.Split(fs.ReadTrim("/proc/cpuinfo"), "\n") {
		if k, v, ok := strings.Cut(l, ":"); ok && strings.TrimSpace(k) == "flags" {
			if slices.Contains(strings.Fields(v), "hypervisor") {
				return "vm", false
			}
			break
		}
	}
	return "", false
}

// ------------------------------------------------------------ instances

// instances finds the running xray cores and reads each one's process.
func (c *ctx) instances() {
	e := c.e
	files := map[string]*hw.Instances{} // instances.json by path
	readFile := func(p string) *hw.Instances {
		if s, ok := files[p]; ok {
			return s
		}
		s, _ := hw.ReadInstances(e.fs, p)
		files[p] = s
		return s
	}
	var insts []*InstanceReport
	var file *hw.Instances
	for _, d := range e.fs.Glob("/proc/[0-9]*") {
		pid, err := strconv.Atoi(path.Base(d))
		if err != nil {
			continue
		}
		data, err := e.fs.Read(d + "/cmdline")
		if err != nil || data == "" {
			continue
		}
		args := strings.Split(strings.TrimRight(data, "\x00"), "\x00")
		base := ""
		if e.root {
			base = strings.TrimSuffix(e.fs.LinkBase(d+"/exe"), " (deleted)")
		}
		if base == "" {
			base = path.Base(args[0])
		}
		// The panel also runs the binary briefly to check a config or ask its
		// version; those are no cores.
		if !strings.HasPrefix(base, xrayBinaryStart) || slices.Contains(args, "-test") || slices.Contains(args, "-version") {
			continue
		}
		cfg := configArg(args[1:])
		if cfg != "" && !path.IsAbs(cfg) {
			if cwd, err := os.Readlink(e.fs.P(d + "/cwd")); err == nil && path.IsAbs(cwd) {
				cfg = path.Join(cwd, cfg)
			}
		}
		in := &InstanceReport{PID: pid, Config: cfg, FDs: -1, TCP: -1, Nodes: []int{}}
		var f *hw.Instances
		if path.IsAbs(cfg) {
			f = readFile(path.Join(path.Dir(cfg), hw.InstancesFile))
		}
		if f == nil && e.exe != "" {
			f = readFile(hw.InstancesPath(filepath.Join(filepath.Dir(e.exe), "bin")))
		}
		if f != nil && file == nil {
			file = f
		}
		in.Name = configName(cfg)
		if f != nil {
			for _, fi := range f.Instances {
				// Every config is in the bin folder: the file name is enough.
				if cfg != "" && (fi.Config == cfg || path.Base(fi.Config) == path.Base(cfg)) {
					in.Name, in.Egress = fi.Name, fi.Egress
					break
				}
			}
		}
		c.readProc(in)
		insts = append(insts, in)
	}
	if file == nil && e.exe != "" {
		file = readFile(hw.InstancesPath(filepath.Join(filepath.Dir(e.exe), "bin")))
	}
	c.file = file
	if file != nil && c.topo != nil {
		if a, err := hw.ParseList(file.Allowed); err == nil && len(a.And(c.topo.Online)) > 0 {
			c.allowed = a.And(c.topo.Online)
		}
	}
	// Two cores of one name (one restarting): tell them apart.
	seen := map[string]int{}
	for _, in := range insts {
		seen[in.Name]++
	}
	for _, in := range insts {
		if seen[in.Name] > 1 {
			in.Name = fmt.Sprintf("%s (pid %d)", in.Name, in.PID)
		}
	}
	sort.SliceStable(insts, func(i, j int) bool { return model.LessInstanceName(insts[i].Name, insts[j].Name) })
	for _, in := range insts {
		in.pinned = len(in.CPUs) > 0 && !in.CPUs.Equal(c.allowed) && (c.topo == nil || !in.CPUs.Equal(c.topo.Online))
		if in.pinned {
			for _, cpu := range in.CPUs {
				c.owners[cpu] = append(c.owners[cpu], in.Name)
			}
		}
		if c.topo != nil {
			in.Nodes = append([]int{}, c.topo.NodesOf(in.CPUs)...)
		}
	}
	c.r.Instances = insts
}

// configArg finds the config file in a core's arguments.
func configArg(args []string) string {
	for i, a := range args {
		for _, f := range []string{"-c", "-config", "--config"} {
			if a == f && i+1 < len(args) {
				return args[i+1]
			}
			if v, ok := strings.CutPrefix(a, f+"="); ok {
				return v
			}
		}
	}
	return ""
}

// configName is the instance name a config file's name gives:
// config-<slug>.json is <slug>, config.json the single core "xray".
func configName(cfg string) string {
	base := path.Base(cfg)
	switch {
	case cfg == "":
		return "xray"
	case base == "config.json":
		return "xray"
	case strings.HasPrefix(base, "config-") && strings.HasSuffix(base, ".json"):
		return strings.TrimSuffix(strings.TrimPrefix(base, "config-"), ".json")
	}
	return strings.TrimSuffix(base, ".json")
}

// readProc reads a core's CPUs, threads, memory, CPU time and open files.
func (c *ctx) readProc(in *InstanceReport) {
	fs := c.e.fs
	d := fmt.Sprintf("/proc/%d", in.PID)
	for _, l := range strings.Split(fs.ReadTrim(d+"/status"), "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Cpus_allowed_list":
			in.CPUs, _ = hw.ParseList(v)
		case "Threads":
			in.Threads, _ = strconv.Atoi(v)
		case "VmRSS":
			if f := strings.Fields(v); len(f) > 0 {
				kb, _ := strconv.ParseInt(f[0], 10, 64)
				in.RSSBytes = kb * 1024
			}
		}
	}
	in.ticks, _ = procTicks(fs, in.PID)
	for _, l := range strings.Split(fs.ReadTrim(d+"/limits"), "\n") {
		if rest, ok := strings.CutPrefix(l, "Max open files"); ok {
			if f := strings.Fields(rest); len(f) > 0 {
				in.FDLimit, _ = strconv.ParseInt(f[0], 10, 64)
			}
		}
	}
	if !c.e.root {
		in.Notes = append(in.Notes, "open files: "+needsRoot)
		return
	}
	in.FDs = c.countFDs(d + "/fd")
}

// countFDs counts a process's open files. Since Linux 6.2 the size of its
// fd directory is the count, which is quick with millions of them.
func (c *ctx) countFDs(dir string) int {
	if c.e.fs.Root == "" && kernelAtLeast(c.r.Kernel, 6, 2) {
		if st, err := os.Stat(dir); err == nil && st.Size() > 0 {
			return int(st.Size())
		}
	}
	f, err := os.Open(c.e.fs.P(dir))
	if err != nil {
		return -1
	}
	defer f.Close()
	n := 0
	for {
		names, err := f.Readdirnames(4096)
		n += len(names)
		if err != nil || len(names) == 0 {
			return n
		}
	}
}

func kernelAtLeast(release string, major, minor int) bool {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return false
	}
	ma, _ := strconv.Atoi(parts[0])
	mi, _ := strconv.Atoi(strings.TrimFunc(parts[1], func(r rune) bool { return r < '0' || r > '9' }))
	return ma > major || (ma == major && mi >= minor)
}

// procTicks is a process's utime+stime, in clock ticks.
func procTicks(fs hw.FS, pid int) (uint64, bool) {
	s, err := fs.Read(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, false
	}
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0, false
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 13 {
		return 0, false
	}
	ut, err1 := strconv.ParseUint(f[11], 10, 64)
	st, err2 := strconv.ParseUint(f[12], 10, 64)
	if err1 != nil || err2 != nil {
		return 0, false
	}
	return ut + st, true
}

// owner names who runs on a CPU: an instance, "free", or "" when no
// instance is pinned anywhere.
func (c *ctx) owner(cpu int) string {
	if len(c.owners) == 0 || cpu < 0 {
		return ""
	}
	switch o := c.owners[cpu]; len(o) {
	case 0:
		return "free"
	case 1:
		return o[0]
	default:
		return strings.Join(o, "+")
	}
}

// split says whether the pinned instances divide the CPUs between them,
// each CPU to at most one.
func (c *ctx) split() bool {
	if len(c.owners) == 0 {
		return false
	}
	for _, o := range c.owners {
		if len(o) > 1 {
			return false
		}
	}
	for _, in := range c.r.Instances {
		if !in.pinned {
			return false
		}
	}
	return true
}

// ------------------------------------------------------------ tuning state

func (c *ctx) readTuneState() {
	data, err := c.e.fs.Read(tuneState)
	if err != nil {
		return
	}
	var st struct {
		Disabled bool                       `json:"disabled"`
		NICs     map[string]json.RawMessage `json:"nics"`
	}
	if json.Unmarshal([]byte(data), &st) != nil {
		return
	}
	c.disable = st.Disabled
	for k := range st.NICs {
		c.tuned[k] = true
	}
}

// ------------------------------------------------------------ irqbalance

func (c *ctx) irqbalance() {
	fs := c.e.fs
	for _, p := range []string{"/etc/systemd/system/irqbalance.service", "/usr/lib/systemd/system/irqbalance.service",
		"/lib/systemd/system/irqbalance.service", "/etc/init.d/irqbalance", "/usr/sbin/irqbalance", "/sbin/irqbalance"} {
		if fs.Exists(p) {
			c.irqb.Installed = true
			break
		}
	}
	c.irqb.DropIn = fs.Exists(irqbalanceDrop)
	for _, d := range fs.Glob("/proc/[0-9]*") {
		if fs.ReadTrim(d+"/comm") != "irqbalance" {
			continue
		}
		c.irqb.Running, c.irqb.Installed = true, true
		args := strings.Split(strings.TrimRight(fs.ReadTrim(d+"/cmdline"), "\x00"), "\x00")
		// The same forms "x-ui tune" accepts: --policyscript=P, -lP, or the
		// flag and P as two words.
		for i, a := range args {
			if a == policyFlag+"="+irqbalancePol || a == "-l"+irqbalancePol ||
				((a == policyFlag || a == "-l") && i+1 < len(args) && args[i+1] == irqbalancePol) {
				c.irqb.Policy = true
			}
		}
		break
	}
}

// ------------------------------------------------------------ NICs

func (c *ctx) nics() {
	nics, notes := hw.UplinkNICs(c.e.fs, c.e.eth)
	c.r.NetNotes = notes
	policy := c.e.fs.ReadTrim(irqbalancePol)
	for _, n := range nics {
		c.r.NICs = append(c.r.NICs, c.nicReport(n, policy))
	}
}

func (c *ctx) nicReport(n *hw.NIC, policy string) *NICReport {
	nr := &NICReport{Name: n.Name, Via: append([]string{}, n.Via...), Driver: n.Driver, PCI: n.PCI, Vendor: n.Vendor, Device: n.Device, Model: n.Model,
		Node: n.Node, SpeedMbps: n.SpeedMbps, Up: n.Up, Carrier: n.Carrier, VF: n.VF, Channels: n.Channels, Queues: n.Queues(),
		Hash: map[string]string{}, Offloads: n.Features, IRQs: []IRQReport{}, OtherIRQs: n.OtherIRQs, Notes: n.Notes, nic: n, rss: map[int]bool{}}
	if nr.Offloads == nil {
		nr.Offloads = map[string]bool{}
	}
	var v4, v6 bool
	for _, r := range n.Routes {
		if r.V6 {
			v6 = true
		} else {
			v4 = true
		}
	}
	switch {
	case v4 && v6:
		nr.Routes = "v4+v6"
	case v6:
		nr.Routes = "v6"
	default:
		nr.Routes = "v4"
	}
	nr.Managed = c.tuned[n.Key()] && !c.disable
	for k, bits := range n.Hash {
		nr.Hash[k] = hw.HashLetters(bits)
	}

	// The hashed queues: those in the RSS table, else all of them.
	if use := n.RSSUse(); use != nil {
		rr := &RSSReport{Size: len(n.Indir)}
		for q, cnt := range use {
			if cnt > 0 {
				rr.Used = append(rr.Used, q)
				nr.rss[q] = true
			}
		}
		rr.Used = hw.NewCPUSet(rr.Used...)
		rr.Queues = len(rr.Used)
		rr.Even = rr.Queues > 0 && rr.Used[rr.Queues-1] == rr.Queues-1 && hw.EvenOver(n.Indir, rr.Queues)
		nr.RSS = rr
	} else {
		for q := 0; q < max(nr.Queues, 1); q++ {
			nr.rss[q] = true
		}
	}

	for _, qi := range n.IRQs {
		ir := IRQReport{IRQ: qi.IRQ, Name: qi.Name, Queue: qi.Queue, Kind: qi.Kind, CPUs: qi.Affinity, Effective: qi.Effective,
			RSS: nr.rss[qi.Queue] && qi.Kind != "tx"}
		ir.Owner = c.owner(irqCPU(qi))
		nr.IRQs = append(nr.IRQs, ir)
	}
	switch {
	case n.UnknownIRQs:
		nr.IRQNote = "interrupt names not recognised"
	case n.SharedIRQ:
		nr.IRQNote = "one interrupt serves every queue"
	case len(n.IRQs) == 0 && n.PCI != "":
		nr.IRQNote = "no queue interrupts found"
	}
	nr.Siblings = c.rssSiblings(nr)

	nr.IRQBal = c.irqb
	nr.IRQBal.Banned = n.PCI != "" && slices.Contains(tune.PolicyBans(policy), n.PCI)
	nr.XPS = c.xps(nr)
	nr.RPS = rpsReport(n)
	return nr
}

// irqCPU is the CPU an interrupt runs on: its effective CPU, else its only
// allowed one; -1 when unknown.
func irqCPU(qi hw.QueueIRQ) int {
	switch {
	case len(qi.Effective) > 0:
		return qi.Effective[0]
	case len(qi.Affinity) == 1:
		return qi.Affinity[0]
	}
	return -1
}

// queueCPUs maps each queue to the CPU of its receive (or combined)
// interrupt.
func queueCPUs(n *hw.NIC) map[int]int {
	out := map[int]int{}
	for _, qi := range n.IRQs {
		if qi.Kind == "tx" {
			continue
		}
		if cpu := irqCPU(qi); cpu >= 0 {
			out[qi.Queue] = cpu
		}
	}
	return out
}

// txCPUs maps each queue to the CPU of its transmit (or combined)
// interrupt.
func txCPUs(n *hw.NIC) map[int]int {
	out := map[int]int{}
	for _, qi := range n.IRQs {
		if qi.Kind == "rx" {
			continue
		}
		if cpu := irqCPU(qi); cpu >= 0 {
			out[qi.Queue] = cpu
		}
	}
	return out
}

// rssSiblings lists the cores with RSS interrupts on two or more of their
// threads: "11/39".
func (c *ctx) rssSiblings(nr *NICReport) []string {
	if c.topo == nil {
		return nil
	}
	byCore := map[int]hw.CPUSet{}
	for q, cpu := range queueCPUs(nr.nic) {
		if !nr.rss[q] {
			continue
		}
		if core := c.topo.CoreOf(cpu); core != nil {
			byCore[core.ID] = byCore[core.ID].Union(hw.CPUSet{cpu})
		}
	}
	var ids []int
	for id, cpus := range byCore {
		if len(cpus) > 1 {
			ids = append(ids, id)
		}
	}
	sort.Ints(ids)
	var out []string
	for _, id := range ids {
		var s []string
		for _, cpu := range byCore[id] {
			s = append(s, strconv.Itoa(cpu))
		}
		out = append(out, strings.Join(s, "/"))
	}
	return out
}

// xps classifies every online CPU by where the queue it sends on has its
// interrupt: on the CPU itself, its core, its node, another node.
func (c *ctx) xps(nr *NICReport) XPSReport {
	n := nr.nic
	x := XPSReport{}
	switch {
	case n.TxQueues < 2 || len(n.XPS) == 0:
		x.Note = "one transmit queue"
		return x
	case n.TCs:
		x.Note = "traffic classes choose the queue"
		return x
	}
	x.Available = true
	x.Queues = n.TxQueues
	x.Map = map[string]string{}
	cpuQueues := map[int][]int{}
	for q, m := range n.XPS {
		if len(m) == 0 {
			continue
		}
		x.Set++
		x.Map[fmt.Sprintf("tx-%d", q)] = m.List()
		for _, cpu := range m {
			cpuQueues[cpu] = append(cpuQueues[cpu], q)
		}
	}
	if c.topo == nil {
		return x
	}
	irq := txCPUs(n)
	for _, cpu := range c.topo.Online {
		qs := cpuQueues[cpu]
		if len(qs) == 0 {
			x.None++
			continue
		}
		best := 4
		for _, q := range qs {
			at, ok := irq[q]
			if !ok {
				continue
			}
			switch {
			case at == cpu:
				best = min(best, 0)
			case c.topo.Siblings(cpu).Has(at):
				best = min(best, 1)
			case c.topo.NodeOf(at) == c.topo.NodeOf(cpu):
				best = min(best, 2)
			default:
				best = min(best, 3)
			}
		}
		switch best {
		case 0:
			x.Own++
		case 1:
			x.Core++
		case 2, 4:
			x.Node++
		case 3:
			x.Remote++
		}
	}
	return x
}

func rpsReport(n *hw.NIC) RPSReport {
	r := RPSReport{Queues: map[string]string{}, FlowCnt: map[string]int{}}
	for q, m := range n.RPS {
		if len(m) > 0 {
			r.Queues[fmt.Sprintf("rx-%d", q)] = m.List()
			r.On = true
		}
	}
	for q, cnt := range n.RPSFlowCnt {
		if cnt > 0 {
			r.FlowCnt[fmt.Sprintf("rx-%d", q)] = cnt
		}
	}
	return r
}

// instanceIRQs counts the NIC queue interrupts on each instance's CPUs, and
// its fair part of the RSS ones: by its share of the instances' CPUs.
func (c *ctx) instanceIRQs() {
	insts := c.r.Instances
	if len(insts) == 0 {
		return
	}
	split := c.split()
	totalCPUs, totalRSS := 0, 0
	for _, in := range insts {
		totalCPUs += len(in.CPUs)
	}
	for _, nr := range c.r.NICs {
		for q, cpu := range queueCPUs(nr.nic) {
			if nr.rss[q] {
				totalRSS++
			}
			for _, in := range insts {
				if !in.pinned || !in.CPUs.Has(cpu) {
					continue
				}
				if nr.rss[q] {
					in.NICIRQs.RSS++
				} else {
					in.NICIRQs.Other++
				}
			}
		}
	}
	if !split || totalCPUs == 0 {
		return
	}
	for _, in := range insts {
		in.NICIRQs.Share = round1(float64(totalRSS) * float64(len(in.CPUs)) / float64(totalCPUs))
	}
}

func round1(x float64) float64 { return math.Round(x*10) / 10 }

// ------------------------------------------------------------ sockets

// sockets counts each instance's established TCP connections on its
// inbounds, and the UDP ports it draws on.
func (c *ctx) sockets() {
	e := c.e
	insts := c.r.Instances
	if e.udp != nil {
		if u, err := sys.ReadUDPPortUseAt(e.fs.Root, e.udp); err == nil {
			c.udp = u
			c.r.TCP.UDPPool = u.Pool
			for _, in := range insts {
				in.UDP = &UDPUse{IP: in.Egress, Used: u.Used(in.Egress), Pool: u.Pool}
			}
		}
	}
	if e.tcp == nil || len(insts) == 0 {
		return
	}
	if !e.root {
		for _, in := range insts {
			in.Notes = append(in.Notes, "TCP connections: "+needsRoot)
		}
		return
	}
	var owners []sys.PortOwner
	var ports []int
	seen := map[int]bool{}
	read := map[*InstanceReport]bool{}
	for _, in := range insts {
		if in.Config == "" || !path.IsAbs(in.Config) {
			continue
		}
		inbounds, err := configInbounds(e.fs, in.Config)
		if err != nil {
			continue
		}
		read[in] = true
		for _, ib := range inbounds {
			if !seen[ib.Port] {
				seen[ib.Port] = true
				ports = append(ports, ib.Port)
			}
			owners = append(owners, sys.PortOwner{Port: ib.Port, IP: ib.IP, Name: in.Name})
		}
	}
	eps, err := e.tcp(ports)
	if err != nil {
		return
	}
	counts := sys.AttributeTCP(eps, owners)
	for _, in := range insts {
		if read[in] {
			in.TCP = counts[in.Name]
		}
	}
}

type inbound struct {
	Port int
	IP   string
}

// configInbounds reads the TCP-listening inbounds of a core's config: port
// and address, the API inbound and unix sockets left out.
func configInbounds(fs hw.FS, file string) ([]inbound, error) {
	data, err := fs.Read(file)
	if err != nil {
		return nil, err
	}
	var cfg struct {
		Inbounds []struct {
			Tag    string          `json:"tag"`
			Listen string          `json:"listen"`
			Port   json.RawMessage `json:"port"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal([]byte(data), &cfg); err != nil {
		return nil, err
	}
	var out []inbound
	for _, ib := range cfg.Inbounds {
		if ib.Tag == "api" || strings.HasPrefix(ib.Listen, "/") || strings.HasPrefix(ib.Listen, "@") {
			continue
		}
		for _, p := range portsOf(ib.Port) {
			out = append(out, inbound{Port: p, IP: ib.Listen})
		}
	}
	return out, nil
}

// portsOf reads an inbound's port: a number, or a string of numbers and
// ranges ("443", "1000-1010,2000").
func portsOf(raw json.RawMessage) []int {
	var n int
	if json.Unmarshal(raw, &n) == nil {
		if n > 0 && n <= 65535 {
			return []int{n}
		}
		return nil
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return nil
	}
	var out []int
	for _, part := range strings.Split(s, ",") {
		lo, hi, isRange := strings.Cut(strings.TrimSpace(part), "-")
		a, err := strconv.Atoi(lo)
		if err != nil {
			continue
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil {
				continue
			}
		}
		for p := max(a, 1); p <= min(b, 65535); p++ {
			out = append(out, p)
		}
	}
	return out
}

// ------------------------------------------------------------ TCP limits

func (c *ctx) tcp() {
	fs := c.e.fs
	t := &c.r.TCP
	stat := func(file, proto string) map[string]int64 {
		for _, l := range strings.Split(fs.ReadTrim(file), "\n") {
			p, rest, ok := strings.Cut(l, ":")
			if !ok || p != proto {
				continue
			}
			f := strings.Fields(rest)
			m := map[string]int64{}
			for i := 0; i+1 < len(f); i += 2 {
				m[f[i]], _ = strconv.ParseInt(f[i+1], 10, 64)
			}
			return m
		}
		return nil
	}
	if m := stat("/proc/net/sockstat", "TCP"); m != nil {
		t.InUse, t.Orphans, t.TimeWait, t.MemPages = m["inuse"], m["orphan"], m["tw"], m["mem"]
	}
	if m := stat("/proc/net/sockstat6", "TCP6"); m != nil {
		t.InUse6 = m["inuse"]
	}
	num := func(p string) int64 {
		v, _ := strconv.ParseInt(fs.ReadTrim(p), 10, 64)
		return v
	}
	t.MaxOrphans = num("/proc/sys/net/ipv4/tcp_max_orphans")
	t.MaxTimeWait = num("/proc/sys/net/ipv4/tcp_max_tw_buckets")
	for _, f := range strings.Fields(fs.ReadTrim("/proc/sys/net/ipv4/tcp_mem")) {
		v, _ := strconv.ParseInt(f, 10, 64)
		t.TCPMem = append(t.TCPMem, v)
	}
	ns := readNetstat(fs)
	t.ListenOverflows, t.ListenDrops, t.AbortOnMemory = ns["TcpExt.ListenOverflows"], ns["TcpExt.ListenDrops"], ns["TcpExt.TCPAbortOnMemory"]
	if fs.Exists("/proc/sys/net/netfilter/nf_conntrack_max") {
		t.Conntrack = &Gauge{Count: num("/proc/sys/net/netfilter/nf_conntrack_count"), Max: num("/proc/sys/net/netfilter/nf_conntrack_max")}
	}
	if f := strings.Fields(fs.ReadTrim("/proc/sys/fs/file-nr")); len(f) == 3 {
		g := &Gauge{}
		g.Count, _ = strconv.ParseInt(f[0], 10, 64)
		g.Max, _ = strconv.ParseInt(f[2], 10, 64)
		t.Files = g
	}
}

// readNetstat reads /proc/net/netstat and /proc/net/snmp: "TcpExt.ListenOverflows" -> value.
func readNetstat(fs hw.FS) map[string]uint64 {
	out := map[string]uint64{}
	for _, file := range []string{"/proc/net/netstat", "/proc/net/snmp"} {
		lines := strings.Split(fs.ReadTrim(file), "\n")
		for i := 0; i+1 < len(lines); i++ {
			p1, names, ok1 := strings.Cut(lines[i], ":")
			p2, vals, ok2 := strings.Cut(lines[i+1], ":")
			if !ok1 || !ok2 || p1 != p2 {
				continue
			}
			nf, vf := strings.Fields(names), strings.Fields(vals)
			if len(nf) != len(vf) {
				continue
			}
			for j := range nf {
				v, err := strconv.ParseUint(vf[j], 10, 64)
				if err == nil {
					out[p1+"."+nf[j]] = v
				}
			}
			i++
		}
	}
	return out
}
