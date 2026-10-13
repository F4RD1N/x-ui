//go:build linux

package diag

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/util/hw"
	"github.com/mhsanaei/3x-ui/v2/util/hw/hwtest"
	"github.com/mhsanaei/3x-ui/v2/util/sys"
)

const binDir = "/usr/local/x-ui/bin"

// pciIDs is the part of the PCI database the fixtures' NICs need.
const pciIDs = `# pci.ids (excerpt)
1af4  Red Hat, Inc.
	1000  Virtio network device
	1041  Virtio 1.0 network device
8086  Intel Corporation
	10fb  82599ES 10-Gigabit SFI/SFP+ Network Connection
	1533  I210 Gigabit Network Connection
`

// fakeInst is a running xray core in a fake tree.
type fakeInst struct {
	name    string
	pid     int
	cpus    string
	cores   int
	egress  string
	port    int    // its inbound (on all addresses)
	threads int    // default 40
	rssMiB  int64  // default 512
	fds     int    // default 20
	limit   int64  // default 2097152
	ticks   uint64 // utime+stime before the sample
	busy    uint64 // ticks it adds in the sample
}

// fixture is a fake machine with its xray cores, the network counters,
// and a script for the sample's second snapshot.
type fixture struct {
	t     *testing.T
	b     *hwtest.Built
	e     *env
	clock time.Time
	insts []fakeInst
	tcp   map[sys.LocalEndpoint]int
	udp   []sys.LocalEndpoint
	// during runs between the sample's snapshots.
	during []func()
	ticks  map[int]uint64
}

func newFixture(t *testing.T, m hwtest.Machine) *fixture {
	t.Helper()
	f := &fixture{t: t, b: m.Build(t), clock: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC), ticks: map[int]uint64{},
		tcp: map[sys.LocalEndpoint]int{}}
	f.e = &env{fs: f.b.FS(), eth: f.b.Eth, root: true, exe: "/usr/local/x-ui/x-ui",
		summary: func() []string { return nil },
		now:     func() time.Time { return f.clock },
		sleep: func(d time.Duration) {
			f.clock = f.clock.Add(d)
			for _, fn := range f.during {
				fn()
			}
		},
		tcp: func(ports []int) (map[sys.LocalEndpoint]int, error) {
			out := map[sys.LocalEndpoint]int{}
			for ep, n := range f.tcp {
				for _, p := range ports {
					if p == ep.Port {
						out[ep] = n
					}
				}
			}
			return out, nil
		},
		udp: func(fn func(sys.LocalEndpoint)) error {
			for _, ep := range f.udp {
				fn(ep)
			}
			return nil
		},
	}
	f.netFiles(netCounters{})
	f.b.WriteFile("/usr/share/misc/pci.ids", pciIDs)
	// The panel itself, which diag must not take for a core.
	f.b.WriteFile("/proc/900/cmdline", "/usr/local/x-ui/x-ui\x00")
	f.b.WriteFile("/proc/900/comm", "x-ui\n")
	f.link("/usr/local/x-ui/x-ui", "/proc/900/exe")
	return f
}

func (f *fixture) link(target, at string) {
	f.t.Helper()
	p := f.b.Path(at)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		f.t.Fatal(err)
	}
	os.Remove(p)
	if err := os.Symlink(target, p); err != nil {
		f.t.Fatal(err)
	}
}

// netCounters are the kernel's socket counters and limits; zero values
// take everyday ones.
type netCounters struct {
	inuse, inuse6, orphan, tw, mem int64
	maxOrphans, maxTW              int64
	tcpMem                         string
	overflows, drops, abortMem     uint64
	conntrack, conntrackMax        int64 // max 0: conntrack not loaded
	files, fileMax                 int64
	portRange, reservedPorts       string
}

func (f *fixture) netFiles(n netCounters) {
	b := f.b
	def := func(v *int64, d int64) {
		if *v == 0 {
			*v = d
		}
	}
	def(&n.inuse, 37000)
	def(&n.orphan, 12)
	def(&n.tw, 4100)
	def(&n.mem, 12000)
	def(&n.maxOrphans, 262144)
	def(&n.maxTW, 2000000)
	def(&n.files, 41000)
	def(&n.fileMax, 9223372036854775807)
	def(&n.inuse6, 1200)
	if n.tcpMem == "" {
		n.tcpMem = "1487430\t1983242\t2974860"
	}
	if n.portRange == "" {
		n.portRange = "10000\t65535"
	}
	b.WriteFile("/proc/net/sockstat", fmt.Sprintf("sockets: used %d\nTCP: inuse %d orphan %d tw %d alloc %d mem %d\nUDP: inuse 6000 mem 300\nUDPLITE: inuse 0\nRAW: inuse 0\nFRAG: inuse 0 memory 0\n",
		n.inuse+7000, n.inuse, n.orphan, n.tw, n.inuse+100, n.mem))
	b.WriteFile("/proc/net/sockstat6", fmt.Sprintf("TCP6: inuse %d\nUDP6: inuse 40\nUDPLITE6: inuse 0\nRAW6: inuse 0\nFRAG6: inuse 0 memory 0\n", n.inuse6))
	b.WriteFile("/proc/sys/net/ipv4/tcp_max_orphans", fmt.Sprintf("%d\n", n.maxOrphans))
	b.WriteFile("/proc/sys/net/ipv4/tcp_max_tw_buckets", fmt.Sprintf("%d\n", n.maxTW))
	b.WriteFile("/proc/sys/net/ipv4/tcp_mem", n.tcpMem+"\n")
	b.WriteFile("/proc/sys/net/ipv4/ip_local_port_range", n.portRange+"\n")
	b.WriteFile("/proc/sys/net/ipv4/ip_local_reserved_ports", n.reservedPorts+"\n")
	b.WriteFile("/proc/sys/fs/file-nr", fmt.Sprintf("%d\t0\t%d\n", n.files, n.fileMax))
	f.netstat(n.overflows, n.drops, n.abortMem)
	if n.conntrackMax > 0 {
		b.WriteFile("/proc/sys/net/netfilter/nf_conntrack_max", fmt.Sprintf("%d\n", n.conntrackMax))
		b.WriteFile("/proc/sys/net/netfilter/nf_conntrack_count", fmt.Sprintf("%d\n", n.conntrack))
	} else {
		os.RemoveAll(b.Path("/proc/sys/net/netfilter"))
	}
}

func (f *fixture) netstat(overflows, drops, abortMem uint64) {
	f.b.WriteFile("/proc/net/netstat", fmt.Sprintf("TcpExt: SyncookiesSent ListenOverflows ListenDrops TCPAbortOnMemory\nTcpExt: 0 %d %d %d\nIpExt: InOctets\nIpExt: 0\n",
		overflows, drops, abortMem))
}

// addInstances writes the cores' processes, their configs and the panel's
// instances.json.
func (f *fixture) addInstances(allowed string, insts ...fakeInst) {
	f.t.Helper()
	b := f.b
	file := &hw.Instances{Version: 1, Allowed: allowed}
	for i, in := range insts {
		if in.pid == 0 {
			in.pid = 2001 + i
		}
		if in.threads == 0 {
			in.threads = 40
		}
		if in.rssMiB == 0 {
			in.rssMiB = 512
		}
		if in.fds == 0 {
			in.fds = 20
		}
		if in.limit == 0 {
			in.limit = 2097152
		}
		if in.port == 0 {
			in.port = 443 + i + 1
		}
		if in.ticks == 0 {
			in.ticks = 100000
		}
		insts[i] = in
		slug := in.name
		cfg := binDir + "/config-" + slug + ".json"
		d := fmt.Sprintf("/proc/%d", in.pid)
		b.WriteFile(d+"/cmdline", "bin/xray-linux-amd64\x00-c\x00bin/config-"+slug+".json\x00")
		b.WriteFile(d+"/comm", "xray-linux-amd6\n")
		f.link(binDir+"/xray-linux-amd64", d+"/exe")
		f.link("/usr/local/x-ui", d+"/cwd")
		b.WriteFile(d+"/status", fmt.Sprintf("Name:\txray-linux-amd6\nState:\tS (sleeping)\nPid:\t%d\nVmRSS:\t  %d kB\nThreads:\t%d\nCpus_allowed:\tff\nCpus_allowed_list:\t%s\n",
			in.pid, in.rssMiB*1024, in.threads, in.cpus))
		f.ticks[in.pid] = in.ticks
		f.writeStat(in.pid, in.threads)
		b.WriteFile(d+"/limits", fmt.Sprintf("Limit                     Soft Limit           Hard Limit           Units     \nMax cpu time              unlimited            unlimited            seconds   \nMax open files            %d              %d              files     \nMax processes             unlimited            unlimited            processes \n",
			in.limit, in.limit))
		for fd := 0; fd < in.fds; fd++ {
			b.WriteFile(fmt.Sprintf("%s/fd/%d", d, fd), "")
		}
		b.WriteFile(cfg, fmt.Sprintf(`{"inbounds":[{"tag":"api","listen":"127.0.0.1","port":%d,"protocol":"tunnel"},{"tag":"in-%d","listen":"","port":%d,"protocol":"vless"}]}`,
			62789+i, in.port, in.port))
		file.Instances = append(file.Instances, hw.Instance{Name: in.name, CPUs: in.cpus, Cores: in.cores, Config: cfg, Egress: in.egress})
		f.during = append(f.during, func() {
			f.ticks[in.pid] += in.busy
			f.writeStat(in.pid, in.threads)
		})
	}
	f.insts = append(f.insts, insts...)
	b.WriteFile(hw.InstancesPath(binDir), string(file.Marshal()))
}

func (f *fixture) writeStat(pid, threads int) {
	t := f.ticks[pid]
	ut, st := t*2/3, t-t*2/3
	f.b.WriteFile(fmt.Sprintf("/proc/%d/stat", pid), fmt.Sprintf("%d (xray-linux-amd6) S 900 %d %d 0 -1 4194560 1000 0 0 0 %d %d 0 0 20 0 %d 0 12345 2000000000 131072 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0\n",
		pid, pid, pid, ut, st, threads))
}

// cpuLoad scripts the sample's CPU time: every CPU gets 300 ticks (3 s), of
// which softirq ones on the listed CPUs and the rest busy as given.
func (f *fixture) cpuLoad(softirq map[int]uint64, base uint64, busy uint64, steal uint64) {
	f.during = append(f.during, func() {
		for _, cpu := range f.online() {
			s := base
			if v, ok := softirq[cpu]; ok {
				s = v
			}
			user, system := 1000+busy*2/3, 500+busy-busy*2/3
			f.b.SetCPUTimes(cpu, user, system, 50+s, steal, 100000+300-busy-s-steal)
		}
	})
}

func (f *fixture) online() []int {
	l, _ := hw.ParseList(f.b.ReadFile("/sys/devices/system/cpu/online"))
	return l
}

// traffic scripts the NIC's counters: packets per queue in the sample, with
// the bytes and totals that follow.
func (f *fixture) traffic(dev string, perQueue func(q int) uint64, queues int) {
	b := f.b
	f.during = append(f.during, func() {
		var total uint64
		for q := 0; q < queues; q++ {
			n := perQueue(q)
			total += n
			k := fmt.Sprintf("rx_queue_%d_packets", q)
			b.SetStat(dev, k, b.Eth.Devs[dev].Stats[k]+n)
		}
		b.SetStat(dev, "rx_packets", 1000000+total)
		b.SetStat(dev, "tx_packets", 1000000+total*9/10)
		b.SetStat(dev, "rx_bytes", 1000000000+total*1250)
		b.SetStat(dev, "tx_bytes", 1000000000+total*1100)
	})
}

// run runs diag with these arguments and returns its output.
func (f *fixture) run(args ...string) string {
	f.t.Helper()
	var out, errOut strings.Builder
	if rc := run(f.e, args, "2.9.0-test", &out, &errOut); rc != 0 {
		f.t.Fatalf("x-ui diag %v: exit %d: %s", args, rc, errOut.String())
	}
	return out.String()
}

// gather runs diag's steps and returns the run, for tests of its parts.
func (f *fixture) gather(seconds int) *ctx {
	c := f.e.gather("2.9.0-test", true)
	if seconds > 0 {
		c.sample(seconds)
	}
	c.r.Seconds = seconds
	c.r.Warnings = c.warnings()
	return c
}

// ------------------------------------------------------------ machines

// productionSplitToday is the x-ui production server as it ran before the
// NUMA-aware split: xray-N on CPUs 5(N-1)..5N-1, RSS interrupts on
// 11,13,...,41, UDP hashed on IPs, Flow Director overflowing.
func productionToday(t *testing.T) *fixture {
	f := newFixture(t, hwtest.Production())
	var insts []fakeInst
	for n := 1; n <= 10; n++ {
		lo := 5 * (n - 1)
		insts = append(insts, fakeInst{name: fmt.Sprintf("xray-%d", n), cpus: fmt.Sprintf("%d-%d", lo, lo+4), cores: 5,
			egress: fmt.Sprintf("76.164.201.%d", 34+n), busy: 450})
	}
	f.addInstances("0-55", insts...)
	f.productionLoad([]int{11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31, 33, 35, 37, 39, 41})
	f.b.SetStat("eno1", "fdir_overflow", 60808)
	f.b.SetStat("eno1", "rx_missed_errors", 175000)
	f.during = append(f.during, func() { f.b.SetStat("eno1", "fdir_overflow", 60811) })
	return f
}

// productionLoad is the production sample: 7% softirq on the RSS CPUs,
// 1.3% elsewhere; RSS queues 0-15 get 80% of the packets.
func (f *fixture) productionLoad(rssCPUs []int) {
	soft := map[int]uint64{}
	for _, c := range rssCPUs {
		soft[c] = 21
	}
	f.cpuLoad(soft, 4, 60, 0)
	f.traffic("eno1", func(q int) uint64 {
		if q < 16 {
			return 150000
		}
		return 15000
	}, 56)
	for i := 0; i < 10; i++ {
		f.tcp[sys.LocalEndpoint{IP: "76.164.201.34", Port: 444 + i}] = 3700 + 10*i
		for p := 0; p < 50; p++ {
			f.udp = append(f.udp, sys.LocalEndpoint{IP: fmt.Sprintf("76.164.201.%d", 35+i), Port: 20000 + p})
		}
	}
	f.tcp[sys.LocalEndpoint{IP: "127.0.0.1", Port: 62789}] = 2 // the API: nobody's inbound
	f.netFiles(netCounters{conntrack: 74000, conntrackMax: 8388608})
}

// afterCPUs is the NUMA-aware split of 10 instances of 5 CPUs on
// production (spec section 3).
var afterCPUs = []string{"1,3,5,29,31", "7,9,33,35,37", "11,13,15,39,41", "17,19,43,45,47", "21,23,25,49,51",
	"0,2,4,28,30", "6,8,32,34,36", "10,12,14,38,40", "16,18,42,44,46", "20,22,24,48,50"}

// afterRSS is where the NIC tuning puts RSS queues 0-15 for that split
// (spec section 5.6): 6 on the free CPUs, then one per instance.
var afterRSS = []int{27, 26, 55, 54, 53, 52, 1, 7, 11, 17, 21, 0, 6, 10, 16, 20}

// productionAfter is production after the update and "x-ui tune apply":
// node-pure instances, one RSS interrupt each, every other queue on its own
// CPU, XPS one to one, UDP hashed on ports, irqbalance banned from eno1.
func productionAfter(t *testing.T) *fixture {
	m := hwtest.Production()
	eff := append([]int(nil), afterRSS...)
	used := hw.NewCPUSet(afterRSS...)
	for cpu := 0; cpu < 56; cpu++ {
		if !used.Has(cpu) {
			eff = append(eff, cpu)
		}
	}
	m.NICs[0].Effective = eff
	m.NICs[0].Hash["udp4"] = hw.HashIPsPorts
	m.NICs[0].Hash["udp6"] = hw.HashIPsPorts
	f := newFixture(t, m)
	b := f.b
	for q, irq := range b.QueueIRQs("eno1") {
		b.WriteFile(fmt.Sprintf("/proc/irq/%d/smp_affinity_list", irq), fmt.Sprintf("%d\n", eff[q]))
		b.WriteFile(fmt.Sprintf("/sys/class/net/eno1/queues/tx-%d/xps_cpus", q), hw.CPUSet{eff[q]}.Mask(56)+"\n")
	}
	b.Settle()
	b.WriteFile("/var/lib/x-ui/tune/state.json", `{"version": 1, "nics": {"0000:82:00.0": {"name": "eno1", "driver": "ixgbe"}}}`+"\n")
	b.WriteFile("/var/lib/x-ui/tune/irqbalance-policy", "#!/bin/sh\n# Written by x-ui tune\ncase \"${1##*/}\" in\n0000:82:00.0) echo ban=true ;;\nesac\nexit 0\n")
	b.WriteFile("/etc/systemd/system/irqbalance.service.d/90-x-ui.conf", "# Written by x-ui tune\n[Service]\nEnvironmentFile=-/var/lib/x-ui/tune/irqbalance.env\n")
	b.WriteFile("/var/lib/x-ui/tune/irqbalance.env", "# Written by x-ui tune\nIRQBALANCE_ARGS=\"--policyscript=/var/lib/x-ui/tune/irqbalance-policy\"\n")
	var insts []fakeInst
	for n := 1; n <= 10; n++ {
		insts = append(insts, fakeInst{name: fmt.Sprintf("xray-%d", n), cpus: afterCPUs[n-1], cores: 5,
			egress: fmt.Sprintf("76.164.201.%d", 34+n), busy: 450})
	}
	f.addInstances("0-55", insts...)
	f.productionLoad(afterRSS)
	f.b.SetStat("eno1", "fdir_overflow", 60808)
	f.b.SetStat("eno1", "rx_missed_errors", 175000)
	return f
}
