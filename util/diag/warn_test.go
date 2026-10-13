//go:build linux

package diag

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/util/hw"
	"github.com/mhsanaei/3x-ui/v2/util/hw/hwtest"
)

// moveIRQ puts a queue's interrupt on a CPU, as "x-ui tune" or an admin
// would.
func (f *fixture) moveIRQ(dev string, q, cpu int) {
	f.b.WriteFile(fmt.Sprintf("/proc/irq/%d/smp_affinity_list", f.b.QueueIRQs(dev)[q]), fmt.Sprintf("%d\n", cpu))
	f.b.Settle()
}

// pin changes the CPUs a core runs on.
func (f *fixture) pin(pid int, cpus string) {
	d := fmt.Sprintf("/proc/%d/status", pid)
	s := f.b.ReadFile(d)
	i := strings.Index(s, "Cpus_allowed_list:")
	f.b.WriteFile(d, s[:i]+"Cpus_allowed_list:\t"+cpus+"\n")
}

func desktopSplit(t *testing.T, a, b string) *fixture {
	f := newFixture(t, hwtest.Desktop())
	f.addInstances("0-15", fakeInst{name: "xray-1", cpus: a}, fakeInst{name: "xray-2", cpus: b})
	f.cpuLoad(nil, 4, 30, 0)
	return f
}

// One case per warning: the base machine does not have it, the change
// brings it.
func TestWarnings(t *testing.T) {
	vpsRPS := func(t *testing.T) *fixture {
		f := vps2(t)
		f.b.WriteFile("/sys/class/net/eth0/queues/rx-0/rps_cpus", "3\n")
		return f
	}
	for _, c := range []struct {
		name   string
		base   func(*testing.T) *fixture
		change func(f *fixture)
		want   string
	}{
		{"softnet drops", productionAfter, func(f *fixture) {
			f.during = append(f.during, func() { f.b.SetSoftnet(3, 100000, 7, 0) })
		}, "softnet: 7 packets dropped because a CPU's backlog was full: raise net.core.netdev_max_backlog (x-ui tune apply)"},
		{"time_squeeze", productionAfter, func(f *fixture) {
			f.during = append(f.during, func() { f.b.SetSoftnet(3, 100000, 0, 600) })
		}, "softnet: the CPUs ran out of packet budget 200 times a second (time_squeeze)"},
		{"NIC drops", productionAfter, func(f *fixture) {
			f.during = append(f.during, func() { f.b.SetStat("eno1", "rx_missed_errors", 175100) })
		}, "eno1 dropped packets in the sample: rx_missed_errors +100"},
		{"cloud allowance", productionAfter, func(f *fixture) {
			f.during = append(f.during, func() { f.b.SetStat("eno1", "pps_allowance_exceeded", 5) })
		}, "eno1 went over the cloud provider's allowance: pps_allowance_exceeded +5"},
		{"flow director", productionAfter, func(f *fixture) {
			f.during = append(f.during, func() { f.b.SetStat("eno1", "fdir_overflow", 60900) })
		}, "eno1 flow director overflowed (+92): TCP flows fall back to the RSS queues"},
		{"listen overflows", productionAfter, func(f *fixture) {
			f.during = append(f.during, func() { f.netstat(5, 5, 0) })
		}, "TCP listen queues overflowed 5 times: raise net.core.somaxconn (x-ui tune apply)"},
		{"UDP on IPs", productionAfter, func(f *fixture) {
			f.b.Eth.Devs["eno1"].Hash["udp6"] = hw.HashIPs
		}, "eno1 hashes UDP on IP addresses only: x-ui tune apply"},
		{"UDP on IPs, other driver", func(t *testing.T) *fixture { return newFixture(t, hwtest.VLAN()) }, func(f *fixture) {
			f.b.Eth.Devs["eno1"].Hash["udp4"] = hw.HashIPs
		}, "eno1 hashes UDP on IP addresses only (its driver's setting)"},
		{"RPS on many queues", productionAfter, func(f *fixture) {
			f.b.WriteFile("/sys/class/net/eno1/queues/rx-0/rps_cpus", "ff\n")
		}, "eno1 has 56 queues and RPS is on: it moves packets between CPUs for nothing"},
		{"RPS off on one queue", vpsRPS, func(f *fixture) {
			f.b.WriteFile("/sys/class/net/eth0/queues/rx-0/rps_cpus", "0\n")
		}, "eth0 has one queue and RPS is off: one CPU takes all its packets; x-ui tune apply"},
		{"RSS on sibling threads", productionAfter, func(f *fixture) {
			f.moveIRQ("eno1", 7, 29)  // RSS queue 7 beside RSS queue 6 on CPU 1
			f.moveIRQ("eno1", 41, 29) // the queue on 35: core 7/35 has none
		}, "eno1: RSS interrupts on both threads of 1 core (1/29) while 1 core has no queue interrupt: x-ui tune apply"},
		{"RSS uneven", productionAfter, func(f *fixture) {
			f.moveIRQ("eno1", 7, 3)  // xray-2's
			f.moveIRQ("eno1", 8, 5)  // xray-3's
			f.moveIRQ("eno1", 17, 7) // the queue that was on 3
		}, "RSS interrupts uneven: xray-1 holds 3; xray-2, xray-3 none (share 1.6): x-ui tune apply"},
		{"softirq uneven", productionAfter, func(f *fixture) {
			f.cpuLoad(map[int]uint64{1: 60, 3: 60, 5: 60, 29: 60, 31: 60}, 4, 60, 0)
		}, "packet work uneven: xray-1 spends 20% of its CPUs in softirq, xray-2 1.3%"},
		{"irqbalance without the policy", productionAfter, func(f *fixture) {
			f.b.WriteFile("/proc/812/comm", "irqbalance\n")
			f.b.WriteFile("/proc/812/cmdline", "/usr/sbin/irqbalance\x00--foreground\x00")
		}, "irqbalance runs without x-ui's policy script and moves eno1's interrupts: x-ui tune apply (if you set IRQBALANCE_ARGS, add --policyscript=/var/lib/x-ui/tune/irqbalance-policy to it first)"},
		{"XPS on another node", productionAfter, func(f *fixture) {
			f.b.WriteFile("/sys/class/net/eno1/queues/tx-11/xps_cpus", "0\n")
			f.b.WriteFile("/sys/class/net/eno1/queues/tx-0/xps_cpus", hw.CPUSet{0, 27}.Mask(56)+"\n")
		}, "eno1: 1 CPU sends on queues whose interrupt is on another NUMA node (XPS): x-ui tune apply"},
		{"instance spans nodes", productionAfter, func(f *fixture) {
			f.pin(2001, "1,3,5,27,52")
		}, "xray-1 spans NUMA nodes 0 and 1 though one node could hold it"},
		{"instances share cores", func(t *testing.T) *fixture { return desktopSplit(t, "0-7", "8-15") }, func(f *fixture) {
			f.pin(2001, "0,2,4,6,8,10,12,14")
			f.pin(2002, "1,3,5,7,9,11,13,15")
		}, "every xray instance shares more than one physical core with other instances"},
		{"orphans", productionAfter, func(f *fixture) {
			f.netFiles(netCounters{orphan: 140000})
		}, "orphaned TCP sockets: 140000 of 262144 (net.ipv4.tcp_max_orphans): x-ui tune apply"},
		{"TIME_WAIT", productionAfter, func(f *fixture) {
			f.netFiles(netCounters{tw: 1600000})
		}, "TIME_WAIT sockets: 1600000 of 2000000 (net.ipv4.tcp_max_tw_buckets): x-ui tune apply"},
		{"TCP memory", productionAfter, func(f *fixture) {
			f.netFiles(netCounters{mem: 1983242})
		}, "TCP memory: 1983242 pages, past the pressure mark 1983242 (net.ipv4.tcp_mem): x-ui tune apply"},
		{"conntrack", productionAfter, func(f *fixture) {
			f.netFiles(netCounters{conntrack: 7000000, conntrackMax: 8388608})
		}, "conntrack table: 7000000 of 8388608 entries (net.netfilter.nf_conntrack_max)"},
		{"system open files", productionAfter, func(f *fixture) {
			f.netFiles(netCounters{files: 900000, fileMax: 1000000})
		}, "open files on the system: 900000 of 1000000 (fs.file-max)"},
		{"instance open files", productionAfter, func(f *fixture) {
			f.b.WriteFile("/proc/2001/limits", "Max open files            24                   24                   files     \n")
		}, "xray-1 has 20 open files of its limit 24"},
		{"instance UDP ports", productionAfter, func(f *fixture) {
			f.netFiles(netCounters{portRange: "20000 20059"})
		}, "xray-1's UDP sockets hold 50 of 60 local ports of 76.164.201.35"},
		{"instance UDP ports, default address", vps2, func(f *fixture) {
			f.netFiles(netCounters{portRange: "30000 30035"})
		}, "xray-1's UDP sockets hold 30 of 36 local ports of the default address: give it an outgoing IP of its own"},
		{"steal", productionAfter, func(f *fixture) {
			f.cpuLoad(nil, 4, 60, 30)
		}, "steal 10%: the host runs other guests on this VM's CPUs"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if w := c.base(t).gather(3).r.Warnings; contains(w, c.want) {
				t.Fatalf("the base already warns %q:\n%s", c.want, strings.Join(w, "\n"))
			}
			f := c.base(t)
			c.change(f)
			if w := f.gather(3).r.Warnings; !contains(w, c.want) {
				t.Errorf("missing %q in:\n%s", c.want, strings.Join(w, "\n"))
			}
		})
	}
}

// irqbalance started with x-ui's policy script, in each form irqbalance
// takes (the ones "x-ui tune" recognises too), is not warned about.
func TestIRQBalancePolicyForms(t *testing.T) {
	const pol = "/var/lib/x-ui/tune/irqbalance-policy"
	for _, args := range []string{"--policyscript=" + pol, "--policyscript\x00" + pol, "-l" + pol, "-l\x00" + pol} {
		f := productionAfter(t)
		f.b.WriteFile("/proc/812/comm", "irqbalance\n")
		f.b.WriteFile("/proc/812/cmdline", "/usr/sbin/irqbalance\x00--foreground\x00"+args+"\x00")
		c := f.gather(0)
		if !c.irqb.Running || !c.irqb.Policy {
			t.Errorf("%q: running %v, policy %v", args, c.irqb.Running, c.irqb.Policy)
		}
		if contains(c.r.Warnings, "irqbalance runs without") {
			t.Errorf("%q: warned:\n%s", args, strings.Join(c.r.Warnings, "\n"))
		}
	}
}

func contains(list []string, part string) bool {
	for _, s := range list {
		if strings.Contains(s, part) {
			return true
		}
	}
	return false
}

// Without a sample there are no sample warnings, and nothing breaks.
func TestNoSample(t *testing.T) {
	f := productionToday(t)
	f.e.sleep = func(time.Duration) { t.Error("--seconds 0 took a sample") }
	out := f.run("--seconds", "0")
	if strings.Contains(out, "Sample (") || strings.Contains(out, "flow director") || !strings.Contains(out, "RSS interrupts uneven") {
		t.Errorf("--seconds 0:\n%s", out)
	}
	var stderr strings.Builder
	for _, args := range [][]string{{"--seconds", "31"}, {"--seconds", "-1"}, {"extra"}, {"--bogus"}} {
		if rc := run(f.e, args, "x", &strings.Builder{}, &stderr); rc != 1 {
			t.Errorf("%v: exit %d", args, rc)
		}
	}
	var out2 strings.Builder
	if rc := run(f.e, []string{"-h"}, "x", &out2, &stderr); rc != 0 || !strings.Contains(out2.String(), "Usage: x-ui diag") {
		t.Errorf("-h: exit %d: %s", rc, out2.String())
	}
}

// placeIRQs puts a NIC's queue interrupts where hw.PlaceQueues puts them for
// the fixture's instances (what "x-ui tune" does), with XPS to match.
func (f *fixture) placeIRQs(dev string) {
	f.t.Helper()
	topo, err := hw.ReadTopology(f.b.FS())
	if err != nil {
		f.t.Fatal(err)
	}
	n := hw.ReadNIC(f.b.FS(), f.b.Eth, dev)
	var units []hw.Unit
	for _, in := range f.insts {
		units = append(units, hw.Unit{Name: in.name, CPUs: mustList(f.t, in.cpus)})
	}
	var rss []int
	for q := range n.RSSUse() {
		rss = append(rss, q)
	}
	sort.Ints(rss)
	pl := hw.PlaceQueues(topo, topo.Online, units, []hw.PlaceNIC{{NIC: n, RSS: rss}})
	for _, qi := range n.IRQs {
		f.b.WriteFile(fmt.Sprintf("/proc/irq/%d/smp_affinity_list", qi.IRQ), fmt.Sprintf("%d\n", pl.CPU[dev][qi.Queue]))
	}
	for q, cpus := range pl.XPS[dev] {
		f.b.WriteFile(fmt.Sprintf("/sys/class/net/%s/queues/tx-%d/xps_cpus", dev, q), cpus.Mask(len(topo.Online))+"\n")
	}
	f.b.Settle()
}

func mustList(t *testing.T, s string) hw.CPUSet {
	t.Helper()
	l, err := hw.ParseList(s)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// splitInsts is x-ui's own split of these requests on a machine, as
// instances for the fixture.
func splitInsts(t *testing.T, m hwtest.Machine, prefer int, cores ...int) []fakeInst {
	t.Helper()
	topo := hwtest.Topo(t, m)
	var reqs []hw.CPURequest
	for i, c := range cores {
		reqs = append(reqs, hw.CPURequest{Name: fmt.Sprintf("xray-%d", i+1), CPUs: c})
	}
	got := hw.SplitCPUs(topo, topo.Online, prefer, reqs, model.LessInstanceName)
	var out []fakeInst
	for i, c := range cores {
		name := fmt.Sprintf("xray-%d", i+1)
		out = append(out, fakeInst{name: name, cpus: hw.CPUSet(got[name]).List(), cores: c})
	}
	return out
}

// x-ui's own split and placement draw no warning about themselves: a node
// cut by an odd number of autos, the panel's split of odd sizes, RSS
// interrupts placed one per core with 16 or 4 queues.
func TestNoWarningsAboutOwnLayout(t *testing.T) {
	for _, c := range []struct {
		name  string
		m     func() hwtest.Machine
		cores []int
	}{
		{"3 autos", hwtest.Production, []int{0, 0, 0}},
		{"7 autos", hwtest.Production, []int{0, 0, 0, 0, 0, 0, 0}},
		{"11 autos", hwtest.Production, []int{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		{"3,4,4,4,4", hwtest.Production, []int{3, 4, 4, 4, 4}},
		{"1 and 10 autos", hwtest.Production, []int{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		{"10x5, 16 queues", func() hwtest.Machine {
			m := hwtest.Production()
			m.NICs[0].Channels.Combined = 16
			return m
		}, []int{5, 5, 5, 5, 5, 5, 5, 5, 5, 5}},
		{"desktop 7+7", hwtest.Desktop, []int{7, 7}},
	} {
		m := c.m()
		f := newFixture(t, m)
		prefer := hw.UplinkNode(f.b.FS())
		f.addInstances(hwtest.Topo(t, m).Online.List(), splitInsts(t, m, prefer, c.cores...)...)
		f.placeIRQs(m.NICs[0].Name)
		for _, w := range f.gather(0).r.Warnings {
			if strings.Contains(w, "NUMA nodes") || strings.Contains(w, "physical core") || strings.Contains(w, "both threads") {
				t.Errorf("%s: %s", c.name, w)
			}
		}
	}
}

// A core outside the default interrupt affinity is no core "without a
// queue interrupt": x-ui may not put one there.
func TestSiblingWarningEligibleCores(t *testing.T) {
	f := productionAfter(t)
	f.moveIRQ("eno1", 7, 29)  // RSS queue 7 beside RSS queue 6 on CPU 1
	f.moveIRQ("eno1", 41, 29) // the queue on 35: core 7/35 has none
	if w := f.gather(0).r.Warnings; !contains(w, "RSS interrupts on both threads") {
		t.Fatalf("no warning to start from:\n%s", strings.Join(w, "\n"))
	}
	f.b.WriteFile("/proc/irq/default_smp_affinity", hw.NewCPUSet(0, 1, 2, 3, 4, 5, 6).Union(mustList(t, "8-34,36-55")).Mask(56)+"\n")
	if w := f.gather(0).r.Warnings; contains(w, "RSS interrupts on both threads") {
		t.Errorf("warned about a core interrupts may not go to:\n%s", strings.Join(w, "\n"))
	}
}

// RPS beside several queues is advice only with a queue per CPU: with fewer
// queues than CPUs it may spread the work.
func TestRPSAdvice(t *testing.T) {
	for _, c := range []struct {
		cpus, queues int
		warn         bool
	}{{8, 2, false}, {8, 8, true}, {4, 4, true}} {
		m := hwtest.VPS(c.cpus)
		m.NICs[0].Channels = hw.Channels{MaxCombined: uint32(c.queues), Combined: uint32(c.queues)}
		f := newFixture(t, m)
		f.addInstances(fmt.Sprintf("0-%d", c.cpus-1), fakeInst{name: "xray-1", cpus: fmt.Sprintf("0-%d", c.cpus-1)})
		for q := 0; q < c.queues; q++ {
			f.b.WriteFile(fmt.Sprintf("/sys/class/net/eth0/queues/rx-%d/rps_cpus", q), "ff\n")
		}
		if got := contains(f.gather(0).r.Warnings, "RPS is on: it moves packets between CPUs for nothing"); got != c.warn {
			t.Errorf("%d CPUs, %d queues: warned %v", c.cpus, c.queues, got)
		}
	}
}

// ENA's conntrack_allowance_available is a gauge of what is left, not a
// limit that was hit.
func TestENAAllowanceGauge(t *testing.T) {
	m := hwtest.VPS(4)
	m.NICs[0].Driver, m.NICs[0].IRQNames = "ena", "ena"
	m.NICs[0].Stats = map[string]uint64{"conntrack_allowance_available": 250000}
	f := newFixture(t, m)
	f.addInstances("0-3", fakeInst{name: "xray-1", cpus: "0-3"})
	f.during = append(f.during, func() {
		f.b.SetStat("eth0", "conntrack_allowance_available", 251200)
		f.b.SetStat("eth0", "pps_allowance_exceeded", 3)
	})
	c := f.gather(3)
	if contains(c.r.Warnings, "conntrack_allowance_available") || !contains(c.r.Warnings, "went over the cloud provider's allowance: pps_allowance_exceeded +3") {
		t.Errorf("warnings:\n%s", strings.Join(c.r.Warnings, "\n"))
	}
	if _, ok := c.r.Sample.NICs[0].Counters["conntrack_allowance_available"]; ok {
		t.Error("the gauge listed among the drop counters")
	}
}

// x-ui's policy script banning two functions (a bond's slaves): both are
// banned.
func TestPolicyBansEveryFunction(t *testing.T) {
	f := newFixture(t, hwtest.Bond())
	f.b.WriteFile(irqbalancePol, "#!/bin/sh\n# Written by x-ui tune\ncase \"${1##*/}\" in\n0000:82:00.0|0000:82:00.1) echo ban=true ;;\nesac\nexit 0\n")
	c := f.gather(0)
	for _, nr := range c.r.NICs {
		if !nr.IRQBal.Banned {
			t.Errorf("%s (%s) not banned", nr.Name, nr.PCI)
		}
	}
}

// A NIC whose device is not a PCI function (Hyper-V's VMBus): "x-ui tune"
// keys it by name, and diag finds it managed.
func TestManagedNonPCI(t *testing.T) {
	f := newFixture(t, hwtest.VPS(2))
	f.addInstances("0-1", fakeInst{name: "xray-1", cpus: "0-1"})
	guid := "000d3a6e-1111-2222-3333-444455556666"
	f.b.WriteFile("/sys/bus/vmbus/drivers/hv_netvsc/uevent", "")
	f.b.WriteFile("/sys/devices/LNXSYSTM:00/VMBUS:00/"+guid+"/uevent", "")
	f.link("/sys/bus/vmbus/drivers/hv_netvsc", "/sys/devices/LNXSYSTM:00/VMBUS:00/"+guid+"/driver")
	f.link("/sys/devices/LNXSYSTM:00/VMBUS:00/"+guid, "/sys/class/net/eth0/device")
	f.b.WriteFile("/var/lib/x-ui/tune/state.json", `{"version": 1, "nics": {"eth0": {"name": "eth0", "driver": "hv_netvsc"}}}`+"\n")
	c := f.gather(0)
	if len(c.r.NICs) != 1 || c.r.NICs[0].PCI != guid || !c.r.NICs[0].Managed {
		t.Fatalf("NICs %+v", c.r.NICs)
	}
}

// A NIC on dedicated RX and TX channels (bnxt_en's "-L rx 16 tx 16") has
// combined 0: its queues are its RX channels.
func TestDedicatedChannels(t *testing.T) {
	m := hwtest.VPS(16)
	m.NICs[0].Driver = "bnxt_en"
	m.NICs[0].Channels = hw.Channels{MaxRx: 63, MaxTx: 63, MaxCombined: 63, Rx: 16, Tx: 16}
	f := newFixture(t, m)
	f.addInstances("0-15", fakeInst{name: "xray-1", cpus: "0-15"})
	out := f.run("--seconds", "0")
	if !strings.Contains(out, "16 of 63") || strings.Contains(out, "0 of 63") {
		t.Errorf("queues:\n%s", out)
	}
	if c := f.gather(0); c.r.NICs[0].Queues != 16 {
		t.Errorf("queues %d", c.r.NICs[0].Queues)
	}
}
