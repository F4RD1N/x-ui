//go:build linux

package diag

import (
	"fmt"
	"strings"
	"testing"
	"time"

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
			f.moveIRQ("eno1", 16, 4)  // CPU 2's queue
			f.moveIRQ("eno1", 34, 4)  // and its sibling 30's: core 2 has none
			f.moveIRQ("eno1", 7, 29)  // RSS queue 7 beside RSS queue 6 on CPU 1
			f.moveIRQ("eno1", 33, 31) // the queue that was on 29
		}, "eno1: RSS interrupts on both threads of 3 cores (1/29, 26/54, 27/55) while 1 core has no queue interrupt: x-ui tune apply"},
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
		}, "irqbalance runs without x-ui's policy script and moves eno1's interrupts: x-ui tune apply, or add --policyscript=/var/lib/x-ui/tune/irqbalance-policy to IRQBALANCE_ARGS"},
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
