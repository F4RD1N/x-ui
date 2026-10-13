//go:build linux

package diag

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v2/util/hw"
)

// Sample is what changed between two snapshots some seconds apart.
type Sample struct {
	Seconds float64     `json:"seconds"`
	CPUs    []CPUSample `json:"cpus"`
	Busy    float64     `json:"busy"`    // average over the CPUs, %
	Softirq float64     `json:"softirq"` // %
	Steal   float64     `json:"steal"`   // %
	NICs    []NICSample `json:"nics"`
	Softnet Softnet     `json:"softnet"`
	Listen  struct {
		Overflows uint64 `json:"overflows"`
		Drops     uint64 `json:"drops"`
	} `json:"listen"`
	AbortOnMemory uint64 `json:"abort_on_memory"`
}

// CPUSample is one CPU's time, in % of the sample. Busy is all but idle,
// I/O wait and steal.
type CPUSample struct {
	CPU     int     `json:"cpu"`
	Busy    float64 `json:"busy"`
	Softirq float64 `json:"softirq"`
	Steal   float64 `json:"steal"`
}

// NICSample is one NIC's traffic.
type NICSample struct {
	Name     string             `json:"name"`
	RxBps    float64            `json:"rx_bps"`
	TxBps    float64            `json:"tx_bps"`
	RxPps    float64            `json:"rx_pps"`
	TxPps    float64            `json:"tx_pps"`
	Dropped  uint64             `json:"dropped"` // rx_dropped + tx_dropped
	Errors   uint64             `json:"errors"`  // rx_errors + tx_errors
	Counters map[string]Counter `json:"counters"`
	Queues   []QueueSample      `json:"queues"`
	RSSShare *float64           `json:"rss_share,omitempty"` // % of RX packets the hashed queues got
	ShareAll bool               `json:"rss_share_since_boot,omitempty"`
}

// Counter is a driver counter: its growth in the sample and its total.
type Counter struct {
	Delta uint64 `json:"delta"`
	Total uint64 `json:"total"`
}

// QueueSample is one receive queue.
type QueueSample struct {
	Q       int     `json:"q"`
	RxPps   float64 `json:"rx_pps"`
	IRQRate float64 `json:"irq_rate"` // its interrupts per second
	RSS     bool    `json:"rss"`

	total, delta uint64
}

// Softnet is /proc/net/softnet_stat summed over the CPUs.
type Softnet struct {
	Drops        uint64  `json:"drops"`
	Squeeze      uint64  `json:"squeeze"`
	SqueezeRate  float64 `json:"squeeze_per_second"`
	DropsTotal   uint64  `json:"drops_total"`
	SqueezeTotal uint64  `json:"squeeze_total"`
}

type snap struct {
	at      time.Time
	cpu     map[int][8]uint64            // user nice system idle iowait irq softirq steal
	softnet map[int][2]uint64            // dropped, time_squeeze
	stats   map[string]map[string]uint64 // NIC -> sysfs statistics
	eth     map[string]map[string]uint64 // NIC -> ethtool counters
	irqs    map[int]uint64
	netstat map[string]uint64
	ticks   map[int]uint64 // pid -> utime+stime
}

// dropCounter matches the driver counters that count lost packets (and a
// cloud provider's limits that were hit; not ENA's *_allowance_available
// gauges).
var dropCounter = regexp.MustCompile(`missed|no_buffer|no_dma|out_of_buffer|discard|fifo|overflow|allowance_exceeded`)

// queueCounters are the drivers' per-queue receive packet counters.
var queueCounters = []*regexp.Regexp{
	regexp.MustCompile(`^rx_queue_(\d+)_packets$`),      // ixgbe, igb, igc, virtio_net
	regexp.MustCompile(`^rx(\d+)_packets$`),             // mlx5_core
	regexp.MustCompile(`^rx-(\d+)\.packets$`),           // i40e, ice
	regexp.MustCompile(`^\[(\d+)\]: rx_ucast_packets$`), // bnxt_en
	regexp.MustCompile(`^queue_(\d+)_rx_cnt$`),          // ena
}

func queueOf(counter string) (int, bool) {
	for _, re := range queueCounters {
		if m := re.FindStringSubmatch(counter); m != nil {
			q, err := strconv.Atoi(m[1])
			return q, err == nil
		}
	}
	return 0, false
}

func (c *ctx) snapshot() *snap {
	fs := c.e.fs
	s := &snap{at: c.e.now(), cpu: map[int][8]uint64{}, softnet: map[int][2]uint64{}, stats: map[string]map[string]uint64{},
		eth: map[string]map[string]uint64{}, irqs: map[int]uint64{}, ticks: map[int]uint64{}}
	for _, l := range strings.Split(fs.ReadTrim("/proc/stat"), "\n") {
		f := strings.Fields(l)
		if len(f) < 9 || !strings.HasPrefix(f[0], "cpu") || f[0] == "cpu" {
			continue
		}
		cpu, err := strconv.Atoi(f[0][3:])
		if err != nil {
			continue
		}
		var v [8]uint64
		for i := range v {
			v[i], _ = strconv.ParseUint(f[1+i], 10, 64)
		}
		s.cpu[cpu] = v
	}
	var online hw.CPUSet
	if c.topo != nil {
		online = c.topo.Online
	}
	for i, l := range strings.Split(fs.ReadTrim("/proc/net/softnet_stat"), "\n") {
		f := strings.Fields(l)
		if len(f) < 3 {
			continue
		}
		cpu := -1
		if len(f) >= 13 {
			if v, err := strconv.ParseUint(f[12], 16, 32); err == nil {
				cpu = int(v)
			}
		} else if i < len(online) {
			cpu = online[i]
		}
		if cpu < 0 {
			continue
		}
		d, _ := strconv.ParseUint(f[1], 16, 64)
		q, _ := strconv.ParseUint(f[2], 16, 64)
		s.softnet[cpu] = [2]uint64{d, q}
	}
	for _, nr := range c.r.NICs {
		m := map[string]uint64{}
		for _, k := range []string{"rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "rx_dropped", "tx_dropped", "rx_errors", "tx_errors"} {
			m[k], _ = strconv.ParseUint(fs.ReadTrim("/sys/class/net/"+nr.Name+"/statistics/"+k), 10, 64)
		}
		s.stats[nr.Name] = m
		if st, err := c.e.eth.Stats(nr.Name); err == nil {
			s.eth[nr.Name] = st
		}
	}
	if counts, err := hw.ReadInterrupts(fs); err == nil {
		for irq, ic := range counts {
			var n uint64
			for _, v := range ic.PerCPU {
				n += v
			}
			s.irqs[irq] = n
		}
	}
	s.netstat = readNetstat(fs)
	for _, in := range c.r.Instances {
		if t, ok := procTicks(fs, in.PID); ok {
			s.ticks[in.PID] = t
		}
	}
	return s
}

// sample takes two snapshots seconds apart and fills in the report.
func (c *ctx) sample(seconds int) {
	c.a = c.snapshot()
	c.e.sleep(time.Duration(seconds) * time.Second)
	c.b = c.snapshot()
	a, b := c.a, c.b
	secs := b.at.Sub(a.at).Seconds()
	if secs <= 0 {
		secs = float64(seconds)
	}
	s := &Sample{Seconds: round1(secs), CPUs: []CPUSample{}, NICs: []NICSample{}}
	c.r.Sample = s

	// CPUs.
	var cpus []int
	for cpu := range b.cpu {
		cpus = append(cpus, cpu)
	}
	sort.Ints(cpus)
	softirq := map[int]float64{}
	var sumBusy, sumSoft, sumSteal float64
	for _, cpu := range cpus {
		va, vb := a.cpu[cpu], b.cpu[cpu]
		var d [8]uint64
		var total uint64
		for i := range d {
			if vb[i] > va[i] {
				d[i] = vb[i] - va[i]
			}
			total += d[i]
		}
		cs := CPUSample{CPU: cpu}
		if total > 0 {
			ft := float64(total)
			cs.Busy = round1(100 * float64(total-d[3]-d[4]-d[7]) / ft)
			cs.Softirq = round1(100 * float64(d[6]) / ft)
			cs.Steal = round1(100 * float64(d[7]) / ft)
		}
		softirq[cpu] = cs.Softirq
		sumBusy += cs.Busy
		sumSoft += cs.Softirq
		sumSteal += cs.Steal
		s.CPUs = append(s.CPUs, cs)
	}
	if n := float64(len(cpus)); n > 0 {
		s.Busy, s.Softirq, s.Steal = round1(sumBusy/n), round1(sumSoft/n), round1(sumSteal/n)
	}

	// NICs.
	for _, nr := range c.r.NICs {
		sa, sb := a.stats[nr.Name], b.stats[nr.Name]
		d := func(k string) uint64 { return sub(sb[k], sa[k]) }
		ns := NICSample{Name: nr.Name, Counters: map[string]Counter{}, Queues: []QueueSample{},
			RxBps: round1(float64(d("rx_bytes")) * 8 / secs), TxBps: round1(float64(d("tx_bytes")) * 8 / secs),
			RxPps: round1(float64(d("rx_packets")) / secs), TxPps: round1(float64(d("tx_packets")) / secs),
			Dropped: d("rx_dropped") + d("tx_dropped"), Errors: d("rx_errors") + d("tx_errors")}
		ea, eb := a.eth[nr.Name], b.eth[nr.Name]
		byQ := map[int]*QueueSample{}
		for k, vb := range eb {
			if dropCounter.MatchString(k) {
				ns.Counters[k] = Counter{Delta: sub(vb, ea[k]), Total: vb}
			}
			if q, ok := queueOf(k); ok {
				qs := &QueueSample{Q: q, RSS: nr.rss[q], total: vb, delta: sub(vb, ea[k])}
				qs.RxPps = round1(float64(qs.delta) / secs)
				byQ[q] = qs
			}
		}
		for _, ir := range nr.IRQs {
			if ir.Kind == "tx" {
				continue
			}
			qs := byQ[ir.Queue]
			if qs == nil {
				qs = &QueueSample{Q: ir.Queue, RSS: nr.rss[ir.Queue]}
				byQ[ir.Queue] = qs
			}
			qs.IRQRate = round1(float64(sub(b.irqs[ir.IRQ], a.irqs[ir.IRQ])) / secs)
		}
		var qs []int
		for q := range byQ {
			qs = append(qs, q)
		}
		sort.Ints(qs)
		var rssD, allD, rssT, allT uint64
		for _, q := range qs {
			x := byQ[q]
			ns.Queues = append(ns.Queues, *x)
			allD += x.delta
			allT += x.total
			if x.RSS {
				rssD += x.delta
				rssT += x.total
			}
		}
		// The hashed queues' part of the received packets: worth saying
		// only when some queues are not hashed (Flow Director, aRFS).
		if nr.RSS != nil && nr.RSS.Queues < nr.Queues && allT > 0 {
			var share float64
			if allD > 0 {
				share = 100 * float64(rssD) / float64(allD)
			} else {
				share = 100 * float64(rssT) / float64(allT)
				ns.ShareAll = true
			}
			share = round1(share)
			ns.RSSShare = &share
		}
		s.NICs = append(s.NICs, ns)
	}

	// softnet: packets dropped because a CPU's backlog was full, and how
	// often a CPU's packet budget ran out.
	for cpu, vb := range b.softnet {
		va := a.softnet[cpu]
		s.Softnet.Drops += sub(vb[0], va[0])
		s.Softnet.Squeeze += sub(vb[1], va[1])
		s.Softnet.DropsTotal += vb[0]
		s.Softnet.SqueezeTotal += vb[1]
	}
	s.Softnet.SqueezeRate = round1(float64(s.Softnet.Squeeze) / secs)
	s.Listen.Overflows = sub(b.netstat["TcpExt.ListenOverflows"], a.netstat["TcpExt.ListenOverflows"])
	s.Listen.Drops = sub(b.netstat["TcpExt.ListenDrops"], a.netstat["TcpExt.ListenDrops"])
	s.AbortOnMemory = sub(b.netstat["TcpExt.TCPAbortOnMemory"], a.netstat["TcpExt.TCPAbortOnMemory"])
	c.r.TCP.ListenOverflows, c.r.TCP.ListenDrops = b.netstat["TcpExt.ListenOverflows"], b.netstat["TcpExt.ListenDrops"]
	c.r.TCP.AbortOnMemory = b.netstat["TcpExt.TCPAbortOnMemory"]

	// Instances: CPU time over their own CPUs, and the softirq time there.
	for _, in := range c.r.Instances {
		ta, ok1 := a.ticks[in.PID]
		tb, ok2 := b.ticks[in.PID]
		n := len(in.CPUs)
		if ok1 && ok2 && n > 0 {
			pct := round1(100 * float64(sub(tb, ta)) / clockTicks / secs / float64(n))
			in.CPUPct = &pct
		}
		if n > 0 && len(softirq) > 0 {
			var sum float64
			for _, cpu := range in.CPUs {
				sum += softirq[cpu]
			}
			pct := round1(sum / float64(n))
			in.SoftirqPct = &pct
		}
	}
}

// clockTicks is USER_HZ, the unit of /proc's CPU times: 100 on every
// architecture x-ui ships for.
const clockTicks = 100.0

func sub(b, a uint64) uint64 {
	if b > a {
		return b - a
	}
	return 0
}

// hottest lists the busiest CPUs of the sample (at most n, busy ones only).
func (s *Sample) hottest(n int) []CPUSample {
	cs := append([]CPUSample(nil), s.CPUs...)
	sort.SliceStable(cs, func(i, j int) bool {
		if cs[i].Busy != cs[j].Busy {
			return cs[i].Busy > cs[j].Busy
		}
		return cs[i].Softirq > cs[j].Softirq
	})
	var out []CPUSample
	for _, x := range cs {
		if len(out) == n || x.Busy <= 0 {
			break
		}
		out = append(out, x)
	}
	return out
}

// queuesOn names the NIC queues whose interrupt runs on a CPU: "eno1 q3".
func (c *ctx) queuesOn(cpu int) string {
	var out []string
	for _, nr := range c.r.NICs {
		var qs []int
		for q, at := range queueCPUs(nr.nic) {
			if at == cpu {
				qs = append(qs, q)
			}
		}
		sort.Ints(qs)
		for _, q := range qs {
			out = append(out, fmt.Sprintf("%s q%d", nr.Name, q))
		}
	}
	return strings.Join(out, ", ")
}
