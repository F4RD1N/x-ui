package hw

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
)

// Channels is ETHTOOL_GCHANNELS: the queue counts, current and maximum.
type Channels struct {
	MaxRx       uint32 `json:"max_rx"`
	MaxTx       uint32 `json:"max_tx"`
	MaxOther    uint32 `json:"max_other"`
	MaxCombined uint32 `json:"max_combined"`
	Rx          uint32 `json:"rx"`
	Tx          uint32 `json:"tx"`
	Other       uint32 `json:"other"`
	Combined    uint32 `json:"combined"`
}

// QueueIRQ is the interrupt of one queue (or of its receive or transmit half).
type QueueIRQ struct {
	IRQ       int    `json:"irq"`
	Name      string `json:"name"`
	Queue     int    `json:"queue"`
	Kind      string `json:"kind"`                // "txrx", "rx", "tx"
	Affinity  CPUSet `json:"affinity"`            // smp_affinity_list
	Effective CPUSet `json:"effective,omitempty"` // effective_affinity_list (nil before 4.15)
	Hint      CPUSet `json:"hint,omitempty"`      // affinity_hint
}

// BondSlave is a NIC's place in a bond.
type BondSlave struct {
	Bond             string `json:"bond"`
	Mode             string `json:"mode"` // "802.3ad", "active-backup", ...
	MIIStatus        string `json:"mii_status"`
	AggregatorID     int    `json:"ad_aggregator_id,omitempty"`
	BondAggregatorID int    `json:"bond_ad_aggregator,omitempty"` // the bond's active aggregator
}

// NIC is a network device with hardware under it, as the kernel and its
// driver describe it.
type NIC struct {
	Name      string   `json:"name"`
	Via       []string `json:"via,omitempty"`    // the devices above it the default route uses (set by UplinkNICs)
	Routes    []Route  `json:"routes,omitempty"` // the default routes through it (set by UplinkNICs)
	Driver    string   `json:"driver"`           // device/driver link basename
	PCI       string   `json:"pci"`              // PCI function; for virtio the parent of virtioN
	Vendor    string   `json:"vendor"`           // "8086"
	Device    string   `json:"device"`           // "10fb"
	Model     string   `json:"model,omitempty"`  // from pci.ids ("" without it)
	Node      int      `json:"node"`             // device/numa_node, -1 unknown
	SpeedMbps int      `json:"speed_mbps"`
	Up        bool     `json:"up"` // IFF_UP
	Carrier   bool     `json:"carrier"`
	VF        bool     `json:"vf,omitempty"` // an SR-IOV virtual function (device/physfn)
	Virtio    bool     `json:"virtio,omitempty"`
	RxQueues  int      `json:"rx_queues"`     // sysfs queues/rx-*
	TxQueues  int      `json:"tx_queues"`     // sysfs queues/tx-*
	TCs       bool     `json:"tcs,omitempty"` // traffic classes split the TX queues: no XPS

	Channels *Channels         `json:"channels,omitempty"` // nil: not supported
	RxRings  int               `json:"rx_rings,omitempty"` // ETHTOOL_GRXRINGS; 0 unknown
	Indir    []uint32          `json:"indir,omitempty"`    // RSS indirection table; nil: unreadable
	Hash     map[string]uint64 `json:"hash"`               // "tcp4", "udp4", "tcp6", "udp6" -> RXH bits; missing when unsupported or 0
	Features map[string]bool   `json:"features,omitempty"` // offloads, by their "ethtool -K" names (report only)

	IRQs        []QueueIRQ `json:"irqs,omitempty"` // queue interrupts, by Queue then Kind
	OtherIRQs   []int      `json:"other_irqs,omitempty"`
	SharedIRQ   bool       `json:"shared_irq,omitempty"`   // one vector serves every queue (virtioN-virtqueues)
	UnknownIRQs bool       `json:"unknown_irqs,omitempty"` // MSI interrupts whose names did not parse: no placement

	XPS        map[int]CPUSet `json:"xps,omitempty"` // tx queue -> xps_cpus
	RPS        map[int]CPUSet `json:"rps,omitempty"` // rx queue -> rps_cpus
	RPSFlowCnt map[int]int    `json:"rps_flow_cnt,omitempty"`

	Bond  *BondSlave `json:"bond,omitempty"`
	Notes []string   `json:"notes,omitempty"`
}

// RXH bits of the RX flow hash (ethtool -n rx-flow-hash).
const (
	RXHL2DA      = 1 << 1
	RXHVLAN      = 1 << 2
	RXHL3Proto   = 1 << 3
	RXHIPSrc     = 1 << 4
	RXHIPDst     = 1 << 5
	RXHL4B01     = 1 << 6
	RXHL4B23     = 1 << 7
	RXHDiscard   = 1 << 31
	HashIPs      = RXHIPSrc | RXHIPDst
	HashIPsPorts = HashIPs | RXHL4B01 | RXHL4B23
)

// irqFiles are /proc/irq/N entries that are not handler names.
var irqFiles = map[string]bool{"affinity_hint": true, "effective_affinity": true, "effective_affinity_list": true,
	"node": true, "smp_affinity": true, "smp_affinity_list": true, "spurious": true}

// pciDir is the device directory of a network device's function (for
// virtio, the PCI device above virtioN), as a system path; "" when the
// device has no hardware under it.
func pciDir(fs FS, name string) string {
	link := "/sys/class/net/" + name + "/device"
	if !fs.Exists(link) {
		return ""
	}
	d := fs.Resolve(link)
	if strings.HasPrefix(path.Base(d), "virtio") && fs.Exists(path.Dir(d)+"/vendor") {
		return path.Dir(d)
	}
	return d
}

func nicNode(fs FS, dir string) int {
	if dir == "" {
		return -1
	}
	n, err := strconv.Atoi(fs.ReadTrim(dir + "/numa_node"))
	if err != nil || n < 0 {
		return -1
	}
	return n
}

func hexID(s string) string { return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x") }

// ReadNIC reads everything about a network device. It never fails: what
// cannot be read stays empty, with a note.
func ReadNIC(fs FS, et Ethtool, name string) *NIC {
	if et == nil {
		et = NoEthtool{}
	}
	n := &NIC{Name: name, Node: -1, Hash: map[string]uint64{}}
	base := "/sys/class/net/" + name
	if !fs.Exists(base) {
		n.Notes = append(n.Notes, "not found")
		return n
	}
	fn := pciDir(fs, name)
	n.Driver = fs.LinkBase(base + "/device/driver")
	n.Virtio = n.Driver == "virtio_net"
	if fn != "" {
		n.PCI = path.Base(fn)
		n.Vendor, n.Device = hexID(fs.ReadTrim(fn+"/vendor")), hexID(fs.ReadTrim(fn+"/device"))
		n.Model = PCIName(fs, n.Vendor, n.Device)
		n.Node = nicNode(fs, fn)
		n.VF = fs.Exists(fn + "/physfn")
	}
	if s, err := strconv.Atoi(fs.ReadTrim(base + "/speed")); err == nil && s > 0 {
		n.SpeedMbps = s
	}
	if f, err := strconv.ParseUint(strings.TrimPrefix(fs.ReadTrim(base+"/flags"), "0x"), 16, 32); err == nil {
		n.Up = f&1 != 0
	}
	n.Carrier = fs.ReadTrim(base+"/carrier") == "1"

	// Queues, XPS and RPS.
	n.XPS, n.RPS, n.RPSFlowCnt = map[int]CPUSet{}, map[int]CPUSet{}, map[int]int{}
	for _, q := range fs.ReadDir(base + "/queues") {
		kind, num, ok := strings.Cut(q, "-")
		i, err := strconv.Atoi(num)
		if !ok || err != nil {
			continue
		}
		d := base + "/queues/" + q
		switch kind {
		case "rx":
			n.RxQueues++
			if s, err := fs.Read(d + "/rps_cpus"); err == nil {
				if m, err := ParseMask(s); err == nil {
					n.RPS[i] = m
				}
			}
			if c, err := strconv.Atoi(fs.ReadTrim(d + "/rps_flow_cnt")); err == nil {
				n.RPSFlowCnt[i] = c
			}
		case "tx":
			n.TxQueues++
			if s, err := fs.Read(d + "/xps_cpus"); err == nil {
				if m, err := ParseMask(s); err == nil {
					n.XPS[i] = m
				}
			}
			// Without traffic classes every queue prints "0".
			if tc := fs.ReadTrim(d + "/traffic_class"); tc != "" && tc != "0" {
				n.TCs = true
			}
		}
	}

	// Driver state through ethtool.
	note := func(what string, err error) {
		if errors.Is(err, ErrNotSupported) {
			n.Notes = append(n.Notes, what+": not supported")
		} else {
			n.Notes = append(n.Notes, fmt.Sprintf("%s: %v", what, err))
		}
	}
	if c, err := et.Channels(name); err == nil {
		n.Channels = &c
	} else {
		note("queue counts", err)
	}
	if r, err := et.RxRings(name); err == nil {
		n.RxRings = r
	}
	if t, err := et.Indir(name); err == nil && len(t) > 0 {
		n.Indir = t
	} else if err != nil {
		note("RSS table", err)
	}
	for _, f := range HashFlows {
		if b, err := et.FlowHash(name, f); err == nil && b != 0 {
			n.Hash[f.String()] = b
		}
	}
	if f, err := et.Features(name); err == nil {
		n.Features = f
	}

	// Interrupts of the function, by name.
	if fn != "" {
		n.readIRQs(fs, fn)
	}

	// Bond membership.
	if fs.Exists(base + "/bonding_slave") {
		b := &BondSlave{Bond: fs.LinkBase(base + "/master")}
		b.MIIStatus = fs.ReadTrim(base + "/bonding_slave/mii_status")
		b.AggregatorID, _ = strconv.Atoi(fs.ReadTrim(base + "/bonding_slave/ad_aggregator_id"))
		if b.Bond != "" {
			mb := "/sys/class/net/" + b.Bond + "/bonding/"
			if f := strings.Fields(fs.ReadTrim(mb + "mode")); len(f) > 0 {
				b.Mode = f[0]
			}
			b.BondAggregatorID, _ = strconv.Atoi(fs.ReadTrim(mb + "ad_aggregator"))
		}
		n.Bond = b
	}
	return n
}

// readIRQs sorts the function's MSI interrupts into queue and other ones.
func (n *NIC) readIRQs(fs FS, fn string) {
	msi := fs.ReadDir(fn + "/msi_irqs")
	if len(msi) == 0 {
		return
	}
	counts, _ := ReadInterrupts(fs)
	for _, s := range msi {
		irq, err := strconv.Atoi(s)
		if err != nil {
			continue
		}
		name := ""
		if c := counts[irq]; c != nil {
			name = c.Name
		}
		if name == "" {
			for _, e := range fs.ReadDir(fmt.Sprintf("/proc/irq/%d", irq)) {
				if !irqFiles[e] {
					name = e
					break
				}
			}
		}
		if name == "" {
			continue // allocated but not in use
		}
		if q, kind, ok := ParseQueueIRQName(name); ok {
			qi := QueueIRQ{IRQ: irq, Name: name, Queue: q, Kind: kind}
			qi.Affinity, qi.Effective, qi.Hint = ReadIRQAffinity(fs, irq)
			n.IRQs = append(n.IRQs, qi)
			continue
		}
		if isSharedIRQName(name) {
			n.SharedIRQ = true
		}
		n.OtherIRQs = append(n.OtherIRQs, irq)
	}
	sort.Slice(n.IRQs, func(i, j int) bool {
		if n.IRQs[i].Queue != n.IRQs[j].Queue {
			return n.IRQs[i].Queue < n.IRQs[j].Queue
		}
		if n.IRQs[i].Kind != n.IRQs[j].Kind {
			return n.IRQs[i].Kind < n.IRQs[j].Kind
		}
		return n.IRQs[i].IRQ < n.IRQs[j].IRQ
	})
	n.dedupIRQs()
	sort.Ints(n.OtherIRQs)
	if len(n.IRQs) == 0 && !n.SharedIRQ && !n.UnknownIRQs && n.Queues() >= 2 {
		n.UnknownIRQs = true
		n.Notes = append(n.Notes, "interrupt names not recognised: their queues are unknown")
	}
}

// Key is how x-ui's tuning state names the NIC: its PCI function
// ("0000:82:00.0"), else its name (a VMBus or platform device's "PCI" is
// not one).
func (n *NIC) Key() string {
	if strings.Count(n.PCI, ":") >= 2 {
		return n.PCI
	}
	return n.Name
}

// dedupIRQs keeps one interrupt per queue and kind (n.IRQs sorted): when
// several claim one, the one named after the device is the queue's and the
// others are not queue interrupts; when that does not tell them apart, the
// queues are unknown (nothing is placed).
func (n *NIC) dedupIRQs() {
	named := func(q QueueIRQ) bool {
		return strings.HasPrefix(q.Name, n.Name+"-") || strings.Contains(q.Name, "-"+n.Name+"-")
	}
	var out []QueueIRQ
	for i := 0; i < len(n.IRQs); {
		j := i + 1
		for j < len(n.IRQs) && n.IRQs[j].Queue == n.IRQs[i].Queue && n.IRQs[j].Kind == n.IRQs[i].Kind {
			j++
		}
		group := n.IRQs[i:j]
		i = j
		if len(group) == 1 {
			out = append(out, group[0])
			continue
		}
		keep := -1
		for k, q := range group {
			if named(q) {
				if keep >= 0 {
					keep = -2
					break
				}
				keep = k
			}
		}
		if keep < 0 {
			n.UnknownIRQs = true
			n.Notes = append(n.Notes, fmt.Sprintf("%d interrupts claim queue %d: its queues are unknown", len(group), group[0].Queue))
			n.IRQs = nil
			return
		}
		out = append(out, group[keep])
		for k, q := range group {
			if k != keep {
				n.OtherIRQs = append(n.OtherIRQs, q.IRQ)
			}
		}
	}
	n.IRQs = out
}

// UplinkNICs reads the NICs under the default routes (see Uplinks), one per
// PCI function (or name, without one).
func UplinkNICs(fs FS, et Ethtool) (nics []*NIC, notes []string) {
	ups, notes := Uplinks(fs)
	seen := map[string]bool{}
	for _, u := range ups {
		n := ReadNIC(fs, et, u.Name)
		key := n.PCI
		if key == "" {
			key = "name:" + n.Name
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		n.Via, n.Routes = u.Via, u.Routes
		nics = append(nics, n)
	}
	return nics, notes
}

// Queues is the NIC's queue count: the combined channels, else the RX
// channels, else the RX queues in sysfs.
func (n *NIC) Queues() int {
	if c := n.Channels; c != nil {
		if c.Combined > 0 {
			return int(c.Combined)
		}
		if c.Rx > 0 {
			return int(c.Rx)
		}
	}
	return n.RxQueues
}

// RSSUse counts the indirection table's entries per queue; nil when the
// table is unreadable.
func (n *NIC) RSSUse() map[int]int {
	if n.Indir == nil {
		return nil
	}
	m := map[int]int{}
	for _, q := range n.Indir {
		m[int(q)]++
	}
	return m
}

// DefaultForm says whether the table is the kernel's default over k queues:
// entry i is i % k.
func DefaultForm(table []uint32, k int) bool {
	if len(table) == 0 || k < 1 {
		return false
	}
	for i, q := range table {
		if int(q) != i%k {
			return false
		}
	}
	return true
}

// EvenOver says whether the table spreads its entries evenly over queues
// 0..k-1 (each gets the floor or the ceiling of size/k) and uses no other.
func EvenOver(table []uint32, k int) bool {
	if len(table) == 0 || k < 1 {
		return false
	}
	use := make([]int, k)
	for _, q := range table {
		if int(q) >= k {
			return false
		}
		use[q]++
	}
	lo, hi := len(table)/k, (len(table)+k-1)/k
	for _, u := range use {
		if u < lo || u > hi {
			return false
		}
	}
	return true
}

// HashLetters writes RXH bits the way ethtool's -N option takes them ("sd",
// "sdfn").
func HashLetters(bits uint64) string {
	var b strings.Builder
	for _, l := range []struct {
		bit uint64
		c   byte
	}{{RXHL2DA, 'm'}, {RXHVLAN, 'v'}, {RXHL3Proto, 't'}, {RXHIPSrc, 's'}, {RXHIPDst, 'd'}, {RXHL4B01, 'f'}, {RXHL4B23, 'n'}, {RXHDiscard, 'r'}} {
		if bits&l.bit != 0 {
			b.WriteByte(l.c)
		}
	}
	return b.String()
}

// HashText says in words what the hash covers.
func HashText(bits uint64) string {
	switch bits {
	case 0:
		return "none"
	case HashIPs:
		return "IPs only"
	case HashIPsPorts:
		return "IPs and ports"
	}
	return HashLetters(bits)
}
