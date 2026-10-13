package hwtest

import (
	"fmt"
	"net"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/mhsanaei/3x-ui/v2/util/hw"
)

// NICSpec is a network device with hardware under it.
type NICSpec struct {
	Name      string
	Driver    string // ixgbe, igb, igc, i40e, ice, bnxt_en, mlx5_core, virtio_net, enic, ena, ...
	PCI       string // PCI function; for virtio_net the PCI device above virtioN
	Vendor    string // "8086"
	Device    string // "10fb"
	Virtio    int    // virtio_net: N of virtioN (default 1)
	Node      int    // NUMA node; -1 none
	SpeedMbps int    // 0: unknown (-1 in sysfs)
	Down      bool   // not up, no carrier
	VF        bool   // an SR-IOV virtual function

	// Channels are the queue counts; all zero: the driver has no channel
	// settings and the device one queue.
	Channels   hw.Channels
	TableSize  int      // RSS indirection table entries; 0: not supported
	RSSCap     int      // queues the table can address (82599: 16); 0: no limit
	Table      []uint32 // the table; nil: the default, entry i = i % min(queues, cap)
	Configured bool     // Table was set by an admin
	Hash       map[string]uint64
	Features   map[string]bool   // nil: a common set
	Stats      map[string]uint64 // extra ethtool counters

	IRQBase int // first MSI interrupt; 0: after the previous device's
	// IRQNames is the naming of the vectors: "txrx" ("<name>-TxRx-N" and a
	// link vector "<name>"), "i40e", "mlx5", "virtio", "split"
	// ("<name>-rx-N", "<name>-tx-N"), "ena", "unknown". Default by driver.
	IRQNames string
	// Affinity of the queue vectors: "node" (the node's CPUs), "default"
	// (the kernel's default for the device), "hint" (the hint), "managed"
	// (the kernel spreads the vectors and owns them: writes fail with EIO).
	Affinity string
	// Hint: "spread" (cpumask_local_spread, as ixgbe and mlx5 do), "virtio"
	// (virtio_net's CPU groups) or "" (none).
	Hint      string
	Effective []int // per queue; nil: the hint's CPU, else round-robin over the affinity
	// XPS: "hint" (each TX queue on its hint, as ixgbe, mlx5, i40e and
	// virtio_net set it) or "" (none).
	XPS string
	// Extra are more vectors of the function, by name, after the queue
	// vectors: i40e's flow director ("i40e-<pci>:fdir-TxRx-0"), ice's
	// control VSI ("ice-<pci>:ctrl-TxRx-0").
	Extra []string
}

// BondSpec is a bond over NICs.
type BondSpec struct {
	Name   string
	Mode   string // "802.3ad" (default), "active-backup", ...
	Slaves []string
}

// BridgeSpec is a bridge; ports that are not NICs are created as taps.
type BridgeSpec struct {
	Name  string
	Ports []string
}

// VLANSpec is a VLAN device over another device.
type VLANSpec struct {
	Name  string
	Lower string
	ID    int
}

// LinkSpec is a device without hardware: "wireguard", "tun", "veth", "dummy".
type LinkSpec struct {
	Name string
	Kind string
}

// RouteSpec is a default route.
type RouteSpec struct {
	Dev     string
	Gateway string // "" on-link
	V6      bool
	Metric  int
}

type fakeNIC struct {
	spec   NICSpec
	fn     string // the function's device directory (system path)
	dev    string // its "device" (virtioN for virtio_net)
	netDir string
	vecs   []int // the MSI interrupts, in vector order
	rx, tx int   // sysfs queue counts
}

type fakeIRQ struct {
	irq, hwirq          int
	name, chip          string
	node                int
	aff, eff, hint      hw.CPUSet
	counts              map[int]uint64
	queue               int    // -1 for other vectors
	nic                 string // the device name, "" for system interrupts
	managed             bool
	wroteList, wroteMsk string               // the affinity files as last written here
	memo                map[string]hw.CPUSet // affinity -> effective CPUs, so a revert restores them
}

var sysfsStats = []string{"collisions", "multicast", "rx_bytes", "rx_compressed", "rx_crc_errors", "rx_dropped", "rx_errors",
	"rx_fifo_errors", "rx_frame_errors", "rx_length_errors", "rx_missed_errors", "rx_nohandler", "rx_over_errors", "rx_packets",
	"tx_aborted_errors", "tx_bytes", "tx_carrier_errors", "tx_compressed", "tx_dropped", "tx_errors", "tx_fifo_errors",
	"tx_heartbeat_errors", "tx_packets", "tx_window_errors"}

func (s *NICSpec) defaults() {
	if s.Virtio == 0 {
		s.Virtio = 1
	}
	if s.IRQNames == "" {
		s.IRQNames = map[string]string{"i40e": "i40e", "mlx5_core": "mlx5", "virtio_net": "virtio", "enic": "split", "ena": "ena"}[s.Driver]
		if s.IRQNames == "" {
			s.IRQNames = "txrx"
		}
	}
	if s.Affinity == "" {
		s.Affinity = "default"
	}
}

// queuesOf is the count of RX and TX queues the channels give.
func queuesOf(c hw.Channels) (rx, tx int) {
	rx, tx = int(c.Combined+c.Rx), int(c.Combined+c.Tx)
	return max(rx, 1), max(tx, 1)
}

func (b *Built) newIfindex() int {
	b.ifindex++
	return b.ifindex
}

func (b *Built) writeNet() {
	m := b.M
	b.writeVirtual("lo", "", 1, 1)
	b.WriteFile("/sys/devices/virtual/net/lo/flags", "0x9\n")
	for _, s := range m.NICs {
		b.addNIC(s)
	}
	for _, l := range m.Links {
		idx := b.newIfindex()
		link := idx
		if l.Kind == "veth" {
			link = idx + 100 // the peer, in another namespace
		}
		kind := l.Kind
		if kind == "veth" || kind == "dummy" {
			kind = ""
		}
		b.writeVirtual(l.Name, kind, idx, link)
		if l.Kind == "tun" {
			b.WriteFile("/sys/devices/virtual/net/"+l.Name+"/tun_flags", "0x1001\n")
		}
	}
	for _, bo := range m.Bonds {
		mode := bo.Mode
		if mode == "" {
			mode = "802.3ad"
		}
		idx := b.newIfindex()
		b.writeVirtual(bo.Name, "bond", idx, idx)
		d := "/sys/devices/virtual/net/" + bo.Name
		modeNum := map[string]int{"balance-rr": 0, "active-backup": 1, "balance-xor": 2, "broadcast": 3, "802.3ad": 4, "balance-tlb": 5, "balance-alb": 6}[mode]
		b.WriteFile(d+"/bonding/mode", fmt.Sprintf("%s %d\n", mode, modeNum))
		b.WriteFile(d+"/bonding/slaves", strings.Join(bo.Slaves, " ")+"\n")
		b.WriteFile(d+"/bonding/miimon", "100\n")
		if mode == "802.3ad" {
			b.WriteFile(d+"/bonding/ad_aggregator", "1\n")
		}
		for _, s := range bo.Slaves {
			b.linkPair(bo.Name, s)
			sd := b.netDir(s)
			b.symlink(d, sd+"/master")
			b.WriteFile(sd+"/bonding_slave/mii_status", "up\n")
			b.WriteFile(sd+"/bonding_slave/state", "active\n")
			if mode == "802.3ad" {
				b.WriteFile(sd+"/bonding_slave/ad_aggregator_id", "1\n")
			}
		}
	}
	for _, br := range m.Bridges {
		idx := b.newIfindex()
		b.writeVirtual(br.Name, "bridge", idx, idx)
		d := "/sys/devices/virtual/net/" + br.Name
		b.WriteFile(d+"/bridge/stp_state", "0\n")
		for _, p := range br.Ports {
			if _, ok := b.nics[p]; !ok && !b.exists("/sys/class/net/"+p) {
				pi := b.newIfindex()
				b.writeVirtual(p, "", pi, pi)
				b.WriteFile("/sys/devices/virtual/net/"+p+"/tun_flags", "0x1002\n")
			}
			b.linkPair(br.Name, p)
			pd := b.netDir(p)
			b.symlink(d, pd+"/master")
			b.symlink(pd, d+"/brif/"+p)
			b.WriteFile(pd+"/brport/state", "3\n")
		}
	}
	for _, v := range m.VLANs {
		idx := b.newIfindex()
		b.writeVirtual(v.Name, "vlan", idx, b.ifindexOf(v.Lower))
		b.linkPair(v.Name, v.Lower)
	}
	b.writeRoutes()
	b.writeInterrupts()
}

func (b *Built) exists(abs string) bool {
	_, err := os.Lstat(b.Path(abs))
	return err == nil
}

// netDir is a device's directory under /sys/devices.
func (b *Built) netDir(name string) string {
	if n, ok := b.nics[name]; ok {
		return n.netDir
	}
	return "/sys/devices/virtual/net/" + name
}

func (b *Built) ifindexOf(name string) int {
	i, _ := strconv.Atoi(strings.TrimSpace(b.ReadFile(b.netDir(name) + "/ifindex")))
	return i
}

// linkPair links an upper device to a lower one (upper_X in the lower one,
// lower_Y in the upper one).
func (b *Built) linkPair(upper, lower string) {
	ud, ld := b.netDir(upper), b.netDir(lower)
	b.symlink(ld, ud+"/lower_"+lower)
	b.symlink(ud, ld+"/upper_"+upper)
}

// writeNetCommon writes the files every network device has.
func (b *Built) writeNetCommon(name, dir, devtype string, idx, link int, up bool, speed int, rx, tx int) {
	b.symlink(dir, "/sys/class/net/"+name)
	ue := ""
	if devtype != "" {
		ue = "DEVTYPE=" + devtype + "\n"
	}
	b.WriteFile(dir+"/uevent", fmt.Sprintf("%sINTERFACE=%s\nIFINDEX=%d\n", ue, name, idx))
	b.WriteFile(dir+"/ifindex", fmt.Sprintf("%d\n", idx))
	b.WriteFile(dir+"/iflink", fmt.Sprintf("%d\n", link))
	flags, carrier, oper := "0x1003", "1", "up"
	if !up {
		flags, carrier, oper = "0x1002", "0", "down"
	}
	b.WriteFile(dir+"/flags", flags+"\n")
	b.WriteFile(dir+"/carrier", carrier+"\n")
	b.WriteFile(dir+"/operstate", oper+"\n")
	b.WriteFile(dir+"/speed", fmt.Sprintf("%d\n", speed))
	b.WriteFile(dir+"/mtu", "1500\n")
	b.WriteFile(dir+"/type", "1\n")
	b.WriteFile(dir+"/address", fmt.Sprintf("02:00:00:00:00:%02x\n", idx%256))
	for _, s := range sysfsStats {
		v := "0"
		switch s {
		case "rx_packets", "tx_packets":
			v = "1000000"
		case "rx_bytes", "tx_bytes":
			v = "1000000000"
		}
		b.WriteFile(dir+"/statistics/"+s, v+"\n")
	}
	b.writeQueues(dir, rx, tx, nil, "")
}

func (b *Built) writeVirtual(name, devtype string, idx, link int) {
	dir := "/sys/devices/virtual/net/" + name
	speed := -1
	b.writeNetCommon(name, dir, devtype, idx, link, true, speed, 1, 1)
}

// writeQueues makes the queue directories rx-0..rx-1 and tx-0..tx-1, keeping
// the files of queues that exist, and removes the others. With xps "hint",
// every TX queue's XPS mask is set to its hint (what such drivers do when
// they set up their rings).
func (b *Built) writeQueues(dir string, rx, tx int, n *fakeNIC, xps string) {
	for _, q := range []struct {
		kind  string
		count int
	}{{"rx", rx}, {"tx", tx}} {
		for _, e := range ls(b.Path(dir + "/queues")) {
			k, num, _ := strings.Cut(e, "-")
			i, _ := strconv.Atoi(num)
			if k == q.kind && i >= q.count {
				os.RemoveAll(b.Path(dir + "/queues/" + e))
			}
		}
		for i := 0; i < q.count; i++ {
			qd := fmt.Sprintf("%s/queues/%s-%d", dir, q.kind, i)
			if q.kind == "rx" {
				if !b.exists(qd) {
					b.WriteFile(qd+"/rps_cpus", hw.CPUSet(nil).Mask(b.cpus)+"\n")
					b.WriteFile(qd+"/rps_flow_cnt", "0\n")
				}
				continue
			}
			if !b.exists(qd) {
				b.WriteFile(qd+"/tx_timeout", "0\n")
			}
			if tx < 2 {
				// No XPS and no traffic classes on a single queue.
				os.Remove(b.Path(qd + "/xps_cpus"))
				os.Remove(b.Path(qd + "/traffic_class"))
				continue
			}
			if n != nil && xps == "hint" {
				b.WriteFile(qd+"/xps_cpus", b.hintOf(n, i).Mask(b.cpus)+"\n")
			} else if !b.exists(qd + "/xps_cpus") {
				b.WriteFile(qd+"/xps_cpus", hw.CPUSet(nil).Mask(b.cpus)+"\n")
			}
			if !b.exists(qd + "/traffic_class") {
				b.WriteFile(qd+"/traffic_class", "0\n")
				b.WriteFile(qd+"/tx_maxrate", "0\n")
			}
		}
	}
}

func ls(dir string) []string {
	ents, _ := os.ReadDir(dir)
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

func (b *Built) addNIC(s NICSpec) {
	s.defaults()
	n := &fakeNIC{spec: s}
	n.fn = "/sys/devices/pci0000:00/0000:00:01.0/" + s.PCI
	n.dev = n.fn
	if s.Driver == "virtio_net" {
		n.fn = "/sys/devices/pci0000:00/" + s.PCI
		n.dev = fmt.Sprintf("%s/virtio%d", n.fn, s.Virtio)
	}
	n.netDir = n.dev + "/net/" + s.Name
	b.nics[s.Name] = n

	// The PCI function.
	node := fmt.Sprint(s.Node)
	b.WriteFile(n.fn+"/vendor", "0x"+s.Vendor+"\n")
	b.WriteFile(n.fn+"/device", "0x"+s.Device+"\n")
	b.WriteFile(n.fn+"/class", "0x020000\n")
	b.WriteFile(n.fn+"/numa_node", node+"\n")
	b.WriteFile(n.fn+"/local_cpulist", b.nodeDefault(s.Node).List()+"\n")
	b.mkdir(n.fn + "/msi_irqs")
	b.symlink(n.fn, "/sys/bus/pci/devices/"+s.PCI)
	pciDrv := s.Driver
	if s.Driver == "virtio_net" {
		pciDrv = "virtio-pci"
		b.WriteFile(n.dev+"/vendor", "0x1af4\n")
		b.WriteFile(n.dev+"/device", "0x0001\n")
		b.mkdir("/sys/bus/virtio/drivers/virtio_net")
		b.symlink("/sys/bus/virtio/drivers/virtio_net", n.dev+"/driver")
	}
	b.mkdir("/sys/bus/pci/drivers/" + pciDrv)
	b.symlink("/sys/bus/pci/drivers/"+pciDrv, n.fn+"/driver")
	if s.VF {
		pf := "/sys/devices/pci0000:00/0000:00:01.0/0000:ff:00.0"
		b.WriteFile(pf+"/vendor", "0x"+s.Vendor+"\n")
		b.symlink(pf, n.fn+"/physfn")
	}

	// The network device.
	n.rx, n.tx = queuesOf(s.Channels)
	speed := s.SpeedMbps
	if speed == 0 || s.Down {
		speed = -1
	}
	idx := b.newIfindex()
	b.symlink(n.dev, n.netDir+"/device")
	b.writeNetCommon(s.Name, n.netDir, "", idx, idx, !s.Down, speed, 0, 0)
	b.writeQueues(n.netDir, n.rx, n.tx, n, s.XPS)

	// The fake driver.
	dev := &FakeDev{Driver: s.Driver, PCI: s.PCI, Channels: s.Channels, TableSize: s.TableSize, RSSCap: s.RSSCap,
		Configured: s.Configured, Hash: map[string]uint64{}, Features: s.Features, Stats: map[string]uint64{}, VF: s.VF}
	for k, v := range s.Hash {
		dev.Hash[k] = v
	}
	dev.RxRings = n.rx
	if s.TableSize > 0 {
		dev.Table = slices.Clone(s.Table)
		if dev.Table == nil {
			dev.Table = defaultTable(s.TableSize, n.rx, s.RSSCap)
		}
	}
	if dev.Features == nil {
		dev.Features = map[string]bool{"rx": true, "tx": true, "sg": true, "tso": true, "gso": true, "gro": true,
			"lro": false, "ntuple": false, "rxhash": true, "rxvlan": true, "txvlan": true}
	}
	b.Eth.Devs[s.Name] = dev
	b.resetStats(s.Name)
	for k, v := range s.Stats {
		dev.Stats[k] = v
	}

	// The interrupts.
	if s.IRQBase > 0 {
		b.nextIRQ = s.IRQBase
	}
	b.makeVectors(n, false)
}

func defaultTable(size, rings, rssCap int) []uint32 {
	k := rings
	if rssCap > 0 && rssCap < k {
		k = rssCap
	}
	t := make([]uint32, size)
	for i := range t {
		t[i] = uint32(i % max(k, 1))
	}
	return t
}

// resetStats makes the driver's counters for its queues, keeping values that
// exist.
func (b *Built) resetStats(name string) {
	n, dev := b.nics[name], b.Eth.Devs[name]
	keep := dev.Stats
	dev.Stats = map[string]uint64{}
	add := func(k string, v uint64) {
		if old, ok := keep[k]; ok {
			v = old
		}
		dev.Stats[k] = v
	}
	add("rx_packets", 1000000)
	add("tx_packets", 1000000)
	add("rx_bytes", 1000000000)
	add("tx_bytes", 1000000000)
	for q := 0; q < n.rx; q++ {
		switch n.spec.Driver {
		case "mlx5_core":
			add(fmt.Sprintf("rx%d_packets", q), 1000)
		case "i40e", "ice":
			add(fmt.Sprintf("rx-%d.packets", q), 1000)
		case "bnxt_en":
			add(fmt.Sprintf("[%d]: rx_ucast_packets", q), 1000)
		case "ena":
			add(fmt.Sprintf("queue_%d_rx_cnt", q), 1000)
		default:
			add(fmt.Sprintf("rx_queue_%d_packets", q), 1000)
		}
	}
	switch n.spec.Driver {
	case "ixgbe":
		add("rx_missed_errors", 0)
		add("rx_no_buffer_count", 0)
		add("fdir_match", 0)
		add("fdir_miss", 0)
		add("fdir_overflow", 0)
	case "igb", "igc":
		add("rx_missed_errors", 0)
		add("rx_no_buffer_count", 0)
	case "mlx5_core":
		add("rx_out_of_buffer", 0)
		add("rx_discards_phy", 0)
	case "i40e", "ice":
		add("port.rx_dropped", 0)
		add("rx_dropped", 0)
	case "ena":
		add("bw_in_allowance_exceeded", 0)
		add("pps_allowance_exceeded", 0)
	case "virtio_net":
		add("rx_queue_0_drops", 0)
	}
}

// hintOf is the driver's affinity hint for a queue.
func (b *Built) hintOf(n *fakeNIC, q int) hw.CPUSet {
	switch n.spec.Hint {
	case "spread":
		return hw.CPUSet{b.localSpread(q, n.spec.Node)}
	case "virtio":
		return b.virtioGroup(q, n.rx)
	}
	return nil
}

// virtioGroup is virtnet_set_affinity's CPUs for queue pair q of qp.
func (b *Built) virtioGroup(q, qp int) hw.CPUSet {
	on := b.online
	stride := max(len(on)/qp, 1)
	strag := 0
	if len(on) >= qp {
		strag = len(on) % qp
	}
	pos := 0
	for i := 0; i < q; i++ {
		pos += stride
		if i < strag {
			pos++
		}
	}
	size := stride
	if q < strag {
		size++
	}
	var out hw.CPUSet
	for j := 0; j < size; j++ {
		out = append(out, on[(pos+j)%len(on)])
	}
	return hw.NewCPUSet(out...)
}

// managedGroup is the kernel's spread of q of n managed vectors.
func (b *Built) managedGroup(q, n int) hw.CPUSet {
	on := b.online
	lo, hi := q*len(on)/n, (q+1)*len(on)/n
	if hi <= lo {
		hi = lo + 1
	}
	return hw.NewCPUSet(on[lo%len(on) : min(hi, len(on))]...)
}

// makeVectors creates the device's interrupts: at build with the spec's
// affinities, and with fresh ones (the kernel's default, the driver's hint)
// when a channel change re-creates them.
func (b *Built) makeVectors(n *fakeNIC, fresh bool) {
	s := n.spec
	style, effective := s.Affinity, s.Effective
	if fresh {
		effective = nil
		if style == "node" {
			style = "default"
		}
	}
	type vec struct {
		name  string
		queue int
	}
	var vecs []vec
	other := func(name string) { vecs = append(vecs, vec{name, -1}) }
	queues := n.rx
	if s.Driver == "virtio_net" {
		// virtio_net has vectors for every queue pair it may use.
		queues = max(int(s.Channels.MaxCombined), n.rx)
	}
	switch s.IRQNames {
	case "i40e":
		other(fmt.Sprintf("i40e-%s:misc", s.PCI))
		for q := 0; q < queues; q++ {
			vecs = append(vecs, vec{fmt.Sprintf("i40e-%s-TxRx-%d", s.Name, q), q})
		}
	case "mlx5":
		other("mlx5_async0@pci:" + s.PCI)
		for q := 0; q < queues; q++ {
			vecs = append(vecs, vec{fmt.Sprintf("mlx5_comp%d@pci:%s", q, s.PCI), q})
		}
	case "virtio":
		other(fmt.Sprintf("virtio%d-config", s.Virtio))
		for q := 0; q < queues; q++ {
			vecs = append(vecs, vec{fmt.Sprintf("virtio%d-input.%d", s.Virtio, q), q}, vec{fmt.Sprintf("virtio%d-output.%d", s.Virtio, q), q})
		}
	case "split":
		for q := 0; q < queues; q++ {
			vecs = append(vecs, vec{fmt.Sprintf("%s-rx-%d", s.Name, q), q})
		}
		for q := 0; q < queues; q++ {
			vecs = append(vecs, vec{fmt.Sprintf("%s-tx-%d", s.Name, q), q})
		}
		other(s.Name + "-err")
		other(s.Name + "-notify")
	case "ena":
		other("ena-mgmnt@pci:" + s.PCI)
		for q := 0; q < queues; q++ {
			vecs = append(vecs, vec{fmt.Sprintf("ena-%s-Tx-Rx-%d", s.PCI, q), q})
		}
	case "unknown":
		for q := 0; q < queues; q++ {
			vecs = append(vecs, vec{fmt.Sprintf("%s-queue%d", s.Name, q), q})
		}
	default:
		for q := 0; q < queues; q++ {
			vecs = append(vecs, vec{fmt.Sprintf("%s-TxRx-%d", s.Name, q), q})
		}
		other(s.Name)
	}
	for _, name := range s.Extra {
		other(name)
	}
	n.vecs = nil
	for hwirq, v := range vecs {
		irq := b.nextIRQ
		b.nextIRQ++
		fi := &fakeIRQ{irq: irq, hwirq: hwirq, name: v.name, chip: "PCI-MSIX-" + s.PCI, node: s.Node, queue: v.queue,
			nic: s.Name, counts: map[int]uint64{}, memo: map[string]hw.CPUSet{}}
		def := b.nodeDefault(s.Node)
		if v.queue < 0 {
			fi.aff = def
			fi.eff = hw.CPUSet{def[0]}
		} else {
			fi.hint = b.hintOf(n, v.queue)
			switch style {
			case "node":
				fi.aff = def
				if s.Node >= 0 && s.Node < len(b.nodes) {
					fi.aff = b.nodes[s.Node].cpus
				}
			case "hint":
				fi.aff = fi.hint
			case "managed":
				fi.aff = b.managedGroup(v.queue, queues)
				fi.managed = true
			default:
				fi.aff = def
			}
			if len(fi.aff) == 0 {
				fi.aff = def
			}
			switch {
			case v.queue < len(effective):
				fi.eff = hw.CPUSet{effective[v.queue]}
			case len(fi.hint.And(fi.aff)) > 0:
				fi.eff = hw.CPUSet{fi.hint.And(fi.aff)[0]}
			case style == "managed":
				fi.eff = fi.aff[:1]
			default:
				fi.eff = hw.CPUSet{fi.aff[v.queue%len(fi.aff)]}
			}
		}
		for _, c := range fi.eff {
			fi.counts[c] = 1000
		}
		fi.memo[fi.aff.List()] = fi.eff
		b.irqs[irq] = fi
		n.vecs = append(n.vecs, irq)
		b.WriteFile(fmt.Sprintf("%s/msi_irqs/%d", n.fn, irq), "msix\n")
		b.writeIRQ(fi)
		if fi.managed {
			for _, f := range []string{"smp_affinity", "smp_affinity_list"} {
				b.FailWrite[fmt.Sprintf("/proc/irq/%d/%s", irq, f)] = syscall.EIO
			}
		}
	}
}

// dropVectors removes the device's interrupts (a channel change frees them).
func (b *Built) dropVectors(n *fakeNIC) {
	for _, irq := range n.vecs {
		delete(b.irqs, irq)
		os.RemoveAll(b.Path(fmt.Sprintf("/proc/irq/%d", irq)))
		os.Remove(b.Path(fmt.Sprintf("%s/msi_irqs/%d", n.fn, irq)))
		for _, f := range []string{"smp_affinity", "smp_affinity_list"} {
			delete(b.FailWrite, fmt.Sprintf("/proc/irq/%d/%s", irq, f))
		}
	}
	n.vecs = nil
}

// writeIRQ writes /proc/irq/N as the kernel shows it.
func (b *Built) writeIRQ(fi *fakeIRQ) {
	d := fmt.Sprintf("/proc/irq/%d", fi.irq)
	fi.wroteList, fi.wroteMsk = fi.aff.List()+"\n", fi.aff.Mask(b.cpus)+"\n"
	b.WriteFile(d+"/smp_affinity", fi.wroteMsk)
	b.WriteFile(d+"/smp_affinity_list", fi.wroteList)
	b.WriteFile(d+"/effective_affinity", fi.eff.Mask(b.cpus)+"\n")
	b.WriteFile(d+"/effective_affinity_list", fi.eff.List()+"\n")
	b.WriteFile(d+"/affinity_hint", fi.hint.Mask(b.cpus)+"\n")
	b.WriteFile(d+"/node", fmt.Sprintf("%d\n", max(fi.node, 0)))
	b.WriteFile(d+"/spurious", "count 0\nunhandled 0\nlast_unhandled 0 ms\n")
	if fi.name != "" {
		b.mkdir(d + "/" + fi.name)
	}
}

// writeInterrupts writes /proc/interrupts from the interrupt model.
func (b *Built) writeInterrupts() {
	var s strings.Builder
	s.WriteString("    ")
	for _, c := range b.online {
		fmt.Fprintf(&s, " %10s", fmt.Sprintf("CPU%d", c))
	}
	s.WriteString("\n")
	row := func(label string, counts map[int]uint64, tail string) {
		fmt.Fprintf(&s, "%4s", label)
		for _, c := range b.online {
			fmt.Fprintf(&s, " %10d", counts[c])
		}
		s.WriteString(tail + "\n")
	}
	row("0:", map[int]uint64{0: 30}, "   IO-APIC   2-edge      timer")
	row("8:", nil, "   IO-APIC   8-edge      rtc0")
	row("9:", nil, "   IO-APIC   9-fasteoi   acpi")
	irqs := make([]int, 0, len(b.irqs))
	for irq := range b.irqs {
		irqs = append(irqs, irq)
	}
	sort.Ints(irqs)
	for _, irq := range irqs {
		fi := b.irqs[irq]
		row(fmt.Sprintf("%d:", irq), fi.counts, fmt.Sprintf("  %s %4d-edge      %s", fi.chip, fi.hwirq, fi.name))
	}
	loc := map[int]uint64{}
	for _, c := range b.online {
		loc[c] = 100000
	}
	row("NMI:", nil, "   Non-maskable interrupts")
	row("LOC:", loc, "   Local timer interrupts")
	s.WriteString(" ERR:          0\n MIS:          0\n")
	b.WriteFile("/proc/interrupts", s.String())
	for _, irq := range []int{0, 8, 9} {
		fi := &fakeIRQ{irq: irq, aff: b.defaultMask().And(b.online), eff: hw.CPUSet{0},
			name: map[int]string{0: "timer", 8: "rtc0", 9: "acpi"}[irq]}
		if !b.exists(fmt.Sprintf("/proc/irq/%d", irq)) {
			b.writeIRQ(fi)
		}
	}
	b.WriteFile("/proc/irq/default_smp_affinity", b.defaultMask().Mask(b.cpus)+"\n")
}

// SetIRQCount sets how many times an interrupt fired on a CPU.
func (b *Built) SetIRQCount(irq, cpu int, n uint64) {
	b.t.Helper()
	fi := b.irqs[irq]
	if fi == nil {
		b.t.Fatalf("hwtest: no interrupt %d", irq)
	}
	fi.counts[cpu] = n
	b.writeInterrupts()
}

// SetStat sets a device counter: the sysfs statistics file of that name,
// and the ethtool counter of that name when the driver has one (a name
// sysfs does not have is an ethtool counter, created when missing).
func (b *Built) SetStat(dev, name string, v uint64) {
	b.t.Helper()
	isSysfs := slices.Contains(sysfsStats, name)
	if isSysfs {
		p := b.netDir(dev) + "/statistics/" + name
		if !b.exists(p) {
			b.t.Fatalf("hwtest: no device %s", dev)
		}
		b.WriteFile(p, fmt.Sprintf("%d\n", v))
	}
	if d := b.Eth.Devs[dev]; d != nil {
		if _, ok := d.Stats[name]; ok || !isSysfs {
			d.Stats[name] = v
		}
	} else if !isSysfs {
		b.t.Fatalf("hwtest: %s has no ethtool counters", dev)
	}
}

// IRQs lists a device's interrupts, in vector order.
func (b *Built) IRQs(dev string) []int {
	if n := b.nics[dev]; n != nil {
		return slices.Clone(n.vecs)
	}
	return nil
}

// QueueIRQs lists a device's queue interrupts (txrx or rx, one per queue),
// by queue.
func (b *Built) QueueIRQs(dev string) []int {
	var out []int
	n := b.nics[dev]
	if n == nil {
		return nil
	}
	for q := 0; ; q++ {
		found := false
		for _, irq := range n.vecs {
			fi := b.irqs[irq]
			if fi.queue == q && !strings.Contains(fi.name, "-tx-") && !strings.Contains(fi.name, "output") {
				out = append(out, irq)
				found = true
				break
			}
		}
		if !found {
			return out
		}
	}
}

// Settle does what the kernel does after interrupt affinities and queue
// masks are written: the affinity files show the new CPUs in both forms,
// the effective CPU follows (back to what it was when an affinity returns),
// and masks are printed at full width.
func (b *Built) Settle() {
	b.t.Helper()
	changed := false
	for _, fi := range b.irqs {
		d := fmt.Sprintf("/proc/irq/%d", fi.irq)
		list, msk := b.ReadFile(d+"/smp_affinity_list"), b.ReadFile(d+"/smp_affinity")
		var aff hw.CPUSet
		var err error
		switch {
		case list != fi.wroteList:
			aff, err = hw.ParseList(list)
		case msk != fi.wroteMsk:
			aff, err = hw.ParseMask(msk)
		default:
			continue
		}
		if err != nil || len(aff.And(b.online)) == 0 {
			b.writeIRQ(fi) // the kernel would have refused it
			continue
		}
		aff = aff.And(b.online)
		eff, ok := fi.memo[aff.List()]
		if !ok {
			if len(fi.eff.And(aff)) > 0 {
				eff = fi.eff.And(aff)[:1]
			} else {
				eff = aff[:1]
			}
			fi.memo[aff.List()] = eff
		}
		fi.aff, fi.eff = aff, eff
		b.writeIRQ(fi)
		changed = true
	}
	if changed {
		b.writeInterrupts()
	}
	for _, n := range b.nics {
		for _, f := range b.FS().Glob(n.netDir + "/queues/*/*_cpus") {
			s := b.ReadFile(f)
			m, err := hw.ParseMask(s)
			if err != nil {
				continue
			}
			if want := m.Mask(b.cpus) + "\n"; s != want {
				b.WriteFile(f, want)
			}
		}
	}
}

// writeRoutes writes /proc/net/route and /proc/net/ipv6_route.
func (b *Built) writeRoutes() {
	var v4, v6 strings.Builder
	v4.WriteString("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n")
	// An unreachable default in another table shows on lo; it is no route.
	v6.WriteString(strings.Repeat("0", 32) + " 00 " + strings.Repeat("0", 32) + " 00 " + strings.Repeat("0", 32) + " ffffffff 00000001 00000000 00200200       lo\n")
	for _, r := range b.M.Routes {
		if !r.V6 {
			gw, flags := "00000000", 0x1
			if ip := net.ParseIP(r.Gateway).To4(); ip != nil {
				gw = fmt.Sprintf("%02X%02X%02X%02X", ip[3], ip[2], ip[1], ip[0])
				flags |= 0x2
			}
			fmt.Fprintf(&v4, "%s\t00000000\t%s\t%04X\t0\t0\t%d\t00000000\t0\t0\t0\n", r.Dev, gw, flags, r.Metric)
			// The route to the gateway's subnet.
			fmt.Fprintf(&v4, "%s\t0000A8C0\t00000000\t0001\t0\t0\t%d\t00FFFFFF\t0\t0\t0\n", r.Dev, r.Metric)
			continue
		}
		gw, flags := strings.Repeat("0", 32), 0x1
		if ip := net.ParseIP(r.Gateway).To16(); ip != nil {
			gw = fmt.Sprintf("%x", []byte(ip))
			flags |= 0x2
		}
		metric := r.Metric
		if metric == 0 {
			metric = 1024
		}
		fmt.Fprintf(&v6, "%s 00 %s 00 %s %08x 00000001 00000000 %08x %8s\n", strings.Repeat("0", 32), strings.Repeat("0", 32), gw, metric, flags, r.Dev)
		fmt.Fprintf(&v6, "fe800000000000000000000000000000 40 %s 00 %s 00000100 00000001 00000000 00000001 %8s\n", strings.Repeat("0", 32), strings.Repeat("0", 32), r.Dev)
	}
	b.WriteFile("/proc/net/route", v4.String())
	b.WriteFile("/proc/net/ipv6_route", v6.String())
}

// IRQBalancePolicy is the policy script x-ui gives irqbalance.
const IRQBalancePolicy = "/var/lib/x-ui/tune/irqbalance-policy"

// IRQBalancePID is the fake irqbalance's process ID.
const IRQBalancePID = 812

// The irqbalance unit Debian and Ubuntu ship, and its defaults file.
const (
	IRQBalanceUnitDebian = `[Unit]
Description=irqbalance daemon
Documentation=man:irqbalance(1)
Documentation=https://github.com/Irqbalance/irqbalance
ConditionVirtualization=!container
ConditionCPUs=>1

[Service]
EnvironmentFile=-/etc/default/irqbalance
ExecStart=/usr/sbin/irqbalance --foreground $IRQBALANCE_ARGS
CapabilityBoundingSet=
NoNewPrivileges=yes
ReadOnlyPaths=/
ReadWritePaths=/proc/irq
RestrictAddressFamilies=AF_UNIX AF_NETLINK
RuntimeDirectory=irqbalance/

[Install]
WantedBy=multi-user.target
`
	IRQBalanceDefaultsDebian = `# irqbalance is a daemon process that distributes interrupts across
# CPUs on SMP systems.  The default is to rebalance once every 10
# seconds.  This is the environment file that is specified to systemd via the
# EnvironmentFile key in the service unit file (or via whatever method the init
# system you're using has).
#
# IRQBALANCE_ONESHOT
#    After starting, wait for ten seconds, then look at the interrupt
#    load and balance it once; after balancing exit and do not change
#    it again.
#
#IRQBALANCE_ONESHOT=

#
# IRQBALANCE_BANNED_CPULIST
#    The CPUs listed are never assigned an interrupt.
#
#IRQBALANCE_BANNED_CPULIST=

#
# IRQBALANCE_ARGS
#    Append any args here to the irqbalance daemon as documented in the man
#    page.
#
#IRQBALANCE_ARGS=
`
)

func (b *Built) writeIRQBalance() {
	if b.M.IRQBalance == "" {
		return
	}
	b.WriteFile("/usr/lib/systemd/system/irqbalance.service", IRQBalanceUnitDebian)
	b.WriteFile("/etc/default/irqbalance", IRQBalanceDefaultsDebian)
	b.WriteFile("/usr/sbin/irqbalance", "")
	if b.M.IRQBalance == "installed" {
		return
	}
	args := []string{"/usr/sbin/irqbalance", "--foreground"}
	if b.M.IRQBalance == "running-ours" {
		args = append(args, "--policyscript="+IRQBalancePolicy)
	}
	d := fmt.Sprintf("/proc/%d", IRQBalancePID)
	b.WriteFile(d+"/comm", "irqbalance\n")
	b.WriteFile(d+"/cmdline", strings.Join(args, "\x00")+"\x00")
	b.WriteFile(d+"/status", "Name:\tirqbalance\nState:\tS (sleeping)\n")
}
