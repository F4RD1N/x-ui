package hw_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/util/hw"
	"github.com/mhsanaei/3x-ui/v2/util/hw/hwtest"
)

func TestParseQueueIRQName(t *testing.T) {
	type res struct {
		q    int
		kind string
		ok   bool
	}
	for name, want := range map[string]res{
		"eno1-TxRx-0":                   {0, "txrx", true},
		"i40e-eno1-TxRx-3":              {3, "txrx", true},
		"ice-0000:01:00.0-TxRx-12":      {12, "txrx", true},
		"ena-0000:00:05.0-Tx-Rx-2":      {2, "txrx", true},
		"eth0-rxtx-1":                   {1, "txrx", true},
		"eth0-fp-4":                     {4, "txrx", true},
		"eth0-rx-5":                     {5, "rx", true},
		"eth0-tx-6":                     {6, "tx", true},
		"mlx5_comp7@pci:0000:41:00.0":   {7, "txrx", true},
		"mlx5_comp62":                   {62, "txrx", true},
		"virtio1-input.0":               {0, "rx", true},
		"virtio12-output.3":             {3, "tx", true},
		"eno1":                          {},
		"mlx5_async0@pci:0000:41:00.0":  {},
		"virtio1-config":                {},
		"virtio1-virtqueues":            {},
		"virtio1-control":               {},
		"i40e-0000:01:00.0:misc":        {},
		"i40e-0000:01:00.0:fdir-TxRx-0": {},
		"ice-0000:01:00.0:ctrl-TxRx-0":  {},
		"eth0-err":                      {},
		"eth0-notify":                   {},
		"eno1-TxRx-":                    {},
		"nvme0q1":                       {},
		"":                              {},
	} {
		q, kind, ok := hw.ParseQueueIRQName(name)
		if (res{q, kind, ok}) != want {
			t.Errorf("ParseQueueIRQName(%q) = %d %q %v, want %+v", name, q, kind, ok, want)
		}
	}
}

func TestReadNICProduction(t *testing.T) {
	b := hwtest.Production().Build(t)
	n := hw.ReadNIC(b.FS(), b.Eth, "eno1")
	if n.Driver != "ixgbe" || n.PCI != "0000:82:00.0" || n.Vendor != "8086" || n.Device != "10fb" || n.Node != 1 ||
		n.SpeedMbps != 10000 || !n.Up || !n.Carrier || n.VF || n.Virtio || n.TCs || n.Bond != nil {
		t.Errorf("eno1: %+v", n)
	}
	if n.RxQueues != 56 || n.TxQueues != 56 || n.Queues() != 56 || n.RxRings != 56 || n.Channels == nil || n.Channels.MaxCombined != 56 || n.Channels.Other != 1 {
		t.Errorf("queues: rx %d tx %d rings %d channels %+v", n.RxQueues, n.TxQueues, n.RxRings, n.Channels)
	}
	if len(n.IRQs) != 56 || !slices.Equal(n.OtherIRQs, []int{157}) || n.SharedIRQ || n.UnknownIRQs {
		t.Fatalf("irqs: %d queue, other %v", len(n.IRQs), n.OtherIRQs)
	}
	q0, q16 := n.IRQs[0], n.IRQs[16]
	if q0.IRQ != 101 || q0.Name != "eno1-TxRx-0" || q0.Queue != 0 || q0.Kind != "txrx" || q0.Effective.List() != "11" || q0.Hint.List() != "1" || len(q0.Affinity) != 28 || q0.Affinity[0] != 1 {
		t.Errorf("q0: %+v", q0)
	}
	if q16.IRQ != 117 || q16.Effective.List() != "1" || n.IRQs[15].Effective.List() != "41" || n.IRQs[28].Hint.List() != "0" {
		t.Errorf("q16: %+v, q15 %v, q28 hint %v", q16, n.IRQs[15].Effective, n.IRQs[28].Hint)
	}
	use := n.RSSUse()
	if len(n.Indir) != 128 || len(use) != 16 || use[0] != 8 || use[15] != 8 {
		t.Errorf("RSS use: %v", use)
	}
	if !hw.DefaultForm(n.Indir, 16) || !hw.EvenOver(n.Indir, 16) || hw.EvenOver(n.Indir, 56) {
		t.Error("table form")
	}
	if n.Hash["udp4"] != hw.HashIPs || n.Hash["udp6"] != hw.HashIPs || n.Hash["tcp4"] != hw.HashIPsPorts {
		t.Errorf("hash: %v", n.Hash)
	}
	if n.XPS[0].List() != "1" || n.XPS[55].List() != "54" || len(n.RPS[0]) != 0 || n.RPSFlowCnt[0] != 0 || len(n.RPS) != 56 {
		t.Errorf("xps %v %v rps %v", n.XPS[0], n.XPS[55], n.RPS[0])
	}
	if !n.Features["gro"] || n.Features["lro"] || len(n.Notes) != 0 {
		t.Errorf("features %v notes %q", n.Features, n.Notes)
	}

	// Without ethtool the driver's settings are unknown, with notes.
	n = hw.ReadNIC(b.FS(), hw.NoEthtool{}, "eno1")
	if n.Channels != nil || n.Indir != nil || len(n.Hash) != 0 || n.Queues() != 56 || len(n.IRQs) != 56 || len(n.Notes) != 2 {
		t.Errorf("no ethtool: %+v %q", n.Channels, n.Notes)
	}
	if n := hw.ReadNIC(b.FS(), nil, "nope"); n.Driver != "" || n.Node != -1 || !slices.Equal(n.Notes, []string{"not found"}) {
		t.Errorf("missing device: %+v", n)
	}
}

// i40e's flow director and ice's control VSI have a "TxRx-0" vector on the
// same function: not queue 0's. Two vectors that still claim one queue go to
// the one named after the device, and when none is, the queues are unknown.
func TestReadNICSideVectors(t *testing.T) {
	for _, c := range []struct {
		driver, extra string
		other         int
	}{
		{"i40e", "i40e-0000:01:00.0:fdir-TxRx-0", 2},
		{"ice", "ice-0000:01:00.0:ctrl-TxRx-0", 2},
		{"i40e", "vf0-TxRx-0", 2}, // not named after eno1: not its queue
	} {
		m := hwtest.ProxmoxBridge()
		m.NICs[0].Driver = c.driver
		m.NICs[0].Extra = []string{c.extra}
		b := m.Build(t)
		n := hw.ReadNIC(b.FS(), b.Eth, "eno1")
		q0 := 0
		for _, q := range n.IRQs {
			if q.Queue == 0 {
				q0++
				if strings.Contains(q.Name, c.extra) {
					t.Errorf("%s: %s taken for queue 0", c.driver, q.Name)
				}
			}
		}
		if q0 != 1 || len(n.IRQs) != n.Queues() || len(n.OtherIRQs) != c.other || n.UnknownIRQs {
			t.Errorf("%s %s: %d vectors for queue 0, %d queue vectors for %d queues, other %v, unknown %v", c.driver, c.extra, q0, len(n.IRQs), n.Queues(), n.OtherIRQs, n.UnknownIRQs)
		}
	}
	m := hwtest.Desktop()
	m.NICs[0].IRQNames = "unknown"
	m.NICs[0].Extra = []string{"a-TxRx-1", "b-TxRx-1"}
	b := m.Build(t)
	if n := hw.ReadNIC(b.FS(), b.Eth, "eno1"); !n.UnknownIRQs || len(n.IRQs) != 0 || !slices.ContainsFunc(n.Notes, func(s string) bool { return strings.Contains(s, "2 interrupts claim queue 1") }) {
		t.Errorf("two unnamed vectors of a queue: %+v %v", n.IRQs, n.Notes)
	}
}

// The receive queues channels give: ethtool counts combined and dedicated
// channels apart, so a NIC on dedicated ones (bnxt_en's "-L rx 16 tx 16")
// has combined 0, and ice's "-L combined 8 rx 2" has 10.
func TestChannelsCount(t *testing.T) {
	for _, c := range []struct {
		name     string
		ch       hw.Channels
		cur, max uint32
	}{
		{"combined", hw.Channels{MaxOther: 1, MaxCombined: 56, Other: 1, Combined: 56}, 56, 56},
		{"dedicated", hw.Channels{MaxRx: 63, MaxTx: 63, MaxCombined: 63, Rx: 16, Tx: 16}, 16, 63},
		{"combined and RX", hw.Channels{MaxRx: 64, MaxTx: 64, MaxCombined: 64, Combined: 8, Rx: 2}, 10, 64},
		{"combined and TX", hw.Channels{MaxRx: 64, MaxTx: 64, MaxCombined: 64, Combined: 8, Tx: 2}, 8, 64},
		{"RX and TX only", hw.Channels{MaxRx: 4, MaxTx: 4, Rx: 4, Tx: 1}, 4, 4},
		{"none", hw.Channels{}, 0, 0},
	} {
		if cur, mx := c.ch.Count(); cur != c.cur || mx != c.max {
			t.Errorf("%s: %d of %d, want %d of %d", c.name, cur, mx, c.cur, c.max)
		}
		n := &hw.NIC{Channels: &c.ch, RxQueues: 1}
		if want := max(int(c.cur), 1); n.Queues() != want {
			t.Errorf("%s: Queues %d, want %d", c.name, n.Queues(), want)
		}
	}
}

func TestReadNICPresets(t *testing.T) {
	// virtio: the PCI device is virtioN's parent; input and output vectors
	// per queue, the config vector among the others.
	b := hwtest.VPS(2).Build(t)
	n := hw.ReadNIC(b.FS(), b.Eth, "eth0")
	if !n.Virtio || n.Driver != "virtio_net" || n.PCI != "0000:00:03.0" || n.Vendor != "1af4" || n.Node != -1 || n.SpeedMbps != 0 {
		t.Errorf("virtio: %+v", n)
	}
	if len(n.IRQs) != 2 || n.IRQs[0].Kind != "rx" || n.IRQs[1].Kind != "tx" || n.IRQs[0].Name != "virtio1-input.0" || len(n.OtherIRQs) != 1 {
		t.Errorf("virtio irqs: %+v other %v", n.IRQs, n.OtherIRQs)
	}
	if n.IRQs[0].Hint.List() != "0-1" || n.IRQs[0].Affinity.List() != "0-1" || n.Indir != nil || len(n.Hash) != 0 || n.Queues() != 1 || len(n.XPS) != 0 {
		t.Errorf("virtio: hint %v indir %v hash %v xps %v", n.IRQs[0].Hint, n.Indir, n.Hash, n.XPS)
	}

	// mlx5: names with @pci, one CPU per vector near the card.
	b = hwtest.EPYC(4).Build(t)
	n = hw.ReadNIC(b.FS(), b.Eth, "enp65s0f0np0")
	if len(n.IRQs) != 63 || len(n.OtherIRQs) != 1 || n.IRQs[32].Affinity.List() != "256" || n.IRQs[32].Effective.List() != "256" || n.Node != 0 || n.SpeedMbps != 100000 {
		t.Errorf("mlx5: %d irqs, q32 %+v", len(n.IRQs), n.IRQs[32])
	}
	if len(n.RSSUse()) != 63 || n.Hash["udp4"] != hw.HashIPsPorts {
		t.Errorf("mlx5 rss %d", len(n.RSSUse()))
	}

	// Separate RX and TX vectors, sorted by queue then kind; channels
	// without combined ones.
	b = hwtest.ManagedIRQs().Build(t)
	n = hw.ReadNIC(b.FS(), b.Eth, "eth0")
	if len(n.IRQs) != 16 || n.IRQs[0].Kind != "rx" || n.IRQs[1].Kind != "tx" || n.IRQs[2].Queue != 1 || len(n.OtherIRQs) != 2 || n.Queues() != 8 {
		t.Errorf("enic: %d irqs, %+v", len(n.IRQs), n.IRQs[:3])
	}
	if n.IRQs[3].Affinity.List() != "2-3" || n.IRQs[3].Effective.List() != "2" {
		t.Errorf("enic managed spread: %+v", n.IRQs[3])
	}
	if len(b.FailWrite) != 32 {
		t.Errorf("enic FailWrite: %d", len(b.FailWrite))
	}

	// A bond slave.
	b = hwtest.Bond().Build(t)
	n = hw.ReadNIC(b.FS(), b.Eth, "eno2")
	if n.Bond == nil || *n.Bond != (hw.BondSlave{Bond: "bond0", Mode: "802.3ad", MIIStatus: "up", AggregatorID: 1, BondAggregatorID: 1}) {
		t.Errorf("bond slave: %+v", n.Bond)
	}
	if n.Queues() != 16 || n.Channels.MaxCombined != 63 || n.IRQs[0].IRQ != 201 {
		t.Errorf("eno2: %d queues, first IRQ %d", n.Queues(), n.IRQs[0].IRQ)
	}

	// Interrupt names that do not parse: the queues are unknown.
	m := hwtest.Desktop()
	m.NICs[0].IRQNames = "unknown"
	b = m.Build(t)
	if n := hw.ReadNIC(b.FS(), b.Eth, "eno1"); !n.UnknownIRQs || len(n.IRQs) != 0 || len(n.OtherIRQs) != 4 {
		t.Errorf("unknown names: %+v", n)
	}

	// A VF, a link that is down, traffic classes, names only in /proc/irq.
	m = hwtest.Desktop()
	m.NICs[0].VF, m.NICs[0].Down = true, true
	b = m.Build(t)
	b.WriteFile("/sys/class/net/eno1/queues/tx-2/traffic_class", "1\n")
	b.WriteFile("/proc/interrupts", "           CPU0\n")
	n = hw.ReadNIC(b.FS(), b.Eth, "eno1")
	if !n.VF || n.Up || n.Carrier || n.SpeedMbps != 0 || !n.TCs || len(n.IRQs) != 4 {
		t.Errorf("vf/down/tc: %+v", n)
	}
}

func TestUplinkNICs(t *testing.T) {
	b := hwtest.Bond().Build(t)
	nics, notes := hw.UplinkNICs(b.FS(), b.Eth)
	if len(nics) != 2 || nics[0].Name != "eno1" || nics[1].Name != "eno2" || !slices.Equal(nics[0].Via, []string{"bond0"}) || len(nics[1].Routes) != 2 || len(notes) != 0 {
		t.Fatalf("bond: %d nics %q", len(nics), notes)
	}
	// Two names for one PCI function count once.
	b = hwtest.Production().Build(t)
	b.WriteFile("/proc/net/route", "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"+
		"eno1\t00000000\t01011FAC\t0003\t0\t0\t100\t00000000\t0\t0\t0\n")
	if err := os.Symlink("eno1", b.Path("/sys/class/net/alias0")); err != nil {
		t.Fatal(err)
	}
	b.WriteFile("/proc/net/ipv6_route", "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003   alias0\n")
	nics, _ = hw.UplinkNICs(b.FS(), b.Eth)
	if len(nics) != 1 || nics[0].Name != "eno1" {
		t.Errorf("dedup: %d", len(nics))
	}
	b = hwtest.Container().Build(t)
	if nics, notes := hw.UplinkNICs(b.FS(), b.Eth); len(nics) != 0 || len(notes) != 1 || len(b.Eth.Calls) != 0 {
		t.Errorf("container: %v %q calls %v", nics, notes, b.Eth.Calls)
	}
}

func TestTableForms(t *testing.T) {
	mod := func(size, k int) []uint32 {
		t := make([]uint32, size)
		for i := range t {
			t[i] = uint32(i % k)
		}
		return t
	}
	for _, c := range []struct {
		table   []uint32
		k       int
		def, ev bool
	}{
		{mod(128, 16), 16, true, true},
		{mod(128, 16), 56, false, false},
		{mod(128, 56), 56, true, true},
		{mod(128, 56), 16, false, false},
		{mod(512, 32), 32, true, true},
		{[]uint32{1, 0, 3, 2}, 4, false, true},
		{[]uint32{0, 0, 0, 1}, 2, false, false},
		{[]uint32{0, 1, 0, 1}, 2, true, true},
		{mod(4, 2), 0, false, false},
		{nil, 4, false, false},
	} {
		if hw.DefaultForm(c.table, c.k) != c.def || hw.EvenOver(c.table, c.k) != c.ev {
			t.Errorf("%v over %d: default %v even %v", c.table[:min(8, len(c.table))], c.k, hw.DefaultForm(c.table, c.k), hw.EvenOver(c.table, c.k))
		}
	}
	if (&hw.NIC{}).RSSUse() != nil {
		t.Error("RSSUse without a table")
	}
}

func TestHashText(t *testing.T) {
	for bits, want := range map[uint64][2]string{
		hw.HashIPs:                      {"sd", "IPs only"},
		hw.HashIPsPorts:                 {"sdfn", "IPs and ports"},
		0:                               {"", "none"},
		hw.HashIPs | hw.RXHVLAN:         {"vsd", "vsd"},
		hw.RXHL2DA | hw.RXHL3Proto:      {"mt", "mt"},
		hw.HashIPsPorts | hw.RXHDiscard: {"sdfnr", "sdfnr"},
	} {
		if hw.HashLetters(bits) != want[0] || hw.HashText(bits) != want[1] {
			t.Errorf("%#x: %q %q", bits, hw.HashLetters(bits), hw.HashText(bits))
		}
	}
}

func TestPCIName(t *testing.T) {
	ids := `# pci.ids
1af4  Red Hat, Inc.
	1000  Virtio network device
		01de fffb  Propolis Virtio network device
8086  Intel Corporation
	10fb  82599ES 10-Gigabit SFI/SFP+ Network Connection
		1028 1f63  Ethernet 10G 2P X520 Adapter
	1533  I210 Gigabit Network Connection
14e4  Broadcom Inc. and subsidiaries
	16d7  BCM57414 NetXtreme-E 10Gb/25Gb RDMA Ethernet Controller
15b3  Mellanox Technologies
	101d  MT2892 Family [ConnectX-6 Dx]
C 00  Unclassified device
	00  Non-VGA unclassified device
`
	root := t.TempDir()
	fsys := hw.FS{Root: root}
	if got := hw.PCIName(fsys, "8086", "10fb"); got != "" {
		t.Errorf("no database: %q", got)
	}
	p := filepath.Join(root, "/usr/share/hwdata/pci.ids")
	os.MkdirAll(filepath.Dir(p), 0o755)
	os.WriteFile(p, []byte(ids), 0o644)
	for in, want := range map[[2]string]string{
		{"8086", "10fb"}:     "Intel 82599ES 10-Gigabit SFI/SFP+",
		{"0x8086", "0x1533"}: "Intel I210 Gigabit",
		{"15b3", "101d"}:     "Mellanox MT2892 Family [ConnectX-6 Dx]",
		{"14e4", "16d7"}:     "Broadcom BCM57414 NetXtreme-E 10Gb/25Gb RDMA",
		{"1af4", "1000"}:     "Red Hat Virtio network device",
		{"8086", "ffff"}:     "",
		{"dead", "beef"}:     "",
		{"", ""}:             "",
	} {
		if got := hw.PCIName(fsys, in[0], in[1]); got != want {
			t.Errorf("PCIName(%s:%s) = %q, want %q", in[0], in[1], got, want)
		}
	}
	// The first database wins.
	p = filepath.Join(root, "/usr/share/misc/pci.ids")
	os.MkdirAll(filepath.Dir(p), 0o755)
	os.WriteFile(p, []byte("8086  Intel Corporation\n\t10fb  Other Name\n"), 0o644)
	if got := hw.PCIName(fsys, "8086", "10fb"); got != "Intel Other Name" {
		t.Errorf("misc first: %q", got)
	}
}

// treeHash hashes every file and link of a tree.
func treeHash(t *testing.T, root string) string {
	t.Helper()
	h := sha256.New()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		h.Write([]byte(p))
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			l, _ := os.Readlink(p)
			h.Write([]byte(l))
		case d.Type().IsRegular():
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			h.Write(data)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Reading changes nothing in the tree.
func TestReadersAreReadOnly(t *testing.T) {
	for _, m := range []hwtest.Machine{hwtest.Production(), hwtest.VPS(2), hwtest.Bond(), hwtest.ManagedIRQs()} {
		b := m.Build(t)
		before := treeHash(t, b.Root)
		hw.ReadTopology(b.FS())
		hw.UplinkNICs(b.FS(), b.Eth)
		hw.ReadInterrupts(b.FS())
		hw.UplinkNode(b.FS())
		if after := treeHash(t, b.Root); after != before {
			t.Errorf("%s: the tree changed", m.Model)
		}
		for _, c := range b.Eth.Calls {
			if c[:3] == "Set" {
				t.Errorf("a setter was called: %s", c)
			}
		}
	}
}

func TestReadInterrupts(t *testing.T) {
	b := hwtest.Restricted().Build(t)
	q0 := b.QueueIRQs("eno1")[0]
	b.SetIRQCount(q0, 11, 4242)
	irqs, err := hw.ReadInterrupts(b.FS())
	if err != nil {
		t.Fatal(err)
	}
	c := irqs[q0]
	if c == nil || c.Name != "eno1-TxRx-0" || c.PerCPU[11] != 4242 || len(c.PerCPU) != 15 {
		t.Fatalf("irq %d: %+v", q0, c)
	}
	if _, ok := c.PerCPU[3]; ok {
		t.Error("an offline CPU has a column")
	}
	if irqs[0].Name != "timer" || len(irqs) != 3+len(b.IRQs("eno1")) {
		t.Errorf("irqs: %d, timer %+v", len(irqs), irqs[0])
	}
	if _, err := hw.ReadInterrupts(hw.FS{Root: t.TempDir()}); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing file: %v", err)
	}
	aff, eff, hint := hw.ReadIRQAffinity(b.FS(), q0)
	if aff.List() != "0,2,4,6,8,10,12,14" || eff.List() != "0" || hint.List() != "0" {
		t.Errorf("affinity %v %v %v", aff, eff, hint)
	}
	// Before 4.15: no effective affinity; only the mask.
	os.Remove(b.Path(fmt.Sprintf("/proc/irq/%d/effective_affinity_list", q0)))
	os.Remove(b.Path(fmt.Sprintf("/proc/irq/%d/smp_affinity_list", q0)))
	aff, eff, _ = hw.ReadIRQAffinity(b.FS(), q0)
	if aff.List() != "0,2,4,6,8,10,12,14" || eff != nil {
		t.Errorf("old kernel: %v %v", aff, eff)
	}
}

func TestDefaultIRQMask(t *testing.T) {
	m := hwtest.Production()
	m.DefaultSMPAffinity = ints(0, 39)
	b := m.Build(t)
	topo, _ := hw.ReadTopology(b.FS())
	if got := hw.DefaultIRQMask(b.FS(), 1, topo.Online); got.List() != "1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39" {
		t.Errorf("node 1: %v", got)
	}
	if got := hw.DefaultIRQMask(b.FS(), -1, topo.Online); got.List() != "0-39" {
		t.Errorf("no node: %v", got)
	}
	// A node outside the default affinity: the default stays.
	m.DefaultSMPAffinity = []int{0, 2}
	b = m.Build(t)
	if got := hw.DefaultIRQMask(b.FS(), 1, topo.Online); got.List() != "0,2" {
		t.Errorf("disjoint: %v", got)
	}
	if got := hw.DefaultIRQMask(hw.FS{Root: t.TempDir()}, 0, topo.Online); got != nil {
		t.Errorf("unreadable: %v", got)
	}
}
