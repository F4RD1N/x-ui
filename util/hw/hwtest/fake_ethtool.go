package hwtest

import (
	"fmt"
	"maps"
	"slices"
	"syscall"

	"github.com/mhsanaei/3x-ui/v2/util/hw"
)

// FakeDev is the driver state of one fake device.
type FakeDev struct {
	Driver     string
	PCI        string
	VF         bool
	Channels   hw.Channels // all zero: no channel settings
	RxRings    int
	TableSize  int // 0: no RSS table
	RSSCap     int // queues the table can address; 0: no limit
	Table      []uint32
	Configured bool // the table was set explicitly (not the default)
	Hash       map[string]uint64
	Features   map[string]bool
	Stats      map[string]uint64
	Resets     int  // link resets of this device
	BreakLink  bool // after a reset the carrier stays down
}

// FakeEthtool is an in-memory driver model for every NIC of a Built tree.
// What a real driver changes in sysfs and procfs it changes in the tree: a
// channel change on most drivers flaps the carrier and re-creates the
// interrupts (new numbers, fresh default affinities) and the queues.
type FakeEthtool struct {
	Devs map[string]*FakeDev
	// Fail makes a call fail before it does anything; keyed by method and
	// device: "SetChannels eno1".
	Fail map[string]error
	// Calls records every call: "Channels eno1", "SetChannels eno1 combined=28".
	Calls  []string
	Resets int // link resets of all devices
	// DuringReset runs while a reset has the carrier down.
	DuringReset func(dev string)

	b *Built
}

func notSupported(method, dev string) error {
	return fmt.Errorf("ethtool %s %s: %w (%w)", method, dev, hw.ErrNotSupported, syscall.EOPNOTSUPP)
}

func invalid(method, dev string) error {
	return fmt.Errorf("ethtool %s %s: %w", method, dev, syscall.EINVAL)
}

func (f *FakeEthtool) call(method, dev, detail string) (*FakeDev, error) {
	c := method + " " + dev
	if detail != "" {
		c += " " + detail
	}
	f.Calls = append(f.Calls, c)
	if err, ok := f.Fail[method+" "+dev]; ok {
		return nil, err
	}
	d := f.Devs[dev]
	if d == nil {
		if f.b.exists("/sys/class/net/" + dev) {
			return nil, notSupported(method, dev)
		}
		return nil, fmt.Errorf("ethtool %s %s: %w", method, dev, syscall.ENODEV)
	}
	return d, nil
}

func (f *FakeEthtool) DrvInfo(dev string) (hw.DrvInfo, error) {
	d, err := f.call("DrvInfo", dev, "")
	if err != nil {
		return hw.DrvInfo{}, err
	}
	return hw.DrvInfo{Driver: d.Driver, Version: "fake", BusInfo: d.PCI}, nil
}

func (f *FakeEthtool) Channels(dev string) (hw.Channels, error) {
	d, err := f.call("Channels", dev, "")
	if err != nil {
		return hw.Channels{}, err
	}
	if d.Channels.MaxCombined == 0 && d.Channels.MaxRx == 0 {
		return hw.Channels{}, notSupported("Channels", dev)
	}
	return d.Channels, nil
}

func (f *FakeEthtool) SetChannels(dev string, c hw.Channels) error {
	d, err := f.call("SetChannels", dev, fmt.Sprintf("rx=%d tx=%d other=%d combined=%d", c.Rx, c.Tx, c.Other, c.Combined))
	if err != nil {
		return err
	}
	cur := d.Channels
	if cur.MaxCombined == 0 && cur.MaxRx == 0 {
		return notSupported("SetChannels", dev)
	}
	if c.Rx > cur.MaxRx || c.Tx > cur.MaxTx || c.Other > cur.MaxOther || c.Combined > cur.MaxCombined ||
		c.Combined+c.Rx == 0 || c.Combined+c.Tx == 0 {
		return invalid("SetChannels", dev)
	}
	switch d.Driver {
	case "ixgbe":
		if c.Other != cur.Other || c.Rx != 0 || c.Tx != 0 {
			return invalid("SetChannels", dev)
		}
	case "virtio_net":
		if c.Rx != 0 || c.Tx != 0 || c.Other != 0 {
			return invalid("SetChannels", dev)
		}
	}
	if c.Rx == cur.Rx && c.Tx == cur.Tx && c.Other == cur.Other && c.Combined == cur.Combined {
		return nil
	}
	d.Channels.Rx, d.Channels.Tx, d.Channels.Other, d.Channels.Combined = c.Rx, c.Tx, c.Other, c.Combined

	b := f.b
	n := b.nics[dev]
	n.rx, n.tx = queuesOf(d.Channels)
	if d.Driver != "virtio_net" && d.Driver != "mlx5_core" {
		f.reset(dev, d)
	}
	if d.Driver == "virtio_net" {
		// The vectors stay (there is one per possible queue); the driver
		// spreads the queues in use again.
		for _, irq := range n.vecs {
			fi := b.irqs[irq]
			if fi.queue < 0 {
				continue
			}
			fi.hint = nil
			if fi.queue < n.rx {
				fi.hint = b.virtioGroup(fi.queue, n.rx)
			}
			fi.aff = fi.hint
			if len(fi.aff) == 0 {
				fi.aff = b.nodeDefault(n.spec.Node)
			}
			fi.eff = fi.aff[:1]
			fi.memo[fi.aff.List()] = fi.eff
			b.writeIRQ(fi)
		}
	} else {
		b.dropVectors(n)
		b.makeVectors(n, true)
	}
	b.writeQueues(n.netDir, n.rx, n.tx, n, n.spec.XPS)
	d.RxRings = n.rx
	if d.TableSize > 0 && !d.Configured {
		d.Table = defaultTable(d.TableSize, n.rx, d.RSSCap)
	}
	b.resetStats(dev)
	b.writeInterrupts()
	return nil
}

// reset takes the link down and, unless BreakLink, up again.
func (f *FakeEthtool) reset(dev string, d *FakeDev) {
	b := f.b
	f.Resets++
	d.Resets++
	dir := b.netDir(dev)
	set := func(carrier, state string) {
		b.WriteFile(dir+"/carrier", carrier+"\n")
		b.WriteFile(dir+"/operstate", state+"\n")
		if b.exists(dir + "/bonding_slave/mii_status") {
			b.WriteFile(dir+"/bonding_slave/mii_status", state+"\n")
		}
	}
	set("0", "down")
	if f.DuringReset != nil {
		f.DuringReset(dev)
	}
	if !d.BreakLink {
		set("1", "up")
	}
}

func (f *FakeEthtool) RxRings(dev string) (int, error) {
	d, err := f.call("RxRings", dev, "")
	if err != nil {
		return 0, err
	}
	return d.RxRings, nil
}

func (f *FakeEthtool) Indir(dev string) ([]uint32, error) {
	d, err := f.call("Indir", dev, "")
	if err != nil {
		return nil, err
	}
	if d.TableSize == 0 {
		return nil, notSupported("Indir", dev)
	}
	return slices.Clone(d.Table), nil
}

func (f *FakeEthtool) SetIndir(dev string, table []uint32) error {
	detail := "default"
	if table != nil {
		detail = fmt.Sprint(len(table))
	}
	d, err := f.call("SetIndir", dev, detail)
	if err != nil {
		return err
	}
	if d.TableSize == 0 {
		return notSupported("SetIndir", dev)
	}
	limit := d.RxRings
	if d.RSSCap > 0 && d.RSSCap < limit {
		limit = d.RSSCap
	}
	if table == nil {
		// Size 0: the kernel's default over the RX rings, which the
		// driver checks against what its table can address.
		t := make([]uint32, d.TableSize)
		for i := range t {
			t[i] = uint32(i % max(d.RxRings, 1))
			if int(t[i]) >= limit {
				return invalid("SetIndir", dev)
			}
		}
		d.Table, d.Configured = t, false
		return nil
	}
	if len(table) != d.TableSize {
		return invalid("SetIndir", dev)
	}
	for _, q := range table {
		if int(q) >= limit {
			return invalid("SetIndir", dev)
		}
	}
	d.Table, d.Configured = slices.Clone(table), true
	return nil
}

func (f *FakeEthtool) FlowHash(dev string, fl hw.Flow) (uint64, error) {
	d, err := f.call("FlowHash", dev, fl.String())
	if err != nil {
		return 0, err
	}
	bits := d.Hash[fl.String()]
	if bits == 0 {
		return 0, notSupported("FlowHash", dev)
	}
	return bits, nil
}

func (f *FakeEthtool) SetFlowHash(dev string, fl hw.Flow, bits uint64) error {
	d, err := f.call("SetFlowHash", dev, fl.String()+" "+hw.HashLetters(bits))
	if err != nil {
		return err
	}
	if _, ok := d.Hash[fl.String()]; !ok {
		return notSupported("SetFlowHash", dev)
	}
	udp := fl == hw.FlowUDP4 || fl == hw.FlowUDP6
	switch d.Driver {
	case "ixgbe", "igb", "igc":
		// They hash TCP on ports always, UDP on ports or not.
		if bits != hw.HashIPsPorts && !(udp && bits == hw.HashIPs) {
			return invalid("SetFlowHash", dev)
		}
	default:
		if bits != hw.HashIPsPorts && bits != hw.HashIPs {
			return invalid("SetFlowHash", dev)
		}
	}
	if d.Driver == "bnxt_en" && d.Hash[fl.String()] != bits {
		f.reset(dev, d) // bnxt_en re-opens the device for it
	}
	d.Hash[fl.String()] = bits
	return nil
}

func (f *FakeEthtool) Stats(dev string) (map[string]uint64, error) {
	d, err := f.call("Stats", dev, "")
	if err != nil {
		return nil, err
	}
	return maps.Clone(d.Stats), nil
}

func (f *FakeEthtool) Features(dev string) (map[string]bool, error) {
	d, err := f.call("Features", dev, "")
	if err != nil {
		return nil, err
	}
	if d.Features == nil {
		return nil, notSupported("Features", dev)
	}
	return maps.Clone(d.Features), nil
}

var _ hw.Ethtool = (*FakeEthtool)(nil)
