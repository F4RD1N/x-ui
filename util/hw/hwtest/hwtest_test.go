package hwtest

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
	"syscall"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/util/hw"
)

func treeHash(t *testing.T, root string) string {
	t.Helper()
	h := sha256.New()
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		h.Write([]byte(p))
		if d.Type().IsRegular() {
			data, _ := os.ReadFile(p)
			h.Write(data)
		}
		return nil
	})
	return hex.EncodeToString(h.Sum(nil))
}

// A raise on ixgbe resets the link and re-creates the interrupts with new
// numbers and the kernel's default affinity; the table stays within what RSS
// can address.
func TestFakeChannelRaise(t *testing.T) {
	b := Bond().Build(t)
	old := b.IRQs("eno1")
	if len(old) != 17 || old[0] != 101 {
		t.Fatalf("eno1 irqs %v", old)
	}
	reset := ""
	b.Eth.DuringReset = func(dev string) {
		reset = dev + " carrier " + strings.TrimSpace(b.ReadFile("/sys/class/net/"+dev+"/carrier"))
	}
	c, _ := b.Eth.Channels("eno1")
	c.Combined = 28
	if err := b.Eth.SetChannels("eno1", c); err != nil {
		t.Fatal(err)
	}
	if reset != "eno1 carrier 0" || b.Eth.Resets != 1 || b.Eth.Devs["eno1"].Resets != 1 || b.ReadFile("/sys/class/net/eno1/carrier") != "1\n" {
		t.Errorf("reset: %q %d, carrier %q", reset, b.Eth.Resets, b.ReadFile("/sys/class/net/eno1/carrier"))
	}
	n := hw.ReadNIC(b.FS(), b.Eth, "eno1")
	if len(n.IRQs) != 28 || n.IRQs[0].IRQ == 101 || n.IRQs[0].IRQ < 218 || n.RxQueues != 28 || n.TxQueues != 28 || n.RxRings != 28 || n.Channels.Combined != 28 {
		t.Fatalf("after: %d irqs from %d, %d queues", len(n.IRQs), n.IRQs[0].IRQ, n.RxQueues)
	}
	if b.ReadFile("/proc/irq/101/smp_affinity_list") != "" || b.ReadFile("/sys/class/net/eno1/device/msi_irqs/101") != "" {
		t.Error("old interrupt 101 still there")
	}
	if !strings.Contains(b.ReadFile("/proc/interrupts"), "eno1-TxRx-27") || strings.Contains(b.ReadFile("/proc/interrupts"), " 101: ") {
		t.Error("/proc/interrupts not renumbered")
	}
	if q := n.IRQs[20]; q.Affinity.List() != b.nodeDefault(1).List() || q.Effective.List() != q.Hint.List() {
		t.Errorf("fresh affinity: %+v", q)
	}
	if use := n.RSSUse(); len(use) != 16 || !hw.DefaultForm(n.Indir, 16) {
		t.Errorf("table after the raise: %v", use)
	}
	if _, ok := b.Eth.Devs["eno1"].Stats["rx_queue_27_packets"]; !ok {
		t.Error("per-queue counters")
	}
	// eno2 is untouched.
	if m := hw.ReadNIC(b.FS(), b.Eth, "eno2"); len(m.IRQs) != 16 || m.IRQs[0].IRQ != 201 {
		t.Errorf("eno2 changed: %d", len(m.IRQs))
	}

	// ixgbe keeps its "other" vector; a lowering works the same way.
	c.Other = 0
	if err := b.Eth.SetChannels("eno1", c); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("other changed: %v", err)
	}
	c.Other, c.Combined = 1, 64
	if err := b.Eth.SetChannels("eno1", c); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("above max: %v", err)
	}
	// A link that does not come back.
	b.Eth.Devs["eno2"].BreakLink = true
	c2, _ := b.Eth.Channels("eno2")
	c2.Combined = 20
	if err := b.Eth.SetChannels("eno2", c2); err != nil || b.ReadFile("/sys/class/net/eno2/carrier") != "0\n" || b.ReadFile("/sys/class/net/eno2/bonding_slave/mii_status") != "down\n" {
		t.Errorf("broken link: %v %q", err, b.ReadFile("/sys/class/net/eno2/carrier"))
	}
	// Failures on demand, and every call recorded.
	b.Eth.Fail["SetChannels eno1"] = fmt.Errorf("busy: %w", syscall.EBUSY)
	if err := b.Eth.SetChannels("eno1", c); !errors.Is(err, syscall.EBUSY) {
		t.Errorf("Fail: %v", err)
	}
	if !slices.Contains(b.Eth.Calls, "SetChannels eno1 rx=0 tx=0 other=1 combined=28") {
		t.Errorf("calls: %v", b.Eth.Calls)
	}
}

func TestFakeIndir(t *testing.T) {
	b := Production().Build(t)
	// Size 0 over 56 rings asks for queues the 82599 cannot address.
	if err := b.Eth.SetIndir("eno1", nil); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("default over 56 rings: %v", err)
	}
	table := make([]uint32, 128)
	for i := range table {
		table[i] = uint32(i % 8)
	}
	if err := b.Eth.SetIndir("eno1", table); err != nil || !b.Eth.Devs["eno1"].Configured {
		t.Fatalf("explicit: %v", err)
	}
	table[0] = 16
	if err := b.Eth.SetIndir("eno1", table); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("entry over the cap: %v", err)
	}
	if err := b.Eth.SetIndir("eno1", table[:64]); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("wrong size: %v", err)
	}
	// A configured table survives a channel change.
	c, _ := b.Eth.Channels("eno1")
	c.Combined = 16
	b.Eth.SetChannels("eno1", c)
	if got, _ := b.Eth.Indir("eno1"); got[1] != 1 || got[8] != 0 {
		t.Errorf("configured table rebuilt: %v", got[:16])
	}
	// Size 0 within the cap resets it and clears the flag.
	if err := b.Eth.SetIndir("eno1", nil); err != nil || b.Eth.Devs["eno1"].Configured {
		t.Errorf("reset: %v", err)
	}
	if got, _ := b.Eth.Indir("eno1"); !hw.DefaultForm(got, 16) {
		t.Errorf("reset table %v", got[:20])
	}
	// No table at all.
	v := VPS(1).Build(t)
	if _, err := v.Eth.Indir("eth0"); !errors.Is(err, hw.ErrNotSupported) {
		t.Errorf("virtio table: %v", err)
	}
	if err := v.Eth.SetIndir("eth0", nil); !errors.Is(err, hw.ErrNotSupported) {
		t.Errorf("virtio set table: %v", err)
	}
}

func TestFakeFlowHash(t *testing.T) {
	b := Production().Build(t)
	if err := b.Eth.SetFlowHash("eno1", hw.FlowUDP4, hw.HashIPsPorts); err != nil {
		t.Fatal(err)
	}
	if bits, _ := b.Eth.FlowHash("eno1", hw.FlowUDP4); bits != hw.HashIPsPorts || b.Eth.Resets != 0 {
		t.Errorf("udp4 %q, resets %d", hw.HashLetters(bits), b.Eth.Resets)
	}
	if err := b.Eth.SetFlowHash("eno1", hw.FlowTCP4, hw.HashIPs); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("ixgbe tcp4 sd: %v", err)
	}
	if err := b.Eth.SetFlowHash("eno1", hw.FlowUDP6, hw.HashIPs|hw.RXHVLAN); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("odd bits: %v", err)
	}
	// bnxt_en re-opens the device for a hash change.
	v := VLAN().Build(t)
	if err := v.Eth.SetFlowHash("eno1", hw.FlowUDP4, hw.HashIPs); err != nil || v.Eth.Resets != 1 {
		t.Errorf("bnxt: %v, resets %d", err, v.Eth.Resets)
	}
	// virtio without RSS hashes on nothing, and cannot be changed.
	p := VPS(1).Build(t)
	if bits, err := p.Eth.FlowHash("eth0", hw.FlowUDP4); bits != 0 || err != nil {
		t.Errorf("virtio hash: %x %v", bits, err)
	}
	if err := p.Eth.SetFlowHash("eth0", hw.FlowUDP4, hw.HashIPsPorts); !errors.Is(err, hw.ErrNotSupported) {
		t.Errorf("virtio set hash: %v", err)
	}
	// Devices without a driver here.
	c := Container().Build(t)
	if _, err := c.Eth.Channels("eth0"); !errors.Is(err, hw.ErrNotSupported) {
		t.Errorf("veth: %v", err)
	}
	if _, err := c.Eth.Channels("eth9"); !errors.Is(err, syscall.ENODEV) {
		t.Errorf("missing device: %v", err)
	}
}

// virtio_net changes queues without a reset; its vectors stay and are
// spread again.
func TestFakeVirtioQueues(t *testing.T) {
	m := VPS(4)
	m.NICs[0].Channels = hw.Channels{MaxCombined: 4, Combined: 1}
	b := m.Build(t)
	irqs := b.IRQs("eth0")
	n := hw.ReadNIC(b.FS(), b.Eth, "eth0")
	if len(irqs) != 9 || len(n.IRQs) != 8 || n.IRQs[0].Hint.List() != "0-3" || len(n.XPS) != 0 {
		t.Fatalf("virtio 1 of 4: %v %+v", irqs, n.IRQs[0])
	}
	if err := b.Eth.SetChannels("eth0", hw.Channels{MaxCombined: 4, Combined: 4}); err != nil {
		t.Fatal(err)
	}
	n = hw.ReadNIC(b.FS(), b.Eth, "eth0")
	if b.Eth.Resets != 0 || !slices.Equal(b.IRQs("eth0"), irqs) || n.RxQueues != 4 || n.IRQs[6].Hint.List() != "3" || n.IRQs[6].Effective.List() != "3" {
		t.Errorf("virtio 4: resets %d, q3 %+v", b.Eth.Resets, n.IRQs[6])
	}
	if len(n.XPS) != 4 || n.XPS[2].List() != "2" {
		t.Errorf("virtio xps: %v", n.XPS)
	}
	if err := b.Eth.SetChannels("eth0", hw.Channels{Rx: 1, Combined: 2}); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("virtio rx: %v", err)
	}
}

// Settle shows written affinities as the kernel would, and an affinity
// written back brings the tree back byte for byte.
func TestSettle(t *testing.T) {
	b := Production().Build(t)
	before := treeHash(t, b.Root)
	b.WriteFile("/proc/irq/101/smp_affinity_list", "27\n")
	b.WriteFile("/sys/class/net/eno1/queues/tx-0/xps_cpus", "8000000\n")
	b.WriteFile("/sys/class/net/eno1/queues/rx-0/rps_cpus", "f\n")
	b.Settle()
	if b.ReadFile("/proc/irq/101/smp_affinity") != "000000,08000000\n" || b.ReadFile("/proc/irq/101/effective_affinity_list") != "27\n" {
		t.Errorf("settled: %q %q", b.ReadFile("/proc/irq/101/smp_affinity"), b.ReadFile("/proc/irq/101/effective_affinity_list"))
	}
	if b.ReadFile("/sys/class/net/eno1/queues/tx-0/xps_cpus") != "000000,08000000\n" || b.ReadFile("/sys/class/net/eno1/queues/rx-0/rps_cpus") != "000000,0000000f\n" {
		t.Errorf("masks: %q", b.ReadFile("/sys/class/net/eno1/queues/tx-0/xps_cpus"))
	}
	irqs, _ := hw.ReadInterrupts(b.FS())
	if irqs[101].Name != "eno1-TxRx-0" {
		t.Error("interrupts")
	}
	odd := hw.NewCPUSet()
	for c := 1; c < 56; c += 2 {
		odd = append(odd, c)
	}
	b.WriteFile("/proc/irq/101/smp_affinity_list", odd.List()+"\n")
	b.WriteFile("/sys/class/net/eno1/queues/tx-0/xps_cpus", "2\n")
	b.WriteFile("/sys/class/net/eno1/queues/rx-0/rps_cpus", "0\n")
	b.Settle()
	if after := treeHash(t, b.Root); after != before {
		t.Errorf("not byte-exact after writing the old values back: effective %q", b.ReadFile("/proc/irq/101/effective_affinity_list"))
	}
	// A write through the mask file, and a value the kernel refuses.
	b.WriteFile("/proc/irq/102/smp_affinity", "4\n")
	b.WriteFile("/proc/irq/103/smp_affinity_list", "200\n")
	b.Settle()
	if b.ReadFile("/proc/irq/102/smp_affinity_list") != "2\n" || b.ReadFile("/proc/irq/103/smp_affinity_list") != odd.List()+"\n" {
		t.Errorf("mask write %q, refused %q", b.ReadFile("/proc/irq/102/smp_affinity_list"), b.ReadFile("/proc/irq/103/smp_affinity_list"))
	}
}

func TestSetters(t *testing.T) {
	b := Production().Build(t)
	b.SetCPUTimes(5, 100, 50, 25, 3, 1000)
	stat := b.ReadFile("/proc/stat")
	if !strings.Contains(stat, "\ncpu5 100 0 50 1000 0 0 25 3 0 0\n") || !strings.HasPrefix(stat, "cpu  ") {
		t.Errorf("stat: %s", stat[:200])
	}
	b.SetSoftnet(3, 7, 2, 1)
	if lines := strings.Split(b.ReadFile("/proc/net/softnet_stat"), "\n"); !strings.HasPrefix(lines[3], "00000007 00000002 00000001 ") || strings.Fields(lines[3])[12] != "00000003" {
		t.Errorf("softnet: %q", lines[3])
	}
	b.SetIRQCount(120, 9, 77)
	if irqs, _ := hw.ReadInterrupts(b.FS()); irqs[120].PerCPU[9] != 77 {
		t.Error("irq count")
	}
	b.SetStat("eno1", "rx_bytes", 12345)
	b.SetStat("eno1", "fdir_overflow", 60808)
	b.SetStat("eno1", "rx_missed_errors", 175000)
	st, _ := b.Eth.Stats("eno1")
	if b.ReadFile("/sys/class/net/eno1/statistics/rx_bytes") != "12345\n" || st["rx_bytes"] != 12345 || st["fdir_overflow"] != 60808 ||
		st["rx_missed_errors"] != 175000 || b.ReadFile("/sys/class/net/eno1/statistics/rx_missed_errors") != "175000\n" {
		t.Errorf("stats: %v", st)
	}
	if st["rx_queue_55_packets"] == 0 {
		t.Error("per-queue counters")
	}
}

func TestPresetFiles(t *testing.T) {
	b := Production().Build(t)
	for p, want := range map[string]string{
		"/sys/devices/system/cpu/online":                        "0-55\n",
		"/sys/devices/system/cpu/cpu29/topology/core_cpus_list": "1,29\n",
		"/sys/devices/system/node/node1/distance":               "21 10\n",
		"/proc/irq/default_smp_affinity":                        "ffffff,ffffffff\n",
		"/proc/irq/101/effective_affinity_list":                 "11\n",
		"/proc/irq/116/effective_affinity_list":                 "41\n",
		"/proc/irq/101/affinity_hint":                           "000000,00000002\n",
		"/sys/class/net/eno1/queues/rx-0/rps_cpus":              "000000,00000000\n",
		"/sys/class/net/eno1/queues/tx-3/traffic_class":         "0\n",
		"/sys/bus/pci/devices/0000:82:00.0/numa_node":           "1\n",
		"/usr/lib/systemd/system/irqbalance.service":            IRQBalanceUnitDebian,
		"/proc/sys/kernel/numa_balancing":                       "1\n",
	} {
		if got := b.ReadFile(p); got != want {
			t.Errorf("%s = %q, want %q", p, got, want)
		}
	}
	if b.ReadFile("/proc/812/comm") != "" || !b.FS().Exists("/run/systemd/system") {
		t.Error("irqbalance runs, or no systemd")
	}
	m := Production()
	m.IRQBalance = "running-ours"
	b = m.Build(t)
	if c := b.ReadFile("/proc/812/cmdline"); c != "/usr/sbin/irqbalance\x00--foreground\x00--policyscript="+IRQBalancePolicy+"\x00" {
		t.Errorf("cmdline %q", c)
	}
	if b := Container().Build(t); !b.FS().Exists("/.dockerenv") || len(b.Eth.Devs) != 0 {
		t.Error("container")
	}
	if b := VPS(1).Build(t); !strings.Contains(b.ReadFile("/proc/cpuinfo"), " hypervisor") || b.FS().Exists("/sys/devices/system/node") {
		t.Error("VM")
	}
	if b := Restricted().Build(t); b.FS().Exists("/sys/devices/system/cpu/cpu3/topology") || b.ReadFile("/sys/devices/system/cpu/cpu3/online") != "0\n" {
		t.Error("offline CPU")
	}
}
