package hwtest

import "github.com/mhsanaei/3x-ui/v2/util/hw"

// Hash values as drivers report them.
var (
	hashIXGBE = map[string]uint64{"tcp4": hw.HashIPsPorts, "udp4": hw.HashIPs, "tcp6": hw.HashIPsPorts, "udp6": hw.HashIPs}
	hashPorts = map[string]uint64{"tcp4": hw.HashIPsPorts, "udp4": hw.HashIPsPorts, "tcp6": hw.HashIPsPorts, "udp6": hw.HashIPsPorts}
)

func cloneHash(h map[string]uint64) map[string]uint64 {
	out := map[string]uint64{}
	for k, v := range h {
		out[k] = v
	}
	return out
}

// Production is the x-ui production server: two Xeon E5-2680 v4 (14 cores,
// 2 threads each; node 0 the even CPUs, node 1 the odd ones, siblings n and
// n+28), 121 GiB, and an Intel 82599ES (ixgbe) on node 1 with 56 queues of
// which RSS can address 16. Its queue interrupts are as found there: RSS
// queues 0-15 on CPUs 11, 13, ..., 41, the others round-robin over the rest
// of node 1. irqbalance is installed, not running.
func Production() Machine {
	var eff []int
	for q := 0; q < 16; q++ {
		eff = append(eff, 11+2*q)
	}
	rest := []int{1, 3, 5, 7, 9, 43, 45, 47, 49, 51, 53, 55}
	for q := 16; q < 56; q++ {
		eff = append(eff, rest[(q-16)%len(rest)])
	}
	return Machine{
		Packages: 2, CoresPerPackage: 14, ThreadsPerCore: 2, Numbering: "interleaved", MemGiB: 121,
		Model: "Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz", Kernel: "7.0.0-x-ui",
		NICs: []NICSpec{{
			Name: "eno1", Driver: "ixgbe", PCI: "0000:82:00.0", Vendor: "8086", Device: "10fb", Node: 1, SpeedMbps: 10000,
			Channels:  hw.Channels{MaxOther: 1, MaxCombined: 56, Other: 1, Combined: 56},
			TableSize: 128, RSSCap: 16, Hash: cloneHash(hashIXGBE),
			IRQBase: 101, Affinity: "node", Hint: "spread", Effective: eff, XPS: "hint",
		}},
		Routes: []RouteSpec{
			{Dev: "eno1", Gateway: "76.164.201.1"},
			{Dev: "eno1", Gateway: "fe80::1", V6: true},
		},
		IRQBalance: "installed",
	}
}

// EPYC is a two-socket AMD EPYC with 128 cores of 2 threads per socket
// (siblings n and n+256), nps NUMA nodes per socket (1 or 4), 1 TiB, and a
// 100G ConnectX-6 Dx (mlx5_core) on node 0 with 63 queues, each pinned by
// the driver to one CPU near the card.
func EPYC(nps int) Machine {
	if nps < 1 {
		nps = 1
	}
	n := 2 * nps
	slit := make([][]int, n)
	for a := range slit {
		slit[a] = make([]int, n)
		for c := range slit[a] {
			switch {
			case a == c:
				slit[a][c] = 10
			case a/nps == c/nps:
				slit[a][c] = 12
			default:
				slit[a][c] = 32
			}
		}
	}
	return Machine{
		Packages: 2, CoresPerPackage: 128, ThreadsPerCore: 2, NodesPerPackage: nps, Numbering: "linear", MemGiB: 1024,
		SLIT: slit, Model: "AMD EPYC 9754 128-Core Processor",
		NICs: []NICSpec{{
			Name: "enp65s0f0np0", Driver: "mlx5_core", PCI: "0000:41:00.0", Vendor: "15b3", Device: "101d", Node: 0, SpeedMbps: 100000,
			Channels:  hw.Channels{MaxCombined: 63, Combined: 63},
			TableSize: 256, Hash: cloneHash(hashPorts),
			Affinity: "hint", Hint: "spread", XPS: "hint",
		}},
		Routes: []RouteSpec{{Dev: "enp65s0f0np0", Gateway: "203.0.113.1"}},
	}
}

// Desktop is one 8-core CPU with 2 threads per core (siblings 2k and 2k+1),
// 32 GiB, and an Intel I210 (igb) with no NUMA node, 4 queues on the
// kernel's default affinity.
func Desktop() Machine {
	return Machine{
		Packages: 1, CoresPerPackage: 8, ThreadsPerCore: 2, Numbering: "adjacent", MemGiB: 32,
		Model: "Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz",
		NICs: []NICSpec{{
			Name: "eno1", Driver: "igb", PCI: "0000:03:00.0", Vendor: "8086", Device: "1533", Node: -1, SpeedMbps: 1000,
			Channels:  hw.Channels{MaxOther: 1, MaxCombined: 4, Other: 1, Combined: 4},
			TableSize: 128, Hash: cloneHash(hashIXGBE), Affinity: "default",
		}},
		Routes: []RouteSpec{{Dev: "eno1", Gateway: "192.168.1.1"}},
	}
}

// VPS is a KVM guest with n single-thread vCPUs, no NUMA directories, n GiB
// (1 GiB at least) and one virtio_net NIC with one queue (Channels makes it
// multi-queue): no RSS table, no hash settings.
func VPS(n int) Machine {
	if n < 1 {
		n = 1
	}
	return Machine{
		Packages: 1, CoresPerPackage: n, ThreadsPerCore: 1, MemGiB: n, NoNUMA: true, Virt: "kvm",
		Model: "Intel Xeon Processor (Skylake, IBRS)",
		NICs: []NICSpec{{
			Name: "eth0", Driver: "virtio_net", PCI: "0000:00:03.0", Virtio: 1, Vendor: "1af4", Device: "1000", Node: -1,
			Channels: hw.Channels{MaxCombined: 1, Combined: 1},
			Affinity: "hint", Hint: "virtio", XPS: "hint",
		}},
		Routes: []RouteSpec{
			{Dev: "eth0", Gateway: "10.0.0.1"},
			{Dev: "eth0", Gateway: "fe80::1", V6: true},
		},
	}
}

// Restricted is two 4-core sockets with 2 threads per core, interleaved
// (siblings n and n+8), CPU 3 offline (its sibling 11 stays online), and the
// panel allowed only 0-2,4-6,8-10,12-13. An ixgbe on node 0 has 8 of 15
// queues.
func Restricted() Machine {
	return Machine{
		Packages: 2, CoresPerPackage: 4, ThreadsPerCore: 2, Numbering: "interleaved", MemGiB: 16,
		Offline: []int{3}, Allowed: []int{0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13},
		NICs: []NICSpec{{
			Name: "eno1", Driver: "ixgbe", PCI: "0000:01:00.0", Vendor: "8086", Device: "10fb", Node: 0, SpeedMbps: 10000,
			Channels:  hw.Channels{MaxOther: 1, MaxCombined: 15, Other: 1, Combined: 8},
			TableSize: 128, RSSCap: 16, Hash: cloneHash(hashIXGBE), Affinity: "node", Hint: "spread", XPS: "hint",
		}},
		Routes: []RouteSpec{{Dev: "eno1", Gateway: "192.0.2.1"}},
	}
}

// CPULessNode is two 8-core sockets with 2 threads per core (siblings n and
// n+16) and a third, memory-only node of 64 GiB (CXL or Optane), with an
// ixgbe on node 0.
func CPULessNode() Machine {
	return Machine{
		Packages: 2, CoresPerPackage: 8, ThreadsPerCore: 2, Numbering: "linear", MemGiB: 64, MemOnlyNodes: []int{64},
		SLIT: [][]int{{10, 21, 17}, {21, 10, 28}, {17, 28, 10}},
		NICs: []NICSpec{{
			Name: "eno1", Driver: "ixgbe", PCI: "0000:01:00.0", Vendor: "8086", Device: "10fb", Node: 0, SpeedMbps: 10000,
			Channels:  hw.Channels{MaxOther: 1, MaxCombined: 32, Other: 1, Combined: 32},
			TableSize: 128, RSSCap: 16, Hash: cloneHash(hashIXGBE), Affinity: "node", Hint: "spread", XPS: "hint",
		}},
		Routes: []RouteSpec{{Dev: "eno1", Gateway: "192.0.2.1"}},
	}
}

// Bond is the production topology with an 802.3ad bond over the two ports
// of an 82599 (ixgbe, node 1, 16 of 63 queues each).
func Bond() Machine {
	m := Production()
	port := func(name, pci string, base int) NICSpec {
		return NICSpec{
			Name: name, Driver: "ixgbe", PCI: pci, Vendor: "8086", Device: "10fb", Node: 1, SpeedMbps: 10000,
			Channels:  hw.Channels{MaxOther: 1, MaxCombined: 63, Other: 1, Combined: 16},
			TableSize: 128, RSSCap: 16, Hash: cloneHash(hashIXGBE), IRQBase: base, Affinity: "node", Hint: "spread", XPS: "hint",
		}
	}
	m.NICs = []NICSpec{port("eno1", "0000:82:00.0", 101), port("eno2", "0000:82:00.1", 201)}
	m.Bonds = []BondSpec{{Name: "bond0", Mode: "802.3ad", Slaves: []string{"eno1", "eno2"}}}
	m.Routes = []RouteSpec{{Dev: "bond0", Gateway: "76.164.201.1"}, {Dev: "bond0", Gateway: "fe80::1", V6: true}}
	m.IRQBalance = ""
	return m
}

// ProxmoxBridge is a Proxmox host: one 16-core CPU with 2 threads per core
// (siblings n and n+16), the default route on the bridge vmbr0 over an Intel
// X710 (i40e, 32 queues, UDP hashed on ports) and a VM's tap.
func ProxmoxBridge() Machine {
	return Machine{
		Packages: 1, CoresPerPackage: 16, ThreadsPerCore: 2, Numbering: "linear", MemGiB: 128,
		NICs: []NICSpec{{
			Name: "eno1", Driver: "i40e", PCI: "0000:01:00.0", Vendor: "8086", Device: "1572", Node: 0, SpeedMbps: 10000,
			Channels:  hw.Channels{MaxOther: 1, MaxCombined: 32, Other: 1, Combined: 32},
			TableSize: 512, Hash: cloneHash(hashPorts), Affinity: "default", Hint: "spread", XPS: "hint",
		}},
		Bridges: []BridgeSpec{{Name: "vmbr0", Ports: []string{"eno1", "tap100i0"}}},
		Routes:  []RouteSpec{{Dev: "vmbr0", Gateway: "192.0.2.1"}},
	}
}

// VLAN is one 8-core CPU with 2 threads per core (siblings n and n+8), the
// default route on VLAN 100 over a Broadcom BCM57414 (bnxt_en, 8 of 74
// queues, UDP hashed on ports).
func VLAN() Machine {
	return Machine{
		Packages: 1, CoresPerPackage: 8, ThreadsPerCore: 2, Numbering: "linear", MemGiB: 64,
		NICs: []NICSpec{{
			Name: "eno1", Driver: "bnxt_en", PCI: "0000:01:00.0", Vendor: "14e4", Device: "16d7", Node: 0, SpeedMbps: 25000,
			Channels:  hw.Channels{MaxCombined: 74, Combined: 8},
			TableSize: 128, Hash: cloneHash(hashPorts), Affinity: "default", Hint: "spread",
		}},
		VLANs:  []VLANSpec{{Name: "eno1.100", Lower: "eno1", ID: 100}},
		Routes: []RouteSpec{{Dev: "eno1.100", Gateway: "192.0.2.1"}},
	}
}

// ManagedIRQs is one 8-core CPU with 2 threads per core (siblings 2k and
// 2k+1) and a Cisco VIC (enic) whose 8 RX and 8 TX vectors the kernel
// manages: writing their affinity fails with EIO (Built.FailWrite).
func ManagedIRQs() Machine {
	return Machine{
		Packages: 1, CoresPerPackage: 8, ThreadsPerCore: 2, Numbering: "adjacent", MemGiB: 32,
		NICs: []NICSpec{{
			Name: "eth0", Driver: "enic", PCI: "0000:07:00.0", Vendor: "1137", Device: "0043", Node: 0, SpeedMbps: 40000,
			Channels: hw.Channels{MaxRx: 8, MaxTx: 8, Rx: 8, Tx: 8},
			Affinity: "managed",
		}},
		Routes: []RouteSpec{{Dev: "eth0", Gateway: "192.0.2.1"}},
	}
}

// Container is a Docker container: the host's CPUs (the Desktop's), and a
// veth eth0 with the default route.
func Container() Machine {
	m := Desktop()
	m.NICs = nil
	m.Virt = "docker"
	m.Links = []LinkSpec{{Name: "eth0", Kind: "veth"}}
	m.Routes = []RouteSpec{{Dev: "eth0", Gateway: "172.17.0.1"}}
	return m
}

// Tunnel is the Desktop with its default route through WireGuard (wg0); the
// igb NIC carries no default route.
func Tunnel() Machine {
	m := Desktop()
	m.Links = []LinkSpec{{Name: "wg0", Kind: "wireguard"}}
	m.Routes = []RouteSpec{{Dev: "wg0"}}
	return m
}
