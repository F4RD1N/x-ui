//go:build linux

package hw

import (
	"errors"
	"os"
	"runtime"
	"slices"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The command numbers and structure sizes match the kernel's (the uapi
// numbers x/sys knows, and C layouts mirrored in Go).
func TestEthtoolLayouts(t *testing.T) {
	for _, c := range [][2]int{
		{ethtoolGDrvInfo, unix.ETHTOOL_GDRVINFO}, {ethtoolGChannels, unix.ETHTOOL_GCHANNELS}, {ethtoolSChannels, unix.ETHTOOL_SCHANNELS},
		{ethtoolGRxRings, unix.ETHTOOL_GRXRINGS}, {ethtoolGRxFHIndir, unix.ETHTOOL_GRXFHINDIR}, {ethtoolSRxFHIndir, unix.ETHTOOL_SRXFHINDIR},
		{ethtoolGRxFH, unix.ETHTOOL_GRXFH}, {ethtoolSRxFH, unix.ETHTOOL_SRXFH}, {ethtoolGSsetInfo, unix.ETHTOOL_GSSET_INFO},
		{ethtoolGStrings, unix.ETHTOOL_GSTRINGS}, {ethtoolGStats, unix.ETHTOOL_GSTATS}, {ethtoolGRxCsum, unix.ETHTOOL_GRXCSUM},
		{ethtoolGTxCsum, unix.ETHTOOL_GTXCSUM}, {ethtoolGSG, unix.ETHTOOL_GSG}, {ethtoolGTSO, unix.ETHTOOL_GTSO}, {ethtoolGGSO, unix.ETHTOOL_GGSO},
		{ethtoolGGRO, unix.ETHTOOL_GGRO}, {ethtoolGFlags, unix.ETHTOOL_GFLAGS},
		{int(FlowTCP4), unix.TCP_V4_FLOW}, {int(FlowUDP4), unix.UDP_V4_FLOW}, {int(FlowTCP6), unix.TCP_V6_FLOW}, {int(FlowUDP6), unix.UDP_V6_FLOW},
		// linux/ethtool.h values x/sys does not carry
		{ethSSStats, 1}, {ethFlagTxVLAN, 1 << 7}, {ethFlagRxVLAN, 1 << 8}, {ethFlagLRO, 1 << 15}, {ethFlagNTuple, 1 << 27}, {ethFlagRxHash, 1 << 28},
		{RXHL2DA, 1 << 1}, {RXHVLAN, 1 << 2}, {RXHL3Proto, 1 << 3}, {RXHIPSrc, 1 << 4}, {RXHIPDst, 1 << 5}, {RXHL4B01, 1 << 6}, {RXHL4B23, 1 << 7}, {RXHDiscard, 1 << 31},
	} {
		if c[0] != c[1] {
			t.Errorf("constant %#x, kernel %#x", c[0], c[1])
		}
	}
	if unsafe.Sizeof(unix.EthtoolDrvinfo{}) != sizeDrvInfo {
		t.Errorf("drvinfo %d", unsafe.Sizeof(unix.EthtoolDrvinfo{}))
	}
	// struct ethtool_channels: nine __u32.
	if unsafe.Sizeof([9]uint32{}) != sizeChannels {
		t.Error("channels")
	}
	// struct ethtool_rxnfc with its flow spec (unions of 52 bytes, flow
	// extensions of 20, aligned as C aligns them).
	type flowSpec struct {
		FlowType   uint32
		HU         [52]byte
		HExt       [20]byte
		MU         [52]byte
		MExt       [20]byte
		RingCookie uint64
		Location   uint32
	}
	type rxnfc struct {
		Cmd, FlowType uint32
		Data          uint64
		FS            flowSpec
		RuleCnt       uint32
	}
	if s := unsafe.Sizeof(rxnfc{}); s > sizeRxNFC || (unsafe.Sizeof(uintptr(0)) == 8 && s != sizeRxNFC) {
		t.Errorf("rxnfc %d", s)
	}
	if unsafe.Offsetof(rxnfc{}.Data) != 8 {
		t.Error("rxnfc data offset")
	}
	// struct ifreq: the name, then a union starting with the pointer (24
	// bytes on 64-bit systems, 16 on 32-bit ones).
	want := uintptr(40)
	if unsafe.Sizeof(uintptr(0)) == 4 {
		want = 32
	}
	if unsafe.Sizeof(ifreq{}) != want || unsafe.Offsetof(ifreq{}.data) != unix.IFNAMSIZ {
		t.Errorf("ifreq %d, data at %d", unsafe.Sizeof(ifreq{}), unsafe.Offsetof(ifreq{}.data))
	}
}

// Read-only ioctls on this machine's uplink, when it has one.
func TestSystemEthtoolLive(t *testing.T) {
	nics, _ := UplinkNICs(FS{}, SystemEthtool())
	if len(nics) == 0 {
		t.Skip("no uplink NIC here")
	}
	n := nics[0]
	et := SystemEthtool()
	info, err := et.DrvInfo(n.Name)
	if err != nil {
		t.Fatalf("DrvInfo(%s): %v", n.Name, err)
	}
	if info.Driver != n.Driver {
		t.Errorf("driver %q, sysfs %q", info.Driver, n.Driver)
	}
	if info.BusInfo != n.PCI && n.PCI != "" && !n.VF {
		t.Logf("bus info %q, sysfs %q", info.BusInfo, n.PCI)
	}
	c, err := et.Channels(n.Name)
	switch {
	case errors.Is(err, ErrNotSupported):
	case err != nil:
		t.Errorf("Channels: %v", err)
	case c.Combined+c.Rx == 0:
		t.Errorf("Channels: %+v", c)
	}
	bits, err := et.FlowHash(n.Name, FlowUDP4)
	if err != nil && !errors.Is(err, ErrNotSupported) {
		t.Errorf("FlowHash: %v", err)
	}
	if _, err := et.Indir(n.Name); err != nil && !errors.Is(err, ErrNotSupported) {
		t.Errorf("Indir: %v", err)
	}
	stats, err := et.Stats(n.Name)
	if err != nil && !errors.Is(err, ErrNotSupported) {
		t.Errorf("Stats: %v", err)
	}
	feats, err := et.Features(n.Name)
	if err != nil {
		t.Errorf("Features: %v", err)
	}
	if _, err := et.DrvInfo("lo"); !errors.Is(err, ErrNotSupported) && err != nil {
		t.Logf("lo: %v", err)
	}
	if _, err := et.Channels("xui-no-such-dev"); !errors.Is(err, syscall.ENODEV) {
		t.Errorf("missing device: %v", err)
	}
	if _, err := et.Channels("a-name-far-too-long-for-a-device"); err == nil {
		t.Error("long name accepted")
	}
	t.Logf("%s: %+v, channels %+v, udp4 hash %q, %d counters, %d features, %d queue IRQs", n.Name, info, c, HashLetters(bits), len(stats), len(feats), len(n.IRQs))
}

// SCHANNELS on a veth pair in a network namespace of its own (root, and
// XUI_HW_LIVE=1). The thread that made the namespace is never unlocked, so
// Go ends it with the goroutine and the namespace goes with it: the host's
// devices are never touched.
func TestSystemEthtoolSetChannelsNetns(t *testing.T) {
	if os.Getenv("XUI_HW_LIVE") != "1" || os.Geteuid() != 0 {
		t.Skip("needs root and XUI_HW_LIVE=1")
	}
	if _, err := os.Stat("/sys/module/veth"); err != nil {
		t.Skip("the veth module is not loaded (this test loads no module)")
	}
	type result struct {
		before, after Channels
		err           error
	}
	done := make(chan result, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread dies with the goroutine
		var r result
		defer func() { done <- r }()
		if r.err = unix.Unshare(unix.CLONE_NEWNET); r.err != nil {
			return
		}
		if r.err = addVeth("xuihw0", "xuihw1", 4); r.err != nil {
			return
		}
		et := SystemEthtool()
		if r.before, r.err = et.Channels("xuihw0"); r.err != nil {
			return
		}
		want := r.before
		if want.MaxCombined > 1 {
			want.Combined = want.Combined%want.MaxCombined + 1
		} else {
			want.Rx = want.Rx%want.MaxRx + 1
			want.Tx = want.Tx%want.MaxTx + 1
		}
		if r.err = et.SetChannels("xuihw0", want); r.err != nil {
			return
		}
		r.after, r.err = et.Channels("xuihw0")
	}()
	r := <-done
	if r.err != nil {
		t.Fatal(r.err)
	}
	if r.before == r.after || r.after.MaxRx != r.before.MaxRx {
		t.Fatalf("channels did not change: %+v -> %+v", r.before, r.after)
	}
	t.Logf("veth channels %+v -> %+v", r.before, r.after)
}

// addVeth creates a veth pair with RTM_NEWLINK, each end with the given
// number of queues.
func addVeth(name, peer string, queues uint32) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	attr := func(typ uint16, data []byte) []byte {
		b := make([]byte, (4+len(data)+3)&^3)
		ne.PutUint16(b, uint16(4+len(data)))
		ne.PutUint16(b[2:], typ)
		copy(b[4:], data)
		return b
	}
	u32 := func(v uint32) []byte { return ne.AppendUint32(nil, v) }
	str := func(s string) []byte { return append([]byte(s), 0) }
	link := func(n string) []byte {
		b := make([]byte, unix.SizeofIfInfomsg)
		b = append(b, attr(unix.IFLA_IFNAME, str(n))...)
		b = append(b, attr(unix.IFLA_NUM_TX_QUEUES, u32(queues))...)
		return append(b, attr(unix.IFLA_NUM_RX_QUEUES, u32(queues))...)
	}
	const vethInfoPeer = 1
	info := slices.Concat(attr(unix.IFLA_INFO_KIND, str("veth")), attr(unix.IFLA_INFO_DATA, attr(vethInfoPeer, link(peer))))
	body := append(link(name), attr(unix.IFLA_LINKINFO, info)...)
	msg := make([]byte, unix.SizeofNlMsghdr, unix.SizeofNlMsghdr+len(body))
	ne.PutUint32(msg, uint32(unix.SizeofNlMsghdr+len(body)))
	ne.PutUint16(msg[4:], unix.RTM_NEWLINK)
	ne.PutUint16(msg[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_EXCL)
	ne.PutUint32(msg[8:], 1)
	msg = append(msg, body...)
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		return err
	}
	if n < unix.SizeofNlMsghdr+4 || ne.Uint16(buf[4:]) != unix.NLMSG_ERROR {
		return errors.New("netlink: unexpected answer")
	}
	if e := int32(ne.Uint32(buf[unix.SizeofNlMsghdr:])); e != 0 {
		return syscall.Errno(-e)
	}
	return nil
}
