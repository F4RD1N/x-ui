//go:build linux

package hw

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ethtool commands (linux/ethtool.h).
const (
	ethtoolGDrvInfo   = 0x03
	ethtoolGRxCsum    = 0x14
	ethtoolGTxCsum    = 0x16
	ethtoolGSG        = 0x18
	ethtoolGStrings   = 0x1b
	ethtoolGStats     = 0x1d
	ethtoolGTSO       = 0x1e
	ethtoolGGSO       = 0x23
	ethtoolGFlags     = 0x25
	ethtoolGRxFH      = 0x29
	ethtoolSRxFH      = 0x2a
	ethtoolGGRO       = 0x2b
	ethtoolGRxRings   = 0x2d
	ethtoolGSsetInfo  = 0x37
	ethtoolGRxFHIndir = 0x38
	ethtoolSRxFHIndir = 0x39
	ethtoolGChannels  = 0x3c
	ethtoolSChannels  = 0x3d

	ethSSStats    = 1  // ETH_SS_STATS
	ethGStringLen = 32 // ETH_GSTRING_LEN

	// Sizes of the structures the commands carry.
	sizeDrvInfo  = 196 // struct ethtool_drvinfo
	sizeChannels = 36  // struct ethtool_channels
	sizeRxNFC    = 192 // struct ethtool_rxnfc, with its flow spec
	sizeValue    = 8   // struct ethtool_value
)

// ETHTOOL_GFLAGS bits.
const (
	ethFlagTxVLAN = 1 << 7
	ethFlagRxVLAN = 1 << 8
	ethFlagLRO    = 1 << 15
	ethFlagNTuple = 1 << 27
	ethFlagRxHash = 1 << 28
)

// ifreq is struct ifreq with the data pointer of SIOCETHTOOL: the name, then
// a union of 24 bytes on 64-bit systems (16 on 32-bit) that starts with the
// pointer.
type ifreq struct {
	name [unix.IFNAMSIZ]byte
	data unsafe.Pointer
	_    [unsafe.Sizeof(uintptr(0)) + 8]byte
}

var ne = binary.NativeEndian

type sysEthtool struct {
	mu sync.Mutex
	fd int
}

// SystemEthtool talks to the kernel through one datagram socket, opened on
// first use in the caller's network namespace and kept.
func SystemEthtool() Ethtool { return &sysEthtool{fd: -1} }

func (s *sysEthtool) socket() (int, error) {
	if s.fd >= 0 {
		return s.fd, nil
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		// No IPv4 here: any socket reaches the device ioctls.
		if fd, err = unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0); err != nil {
			return -1, err
		}
	}
	s.fd = fd
	return fd, nil
}

// ioctl runs one ethtool command; buf holds the command's structure, its
// first word the command.
func (s *sysEthtool) ioctl(dev string, buf []byte, set bool) error {
	if len(dev) == 0 || len(dev) >= unix.IFNAMSIZ {
		return fmt.Errorf("ethtool: bad device name %q", dev)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	fd, err := s.socket()
	if err != nil {
		return err
	}
	ifr := new(ifreq)
	copy(ifr.name[:], dev)
	ifr.data = unsafe.Pointer(&buf[0])
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCETHTOOL, uintptr(unsafe.Pointer(ifr)))
	runtime.KeepAlive(ifr)
	runtime.KeepAlive(buf)
	if errno == 0 {
		return nil
	}
	op := fmt.Sprintf("ethtool %#x %s", ne.Uint32(buf), dev)
	switch {
	case errno == unix.EOPNOTSUPP || errno == unix.ENOTSUP || (errno == unix.EINVAL && !set):
		return fmt.Errorf("%s: %w (%w)", op, ErrNotSupported, errno)
	case errno == unix.EBUSY:
		return fmt.Errorf("%s: %w (%w)", op, ErrBusy, errno)
	}
	return fmt.Errorf("%s: %w", op, errno)
}

func cmdBuf(size int, cmd uint32) []byte {
	b := make([]byte, size)
	ne.PutUint32(b, cmd)
	return b
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func (s *sysEthtool) DrvInfo(dev string) (DrvInfo, error) {
	b := cmdBuf(sizeDrvInfo, ethtoolGDrvInfo)
	if err := s.ioctl(dev, b, false); err != nil {
		return DrvInfo{}, err
	}
	// driver[32] version[32] fw_version[32] bus_info[32] after the command
	return DrvInfo{Driver: cstr(b[4:36]), Version: cstr(b[36:68]), Firmware: cstr(b[68:100]), BusInfo: cstr(b[100:132])}, nil
}

func (s *sysEthtool) Channels(dev string) (Channels, error) {
	b := cmdBuf(sizeChannels, ethtoolGChannels)
	if err := s.ioctl(dev, b, false); err != nil {
		return Channels{}, err
	}
	u := func(i int) uint32 { return ne.Uint32(b[4+4*i:]) }
	return Channels{MaxRx: u(0), MaxTx: u(1), MaxOther: u(2), MaxCombined: u(3), Rx: u(4), Tx: u(5), Other: u(6), Combined: u(7)}, nil
}

func (s *sysEthtool) SetChannels(dev string, c Channels) error {
	b := cmdBuf(sizeChannels, ethtoolSChannels)
	for i, v := range []uint32{c.MaxRx, c.MaxTx, c.MaxOther, c.MaxCombined, c.Rx, c.Tx, c.Other, c.Combined} {
		ne.PutUint32(b[4+4*i:], v)
	}
	return s.ioctl(dev, b, true)
}

// rxnfc runs a command that carries struct ethtool_rxnfc: cmd, flow_type,
// then the 64-bit data. The whole structure is passed, as the kernel may copy
// all of it.
func (s *sysEthtool) rxnfc(dev string, cmd uint32, flow Flow, data uint64, set bool) (uint64, error) {
	b := cmdBuf(sizeRxNFC, cmd)
	ne.PutUint32(b[4:], uint32(flow))
	ne.PutUint64(b[8:], data)
	if err := s.ioctl(dev, b, set); err != nil {
		return 0, err
	}
	return ne.Uint64(b[8:]), nil
}

func (s *sysEthtool) RxRings(dev string) (int, error) {
	n, err := s.rxnfc(dev, ethtoolGRxRings, 0, 0, false)
	return int(n), err
}

func (s *sysEthtool) FlowHash(dev string, f Flow) (uint64, error) {
	bits, err := s.rxnfc(dev, ethtoolGRxFH, f, 0, false)
	if err == nil && bits == 0 {
		return 0, fmt.Errorf("ethtool rx-flow-hash %s %s: %w", f, dev, ErrNotSupported)
	}
	return bits, err
}

func (s *sysEthtool) SetFlowHash(dev string, f Flow, bits uint64) error {
	_, err := s.rxnfc(dev, ethtoolSRxFH, f, bits, true)
	return err
}

// struct ethtool_rxfh_indir: cmd, size, then size ring indexes.
func (s *sysEthtool) Indir(dev string) ([]uint32, error) {
	b := cmdBuf(8, ethtoolGRxFHIndir)
	if err := s.ioctl(dev, b, false); err != nil {
		return nil, err
	}
	n := int(ne.Uint32(b[4:]))
	if n == 0 {
		return nil, fmt.Errorf("ethtool RSS table %s: %w", dev, ErrNotSupported)
	}
	if n > 1<<16 {
		return nil, fmt.Errorf("ethtool RSS table %s: size %d", dev, n)
	}
	b = cmdBuf(8+4*n, ethtoolGRxFHIndir)
	ne.PutUint32(b[4:], uint32(n))
	if err := s.ioctl(dev, b, false); err != nil {
		return nil, err
	}
	out := make([]uint32, n)
	for i := range out {
		out[i] = ne.Uint32(b[8+4*i:])
	}
	return out, nil
}

func (s *sysEthtool) SetIndir(dev string, table []uint32) error {
	b := cmdBuf(8+4*len(table), ethtoolSRxFHIndir)
	ne.PutUint32(b[4:], uint32(len(table)))
	for i, q := range table {
		ne.PutUint32(b[8+4*i:], q)
	}
	return s.ioctl(dev, b, true)
}

// Stats is "ethtool -S": the names (GSTRINGS) and values (GSTATS) of the
// driver's counters. The kernel writes as many as the driver has at that
// moment, whatever the buffer, and a channel change in between adds
// per-queue counters: the buffers have ample room, and counts that differ
// between the calls are read again.
func (s *sysEthtool) Stats(dev string) (map[string]uint64, error) {
	for try := 0; try < 3; try++ {
		n, err := s.statsCount(dev)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return map[string]uint64{}, nil
		}
		if n > 1<<16 {
			return nil, fmt.Errorf("ethtool stats %s: %d counters", dev, n)
		}
		room := 2*n + 1024
		sb := cmdBuf(12+ethGStringLen*room, ethtoolGStrings)
		ne.PutUint32(sb[4:], ethSSStats)
		ne.PutUint32(sb[8:], uint32(n))
		if err := s.ioctl(dev, sb, false); err != nil {
			return nil, err
		}
		ns := int(ne.Uint32(sb[8:]))
		vb := cmdBuf(8+8*room, ethtoolGStats)
		ne.PutUint32(vb[4:], uint32(n))
		if err := s.ioctl(dev, vb, false); err != nil {
			return nil, err
		}
		nv := int(ne.Uint32(vb[4:]))
		if ns != nv || ns > room {
			continue
		}
		out := make(map[string]uint64, ns)
		for i := 0; i < ns; i++ {
			name := cstr(sb[12+ethGStringLen*i : 12+ethGStringLen*(i+1)])
			out[name] = ne.Uint64(vb[8+8*i:])
		}
		return out, nil
	}
	return nil, fmt.Errorf("ethtool stats %s: %w", dev, ErrBusy)
}

// statsCount is GSSET_INFO for the stats set: struct ethtool_sset_info is
// cmd, reserved, a 64-bit set mask, then one count per set in the mask.
func (s *sysEthtool) statsCount(dev string) (int, error) {
	b := cmdBuf(24, ethtoolGSsetInfo)
	ne.PutUint64(b[8:], 1<<ethSSStats)
	if err := s.ioctl(dev, b, false); err != nil {
		return 0, err
	}
	if ne.Uint64(b[8:])&(1<<ethSSStats) == 0 {
		return 0, fmt.Errorf("ethtool stats %s: %w", dev, ErrNotSupported)
	}
	return int(ne.Uint32(b[16:])), nil
}

// Features reads the offloads with the legacy getters, named as "ethtool
// -K" names them.
func (s *sysEthtool) Features(dev string) (map[string]bool, error) {
	out := map[string]bool{}
	var last error
	get := func(cmd uint32) (uint32, bool) {
		b := cmdBuf(sizeValue, cmd)
		if err := s.ioctl(dev, b, false); err != nil {
			last = err
			return 0, false
		}
		return ne.Uint32(b[4:]), true
	}
	for _, f := range []struct {
		name string
		cmd  uint32
	}{{"rx", ethtoolGRxCsum}, {"tx", ethtoolGTxCsum}, {"sg", ethtoolGSG}, {"tso", ethtoolGTSO}, {"gso", ethtoolGGSO}, {"gro", ethtoolGGRO}} {
		if v, ok := get(f.cmd); ok {
			out[f.name] = v != 0
		}
	}
	if v, ok := get(ethtoolGFlags); ok {
		for name, bit := range map[string]uint32{"lro": ethFlagLRO, "ntuple": ethFlagNTuple, "rxhash": ethFlagRxHash, "rxvlan": ethFlagRxVLAN, "txvlan": ethFlagTxVLAN} {
			out[name] = v&bit != 0
		}
	}
	if len(out) == 0 {
		if last == nil || errors.Is(last, ErrNotSupported) {
			return nil, fmt.Errorf("ethtool features %s: %w", dev, ErrNotSupported)
		}
		return nil, last
	}
	return out, nil
}
