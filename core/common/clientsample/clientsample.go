// Package clientsample keeps a small ring of the real client IPs that CDN
// inbounds (WebSocket, HTTPUpgrade, XHTTP) took from X-Forwarded-For.
//
// It is a sample, not a log: the last Size addresses overwrite older ones,
// and Recorded counts how many were seen since start. Record does not
// allocate; the metrics server reads the ring at /debug/clientips.
package clientsample

import (
	"encoding/binary"
	"net"
	"net/netip"
	"strconv"
	"sync"
)

// Size is the number of addresses kept.
const Size = 4096

const mask = Size - 1

var (
	mu    sync.Mutex
	count uint64          // addresses recorded since start; guarded by mu
	ring  [Size][2]uint64 // 16-byte form, IPv4 v4-mapped; guarded by mu

	snapMu sync.Mutex
	snap   [Size][2]uint64 // the reader's copy of ring; guarded by snapMu
)

// Record adds ip to the ring. Addresses that are neither 4 nor 16 bytes long
// are ignored.
func Record(ip net.IP) {
	if !enabled {
		return
	}
	// Two words, built in registers: byte-wise building of a [16]byte
	// costs a store-forwarding stall on the copy into the ring.
	var hi, lo uint64
	switch len(ip) {
	case net.IPv4len:
		lo = 0xffff<<32 | uint64(binary.BigEndian.Uint32(ip))
	case net.IPv6len:
		hi = binary.BigEndian.Uint64(ip[:8])
		lo = binary.BigEndian.Uint64(ip[8:])
	default:
		return
	}
	mu.Lock()
	ring[count&mask] = [2]uint64{hi, lo}
	count++
	mu.Unlock()
}

// Recorded returns how many addresses Record has taken since start.
func Recorded() uint64 {
	mu.Lock()
	c := count
	mu.Unlock()
	return c
}

// AppendJSON appends {"v":1,"recorded":N,"ips":["a.b.c.d",...]} to dst, the
// addresses oldest to newest. IPv4 addresses come out unmapped.
func AppendJSON(dst []byte) []byte {
	snapMu.Lock()
	defer snapMu.Unlock()
	// Copy under the lock (a few microseconds), format outside it.
	mu.Lock()
	c := count
	snap = ring
	mu.Unlock()

	first := uint64(0)
	if c > Size {
		first = c - Size
	}
	dst = append(dst, `{"v":1,"recorded":`...)
	dst = strconv.AppendUint(dst, c, 10)
	dst = append(dst, `,"ips":[`...)
	var b [16]byte
	for n := first; n < c; n++ {
		if n != first {
			dst = append(dst, ',')
		}
		w := &snap[n&mask]
		binary.BigEndian.PutUint64(b[:8], w[0])
		binary.BigEndian.PutUint64(b[8:], w[1])
		dst = append(dst, '"')
		dst = netip.AddrFrom16(b).Unmap().AppendTo(dst)
		dst = append(dst, '"')
	}
	return append(dst, "]}"...)
}
