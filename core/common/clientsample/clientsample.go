// Package clientsample keeps a small ring of the real client IPs that CDN
// inbounds (WebSocket, HTTPUpgrade, XHTTP) took from X-Forwarded-For, each
// with the address of the peer that delivered it (the socket's remote IP:
// the CDN edge, or a reverse proxy in front of the core).
//
// It is a sample, not a log: the last Size entries overwrite older ones, and
// Recorded counts how many were seen since start. Record does not allocate;
// the metrics server reads the ring at /debug/clientips.
package clientsample

import (
	"encoding/binary"
	"net"
	"net/netip"
	"strconv"
	"sync"
)

// Size is the number of entries kept.
const Size = 4096

const mask = Size - 1

// entry is a client IP and its peer IP, each in 16-byte form as two
// big-endian words, IPv4 v4-mapped. A zero peer means unknown (no real peer
// is "::").
type entry [4]uint64

var (
	mu    sync.Mutex
	count uint64      // entries recorded since start; guarded by mu
	ring  [Size]entry // guarded by mu

	snapMu sync.Mutex
	snap   [Size]entry // the reader's copy of ring; guarded by snapMu
)

// words returns ip as two words, IPv4 v4-mapped; ok is false for an address
// that is neither 4 nor 16 bytes long.
func words(ip net.IP) (hi, lo uint64, ok bool) {
	// Built in registers: byte-wise building of a [16]byte costs a
	// store-forwarding stall on the copy into the ring.
	switch len(ip) {
	case net.IPv4len:
		return 0, 0xffff<<32 | uint64(binary.BigEndian.Uint32(ip)), true
	case net.IPv6len:
		return binary.BigEndian.Uint64(ip[:8]), binary.BigEndian.Uint64(ip[8:]), true
	}
	return 0, 0, false
}

// Record adds the client address ip, as it arrived from peer, to the ring.
// An ip that is neither 4 nor 16 bytes long is ignored; such a peer (nil
// when unknown) is recorded as unknown.
func Record(ip, peer net.IP) {
	if !enabled {
		return
	}
	hi, lo, ok := words(ip)
	if !ok {
		return
	}
	phi, plo, _ := words(peer)
	mu.Lock()
	// Four word stores: a composite literal is built on the stack and
	// copied, which costs a store-forwarding stall inside the lock.
	e := &ring[count&mask]
	e[0], e[1], e[2], e[3] = hi, lo, phi, plo
	count++
	mu.Unlock()
}

// PeerIP returns the IP of a socket's remote address, or nil when addr is
// not a TCP or UDP address (a Unix socket, say). It does not allocate.
func PeerIP(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP
	case *net.UDPAddr:
		return a.IP
	}
	return nil
}

// Recorded returns how many entries Record has taken since start.
func Recorded() uint64 {
	mu.Lock()
	c := count
	mu.Unlock()
	return c
}

// appendAddr appends the quoted address of words hi, lo; IPv4 comes out
// unmapped.
func appendAddr(dst []byte, hi, lo uint64) []byte {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], hi)
	binary.BigEndian.PutUint64(b[8:], lo)
	dst = append(dst, '"')
	dst = netip.AddrFrom16(b).Unmap().AppendTo(dst)
	return append(dst, '"')
}

// AppendJSON appends
//
//	{"v":1,"recorded":N,"ips":["a.b.c.d",...],"peers":["e.f.g.h",...]}
//
// to dst, the entries oldest to newest. "peers" has the same length and
// order as "ips": the peer each client address arrived from, or "" when
// unknown. IPv4 addresses come out unmapped.
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
	for n := first; n < c; n++ {
		if n != first {
			dst = append(dst, ',')
		}
		e := &snap[n&mask]
		dst = appendAddr(dst, e[0], e[1])
	}
	dst = append(dst, `],"peers":[`...)
	for n := first; n < c; n++ {
		if n != first {
			dst = append(dst, ',')
		}
		e := &snap[n&mask]
		if e[2] == 0 && e[3] == 0 {
			dst = append(dst, `""`...)
			continue
		}
		dst = appendAddr(dst, e[2], e[3])
	}
	return append(dst, "]}"...)
}
