// Package icmpecho is the marker that carries a ping through Xray as UDP.
//
// Xray moves TCP and UDP only, so an ICMP echo request is sent as one UDP
// datagram to port 0 of the address that was pinged: an IP literal, or a
// domain when the client maps a fake address back to a name. The payload is
// the echo request message exactly as on the wire -- type, code, checksum,
// identifier, sequence number, data -- and nothing else. Port 0 is never
// legitimate UDP, so the marker cannot be confused with real traffic.
//
// Whoever executes the ping (freedom on the server) answers with one datagram
// on the same flow, from the pinged address and port 0, whose payload is the
// echo reply carrying the request's identifier and sequence number and the
// data the target returned. No reply means nothing comes back: a reply is
// never made up, and no unreachable message is ever sent.
package icmpecho

import (
	"encoding/binary"
	"hash/maphash"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/net"
)

// ICMP message types used by the marker.
const (
	TypeEchoReply4   = 0
	TypeEchoRequest4 = 8
	TypeEchoRequest6 = 128
	TypeEchoReply6   = 129
)

const (
	// HeaderLen is the length of an echo message without its data.
	HeaderLen = 8
	// MaxMessageLen is the longest echo request the marker carries.
	MaxMessageLen = 65000

	// MaxOutstanding bounds the echoes one flow may have in flight.
	MaxOutstanding = 64
	// MaxRequestsPerSecond bounds the echoes one flow may start per second.
	MaxRequestsPerSecond = 100
	// Timeout is how long an echo waits for its reply.
	Timeout = 10 * time.Second
)

// IsMarker reports whether dest is where the marker is sent: UDP, port 0.
func IsMarker(dest net.Destination) bool {
	return dest.Network == net.Network_UDP && dest.Port == 0
}

// Echo is an echo request or reply.
type Echo struct {
	IPv6 bool
	ID   uint16
	Seq  uint16
	// Data aliases the message it was parsed from.
	Data []byte
}

// ParseRequest parses a marker payload. It accepts an IPv4 (type 8) or IPv6
// (type 128) echo request with code 0 and HeaderLen to MaxMessageLen bytes,
// and nothing else. The checksum is not checked: it may be 0.
func ParseRequest(msg []byte) (Echo, bool) {
	if len(msg) < HeaderLen || len(msg) > MaxMessageLen || msg[1] != 0 {
		return Echo{}, false
	}
	var e Echo
	switch msg[0] {
	case TypeEchoRequest4:
	case TypeEchoRequest6:
		e.IPv6 = true
	default:
		return Echo{}, false
	}
	e.ID = binary.BigEndian.Uint16(msg[4:6])
	e.Seq = binary.BigEndian.Uint16(msg[6:8])
	e.Data = msg[HeaderLen:]
	return e, true
}

// ParseReply parses an echo reply of the given family: type 0 (IPv4) or 129
// (IPv6), code 0. The checksum is not checked.
func ParseReply(msg []byte, ipv6 bool) (Echo, bool) {
	if len(msg) < HeaderLen || msg[1] != 0 || msg[0] != replyType(ipv6) {
		return Echo{}, false
	}
	return Echo{
		IPv6: ipv6,
		ID:   binary.BigEndian.Uint16(msg[4:6]),
		Seq:  binary.BigEndian.Uint16(msg[6:8]),
		Data: msg[HeaderLen:],
	}, true
}

// FamilyMatches reports whether e may be sent to addr: an IP literal must be
// of the echo's family, and a domain is resolved to that family only.
func FamilyMatches(e Echo, addr net.Address) bool {
	switch addr.Family() {
	case net.AddressFamilyIPv4:
		return !e.IPv6
	case net.AddressFamilyIPv6:
		return e.IPv6
	case net.AddressFamilyDomain:
		return true
	}
	return false
}

// AppendRequest appends e as an echo request message to b.
func AppendRequest(b []byte, e Echo) []byte {
	return appendMessage(b, requestType(e.IPv6), e)
}

// AppendReply appends e as an echo reply message to b.
func AppendReply(b []byte, e Echo) []byte {
	return appendMessage(b, replyType(e.IPv6), e)
}

// appendMessage writes the message with an IPv4 checksum filled in. The
// ICMPv6 checksum covers a pseudo-header with addresses the marker does not
// know, so it is left 0 for whoever builds the packet.
func appendMessage(b []byte, typ byte, e Echo) []byte {
	start := len(b)
	b = append(b, typ, 0, 0, 0, byte(e.ID>>8), byte(e.ID), byte(e.Seq>>8), byte(e.Seq))
	b = append(b, e.Data...)
	if !e.IPv6 {
		binary.BigEndian.PutUint16(b[start+2:], Checksum(b[start:]))
	}
	return b
}

func requestType(ipv6 bool) byte {
	if ipv6 {
		return TypeEchoRequest6
	}
	return TypeEchoRequest4
}

func replyType(ipv6 bool) byte {
	if ipv6 {
		return TypeEchoReply6
	}
	return TypeEchoReply4
}

// Checksum is the Internet checksum (RFC 1071) of b. A message whose checksum
// field is correct sums to 0.
func Checksum(b []byte) uint16 {
	var sum uint32
	for len(b) >= 2 {
		sum += uint32(b[0])<<8 | uint32(b[1])
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	return ^uint16(sum)
}

// Pending is an echo sent and not yet answered.
type Pending struct {
	// Target is the address the client pinged; the reply comes from it.
	Target net.Address
	// Peer is the IP the echo was sent to; only it may answer.
	Peer net.IP
	// ID and Seq are the request's, restored in the reply.
	ID  uint16
	Seq uint16

	dataLen  int
	dataHash uint64
	deadline time.Time
}

var dataSeed = maphash.MakeSeed()

// Tracker bounds and matches the echoes of one flow. Each echo goes on the
// wire with a sequence number of the tracker's choosing, unique among those
// in flight, so requests from several pinging programs sharing a flow never
// collide; Match restores the request's own identifier and sequence number.
//
// A flow may start MaxRequestsPerSecond echoes a second (a token bucket of
// that size) and have MaxOutstanding in flight; an echo is forgotten after
// Timeout. The zero value is not usable; use NewTracker.
type Tracker struct {
	mu      sync.Mutex
	pending map[uint16]*Pending
	nextSeq uint16
	tokens  float64
	last    time.Time
}

// NewTracker returns a tracker with a full token bucket.
func NewTracker() *Tracker {
	return &Tracker{
		pending: make(map[uint16]*Pending),
		// A random start keeps a new flow from matching late replies to a
		// previous flow that used the same socket identifier.
		nextSeq: uint16(dice.Roll(1 << 16)),
		tokens:  MaxRequestsPerSecond,
	}
}

// Admit takes one request's share of the rate limit and reports whether it
// may go ahead: false when the flow is over its rate or has MaxOutstanding
// echoes in flight. A request that is admitted but never sent costs nothing
// more.
func (t *Tracker) Admit(now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.last.IsZero() {
		if d := now.Sub(t.last); d > 0 {
			t.tokens += d.Seconds() * MaxRequestsPerSecond
			if t.tokens > MaxRequestsPerSecond {
				t.tokens = MaxRequestsPerSecond
			}
		}
	}
	t.last = now
	if t.tokens < 1 {
		return false
	}
	t.tokens--
	t.expire(now)
	return len(t.pending) < MaxOutstanding
}

// Add records an echo about to be sent to p.Peer with the given data, and
// returns the sequence number to put on the wire. It fails when the flow
// already has MaxOutstanding echoes in flight.
func (t *Tracker) Add(now time.Time, p Pending, data []byte) (uint16, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.expire(now)
	if len(t.pending) >= MaxOutstanding {
		return 0, false
	}
	for t.pending[t.nextSeq] != nil {
		t.nextSeq++
	}
	seq := t.nextSeq
	t.nextSeq++
	p.dataLen = len(data)
	p.dataHash = maphash.Bytes(dataSeed, data)
	p.deadline = now.Add(Timeout)
	t.pending[seq] = &p
	return seq, true
}

// Cancel forgets an echo that could not be sent.
func (t *Tracker) Cancel(wireSeq uint16) {
	t.mu.Lock()
	delete(t.pending, wireSeq)
	t.mu.Unlock()
}

// Match returns and forgets the echo answered by a reply with this wire
// sequence number from peer carrying data. A reply from any other address,
// with other data, or after Timeout matches nothing, and an echo is answered
// once only.
func (t *Tracker) Match(now time.Time, wireSeq uint16, peer net.IP, data []byte) (Pending, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	p := t.pending[wireSeq]
	if p == nil {
		return Pending{}, false
	}
	if now.After(p.deadline) {
		delete(t.pending, wireSeq)
		return Pending{}, false
	}
	if !p.Peer.Equal(peer) || len(data) != p.dataLen || maphash.Bytes(dataSeed, data) != p.dataHash {
		return Pending{}, false
	}
	delete(t.pending, wireSeq)
	return *p, true
}

// Outstanding is the number of echoes in flight.
func (t *Tracker) Outstanding(now time.Time) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.expire(now)
	return len(t.pending)
}

func (t *Tracker) expire(now time.Time) {
	for seq, p := range t.pending {
		if now.After(p.deadline) {
			delete(t.pending, seq)
		}
	}
}
