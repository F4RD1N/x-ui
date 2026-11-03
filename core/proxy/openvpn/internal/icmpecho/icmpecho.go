// Package icmpecho carries ICMP echo (ping) through Xray as UDP.
//
// A tun front end (hev-socks5-tunnel) cannot hand Xray an ICMP packet: SOCKS5
// carries TCP and UDP only. It sends each echo request instead as ONE UDP
// datagram to port 0 of the address that was pinged -- the marker -- and
// turns the datagram that comes back from that address and port 0 into the
// echo reply on its tun. Port 0 is never legitimate UDP, so nothing else is
// taken for a ping.
//
// The payload of the datagram is the ICMP echo message as on the wire:
//
//	IPv4: type 8 (request) / 0 (reply), code 0, checksum, identifier, sequence, data
//	IPv6: type 128 (request) / 129 (reply), code 0, checksum, identifier, sequence, data
//
// The type gives the family: an IPv4 echo is never sent to an IPv6 address
// (or a name's IPv6 address) and the other way round. Receivers ignore the
// checksum. Anything else addressed to port 0 -- another ICMP type, a
// message shorter than 8 bytes or longer than 65000 -- is dropped silently.
//
// An executor (an outbound that can reach the network itself: freedom, or
// the OpenVPN and WireGuard netstacks) performs the ping for real and answers
// with the echo reply on the same UDP flow, from the pinged address and port
// 0, carrying the request's identifier and sequence and the data the target
// returned. No reply means nothing comes back: a dead host or a server that
// does not know the marker times out, nothing is ever made up. Flow is that
// executor's half, shared by every outbound that executes pings.
package icmpecho

import (
	"encoding/binary"
	"time"

	"github.com/xtls/xray-core/common/net"
)

// ICMP types of the echo messages.
const (
	TypeEchoReply4   = 0
	TypeEchoRequest4 = 8
	TypeEchoRequest6 = 128
	TypeEchoReply6   = 129
)

const (
	// HeaderLen is the size of the echo header: type, code, checksum,
	// identifier, sequence.
	HeaderLen = 8
	// MaxLen bounds a marker payload (the echo message, header included).
	MaxLen = 65000

	// MaxOutstanding bounds the echoes one flow has in flight; more are
	// dropped.
	MaxOutstanding = 64
	// MaxRate is how many echo requests one flow may send per second; more
	// are dropped.
	MaxRate = 100
	// EchoTimeout is how long an echo waits for its reply.
	EchoTimeout = 10 * time.Second
)

// IsMarker reports whether dest is where a ping travels: UDP to port 0.
func IsMarker(dest net.Destination) bool {
	return dest.Network == net.Network_UDP && dest.Port == 0
}

// Echo is an ICMP echo message, request or reply, IPv4 or IPv6.
type Echo struct {
	V6    bool // ICMPv6 (types 128/129); otherwise ICMPv4 (8/0)
	Reply bool
	ID    uint16
	Seq   uint16
	Data  []byte
}

// Type is the message's ICMP type.
func (e Echo) Type() byte {
	switch {
	case e.V6 && e.Reply:
		return TypeEchoReply6
	case e.V6:
		return TypeEchoRequest6
	case e.Reply:
		return TypeEchoReply4
	default:
		return TypeEchoRequest4
	}
}

// Len is the size of the message on the wire.
func (e Echo) Len() int { return HeaderLen + len(e.Data) }

// Append appends the message to b. An ICMPv4 message gets its checksum; an
// ICMPv6 one keeps 0 there, since its checksum covers a pseudo-header with
// addresses only the sender of the IP packet knows (the kernel, the netstack
// or the tun front end fill it in).
func (e Echo) Append(b []byte) []byte {
	off := len(b)
	b = append(b, e.Type(), 0, 0, 0, 0, 0, 0, 0)
	binary.BigEndian.PutUint16(b[off+4:], e.ID)
	binary.BigEndian.PutUint16(b[off+6:], e.Seq)
	b = append(b, e.Data...)
	if !e.V6 {
		binary.BigEndian.PutUint16(b[off+2:], Checksum(b[off:], 0))
	}
	return b
}

// Marshal returns the message as on the wire (see Append).
func (e Echo) Marshal() []byte { return e.Append(make([]byte, 0, e.Len())) }

// parse reads an echo message of one of the two types given; Data aliases b.
func parse(b []byte, t4, t6 byte) (Echo, bool) {
	if len(b) < HeaderLen || len(b) > MaxLen || b[1] != 0 {
		return Echo{}, false
	}
	var e Echo
	switch b[0] {
	case t4:
	case t6:
		e.V6 = true
	default:
		return Echo{}, false
	}
	e.Reply = t4 == TypeEchoReply4
	e.ID = binary.BigEndian.Uint16(b[4:])
	e.Seq = binary.BigEndian.Uint16(b[6:])
	e.Data = b[HeaderLen:]
	return e, true
}

// ParseRequest parses a marker payload: an ICMPv4 or ICMPv6 echo request
// with code 0, 8 to MaxLen bytes. The checksum is not checked. Data aliases
// b. ok is false for anything else, which the receiver drops.
func ParseRequest(b []byte) (e Echo, ok bool) {
	return parse(b, TypeEchoRequest4, TypeEchoRequest6)
}

// ParseReply parses an echo reply (code 0, 8 to MaxLen bytes), as a marker
// payload coming back or as an executor reads it from its socket. Data
// aliases b.
func ParseReply(b []byte) (e Echo, ok bool) {
	return parse(b, TypeEchoReply4, TypeEchoReply6)
}

// FamilyMatches reports whether an echo of the given family may go to addr:
// an IP literal must be of that family; a name may be (it is resolved to
// that family only).
func FamilyMatches(addr net.Address, v6 bool) bool {
	if addr == nil {
		return false
	}
	switch addr.Family() {
	case net.AddressFamilyIPv4:
		return !v6
	case net.AddressFamilyIPv6:
		return v6
	case net.AddressFamilyDomain:
		return addr.Domain() != ""
	}
	return false
}

// Checksum is the Internet checksum (RFC 1071) of b, folded into the partial
// sum initial (0, or a pseudo-header's PartialSum).
func Checksum(b []byte, initial uint32) uint16 {
	return ^fold(sum(b, initial))
}

// PseudoHeaderSum is the partial sum of the IPv6 pseudo-header for an
// upper-layer message of length bytes and protocol next (58 for ICMPv6),
// from src to dst, to pass to Checksum. src and dst must be IPv6.
func PseudoHeaderSum(src, dst [16]byte, length int, next byte) uint32 {
	s := sum(src[:], 0)
	s = sum(dst[:], s)
	s += uint32(length>>16) + uint32(length&0xffff)
	s += uint32(next)
	return s
}

func sum(b []byte, s uint32) uint32 {
	for len(b) >= 2 {
		s += uint32(b[0])<<8 | uint32(b[1])
		b = b[2:]
		if s >= 1<<31 {
			s = (s & 0xffff) + s>>16
		}
	}
	if len(b) == 1 {
		s += uint32(b[0]) << 8
	}
	return s
}

func fold(s uint32) uint16 {
	for s > 0xffff {
		s = (s & 0xffff) + s>>16
	}
	return uint16(s)
}
