// Package reliable is OpenVPN's control-channel reliability layer for one key
// state: it numbers outgoing messages, retransmits them until acknowledged,
// acknowledges and reorders incoming ones, and delivers each in order once.
//
// A Layer is a plain data structure driven by its owner with an injected
// clock; it starts no goroutines and is not safe for concurrent use.
//
// Message ids start at 0 in both directions (the reset message is 0). An
// incoming message is acknowledged every time it arrives, duplicates
// included, because the earlier ack may have been lost. Acks are carried on
// outgoing messages when there are any (at most MaxAcksPerPacket each), and
// otherwise in a P_ACK_V1. OpenVPN 2.x peers buffer at most 12 messages
// ahead of the next one expected and keep at most 6 of their own in flight;
// the defaults below stay inside both.
//
// The send window is a span of ids: a message is put on the wire only while
// its id is less than the oldest unacknowledged id plus SendWindow, so the
// peer, whose next expected id is never below our oldest unacknowledged one,
// always has room for it. This also keeps at most SendWindow messages in
// flight.
package reliable

import (
	"slices"
	"time"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/wire"
)

// Options tunes a Layer. Zero fields take the defaults noted.
type Options struct {
	// InitialTimeout is the first retransmission timeout, doubled on every
	// retry up to MaxTimeout. Default 1s. Negative disables retransmission
	// entirely (TCP, where the stream is already reliable).
	InitialTimeout time.Duration
	// MaxTimeout caps the backoff. Default 8s.
	MaxTimeout time.Duration
	// SendWindow is the most messages in flight unacknowledged. Default 6.
	SendWindow int
	// RecvWindow is how far past the next expected id a message is still
	// buffered; further ones are dropped unacknowledged. Default 12.
	RecvWindow int
	// MaxAcksPerPacket bounds the ack array of one packet. Default 4.
	MaxAcksPerPacket int
	// RecentAcks is how many of the acks sent most recently are repeated in
	// the spare ack slots of later messages (never in P_ACK_V1s), as OpenVPN
	// 2.6 does. A lost P_ACK_V1 then costs the peer no retransmission, and an
	// OpenVPN 2.6 server in its stateless three-way handshake, which accepts
	// a client packet only if it acknowledges the server's reset, still sees
	// that ack on the first P_CONTROL_V1 when the P_ACK_V1 before it was lost.
	// Default (and at most) MaxAcksPerPacket; negative disables.
	RecentAcks int
}

// Defaults applied by New to zero (or negative, except InitialTimeout)
// Options fields, and the limits it clamps them to.
const (
	DefaultInitialTimeout   = time.Second
	DefaultMaxTimeout       = 8 * time.Second
	DefaultSendWindow       = 6
	DefaultRecvWindow       = 12
	DefaultMaxAcksPerPacket = 4

	// MaxWindow is the largest SendWindow or RecvWindow New accepts; larger
	// values are clamped to it. MaxAcksPerPacket is clamped to wire.MaxAcks,
	// the most a peer's parser accepts.
	MaxWindow = 1024
)

// minPendingAcks is the least number of distinct acks a Layer holds between
// two Polls. Beyond the bound new acks are dropped: the peer retransmits and
// the message is acknowledged then.
const minPendingAcks = 64

// longAgo is the earliest non-zero time, returned by NextDeadline when
// something can be sent at once but the Layer has not seen a clock reading.
var longAgo = time.Time{}.Add(time.Nanosecond)

// Message is one in-order message handed to the owner.
type Message struct {
	Opcode  wire.Opcode
	ID      wire.PacketID
	Payload []byte // owned by the caller
}

// outMsg is one of our messages, queued or in flight.
type outMsg struct {
	op      wire.Opcode
	payload []byte
	acked   bool
	timeout time.Duration // current retransmission timeout
	due     time.Time     // next retransmission
}

// inMsg is a received message buffered ahead of the next expected id.
type inMsg struct {
	ok      bool
	op      wire.Opcode
	id      wire.PacketID
	payload []byte
}

// Layer is the reliability state of one key state.
type Layer struct {
	opts       Options
	retransmit bool

	// Send side. out holds every message not yet retired, in id order:
	// out[i] has id base+i. out[:nsent] have been put on the wire at least
	// once; some of those may be acked already but not yet popped because
	// an older one is still outstanding.
	out     []outMsg
	base    wire.PacketID
	nsent   int
	unacked int

	// Receive side. next is the next id to deliver; ring buffers ids
	// next+1 .. next+RecvWindow at index id % RecvWindow (allocated on first
	// use). acks are the ids to acknowledge, oldest first, pending since
	// ackSince. recent are the acks sent most recently, newest first, at most
	// cap(recent) of them.
	next       wire.PacketID
	ring       []inMsg
	acks       []wire.PacketID
	ackSince   time.Time
	maxPending int
	recent     []wire.PacketID

	// lastNow is the latest time seen by Receive or Poll.
	lastNow time.Time
}

// New returns an empty Layer.
func New(opts Options) *Layer {
	if opts.InitialTimeout == 0 {
		opts.InitialTimeout = DefaultInitialTimeout
	}
	if opts.MaxTimeout <= 0 {
		opts.MaxTimeout = DefaultMaxTimeout
	}
	if opts.InitialTimeout > 0 && opts.MaxTimeout < opts.InitialTimeout {
		opts.MaxTimeout = opts.InitialTimeout
	}
	if opts.SendWindow <= 0 {
		opts.SendWindow = DefaultSendWindow
	}
	opts.SendWindow = min(opts.SendWindow, MaxWindow)
	if opts.RecvWindow <= 0 {
		opts.RecvWindow = DefaultRecvWindow
	}
	opts.RecvWindow = min(opts.RecvWindow, MaxWindow)
	if opts.MaxAcksPerPacket <= 0 {
		opts.MaxAcksPerPacket = DefaultMaxAcksPerPacket
	}
	opts.MaxAcksPerPacket = min(opts.MaxAcksPerPacket, wire.MaxAcks)
	switch {
	case opts.RecentAcks < 0:
		opts.RecentAcks = -1
	case opts.RecentAcks == 0:
		opts.RecentAcks = opts.MaxAcksPerPacket
	default:
		opts.RecentAcks = min(opts.RecentAcks, opts.MaxAcksPerPacket)
	}
	l := &Layer{
		opts:       opts,
		retransmit: opts.InitialTimeout > 0,
		maxPending: max(minPendingAcks, 2*opts.RecvWindow),
	}
	if opts.RecentAcks > 0 {
		l.recent = make([]wire.PacketID, 0, opts.RecentAcks)
	}
	return l
}

// Options returns the options in effect, defaults filled in and limits
// applied.
func (l *Layer) Options() Options { return l.opts }

// Send queues a message (a reset opcode or wire.ControlV1) and returns its
// id. The payload is copied.
func (l *Layer) Send(op wire.Opcode, payload []byte) wire.PacketID {
	id := l.base + wire.PacketID(len(l.out))
	var p []byte
	if len(payload) > 0 {
		p = make([]byte, len(payload))
		copy(p, payload)
	}
	l.out = append(l.out, outMsg{op: op, payload: p})
	l.unacked++
	return id
}

// Receive takes one incoming packet of this key state: its acks retire
// in-flight messages, and its message (if it has one) is acknowledged and,
// when in order, returned together with any buffered messages it unblocks.
//
// A message id below the next expected one is a duplicate: it is
// acknowledged again and not delivered. One up to RecvWindow past the next
// expected id is buffered and acknowledged; one further ahead is dropped
// without an ack. Acks for ids not in flight are ignored, and so is a nil
// packet or one with a data opcode. Payloads are copied.
func (l *Layer) Receive(p *wire.ControlPacket, now time.Time) []Message {
	if p == nil || !p.Opcode.IsControl() {
		return nil
	}
	l.observe(now)
	if len(p.Acks) > 0 {
		for _, id := range p.Acks {
			l.retire(id)
		}
		l.pop()
	}
	if !p.HasMessageID() {
		return nil
	}
	id := p.PacketID
	if id < l.next {
		l.ack(id, now)
		return nil
	}
	if id == l.next {
		l.ack(id, now)
		msgs := []Message{{Opcode: p.Opcode, ID: id, Payload: clone(p.Payload)}}
		l.next++
		return l.drain(msgs)
	}
	if uint64(id-l.next) > uint64(l.opts.RecvWindow) {
		return nil
	}
	l.ack(id, now)
	if l.ring == nil {
		l.ring = make([]inMsg, l.opts.RecvWindow)
	}
	s := &l.ring[uint64(id)%uint64(len(l.ring))]
	if s.ok {
		// The same id again: ids next+1 .. next+RecvWindow have distinct
		// slots, so an occupied slot holds this id.
		return nil
	}
	*s = inMsg{ok: true, op: p.Opcode, id: id, payload: clone(p.Payload)}
	return nil
}

// drain appends the buffered messages that follow the one just delivered.
func (l *Layer) drain(msgs []Message) []Message {
	if l.ring == nil {
		return msgs
	}
	for {
		s := &l.ring[uint64(l.next)%uint64(len(l.ring))]
		if !s.ok || s.id != l.next {
			return msgs
		}
		msgs = append(msgs, Message{Opcode: s.op, ID: s.id, Payload: s.payload})
		*s = inMsg{}
		l.next++
	}
}

// retire marks the in-flight message id as acknowledged.
func (l *Layer) retire(id wire.PacketID) {
	i := uint64(id - l.base)
	if i >= uint64(l.nsent) {
		return // queued but never sent, already popped, or unknown
	}
	m := &l.out[i]
	if m.acked {
		return
	}
	m.acked = true
	m.payload = nil
	l.unacked--
}

// pop removes acknowledged messages from the front of the send queue.
func (l *Layer) pop() {
	for l.nsent > 0 && l.out[0].acked {
		l.out[0] = outMsg{}
		l.out = l.out[1:]
		l.base++
		l.nsent--
	}
}

// ack records that id must be acknowledged.
func (l *Layer) ack(id wire.PacketID, now time.Time) {
	if len(l.acks) >= l.maxPending || slices.Contains(l.acks, id) {
		return
	}
	if len(l.acks) == 0 {
		if now.IsZero() {
			now = longAgo // the zero Time would read as "nothing pending"
		}
		l.ackSince = now
	}
	l.acks = append(l.acks, id)
}

func (l *Layer) observe(now time.Time) {
	if now.After(l.lastNow) {
		l.lastNow = now
	}
}

// Poll returns the packets to put on the wire now, in order: queued
// messages that fit the send window, retransmissions that are due, and a
// P_ACK_V1 if acks are pending that no message carried. Only Opcode, Acks,
// PacketID and Payload are set; the owner fills KeyID, SessionID and
// RemoteSessionID.
//
// Every pending ack goes out exactly once, oldest first, at most
// MaxAcksPerPacket per packet. Ack slots a message has to spare then repeat
// up to RecentAcks of the acks sent in earlier Polls, newest first. A Payload
// aliases the Layer's copy of the message, which is reused for
// retransmissions: the owner must not modify it. The packets themselves are
// the owner's.
func (l *Layer) Poll(now time.Time) []*wire.ControlPacket {
	l.observe(now)
	limit := min(len(l.out), l.opts.SendWindow)
	fresh := limit - l.nsent
	due := 0
	if l.retransmit {
		for i := range l.nsent {
			if m := &l.out[i]; !m.acked && !now.Before(m.due) {
				due++
			}
		}
	}
	nacks := len(l.acks)
	if fresh+due == 0 && nacks == 0 {
		return nil
	}
	per := l.opts.MaxAcksPerPacket
	msgs := fresh + due
	carried := min(nacks, msgs*per)
	n := msgs + (nacks-carried+per-1)/per
	pkts := make([]wire.ControlPacket, n)
	res := make([]*wire.ControlPacket, n)
	pending := l.acks
	extras := l.recent
	var buf []wire.PacketID // backs every packet's ack array
	if room := nacks + msgs*min(per, len(extras)); room > 0 {
		buf = make([]wire.PacketID, 0, room)
	}
	k := 0
	put := func(op wire.Opcode, id wire.PacketID, payload []byte) {
		p := &pkts[k]
		p.Opcode = op
		p.PacketID = id
		p.Payload = payload[:len(payload):len(payload)]
		start := len(buf)
		j := min(per, len(pending))
		buf = append(buf, pending[:j]...)
		pending = pending[j:]
		if op != wire.AckV1 {
			for _, e := range extras {
				if len(buf)-start >= per {
					break
				}
				if !slices.Contains(buf[start:], e) {
					buf = append(buf, e)
				}
			}
		}
		if len(buf) > start {
			p.Acks = buf[start:len(buf):len(buf)]
		}
		res[k] = p
		k++
	}
	sentBefore := l.nsent
	for i := sentBefore; i < limit; i++ {
		m := &l.out[i]
		if l.retransmit {
			m.timeout = l.opts.InitialTimeout
			m.due = now.Add(m.timeout)
		}
		put(m.op, l.base+wire.PacketID(i), m.payload)
	}
	l.nsent = limit
	if due > 0 {
		for i := range sentBefore {
			m := &l.out[i]
			if m.acked || now.Before(m.due) {
				continue
			}
			if m.timeout > l.opts.MaxTimeout/2 {
				m.timeout = l.opts.MaxTimeout
			} else {
				m.timeout *= 2
			}
			m.due = now.Add(m.timeout)
			put(m.op, l.base+wire.PacketID(i), m.payload)
		}
	}
	for len(pending) > 0 {
		put(wire.AckV1, 0, nil)
	}
	if nacks > 0 {
		l.remember(l.acks)
		l.acks = l.acks[:0]
		l.ackSince = time.Time{}
	}
	return res
}

// remember puts the acks just sent, oldest first, at the front of recent.
func (l *Layer) remember(sent []wire.PacketID) {
	r := cap(l.recent)
	if r == 0 {
		return
	}
	if len(sent) > r {
		sent = sent[len(sent)-r:]
	}
	for _, id := range sent {
		i := slices.Index(l.recent, id)
		if i < 0 {
			if len(l.recent) < r {
				l.recent = l.recent[:len(l.recent)+1]
			}
			i = len(l.recent) - 1
		}
		copy(l.recent[1:i+1], l.recent[:i])
		l.recent[0] = id
	}
}

// NextDeadline is the earliest time Poll has something to send: a
// retransmission or a pending ack. The zero Time means nothing is pending.
//
// When acks are pending it returns the time they became pending, and when
// queued messages fit the send window the latest time seen by Receive or
// Poll; both are not after the present, so the owner polls at once.
// In-flight messages count only while retransmission is enabled.
func (l *Layer) NextDeadline() time.Time {
	var t time.Time
	if len(l.acks) > 0 {
		t = l.ackSince
	}
	if l.nsent < min(len(l.out), l.opts.SendWindow) {
		ready := l.lastNow
		if ready.IsZero() {
			ready = longAgo
		}
		t = earliest(t, ready)
	}
	if l.retransmit {
		for i := range l.nsent {
			if m := &l.out[i]; !m.acked {
				t = earliest(t, m.due)
			}
		}
	}
	return t
}

// Unacked reports how many messages are queued or in flight.
func (l *Layer) Unacked() int { return l.unacked }

// earliest returns the earlier of a and b, treating the zero Time as unset.
func earliest(a, b time.Time) time.Time {
	if a.IsZero() || !b.IsZero() && b.Before(a) {
		return b
	}
	return a
}

func clone(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	c := make([]byte, len(b))
	copy(c, b)
	return c
}
