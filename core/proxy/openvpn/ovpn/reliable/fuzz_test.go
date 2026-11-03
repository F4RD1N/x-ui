package reliable

import (
	"bytes"
	"encoding/binary"
	"slices"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/wire"
)

// fuzzReader hands out the fuzz input piece by piece; past the end it
// returns zeros.
type fuzzReader struct{ b []byte }

func (r *fuzzReader) empty() bool { return len(r.b) == 0 }

func (r *fuzzReader) byte() byte {
	if len(r.b) == 0 {
		return 0
	}
	c := r.b[0]
	r.b = r.b[1:]
	return c
}

// bytes returns a copy of the next n bytes (fewer at the end).
func (r *fuzzReader) bytes(n int) []byte {
	n = min(n, len(r.b))
	c := append([]byte(nil), r.b[:n]...)
	r.b = r.b[n:]
	return c
}

// id reads a message id: mostly small ones, so they hit the windows, and
// sometimes a full 32-bit one.
func (r *fuzzReader) id() wire.PacketID {
	c := r.byte()
	if c&0x80 == 0 {
		return wire.PacketID(c)
	}
	var b [4]byte
	copy(b[:], r.bytes(4))
	return wire.PacketID(binary.BigEndian.Uint32(b[:]))
}

// recvModel is the receive side's specification written the obvious way.
type recvModel struct {
	next   wire.PacketID
	window wire.PacketID
	buf    map[wire.PacketID]Message
	acks   []wire.PacketID
	limit  int
	recent []wire.PacketID // newest first
	nrec   int
}

// polled checks the ack arrays of one Poll's packets and moves the pending
// acks to recent.
func (m *recvModel) polled(t *testing.T, ps []*wire.ControlPacket, per int) {
	t.Helper()
	pending := m.acks
	for _, p := range ps {
		j := min(per, len(pending))
		want := append([]wire.PacketID(nil), pending[:j]...)
		pending = pending[j:]
		if p.Opcode != wire.AckV1 {
			for _, e := range m.recent {
				if len(want) < per && !slices.Contains(want, e) {
					want = append(want, e)
				}
			}
		}
		if !slices.Equal(p.Acks, want) {
			t.Fatalf("packet %v acks %v, want %v (pending %v, recent %v)", p.Opcode, p.Acks, want, m.acks, m.recent)
		}
	}
	if len(pending) != 0 {
		t.Fatalf("acks %v left unsent", pending)
	}
	for _, id := range m.acks {
		m.recent = slices.DeleteFunc(m.recent, func(x wire.PacketID) bool { return x == id })
		m.recent = append([]wire.PacketID{id}, m.recent...)
		if len(m.recent) > m.nrec {
			m.recent = m.recent[:m.nrec]
		}
	}
	m.acks = m.acks[:0]
}

func (m *recvModel) ack(id wire.PacketID) {
	for _, a := range m.acks {
		if a == id {
			return
		}
	}
	if len(m.acks) < m.limit {
		m.acks = append(m.acks, id)
	}
}

func (m *recvModel) receive(p *wire.ControlPacket) []Message {
	if !p.Opcode.IsControl() || !p.HasMessageID() {
		return nil
	}
	id := p.PacketID
	switch {
	case id < m.next:
		m.ack(id)
		return nil
	case id-m.next > m.window:
		return nil
	}
	m.ack(id)
	if _, ok := m.buf[id]; !ok {
		m.buf[id] = Message{Opcode: p.Opcode, ID: id, Payload: append([]byte(nil), p.Payload...)}
	}
	var out []Message
	for {
		msg, ok := m.buf[m.next]
		if !ok {
			return out
		}
		delete(m.buf, m.next)
		out = append(out, msg)
		m.next++
	}
}

func FuzzReceive(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x00, 0, 1, 'a', 0, 0, 1, 1, 0})
	// Out of order then the gap, a poll, raw acks.
	f.Add([]byte{0x31, 0x02, 2, 4, 0, 2, 'x', 'y', 2, 4, 0, 1, 'z', 2, 4, 0, 0, 1, 10, 0, 3, 5, 1, 0})
	f.Add([]byte{0x7f, 0x81,
		0, 3, 'a', 'b', 'c', 0, 0, 1, 0, 5,
		4, 14, 0x20, 1, 2, 3, 4, 5, 6, 7, 8, 1, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 'h', 'i',
		3, 0x28, 1, 1, 0x80, 0xff, 0xff, 0xff, 0xf0, 2, 'q', 'r', 1, 200})
	f.Fuzz(func(t *testing.T, data []byte) {
		r := &fuzzReader{b: data}
		c0, c1 := r.byte(), r.byte()
		opts := Options{
			SendWindow:       1 + int(c0&7),
			RecvWindow:       1 + int(c0>>3&15),
			MaxAcksPerPacket: int(c1 & 15), // 0 takes the default, above 8 is clamped
			InitialTimeout:   time.Duration(c1>>4&7) * 300 * time.Millisecond,
			MaxTimeout:       2 * time.Second,
			RecentAcks:       int(c0>>7) - 1, // -1: off, 0: default
		}
		if c1&0x80 != 0 {
			opts.InitialTimeout = -1
		}
		l := New(opts)
		opts = l.Options()
		model := &recvModel{window: wire.PacketID(opts.RecvWindow), buf: map[wire.PacketID]Message{}, limit: l.maxPending, nrec: max(opts.RecentAcks, 0)}
		now := t0

		sent := 0                            // messages queued
		onWire := map[wire.PacketID]int{}    // times each id was polled
		acked := map[wire.PacketID]bool{}    // in-flight ids the peer acked
		highest := wire.PacketID(0xffffffff) // last fresh id polled

		feed := func(p *wire.ControlPacket) {
			if p.Opcode.IsControl() {
				for _, id := range p.Acks {
					if onWire[id] > 0 {
						acked[id] = true
					}
				}
			}
			want := model.receive(p)
			got := l.Receive(p, now)
			for i := range p.Payload {
				p.Payload[i] ^= 0xff // the Layer must hold copies
			}
			if len(got) != len(want) {
				t.Fatalf("delivered %d messages, model %d", len(got), len(want))
			}
			for i := range got {
				if got[i].ID != want[i].ID || got[i].Opcode != want[i].Opcode || !bytes.Equal(got[i].Payload, want[i].Payload) {
					t.Fatalf("delivered %+v, model %+v", got[i], want[i])
				}
			}
			if l.next != model.next {
				t.Fatalf("next %d, model %d", l.next, model.next)
			}
			if u := sent - len(acked); l.Unacked() != u {
				t.Fatalf("Unacked %d, want %d", l.Unacked(), u)
			}
		}

		for !r.empty() {
			switch r.byte() % 6 {
			case 0:
				l.Send(wire.ControlV1, r.bytes(int(r.byte()%8)))
				sent++
			case 1:
				now = now.Add(time.Duration(r.byte()) * 50 * time.Millisecond)
				base := l.base
				ps := l.Poll(now)
				model.polled(t, ps, opts.MaxAcksPerPacket)
				fresh, ackOnly := true, false
				for _, p := range ps {
					checkPacket(t, opts, base, p)
					if p.Opcode == wire.AckV1 {
						ackOnly = true
						continue
					}
					if ackOnly {
						t.Fatal("a message after a P_ACK_V1")
					}
					if acked[p.PacketID] {
						t.Fatalf("message %d sent after its ack", p.PacketID)
					}
					onWire[p.PacketID]++
					if onWire[p.PacketID] == 1 {
						if !fresh {
							t.Fatalf("fresh message %d after a retransmission", p.PacketID)
						}
						if p.PacketID != highest+1 {
							t.Fatalf("fresh message %d after %d", p.PacketID, highest)
						}
						highest = p.PacketID
					} else {
						fresh = false
						if opts.InitialTimeout < 0 {
							t.Fatalf("message %d retransmitted with retransmission disabled", p.PacketID)
						}
					}
				}
				if d := l.NextDeadline(); !d.IsZero() && !d.After(now) {
					t.Fatalf("deadline %v right after polling at %v", d, now)
				}
			case 2, 3:
				p := &wire.ControlPacket{Opcode: wire.Opcode(r.byte() % 16)}
				for range int(r.byte() % 10) {
					p.Acks = append(p.Acks, r.id())
				}
				p.PacketID = r.id()
				p.Payload = r.bytes(int(r.byte() % 8))
				feed(p)
			case 4:
				p, err := wire.Unmarshal(r.bytes(int(r.byte())))
				if err == nil {
					feed(p)
				}
			case 5:
				d := l.NextDeadline()
				if len(model.acks) > 0 && (d.IsZero() || d.After(now)) {
					t.Fatalf("acks pending but deadline %v (now %v)", d, now)
				}
				if l.Unacked() == 0 && len(model.acks) == 0 && !d.IsZero() {
					t.Fatalf("idle but deadline %v", d)
				}
			}
		}
	})
}
