package reliable

import (
	"bytes"
	"container/heap"
	"fmt"
	"math/rand/v2"
	"reflect"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/wire"
)

var t0 = time.Unix(1_000_000, 0)

func at(d time.Duration) time.Time { return t0.Add(d) }

func msgPkt(op wire.Opcode, id wire.PacketID, payload string, acks ...wire.PacketID) *wire.ControlPacket {
	p := &wire.ControlPacket{Opcode: op, PacketID: id, Acks: acks}
	if payload != "" {
		p.Payload = []byte(payload)
	}
	return p
}

func ctl(id wire.PacketID, acks ...wire.PacketID) *wire.ControlPacket {
	return msgPkt(wire.ControlV1, id, fmt.Sprintf("m%d", id), acks...)
}

func ackPkt(acks ...wire.PacketID) *wire.ControlPacket {
	return &wire.ControlPacket{Opcode: wire.AckV1, Acks: acks}
}

// shape renders packets compactly: "4:0[1 2]" is P_CONTROL_V1 id 0 acking 1
// and 2, "A[3]" a P_ACK_V1 acking 3.
func shape(ps []*wire.ControlPacket) []string {
	var s []string
	for _, p := range ps {
		if p.Opcode == wire.AckV1 {
			s = append(s, fmt.Sprintf("A%v", p.Acks))
			continue
		}
		s = append(s, fmt.Sprintf("%d:%d%v", p.Opcode, p.PacketID, p.Acks))
	}
	return s
}

func wantShape(t *testing.T, what string, ps []*wire.ControlPacket, want ...string) {
	t.Helper()
	got := shape(ps)
	if len(got) == 0 && len(want) == 0 {
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s: packets %v, want %v", what, got, want)
	}
}

func deliveredIDs(ms []Message) []wire.PacketID {
	var ids []wire.PacketID
	for _, m := range ms {
		ids = append(ids, m.ID)
	}
	return ids
}

func wantDelivered(t *testing.T, what string, ms []Message, want ...wire.PacketID) {
	t.Helper()
	got := deliveredIDs(ms)
	if len(got) == 0 && len(want) == 0 {
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s: delivered %v, want %v", what, got, want)
	}
	for _, m := range ms {
		if m.Opcode == wire.ControlV1 && string(m.Payload) != fmt.Sprintf("m%d", m.ID) {
			t.Fatalf("%s: message %d payload %q", what, m.ID, m.Payload)
		}
	}
}

func TestNewDefaults(t *testing.T) {
	def := Options{InitialTimeout: time.Second, MaxTimeout: 8 * time.Second, SendWindow: 6, RecvWindow: 12, MaxAcksPerPacket: 4, RecentAcks: 4}
	for _, c := range []struct {
		name string
		in   Options
		want Options
		retx bool
	}{
		{"zero", Options{}, def, true},
		{"negative", Options{MaxTimeout: -1, SendWindow: -1, RecvWindow: -5, MaxAcksPerPacket: -2}, def, true},
		{"tcp", Options{InitialTimeout: -1}, Options{InitialTimeout: -1, MaxTimeout: 8 * time.Second, SendWindow: 6, RecvWindow: 12, MaxAcksPerPacket: 4, RecentAcks: 4}, false},
		{"set", Options{InitialTimeout: 2 * time.Second, MaxTimeout: 60 * time.Second, SendWindow: 4, RecvWindow: 8, MaxAcksPerPacket: 8, RecentAcks: 3},
			Options{InitialTimeout: 2 * time.Second, MaxTimeout: 60 * time.Second, SendWindow: 4, RecvWindow: 8, MaxAcksPerPacket: 8, RecentAcks: 3}, true},
		{"max below initial", Options{InitialTimeout: 10 * time.Second}, Options{InitialTimeout: 10 * time.Second, MaxTimeout: 10 * time.Second, SendWindow: 6, RecvWindow: 12, MaxAcksPerPacket: 4, RecentAcks: 4}, true},
		{"clamped", Options{SendWindow: 1 << 20, RecvWindow: 1 << 30, MaxAcksPerPacket: 255},
			Options{InitialTimeout: time.Second, MaxTimeout: 8 * time.Second, SendWindow: MaxWindow, RecvWindow: MaxWindow, MaxAcksPerPacket: wire.MaxAcks, RecentAcks: wire.MaxAcks}, true},
		{"recent acks off", Options{RecentAcks: -3}, Options{InitialTimeout: time.Second, MaxTimeout: 8 * time.Second, SendWindow: 6, RecvWindow: 12, MaxAcksPerPacket: 4, RecentAcks: -1}, true},
		{"recent acks above per packet", Options{MaxAcksPerPacket: 2, RecentAcks: 6}, Options{InitialTimeout: time.Second, MaxTimeout: 8 * time.Second, SendWindow: 6, RecvWindow: 12, MaxAcksPerPacket: 2, RecentAcks: 2}, true},
	} {
		l := New(c.in)
		if got := l.Options(); got != c.want {
			t.Errorf("%s: options %+v, want %+v", c.name, got, c.want)
		}
		if l.retransmit != c.retx {
			t.Errorf("%s: retransmit %v", c.name, l.retransmit)
		}
		if !l.NextDeadline().IsZero() || l.Unacked() != 0 || l.Poll(t0) != nil {
			t.Errorf("%s: new Layer is not idle", c.name)
		}
	}
}

func TestInOrderDelivery(t *testing.T) {
	a, b := New(Options{}), New(Options{})
	if id := a.Send(wire.ControlHardResetClientV2, nil); id != 0 {
		t.Fatalf("first id %d", id)
	}
	if id := a.Send(wire.ControlV1, []byte("m1")); id != 1 {
		t.Fatalf("second id %d", id)
	}
	if id := a.Send(wire.ControlV1, []byte("m2")); id != 2 {
		t.Fatalf("third id %d", id)
	}
	if a.Unacked() != 3 {
		t.Fatalf("Unacked %d", a.Unacked())
	}
	ps := a.Poll(t0)
	wantShape(t, "first poll", ps, "7:0[]", "4:1[]", "4:2[]")
	if ps[0].Payload != nil || string(ps[1].Payload) != "m1" || string(ps[2].Payload) != "m2" {
		t.Fatalf("payloads %q %q %q", ps[0].Payload, ps[1].Payload, ps[2].Payload)
	}
	for i, p := range ps {
		ms := b.Receive(p, t0)
		if len(ms) != 1 || ms[0].ID != wire.PacketID(i) || ms[0].Opcode != p.Opcode || !bytes.Equal(ms[0].Payload, p.Payload) {
			t.Fatalf("receive %d: %+v", i, ms)
		}
	}
	acks := b.Poll(t0)
	wantShape(t, "b acks", acks, "A[0 1 2]")
	if a.Receive(acks[0], at(time.Millisecond)) != nil {
		t.Fatal("an ack delivered something")
	}
	if a.Unacked() != 0 || !a.NextDeadline().IsZero() {
		t.Fatalf("after acks: Unacked %d, deadline %v", a.Unacked(), a.NextDeadline())
	}
	wantShape(t, "a after acks", a.Poll(at(time.Hour)))
	wantShape(t, "b after acks", b.Poll(at(time.Hour)))
	if a.Send(wire.ControlV1, nil) != 3 {
		t.Fatal("ids do not continue after retirement")
	}
}

func TestReordering(t *testing.T) {
	b := New(Options{})
	for _, id := range []wire.PacketID{3, 1, 2} {
		wantDelivered(t, fmt.Sprintf("early %d", id), b.Receive(ctl(id), t0))
	}
	wantDelivered(t, "the gap", b.Receive(ctl(0), t0), 0, 1, 2, 3)
	wantDelivered(t, "buffered one again", b.Receive(ctl(2), t0))
	wantShape(t, "acks", b.Poll(t0), "A[3 1 2 0]")
	wantDelivered(t, "next", b.Receive(ctl(4), t0), 4)
	// A second gap, filled from the far end.
	for _, id := range []wire.PacketID{9, 8, 7, 6} {
		wantDelivered(t, fmt.Sprintf("early %d", id), b.Receive(ctl(id), t0))
	}
	wantDelivered(t, "second gap", b.Receive(ctl(5), t0), 5, 6, 7, 8, 9)
	wantShape(t, "acks", b.Poll(t0), "A[4 9 8 7]", "A[6 5]")
}

func TestDuplicateReacked(t *testing.T) {
	b := New(Options{})
	wantDelivered(t, "first", b.Receive(ctl(0), t0), 0)
	wantShape(t, "ack", b.Poll(t0), "A[0]")
	wantDelivered(t, "again", b.Receive(ctl(0), at(time.Second)))
	if d := b.NextDeadline(); !d.Equal(at(time.Second)) {
		t.Fatalf("deadline %v after a duplicate", d)
	}
	wantShape(t, "re-ack", b.Poll(at(time.Second)), "A[0]")
	// Twice before a poll: acked once.
	b.Receive(ctl(0), at(2*time.Second))
	b.Receive(ctl(0), at(2*time.Second))
	wantShape(t, "one re-ack", b.Poll(at(2*time.Second)), "A[0]")
	// A buffered message repeated is re-acked but kept once.
	b.Receive(ctl(2), t0)
	wantShape(t, "buffered", b.Poll(t0), "A[2]")
	b.Receive(ctl(2), t0)
	wantShape(t, "buffered again", b.Poll(t0), "A[2]")
	wantDelivered(t, "gap", b.Receive(ctl(1), t0), 1, 2)
	wantDelivered(t, "late duplicate", b.Receive(ctl(1), t0))
	wantShape(t, "late re-ack", b.Poll(t0), "A[1]")
}

func TestSendWindow(t *testing.T) {
	a := New(Options{SendWindow: 3})
	for i := range 7 {
		a.Send(wire.ControlV1, []byte{byte(i)})
	}
	wantShape(t, "first", a.Poll(t0), "4:0[]", "4:1[]", "4:2[]")
	if a.Unacked() != 7 {
		t.Fatalf("Unacked %d", a.Unacked())
	}
	// 1 and 2 retire, but 0 still holds the window.
	a.Receive(ackPkt(2, 1), t0)
	if a.Unacked() != 5 {
		t.Fatalf("Unacked %d", a.Unacked())
	}
	wantShape(t, "window held by 0", a.Poll(t0))
	if d := a.NextDeadline(); !d.Equal(at(time.Second)) {
		t.Fatalf("deadline %v, want 0's retransmission", d)
	}
	// Acks for ids never sent or unknown are ignored.
	a.Receive(ackPkt(5, 99, 1), t0)
	if a.Unacked() != 5 {
		t.Fatalf("Unacked %d after bogus acks", a.Unacked())
	}
	a.Receive(ackPkt(0), at(100*time.Millisecond))
	if d := a.NextDeadline(); d.IsZero() || d.After(at(100*time.Millisecond)) {
		t.Fatalf("deadline %v with sendable messages queued", d)
	}
	wantShape(t, "window moved", a.Poll(at(100*time.Millisecond)), "4:3[]", "4:4[]", "4:5[]")
	a.Receive(ackPkt(3, 4, 5), at(200*time.Millisecond))
	wantShape(t, "last", a.Poll(at(200*time.Millisecond)), "4:6[]")
	a.Receive(ackPkt(6), at(300*time.Millisecond))
	if a.Unacked() != 0 || !a.NextDeadline().IsZero() {
		t.Fatalf("Unacked %d, deadline %v", a.Unacked(), a.NextDeadline())
	}
}

func TestRecvWindow(t *testing.T) {
	b := New(Options{RecvWindow: 4})
	wantDelivered(t, "edge of window", b.Receive(ctl(4), t0))
	wantDelivered(t, "past window", b.Receive(ctl(5), t0))
	wantDelivered(t, "far past window", b.Receive(ctl(0xfffffff0), t0))
	wantShape(t, "acks", b.Poll(t0), "A[4]")
	for id := wire.PacketID(0); id < 3; id++ {
		wantDelivered(t, "fill", b.Receive(ctl(id), t0), id)
	}
	wantDelivered(t, "fill", b.Receive(ctl(3), t0), 3, 4)
	wantDelivered(t, "waits for the dropped 5", b.Receive(ctl(6), t0))
	wantShape(t, "acks", b.Poll(t0), "A[0 1 2 3]", "A[6]")
	// next is 5: 9 is the edge, 10 is out.
	wantDelivered(t, "edge", b.Receive(ctl(9), t0))
	wantDelivered(t, "out", b.Receive(ctl(10), t0))
	wantShape(t, "acks", b.Poll(t0), "A[9]")
	wantDelivered(t, "5", b.Receive(ctl(5), t0), 5, 6)
	wantDelivered(t, "8", b.Receive(ctl(8), t0))
	wantDelivered(t, "7", b.Receive(ctl(7), t0), 7, 8, 9)
}

func TestRetransmissionBackoff(t *testing.T) {
	for _, c := range []struct {
		name  string
		opts  Options
		sends []time.Duration // when the message goes out, from t0
	}{
		{"default", Options{}, []time.Duration{0, 1, 3, 7, 15, 23, 31}},
		{"cap not a power of two", Options{InitialTimeout: time.Second, MaxTimeout: 5 * time.Second}, []time.Duration{0, 1, 3, 7, 12, 17}},
		{"short", Options{InitialTimeout: 2 * time.Second, MaxTimeout: 2 * time.Second}, []time.Duration{0, 2, 4, 6}},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := New(c.opts)
			a.Send(wire.ControlV1, []byte("x"))
			for i, s := range c.sends {
				when := at(s * time.Second)
				if i > 0 {
					if d := a.NextDeadline(); !d.Equal(when) {
						t.Fatalf("send %d: deadline %v, want %v", i, d.Sub(t0), s*time.Second)
					}
					wantShape(t, "early", a.Poll(when.Add(-time.Nanosecond)))
				}
				ps := a.Poll(when)
				wantShape(t, fmt.Sprintf("send %d", i), ps, "4:0[]")
				if string(ps[0].Payload) != "x" {
					t.Fatalf("retransmitted payload %q", ps[0].Payload)
				}
			}
			a.Receive(ackPkt(0), at(time.Hour))
			if !a.NextDeadline().IsZero() {
				t.Fatal("deadline after the ack")
			}
			wantShape(t, "after ack", a.Poll(at(2*time.Hour)))
		})
	}
}

func TestRetransmissionFromPollTime(t *testing.T) {
	a := New(Options{})
	a.Send(wire.ControlV1, nil)
	a.Poll(t0)
	// Polled late: the next timeout runs from the actual retransmission.
	wantShape(t, "late", a.Poll(at(2500*time.Millisecond)), "4:0[]")
	if d := a.NextDeadline(); !d.Equal(at(4500 * time.Millisecond)) {
		t.Fatalf("deadline %v", d.Sub(t0))
	}
	// Fresh messages go before retransmissions; a fresh one is not also
	// retransmitted.
	a.Send(wire.ControlV1, nil)
	wantShape(t, "order", a.Poll(at(4500*time.Millisecond)), "4:1[]", "4:0[]")
	if d := a.NextDeadline(); !d.Equal(at(5500 * time.Millisecond)) {
		t.Fatalf("deadline %v", d.Sub(t0))
	}
	// Acking the older one leaves the newer one's timer.
	a.Receive(ackPkt(0), at(5*time.Second))
	if d := a.NextDeadline(); !d.Equal(at(5500 * time.Millisecond)) {
		t.Fatalf("deadline %v", d.Sub(t0))
	}
	wantShape(t, "newer", a.Poll(at(5500*time.Millisecond)), "4:1[]")
}

func TestAckPiggyback(t *testing.T) {
	t.Run("on a message, rest in P_ACK_V1", func(t *testing.T) {
		b := New(Options{})
		for id := range wire.PacketID(6) {
			b.Receive(ctl(id), t0)
		}
		b.Send(wire.ControlV1, []byte("reply"))
		wantShape(t, "poll", b.Poll(t0), "4:0[0 1 2 3]", "A[4 5]")
		wantShape(t, "acks carried once", b.Poll(t0))
		// A retransmission carries the acks pending now, then the ones sent
		// most recently.
		b.Receive(ctl(6), at(time.Second))
		wantShape(t, "retransmission", b.Poll(at(time.Second)), "4:0[6 5 4 3]")
	})
	t.Run("recent acks off", func(t *testing.T) {
		b := New(Options{RecentAcks: -1})
		for id := range wire.PacketID(6) {
			b.Receive(ctl(id), t0)
		}
		b.Send(wire.ControlV1, []byte("reply"))
		wantShape(t, "poll", b.Poll(t0), "4:0[0 1 2 3]", "A[4 5]")
		b.Receive(ctl(6), at(time.Second))
		wantShape(t, "retransmission", b.Poll(at(time.Second)), "4:0[6]")
		wantShape(t, "bare retransmission", b.Poll(at(3*time.Second)), "4:0[]")
	})
	t.Run("recent acks", func(t *testing.T) {
		b := New(Options{RecentAcks: 2, MaxAcksPerPacket: 3})
		b.Receive(ctl(0), t0)
		wantShape(t, "ack", b.Poll(t0), "A[0]")
		b.Send(wire.ControlV1, nil)
		wantShape(t, "repeated", b.Poll(t0), "4:0[0]")
		b.Receive(ctl(1), t0)
		b.Receive(ctl(2), t0)
		b.Receive(ctl(0), t0)
		b.Send(wire.ControlV1, nil)
		// Pending 1 2 0, nothing spare; then recent is 0 2.
		wantShape(t, "full", b.Poll(t0), "4:1[1 2 0]")
		b.Receive(ctl(3), t0)
		b.Send(wire.ControlV1, nil)
		b.Send(wire.ControlV1, nil)
		wantShape(t, "fill without duplicates", b.Poll(t0), "4:2[3 0 2]", "4:3[0 2]")
		wantShape(t, "retransmissions", b.Poll(at(time.Second)), "4:0[3 0]", "4:1[3 0]", "4:2[3 0]", "4:3[3 0]")
	})
	t.Run("ack packets only", func(t *testing.T) {
		b := New(Options{MaxAcksPerPacket: 2})
		for id := range wire.PacketID(7) {
			b.Receive(ctl(id), t0)
		}
		wantShape(t, "poll", b.Poll(t0), "A[0 1]", "A[2 3]", "A[4 5]", "A[6]")
	})
	t.Run("spread over messages", func(t *testing.T) {
		b := New(Options{MaxAcksPerPacket: 2})
		for id := range wire.PacketID(3) {
			b.Receive(ctl(id), t0)
		}
		b.Send(wire.ControlV1, nil)
		b.Send(wire.ControlV1, nil)
		wantShape(t, "poll", b.Poll(t0), "4:0[0 1]", "4:1[2]")
	})
	t.Run("more messages than acks", func(t *testing.T) {
		b := New(Options{})
		b.Receive(ctl(0), t0)
		b.Send(wire.ControlHardResetServerV2, nil)
		b.Send(wire.ControlV1, nil)
		b.Send(wire.ControlV1, nil)
		wantShape(t, "poll", b.Poll(t0), "8:0[0]", "4:1[]", "4:2[]")
	})
	t.Run("pending is bounded", func(t *testing.T) {
		b := New(Options{})
		for id := range wire.PacketID(100) {
			b.Receive(ctl(id), t0)
			b.Poll(t0)
		}
		for id := range wire.PacketID(100) {
			b.Receive(ctl(id), t0) // all duplicates
		}
		var got []wire.PacketID
		for _, p := range b.Poll(t0) {
			if p.Opcode != wire.AckV1 || len(p.Acks) == 0 || len(p.Acks) > 4 {
				t.Fatalf("packet %v", shape([]*wire.ControlPacket{p}))
			}
			got = append(got, p.Acks...)
		}
		if len(got) != minPendingAcks {
			t.Fatalf("%d acks, want %d", len(got), minPendingAcks)
		}
		for i, id := range got {
			if id != wire.PacketID(i) {
				t.Fatalf("ack %d is %d", i, id)
			}
		}
	})
}

// TestHandshakeAckRecovered: the client's P_ACK_V1 for the server's reset is
// lost; its first P_CONTROL_V1 must still acknowledge the reset, which is
// what an OpenVPN 2.6 server in its stateless handshake waits for.
func TestHandshakeAckRecovered(t *testing.T) {
	c := New(Options{})
	c.Send(wire.ControlHardResetClientV2, nil)
	wantShape(t, "reset", c.Poll(t0), "7:0[]")
	c.Receive(msgPkt(wire.ControlHardResetServerV2, 0, "", 0), at(50*time.Millisecond))
	wantShape(t, "ack (lost)", c.Poll(at(50*time.Millisecond)), "A[0]")
	c.Send(wire.ControlV1, []byte("client hello"))
	wantShape(t, "client hello", c.Poll(at(60*time.Millisecond)), "4:1[0]")
	wantShape(t, "its retransmission", c.Poll(at(1060*time.Millisecond)), "4:1[0]")
}

func TestDisabledRetransmission(t *testing.T) {
	a := New(Options{InitialTimeout: -1, SendWindow: 2})
	for range 3 {
		a.Send(wire.ControlV1, nil)
	}
	if d := a.NextDeadline(); d.IsZero() {
		t.Fatal("no deadline with messages to send")
	}
	wantShape(t, "first", a.Poll(t0), "4:0[]", "4:1[]")
	if d := a.NextDeadline(); !d.IsZero() {
		t.Fatalf("deadline %v with only messages in flight", d)
	}
	wantShape(t, "much later", a.Poll(at(time.Hour)))
	if a.Unacked() != 3 {
		t.Fatalf("Unacked %d", a.Unacked())
	}
	// The window still applies, and acks still flow.
	wantDelivered(t, "peer message", a.Receive(ctl(0, 0), at(time.Hour)), 0)
	if d := a.NextDeadline(); !d.Equal(at(time.Hour)) {
		t.Fatalf("deadline %v", d)
	}
	wantShape(t, "window moved", a.Poll(at(time.Hour)), "4:2[0]")
	wantShape(t, "never again", a.Poll(at(100*time.Hour)))
	a.Receive(ackPkt(1, 2), at(100*time.Hour))
	if a.Unacked() != 0 || !a.NextDeadline().IsZero() {
		t.Fatalf("Unacked %d, deadline %v", a.Unacked(), a.NextDeadline())
	}
}

func TestNextDeadline(t *testing.T) {
	a := New(Options{})
	if !a.NextDeadline().IsZero() {
		t.Fatal("idle Layer has a deadline")
	}
	a.Send(wire.ControlHardResetClientV2, nil)
	if d := a.NextDeadline(); d.IsZero() || d.After(t0) {
		t.Fatalf("queued before any clock reading: %v", d)
	}
	a.Poll(t0)
	if d := a.NextDeadline(); !d.Equal(at(time.Second)) {
		t.Fatalf("in flight: %v", d)
	}
	a.Receive(msgPkt(wire.ControlHardResetServerV2, 0, "", 0), at(100*time.Millisecond))
	if d := a.NextDeadline(); !d.Equal(at(100 * time.Millisecond)) {
		t.Fatalf("ack pending: %v", d)
	}
	a.Receive(ctl(2), at(150*time.Millisecond))
	if d := a.NextDeadline(); !d.Equal(at(100 * time.Millisecond)) {
		t.Fatalf("second ack pending: %v, want the first one's time", d)
	}
	wantShape(t, "acks", a.Poll(at(200*time.Millisecond)), "A[0 2]")
	if d := a.NextDeadline(); !d.IsZero() {
		t.Fatalf("idle again: %v", d)
	}
	// A zero clock reading still yields a non-zero deadline.
	a.Receive(ctl(1), time.Time{})
	if d := a.NextDeadline(); d.IsZero() {
		t.Fatal("ack received at the zero time has no deadline")
	}
}

func TestPayloadsCopied(t *testing.T) {
	a, b := New(Options{}), New(Options{})
	buf := []byte("hello")
	a.Send(wire.ControlV1, buf)
	copy(buf, "XXXXX")
	ps := a.Poll(t0)
	if string(ps[0].Payload) != "hello" {
		t.Fatalf("Send kept the caller's buffer: %q", ps[0].Payload)
	}
	if cap(ps[0].Payload) != len(ps[0].Payload) {
		t.Fatal("polled payload can be appended into the Layer's copy")
	}

	in := []byte("ahead")
	b.Receive(&wire.ControlPacket{Opcode: wire.ControlV1, PacketID: 1, Payload: in}, t0)
	copy(in, "XXXXX")
	in0 := []byte("first")
	ms := b.Receive(&wire.ControlPacket{Opcode: wire.ControlV1, PacketID: 0, Payload: in0}, t0)
	copy(in0, "XXXXX")
	if len(ms) != 2 || string(ms[0].Payload) != "first" || string(ms[1].Payload) != "ahead" {
		t.Fatalf("delivered %q %q", ms[0].Payload, ms[1].Payload)
	}
}

func TestIgnoredPackets(t *testing.T) {
	a := New(Options{})
	a.Send(wire.ControlV1, nil)
	a.Poll(t0)
	if a.Receive(nil, t0) != nil {
		t.Fatal("nil packet delivered something")
	}
	for _, op := range []wire.Opcode{0, wire.DataV1, wire.DataV2, 31} {
		if ms := a.Receive(&wire.ControlPacket{Opcode: op, Acks: []wire.PacketID{0}}, t0); ms != nil {
			t.Fatalf("%v delivered %v", op, ms)
		}
	}
	if a.Unacked() != 1 || !a.NextDeadline().Equal(at(time.Second)) {
		t.Fatalf("a non-control packet changed state: Unacked %d", a.Unacked())
	}
	// Every control opcode carrying an id is a message.
	b := New(Options{})
	for i, op := range []wire.Opcode{wire.ControlHardResetClientV2, wire.ControlV1, wire.ControlSoftResetV1, wire.ControlWKCV1} {
		ms := b.Receive(&wire.ControlPacket{Opcode: op, PacketID: wire.PacketID(i)}, t0)
		if len(ms) != 1 || ms[0].Opcode != op {
			t.Fatalf("%v: %+v", op, ms)
		}
	}
}

func TestAllocs(t *testing.T) {
	a := New(Options{})
	for range 3 {
		a.Send(wire.ControlV1, []byte("payload"))
	}
	a.Poll(t0)
	if n := testing.AllocsPerRun(100, func() { a.Poll(t0) }); n != 0 {
		t.Errorf("idle Poll: %v allocs", n)
	}
	if n := testing.AllocsPerRun(100, func() { a.NextDeadline() }); n != 0 {
		t.Errorf("NextDeadline: %v allocs", n)
	}
	ack := ackPkt(7)
	if n := testing.AllocsPerRun(100, func() { a.Receive(ack, t0) }); n != 0 {
		t.Errorf("Receive of a stray ack: %v allocs", n)
	}
	b := New(Options{})
	var id wire.PacketID
	p := &wire.ControlPacket{Opcode: wire.ControlV1, Payload: []byte("hello")}
	if n := testing.AllocsPerRun(100, func() {
		p.PacketID = id
		id++
		b.Receive(p, t0)
		b.Poll(t0)
	}); n > 6 {
		t.Errorf("receive, deliver and ack: %v allocs", n)
	}
}

// --- simulation over a lossy channel ---

type flight struct {
	at  time.Time
	seq int
	to  int
	b   []byte
}

type flights []flight

func (h flights) Len() int { return len(h) }
func (h flights) Less(i, j int) bool {
	if !h[i].at.Equal(h[j].at) {
		return h[i].at.Before(h[j].at)
	}
	return h[i].seq < h[j].seq
}
func (h flights) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *flights) Push(x any)   { *h = append(*h, x.(flight)) }
func (h *flights) Pop() any {
	old := *h
	f := old[len(old)-1]
	*h = old[:len(old)-1]
	return f
}

type simConfig struct {
	opts        [2]Options
	messages    int
	loss, dup   float64
	maxDelay    time.Duration // reordering comes from random delays
	inOrder     bool          // fixed delay: a TCP-like stream
	maxSendGap  time.Duration
	burstChance float64
}

type simStats struct {
	packets, lost, duplicated, retransmissions int
	elapsed                                    time.Duration
}

// simulate runs two Layers exchanging cfg.messages messages each way and
// checks that every one arrives exactly once and in order.
func simulate(t *testing.T, seed uint64, cfg simConfig) simStats {
	t.Helper()
	rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	type side struct {
		l        *Layer
		payloads [][]byte
		sendAt   []time.Time
		sent     int
		got      int
		ids      map[wire.PacketID]int // times each id went on the wire
	}
	var sides [2]*side
	now := t0
	for i := range sides {
		s := &side{l: New(cfg.opts[i]), ids: map[wire.PacketID]int{}}
		reset := wire.ControlHardResetClientV2
		if i == 1 {
			reset = wire.ControlHardResetServerV2
		}
		s.payloads = append(s.payloads, nil)
		s.sendAt = append(s.sendAt, now)
		when := now
		for k := 1; k <= cfg.messages; k++ {
			p := make([]byte, 1+rng.IntN(300))
			for j := range p {
				p[j] = byte(rng.Uint32())
			}
			p[0] = byte(k)
			s.payloads = append(s.payloads, p)
			if rng.Float64() >= cfg.burstChance {
				when = when.Add(time.Duration(rng.Int64N(int64(cfg.maxSendGap) + 1)))
			}
			s.sendAt = append(s.sendAt, when)
		}
		s.l.Send(reset, nil)
		s.sent = 1
		sides[i] = s
	}
	var st simStats
	var h flights
	seq := 0
	transmit := func(to int, b []byte) {
		st.packets++
		if rng.Float64() < cfg.loss {
			st.lost++
			return
		}
		copies := 1
		if rng.Float64() < cfg.dup {
			copies = 2
			st.duplicated++
		}
		for range copies {
			d := cfg.maxDelay
			if !cfg.inOrder {
				d = time.Millisecond + time.Duration(rng.Int64N(int64(cfg.maxDelay)))
			}
			seq++
			heap.Push(&h, flight{at: now.Add(d), seq: seq, to: to, b: b})
		}
	}
	done := func() bool {
		for i, s := range sides {
			if s.got != len(sides[1-i].payloads) || s.l.Unacked() != 0 {
				return false
			}
		}
		return true
	}
	for iter := 0; !done(); iter++ {
		if iter > 2_000_000 {
			t.Fatalf("seed %d: no convergence: got %d/%d and %d/%d, unacked %d and %d",
				seed, sides[0].got, len(sides[1].payloads), sides[1].got, len(sides[0].payloads),
				sides[0].l.Unacked(), sides[1].l.Unacked())
		}
		var next time.Time
		if len(h) > 0 {
			next = h[0].at
		}
		for _, s := range sides {
			next = earliest(next, s.l.NextDeadline())
			if s.sent < len(s.payloads) {
				next = earliest(next, s.sendAt[s.sent])
			}
		}
		if next.IsZero() {
			t.Fatalf("seed %d: stalled with nothing scheduled: got %d and %d, unacked %d and %d",
				seed, sides[0].got, sides[1].got, sides[0].l.Unacked(), sides[1].l.Unacked())
		}
		if next.After(now) {
			now = next
		}
		for _, s := range sides {
			for s.sent < len(s.payloads) && !s.sendAt[s.sent].After(now) {
				if id := s.l.Send(wire.ControlV1, s.payloads[s.sent]); id != wire.PacketID(s.sent) {
					t.Fatalf("Send returned id %d for message %d", id, s.sent)
				}
				s.sent++
			}
		}
		for len(h) > 0 && !h[0].at.After(now) {
			f := heap.Pop(&h).(flight)
			p, err := wire.Unmarshal(f.b)
			if err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			to, from := sides[f.to], sides[1-f.to]
			for _, m := range to.l.Receive(p, now) {
				if m.ID != wire.PacketID(to.got) {
					t.Fatalf("seed %d: side %d got message %d, want %d", seed, f.to, m.ID, to.got)
				}
				if !bytes.Equal(m.Payload, from.payloads[m.ID]) {
					t.Fatalf("seed %d: side %d message %d payload differs", seed, f.to, m.ID)
				}
				to.got++
			}
			if to.got > len(from.payloads) {
				t.Fatalf("seed %d: side %d got %d messages", seed, f.to, to.got)
			}
		}
		for i, s := range sides {
			base := s.l.base
			for _, p := range s.l.Poll(now) {
				checkPacket(t, s.l.opts, base, p)
				if p.HasMessageID() {
					s.ids[p.PacketID]++
					if s.ids[p.PacketID] > 1 {
						st.retransmissions++
					}
				}
				p.SessionID = wire.SessionID{byte(i)}
				transmit(1-i, wire.Marshal(p))
			}
			if d := s.l.NextDeadline(); !d.IsZero() && !d.After(now) {
				t.Fatalf("seed %d: deadline %v not after the poll at %v", seed, d, now)
			}
		}
	}
	for i, s := range sides {
		if !s.l.retransmit {
			for id, n := range s.ids {
				if n != 1 {
					t.Fatalf("side %d sent message %d %d times without retransmission", i, id, n)
				}
			}
		}
	}
	st.elapsed = now.Sub(t0)
	return st
}

// checkPacket checks one polled packet against the Layer's options; base is
// the oldest unretired id before the poll.
func checkPacket(t *testing.T, opts Options, base wire.PacketID, p *wire.ControlPacket) {
	t.Helper()
	if len(p.Acks) > opts.MaxAcksPerPacket {
		t.Fatalf("%d acks in one packet, limit %d", len(p.Acks), opts.MaxAcksPerPacket)
	}
	if p.Opcode == wire.AckV1 {
		if len(p.Acks) == 0 || p.PacketID != 0 || p.Payload != nil {
			t.Fatalf("bad P_ACK_V1 %+v", p)
		}
		return
	}
	if uint64(p.PacketID-base) >= uint64(opts.SendWindow) {
		t.Fatalf("message %d outside the send window [%d, %d)", p.PacketID, base, uint64(base)+uint64(opts.SendWindow))
	}
}

func TestSimulationLossy(t *testing.T) {
	for _, c := range []struct {
		name string
		opts [2]Options
	}{
		{"defaults", [2]Options{{}, {}}},
		{"receiver window below sender window", [2]Options{{SendWindow: 8, RecvWindow: 3}, {SendWindow: 8, RecvWindow: 2}}},
		{"one ack per packet", [2]Options{{MaxAcksPerPacket: 1}, {MaxAcksPerPacket: 1, SendWindow: 1}}},
		{"fast timers", [2]Options{{InitialTimeout: 50 * time.Millisecond, MaxTimeout: 400 * time.Millisecond}, {InitialTimeout: 30 * time.Millisecond}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			for seed := uint64(1); seed <= 3; seed++ {
				st := simulate(t, seed, simConfig{
					opts:        c.opts,
					messages:    500,
					loss:        0.3,
					dup:         0.2,
					maxDelay:    300 * time.Millisecond,
					maxSendGap:  50 * time.Millisecond,
					burstChance: 0.5,
				})
				if st.lost == 0 || st.duplicated == 0 || st.retransmissions == 0 {
					t.Fatalf("seed %d: the channel did not misbehave: %+v", seed, st)
				}
				t.Logf("seed %d: %+v", seed, st)
			}
		})
	}
}

func TestSimulationStream(t *testing.T) {
	st := simulate(t, 7, simConfig{
		opts:       [2]Options{{InitialTimeout: -1}, {InitialTimeout: -1, SendWindow: 2}},
		messages:   500,
		maxDelay:   20 * time.Millisecond,
		inOrder:    true,
		maxSendGap: 5 * time.Millisecond,
	})
	if st.retransmissions != 0 {
		t.Fatalf("%d retransmissions with retransmission disabled", st.retransmissions)
	}
}
