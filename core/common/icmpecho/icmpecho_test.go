package icmpecho_test

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	. "github.com/xtls/xray-core/common/icmpecho"
	"github.com/xtls/xray-core/common/net"
)

func TestIsMarker(t *testing.T) {
	cases := []struct {
		dest net.Destination
		want bool
	}{
		{net.UDPDestination(net.LocalHostIP, 0), true},
		{net.UDPDestination(net.DomainAddress("example.com"), 0), true},
		{net.UDPDestination(net.LocalHostIP, 53), false},
		{net.TCPDestination(net.LocalHostIP, 0), false},
	}
	for _, c := range cases {
		if got := IsMarker(c.dest); got != c.want {
			t.Errorf("IsMarker(%v) = %v, want %v", c.dest, got, c.want)
		}
	}
}

func TestParseRequest(t *testing.T) {
	v4 := []byte{8, 0, 0xab, 0xcd, 0x12, 0x34, 0x00, 0x07, 'h', 'i'}
	e, ok := ParseRequest(v4)
	if !ok || e.IPv6 || e.ID != 0x1234 || e.Seq != 7 || string(e.Data) != "hi" {
		t.Fatalf("v4: got %+v %v", e, ok)
	}
	v6 := []byte{128, 0, 0, 0, 0xbe, 0xef, 0x01, 0x00}
	e, ok = ParseRequest(v6)
	if !ok || !e.IPv6 || e.ID != 0xbeef || e.Seq != 256 || len(e.Data) != 0 {
		t.Fatalf("v6: got %+v %v", e, ok)
	}

	long := make([]byte, MaxMessageLen)
	long[0] = TypeEchoRequest4
	if _, ok := ParseRequest(long); !ok {
		t.Error("a request of MaxMessageLen bytes must be accepted")
	}
	tooLong := append(long, 0)
	bad := map[string][]byte{
		"empty":            nil,
		"short":            {8, 0, 0, 0, 0, 0, 0},
		"too long":         tooLong,
		"echo reply v4":    {0, 0, 0, 0, 0, 0, 0, 0},
		"echo reply v6":    {129, 0, 0, 0, 0, 0, 0, 0},
		"code not 0":       {8, 1, 0, 0, 0, 0, 0, 0},
		"dest unreachable": {3, 1, 0, 0, 0, 0, 0, 0},
		"timestamp":        {13, 0, 0, 0, 0, 0, 0, 0},
		"router solicit":   {133, 0, 0, 0, 0, 0, 0, 0},
	}
	for name, msg := range bad {
		if _, ok := ParseRequest(msg); ok {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseReply(t *testing.T) {
	if _, ok := ParseReply([]byte{0, 0, 0, 0, 0, 1, 0, 2}, false); !ok {
		t.Error("v4 reply rejected")
	}
	if _, ok := ParseReply([]byte{0, 0, 0, 0, 0, 1, 0, 2}, true); ok {
		t.Error("type 0 accepted as an ICMPv6 reply")
	}
	if _, ok := ParseReply([]byte{129, 0, 0, 0, 0, 1, 0, 2}, false); ok {
		t.Error("type 129 accepted as an ICMPv4 reply")
	}
	if _, ok := ParseReply([]byte{8, 0, 0, 0, 0, 1, 0, 2}, false); ok {
		t.Error("a request accepted as a reply")
	}
	if _, ok := ParseReply([]byte{0, 0, 0, 0, 0, 1, 0}, false); ok {
		t.Error("short reply accepted")
	}
}

func TestAppendRoundTrip(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		in := Echo{IPv6: ipv6, ID: 0xa1b2, Seq: 0xc3d4, Data: []byte("abcdefg")}
		req := AppendRequest([]byte("prefix"), in)
		if string(req[:6]) != "prefix" {
			t.Fatal("prefix lost")
		}
		req = req[6:]
		got, ok := ParseRequest(req)
		if !ok || got.IPv6 != ipv6 || got.ID != in.ID || got.Seq != in.Seq || !bytes.Equal(got.Data, in.Data) {
			t.Fatalf("request round trip (ipv6=%v): %+v %v", ipv6, got, ok)
		}
		rep := AppendReply(nil, in)
		got, ok = ParseReply(rep, ipv6)
		if !ok || got.ID != in.ID || got.Seq != in.Seq || !bytes.Equal(got.Data, in.Data) {
			t.Fatalf("reply round trip (ipv6=%v): %+v %v", ipv6, got, ok)
		}
		if ipv6 {
			if req[2] != 0 || req[3] != 0 {
				t.Error("ICMPv6 checksum must be left 0")
			}
		} else if Checksum(req) != 0 || Checksum(rep) != 0 {
			t.Error("IPv4 checksum is wrong")
		}
	}
}

func TestChecksum(t *testing.T) {
	// RFC 1071, section 3: the sum of these bytes is 0xddf2.
	if got := Checksum([]byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}); got != ^uint16(0xddf2) {
		t.Errorf("Checksum = %#04x, want %#04x", got, ^uint16(0xddf2))
	}
	// An odd length pads with a zero byte.
	if Checksum([]byte{0x01}) != Checksum([]byte{0x01, 0x00}) {
		t.Error("odd length handled wrongly")
	}
	// A captured echo request from ping(8): its checksum field is correct.
	msg := []byte{0x08, 0x00, 0xf7, 0xfc, 0x00, 0x01, 0x00, 0x02}
	if Checksum(msg) != 0 {
		t.Error("valid message does not sum to 0")
	}
}

func TestFamilyMatches(t *testing.T) {
	v4 := Echo{}
	v6 := Echo{IPv6: true}
	cases := []struct {
		e    Echo
		addr net.Address
		want bool
	}{
		{v4, net.ParseAddress("1.2.3.4"), true},
		{v4, net.ParseAddress("::1"), false},
		{v4, net.ParseAddress("::ffff:1.2.3.4"), true},
		{v6, net.ParseAddress("::1"), true},
		{v6, net.ParseAddress("1.2.3.4"), false},
		{v4, net.DomainAddress("example.com"), true},
		{v6, net.DomainAddress("example.com"), true},
	}
	for _, c := range cases {
		if got := FamilyMatches(c.e, c.addr); got != c.want {
			t.Errorf("FamilyMatches(ipv6=%v, %v) = %v, want %v", c.e.IPv6, c.addr, got, c.want)
		}
	}
}

func TestTrackerRate(t *testing.T) {
	tr := NewTracker()
	now := time.Unix(1000, 0)
	for i := 0; i < MaxRequestsPerSecond; i++ {
		if !tr.Admit(now) {
			t.Fatalf("request %d refused inside the burst", i)
		}
	}
	if tr.Admit(now) {
		t.Fatal("request over the rate admitted")
	}
	// Ten milliseconds bring back one request's worth.
	now = now.Add(10 * time.Millisecond)
	if !tr.Admit(now) {
		t.Fatal("refill did not happen")
	}
	if tr.Admit(now) {
		t.Fatal("refill gave more than earned")
	}
	// A long pause refills to the bucket's size and no further.
	now = now.Add(time.Hour)
	n := 0
	for tr.Admit(now) {
		n++
	}
	if n != MaxRequestsPerSecond {
		t.Fatalf("after a pause %d admitted, want %d", n, MaxRequestsPerSecond)
	}
}

func TestTrackerOutstanding(t *testing.T) {
	tr := NewTracker()
	now := time.Unix(1000, 0)
	peer := net.ParseIP("192.0.2.1")
	seqs := map[uint16]bool{}
	for i := 0; i < MaxOutstanding; i++ {
		seq, ok := tr.Add(now, Pending{Peer: peer, Seq: 1}, []byte{byte(i)})
		if !ok {
			t.Fatalf("echo %d refused", i)
		}
		if seqs[seq] {
			t.Fatalf("wire sequence %d handed out twice", seq)
		}
		seqs[seq] = true
	}
	if _, ok := tr.Add(now, Pending{Peer: peer}, nil); ok {
		t.Fatal("echo over MaxOutstanding accepted")
	}
	if tr.Admit(now) {
		t.Fatal("Admit must refuse while MaxOutstanding are in flight")
	}
	// After Timeout they are forgotten.
	later := now.Add(Timeout + time.Millisecond)
	if got := tr.Outstanding(later); got != 0 {
		t.Fatalf("%d outstanding after the timeout", got)
	}
	if _, ok := tr.Add(later, Pending{Peer: peer}, nil); !ok {
		t.Fatal("echo refused after the old ones expired")
	}
}

func TestTrackerMatch(t *testing.T) {
	tr := NewTracker()
	now := time.Unix(1000, 0)
	peer := net.ParseIP("192.0.2.1")
	target := net.DomainAddress("example.com")
	data := []byte("payload")
	seq, ok := tr.Add(now, Pending{Target: target, Peer: peer, ID: 77, Seq: 9}, data)
	if !ok {
		t.Fatal("Add failed")
	}
	if _, ok := tr.Match(now, seq+1, peer, data); ok {
		t.Error("matched a sequence number never sent")
	}
	if _, ok := tr.Match(now, seq, net.ParseIP("192.0.2.2"), data); ok {
		t.Error("matched a reply from another address")
	}
	if _, ok := tr.Match(now, seq, peer, []byte("payloaX")); ok {
		t.Error("matched a reply with other data")
	}
	if _, ok := tr.Match(now, seq, peer, data[:3]); ok {
		t.Error("matched a reply with truncated data")
	}
	// The 4-byte and 16-byte forms of an IPv4 address are the same peer.
	p, ok := tr.Match(now.Add(time.Second), seq, peer.To16(), data)
	if !ok || p.Target != target || p.ID != 77 || p.Seq != 9 {
		t.Fatalf("Match = %+v, %v", p, ok)
	}
	if _, ok := tr.Match(now, seq, peer, data); ok {
		t.Error("an echo was answered twice")
	}

	seq, _ = tr.Add(now, Pending{Peer: peer}, data)
	if _, ok := tr.Match(now.Add(Timeout+time.Millisecond), seq, peer, data); ok {
		t.Error("matched a reply after the timeout")
	}

	seq, _ = tr.Add(now, Pending{Peer: peer}, data)
	tr.Cancel(seq)
	if _, ok := tr.Match(now, seq, peer, data); ok {
		t.Error("matched a cancelled echo")
	}
}

func TestTrackerSequenceWraps(t *testing.T) {
	tr := NewTracker()
	now := time.Unix(1000, 0)
	peer := net.ParseIP("192.0.2.1")
	// Run the counter round several times, keeping one echo in flight: the
	// sequence number it holds is never handed out again.
	held, _ := tr.Add(now, Pending{Peer: peer}, nil)
	for i := 0; i < 3<<16; i++ {
		seq, ok := tr.Add(now, Pending{Peer: peer}, nil)
		if !ok {
			t.Fatal("Add failed")
		}
		if seq == held {
			t.Fatal("sequence number in flight handed out again")
		}
		tr.Cancel(seq)
	}
}

// FuzzParseRequest checks that any payload either is rejected or is exactly
// an echo request that AppendRequest reproduces, checksum aside.
func FuzzParseRequest(f *testing.F) {
	f.Add([]byte{8, 0, 0, 0, 0, 1, 0, 1})
	f.Add([]byte{128, 0, 0xff, 0xff, 0, 1, 0, 1, 1, 2, 3})
	f.Add([]byte{0, 0, 0, 0, 0, 1, 0, 1})
	f.Add([]byte{8, 1, 0, 0})
	f.Fuzz(func(t *testing.T, msg []byte) {
		e, ok := ParseRequest(msg)
		if !ok {
			return
		}
		if len(msg) < HeaderLen || len(msg) > MaxMessageLen {
			t.Fatalf("accepted %d bytes", len(msg))
		}
		if msg[1] != 0 || (msg[0] != TypeEchoRequest4 && msg[0] != TypeEchoRequest6) {
			t.Fatalf("accepted type %d code %d", msg[0], msg[1])
		}
		if e.IPv6 != (msg[0] == TypeEchoRequest6) {
			t.Fatal("wrong family")
		}
		out := AppendRequest(nil, e)
		if len(out) != len(msg) || !bytes.Equal(out[:2], msg[:2]) || !bytes.Equal(out[4:], msg[4:]) {
			t.Fatalf("round trip changed the message:\n in %x\nout %x", msg, out)
		}
		if !e.IPv6 && Checksum(out) != 0 {
			t.Fatal("bad checksum")
		}
		rep, ok := ParseReply(AppendReply(nil, e), e.IPv6)
		if !ok || rep.ID != binary.BigEndian.Uint16(msg[4:]) || rep.Seq != binary.BigEndian.Uint16(msg[6:]) || !bytes.Equal(rep.Data, msg[8:]) {
			t.Fatal("reply does not carry the request's identifier, sequence and data")
		}
	})
}

// FuzzTracker drives a tracker with arbitrary operations and checks its
// bounds: never more than MaxOutstanding in flight, never two in flight on
// one sequence number, and a match only for what was added.
func FuzzTracker(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 0, 0, 0, 2, 2, 1})
	f.Fuzz(func(t *testing.T, ops []byte) {
		tr := NewTracker()
		now := time.Unix(1000, 0)
		peer := net.ParseIP("192.0.2.1")
		type echo struct {
			id   uint16
			data []byte
		}
		live := map[uint16]echo{}
		for i, op := range ops {
			switch op % 4 {
			case 0:
				e := echo{id: uint16(i), data: []byte{byte(i), byte(i >> 8)}}
				seq, ok := tr.Add(now, Pending{Peer: peer, ID: e.id}, e.data)
				if ok {
					if _, dup := live[seq]; dup {
						t.Fatal("duplicate sequence number in flight")
					}
					live[seq] = e
				}
			case 1:
				for seq, e := range live {
					p, ok := tr.Match(now, seq, peer, e.data)
					if !ok {
						t.Fatal("live echo did not match")
					}
					if p.ID != e.id {
						t.Fatal("matched the wrong echo")
					}
					delete(live, seq)
					break
				}
			case 2:
				now = now.Add(time.Duration(op) * 100 * time.Millisecond)
				if now.Sub(time.Unix(1000, 0)) > Timeout {
					// Everything may have expired; start the bookkeeping over.
					tr.Outstanding(now)
					live = map[uint16]echo{}
					tr = NewTracker()
					now = time.Unix(1000, 0)
				}
			case 3:
				tr.Admit(now)
			}
			if n := tr.Outstanding(now); n > MaxOutstanding || n != len(live) {
				t.Fatalf("outstanding %d, expected %d (max %d)", n, len(live), MaxOutstanding)
			}
		}
	})
}
