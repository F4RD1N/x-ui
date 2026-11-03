package icmpecho

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	xnet "github.com/xtls/xray-core/common/net"
)

func TestIsMarker(t *testing.T) {
	ip := xnet.ParseAddress("192.0.2.1")
	for _, c := range []struct {
		d    xnet.Destination
		want bool
	}{
		{xnet.UDPDestination(ip, 0), true},
		{xnet.UDPDestination(xnet.DomainAddress("example.com"), 0), true},
		{xnet.UDPDestination(ip, 53), false},
		{xnet.TCPDestination(ip, 0), false},
		{xnet.Destination{}, false},
	} {
		if got := IsMarker(c.d); got != c.want {
			t.Errorf("IsMarker(%v) = %v, want %v", c.d, got, c.want)
		}
	}
}

// TestMarshalMatchesXNet checks the wire format against golang.org/x/net/icmp.
func TestMarshalMatchesXNet(t *testing.T) {
	data := []byte("abcdefghijklmnopqrstuvwxyz0123456789!") // odd length
	for _, reply := range []bool{false, true} {
		var typ icmp.Type = ipv4.ICMPTypeEcho
		if reply {
			typ = ipv4.ICMPTypeEchoReply
		}
		want, err := (&icmp.Message{Type: typ, Body: &icmp.Echo{ID: 0xbeef, Seq: 0x1234, Data: data}}).Marshal(nil)
		if err != nil {
			t.Fatal(err)
		}
		got := Echo{Reply: reply, ID: 0xbeef, Seq: 0x1234, Data: data}.Marshal()
		if !bytes.Equal(got, want) {
			t.Errorf("IPv4 reply=%v:\n got % x\nwant % x", reply, got, want)
		}
	}

	// ICMPv6: x/net computes the checksum with the pseudo-header; Marshal
	// leaves 0 there, and Checksum over PseudoHeaderSum gives x/net's.
	src := netip.MustParseAddr("fd00::1")
	dst := netip.MustParseAddr("2001:db8::77")
	for _, reply := range []bool{false, true} {
		var typ icmp.Type = ipv6.ICMPTypeEchoRequest
		if reply {
			typ = ipv6.ICMPTypeEchoReply
		}
		want, err := (&icmp.Message{Type: typ, Body: &icmp.Echo{ID: 7, Seq: 9, Data: data}}).
			Marshal(icmp.IPv6PseudoHeader(src.AsSlice(), dst.AsSlice()))
		if err != nil {
			t.Fatal(err)
		}
		got := Echo{V6: true, Reply: reply, ID: 7, Seq: 9, Data: data}.Marshal()
		if got[2] != 0 || got[3] != 0 {
			t.Errorf("IPv6 checksum = % x, want 0", got[2:4])
		}
		cs := Checksum(got, PseudoHeaderSum(src.As16(), dst.As16(), len(got), 58))
		binary.BigEndian.PutUint16(got[2:], cs)
		if !bytes.Equal(got, want) {
			t.Errorf("IPv6 reply=%v:\n got % x\nwant % x", reply, got, want)
		}
	}
}

func TestChecksumVerifies(t *testing.T) {
	for n := 0; n < 40; n++ {
		m := Echo{ID: uint16(n * 977), Seq: uint16(n), Data: bytes.Repeat([]byte{byte(n), 0xff}, n)[:n]}.Marshal()
		if Checksum(m, 0) != 0 {
			t.Fatalf("data %d bytes: a message with its checksum does not sum to 0", n)
		}
	}
}

func TestParse(t *testing.T) {
	req4 := Echo{ID: 1, Seq: 2, Data: []byte("x")}.Marshal()
	req6 := Echo{V6: true, ID: 3, Seq: 4}.Marshal()
	rep4 := Echo{Reply: true, ID: 5, Seq: 6, Data: []byte("yz")}.Marshal()
	rep6 := Echo{V6: true, Reply: true, ID: 7, Seq: 8}.Marshal()

	if e, ok := ParseRequest(req4); !ok || e.V6 || e.Reply || e.ID != 1 || e.Seq != 2 || string(e.Data) != "x" {
		t.Errorf("ParseRequest(v4) = %+v, %v", e, ok)
	}
	if e, ok := ParseRequest(req6); !ok || !e.V6 || e.Reply || e.ID != 3 || e.Seq != 4 || len(e.Data) != 0 {
		t.Errorf("ParseRequest(v6) = %+v, %v", e, ok)
	}
	if e, ok := ParseReply(rep4); !ok || e.V6 || !e.Reply || e.ID != 5 || e.Seq != 6 || string(e.Data) != "yz" {
		t.Errorf("ParseReply(v4) = %+v, %v", e, ok)
	}
	if e, ok := ParseReply(rep6); !ok || !e.V6 || !e.Reply || e.ID != 7 || e.Seq != 8 {
		t.Errorf("ParseReply(v6) = %+v, %v", e, ok)
	}
	// The checksum is ignored.
	bad := bytes.Clone(req4)
	bad[2], bad[3] = 0, 0
	if _, ok := ParseRequest(bad); !ok {
		t.Error("ParseRequest rejected a request with checksum 0")
	}

	code1 := bytes.Clone(req4)
	code1[1] = 1
	for name, b := range map[string][]byte{
		"empty":         nil,
		"7 bytes":       req4[:7],
		"too long":      append(Echo{}.Marshal(), make([]byte, MaxLen-HeaderLen+1)...),
		"reply as req":  rep4,
		"reply6 as req": rep6,
		"code 1":        code1,
		"unreachable":   {3, 1, 0, 0, 0, 0, 0, 0},
		"timestamp":     {13, 0, 0, 0, 0, 0, 0, 0},
		"nd":            {135, 0, 0, 0, 0, 0, 0, 0},
	} {
		if _, ok := ParseRequest(b); ok {
			t.Errorf("ParseRequest accepted %s", name)
		}
	}
	if _, ok := ParseRequest(append(Echo{}.Marshal(), make([]byte, MaxLen-HeaderLen)...)); !ok {
		t.Error("ParseRequest rejected a request of exactly MaxLen bytes")
	}
	for name, b := range map[string][]byte{"req4": req4, "req6": req6, "short": rep4[:7]} {
		if _, ok := ParseReply(b); ok {
			t.Errorf("ParseReply accepted %s", name)
		}
	}
}

func TestFamilyMatches(t *testing.T) {
	for _, c := range []struct {
		addr   xnet.Address
		v4, v6 bool
	}{
		{xnet.ParseAddress("192.0.2.1"), true, false},
		{xnet.ParseAddress("2001:db8::1"), false, true},
		{xnet.ParseAddress("::ffff:192.0.2.1"), true, false}, // Xray keeps it as IPv4
		{xnet.DomainAddress("example.com"), true, true},
		{xnet.DomainAddress(""), false, false},
		{nil, false, false},
	} {
		if got := FamilyMatches(c.addr, false); got != c.v4 {
			t.Errorf("FamilyMatches(%v, v4) = %v", c.addr, got)
		}
		if got := FamilyMatches(c.addr, true); got != c.v6 {
			t.Errorf("FamilyMatches(%v, v6) = %v", c.addr, got)
		}
	}
}

// FuzzParse: parsing never panics, accepts only what the marker allows, and
// a parsed message marshals back to the same bytes (bar the checksum).
func FuzzParse(f *testing.F) {
	f.Add(Echo{ID: 1, Seq: 2, Data: []byte("ping")}.Marshal())
	f.Add(Echo{V6: true, ID: 1, Seq: 2}.Marshal())
	f.Add(Echo{Reply: true, ID: 1, Seq: 2}.Marshal())
	f.Add(Echo{V6: true, Reply: true}.Marshal())
	f.Add([]byte{8, 1, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{3, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, parse := range []func([]byte) (Echo, bool){ParseRequest, ParseReply} {
			e, ok := parse(b)
			if !ok {
				continue
			}
			if len(b) < HeaderLen || len(b) > MaxLen || b[1] != 0 {
				t.Fatalf("accepted % x", b)
			}
			if e.Type() != b[0] {
				t.Fatalf("type %d parsed as %d", b[0], e.Type())
			}
			m := e.Marshal()
			if len(m) != len(b) || m[0] != b[0] || m[1] != b[1] || !bytes.Equal(m[4:], b[4:]) {
				t.Fatalf("round trip:\n in % x\nout % x", b, m)
			}
			if !e.V6 && Checksum(m, 0) != 0 {
				t.Fatalf("bad IPv4 checksum on % x", m)
			}
		}
	})
}
