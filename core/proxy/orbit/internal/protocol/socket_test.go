package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestNativePacketGoldens(t *testing.T) {
	for _, file := range []string{"native-packets.json", "native-crypto.json"} {
		for _, v := range loadNative(t, file).Tests {
			if v.Hex == "" || strings.Contains(v.Test, "obfuscation") {
				continue
			}
			t.Run(v.Test, func(t *testing.T) {
				golden := mustHex(t, v.Hex)
				f, err := ParseFrame(golden)
				if err != nil {
					t.Fatal(err)
				}
				var rebuilt Frame
				switch f.Type {
				case TypeConnect:
					c, err := ParseConnectRequest(f)
					if err != nil {
						t.Fatal(err)
					}
					rebuilt = c.Frame(f.Flags)
				case TypeSocketConnect:
					s, err := ParseSocketConnect(f)
					if err != nil {
						t.Fatal(err)
					}
					rebuilt = s.Frame()
				case TypeSocketClose:
					s, err := ParseSocketClose(f)
					if err != nil {
						t.Fatal(err)
					}
					rebuilt = s.Frame()
				case TypeSocketBuffer:
					s, err := ParseSocketBuffer(f)
					if err != nil {
						t.Fatal(err)
					}
					rebuilt = s.Frame()
				case TypeKickOut:
					n, err := ParseKickOut(f)
					if err != nil {
						t.Fatal(err)
					}
					rebuilt = KickOut(n)
				case TypeUDP:
					rebuilt, err = UDPFrame(f.Payload)
					if err != nil {
						t.Fatal(err)
					}
				default:
					rebuilt, err = Control(f.Type, f.Flags)
					if err != nil {
						t.Fatal(err)
					}
				}
				if !bytes.Equal(wire(t, rebuilt), golden) {
					t.Fatalf("native mismatch: got %x want %x", wire(t, rebuilt), golden)
				}
			})
		}
	}
}

func TestAddressVariantsAndOpaqueRoundtrip(t *testing.T) {
	for _, host := range []string{"192.0.2.1", "2001:db8::1", "::ffff:192.0.2.1", "example.test", strings.Repeat("a", 127)} {
		a, err := NewAddress(host, 443)
		if err != nil {
			t.Fatal(err)
		}
		got, err := a.Host()
		if err != nil || got != host {
			t.Fatalf("%q %v", got, err)
		}
		b, _ := a.MarshalBinary()
		if len(b) != 131 || binary.LittleEndian.Uint16(b[1:3]) != 443 {
			t.Fatal("address wire")
		}
		decoded, err := ParseAddress(b)
		if err != nil || decoded != a {
			t.Fatal("address roundtrip")
		}
		if got, err := a.NetworkAddress(); err != nil || !strings.HasSuffix(got, ":443") {
			t.Fatalf("%s %v", got, err)
		}
	}
	for _, host := range []string{"", strings.Repeat("a", 128), "a\x00b", "https://example.test", "bad host", "[::1]", "fe80::1%eth0"} {
		if _, err := NewAddress(host, 443); err == nil {
			t.Fatal("bad host accepted", host)
		}
	}
	if _, err := (Address{}).Host(); err == nil {
		t.Fatal("kind0accepted")
	}
	if _, err := (Address{Kind: 3}).Host(); err == nil {
		t.Fatal("empty domain accepted")
	}
	if _, err := (Address{}).NetworkAddress(); err == nil {
		t.Fatal("bad hostPort accepted")
	}
	for _, n := range []int{0, 130, 132} {
		if _, err := ParseAddress(make([]byte, n)); err == nil {
			t.Fatal(n)
		}
	}
	var a Address
	a.Kind = 255
	a.Port = 123
	for i := range a.Storage {
		a.Storage[i] = byte(i + 1)
	}
	b, _ := a.MarshalBinary()
	got, _ := ParseAddress(b)
	if got != a {
		t.Fatal("opaque padding lost")
	}
}

func TestSocketControlRoundtrips(t *testing.T) {
	a, _ := NewAddress("example.test", 53)
	for _, s := range []SocketConnect{{0, 0, nil}, {0xffffffff, 0xffff, &a}} {
		f := s.Frame()
		got, err := ParseSocketConnect(f)
		if err != nil || !reflect.DeepEqual(got, s) {
			t.Fatalf("%+v %v", got, err)
		}
		if (f.Flags&1 != 0) != (s.Address != nil) {
			t.Fatal("address flag")
		}
	}
	s := SocketConnectResponse{0x12345678, 0x3344}
	f := s.Frame()
	if got := hex.EncodeToString(wire(t, f)); got != "09000600785634124433" {
		t.Fatal(got)
	}
	if got, err := ParseSocketConnectResponse(f); got != s || err != nil {
		t.Fatal(got, err)
	}
	for _, flag := range []bool{false, true} {
		s := SocketClose{55, flag}
		got, err := ParseSocketClose(s.Frame())
		if err != nil || got != s {
			t.Fatal(got, err)
		}
		s2 := SocketBuffer{55, 123456789, 8192, flag}
		got2, err := ParseSocketBuffer(s2.Frame())
		if err != nil || got2 != s2 {
			t.Fatal(got2, err)
		}
	}
	buf := SocketBuffer{}.Frame()
	buf.Payload[16] = 2
	got, _ := ParseSocketBuffer(buf)
	if got.Flag {
		t.Fatal("native buffer boolean requires exactly1")
	}
	cl := SocketClose{}.Frame()
	cl.Payload[4] = 2
	gotClose, _ := ParseSocketClose(cl)
	if !gotClose.Flag {
		t.Fatal("native close response treats anynonzero as true")
	}
	s3 := SocketReadClose{SocketID: 44, Tail: [2]byte{0xab, 0xcd}}
	got3, err := ParseSocketReadClose(s3.Frame())
	if err != nil || got3 != s3 {
		t.Fatal(got3, err)
	}
}

func TestSocketMalformedBodies(t *testing.T) {
	cases := []struct {
		valid Frame
		parse func(Frame) error
	}{
		{SocketConnect{}.Frame(), func(f Frame) error { _, e := ParseSocketConnect(f); return e }},
		{SocketConnectResponse{}.Frame(), func(f Frame) error { _, e := ParseSocketConnectResponse(f); return e }},
		{SocketClose{}.Frame(), func(f Frame) error { _, e := ParseSocketClose(f); return e }},
		{SocketBuffer{}.Frame(), func(f Frame) error { _, e := ParseSocketBuffer(f); return e }},
		{SocketReadClose{}.Frame(), func(f Frame) error { _, e := ParseSocketReadClose(f); return e }},
	}
	for _, tc := range cases {
		for _, bad := range []Frame{{Type: 255, Payload: tc.valid.Payload}, {Type: tc.valid.Type, Payload: tc.valid.Payload[:len(tc.valid.Payload)-1]}, {Type: tc.valid.Type, Payload: append(append([]byte(nil), tc.valid.Payload...), 0)}} {
			if err := tc.parse(bad); err == nil {
				t.Fatalf("type%d accepted malformed", tc.valid.Type)
			}
		}
	}
}

func TestDataNativeBoundaryAndFields(t *testing.T) {
	for _, n := range []int{0, 1, 5, 2047, 2048} {
		d := DataChunk{SocketID: 0x12345678, Sequence: 7, Offset: 0, Data: bytes.Repeat([]byte{0x41}, n)}
		f, err := d.Frame()
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseDataChunk(f)
		if err != nil || got.SocketID != d.SocketID || got.Sequence != 7 || got.Offset != 0 || !bytes.Equal(got.Data, d.Data) {
			t.Fatal(got, err)
		}
		if n == 5 {
			if h := hex.EncodeToString(wire(t, f)[:24]); h != "100019007856341207000000000000000000000000000000" {
				t.Fatal(h)
			}
		}
		if n == 2048 {
			if h := hex.EncodeToString(wire(t, f)[:24]); h != "100014087856341207000000000000000000000000000000" {
				t.Fatal(h)
			}
		}
		if n > 0 {
			f.Payload[20] ^= 255
			if got.Data[0] != 0x41 {
				t.Fatal("alias")
			}
		}
	}
	if _, err := (DataChunk{Data: make([]byte, 2049)}).Frame(); err == nil {
		t.Fatal("oversized")
	}
	for _, f := range []Frame{{Type: TypeHeartbeat, Payload: make([]byte, 20)}, {Type: TypeData, Payload: make([]byte, 19)}, {Type: TypeData, Payload: make([]byte, 2069)}} {
		if _, err := ParseDataChunk(f); err == nil {
			t.Fatal("malformed data")
		}
	}
	d := DataChunk{SocketID: ^uint32(0), Sequence: ^uint64(0), Offset: ^uint64(0)}
	f, _ := d.Frame()
	got, err := ParseDataChunk(f)
	if err != nil || got.SocketID != d.SocketID || got.Sequence != d.Sequence || got.Offset != d.Offset {
		t.Fatal("maximum unsigned fields")
	}
}

func TestUDPEnvelopeFieldsBoundariesAndValidation(t *testing.T) {
	base := UDPEnvelope{Kind: UDPKindData, Source: netip.MustParseAddrPort("192.0.2.1:1234"), Destination: netip.MustParseAddrPort("198.51.100.2:53"), Data: []byte("dns")}
	b, err := base.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(b); got != "15c0000201d204c633640235000300646e73" {
		t.Fatal(got)
	}
	for _, n := range []int{0, 1, 1470} {
		for _, kind := range []byte{UDPKindData, UDPKindDNS} {
			u := base
			u.Kind = kind
			u.Data = bytes.Repeat([]byte{7}, n)
			f, err := u.Frame()
			if err != nil {
				t.Fatal(err)
			}
			got, err := ParseUDPFrame(f)
			if err != nil || got.Kind != kind || got.Source != u.Source || got.Destination != u.Destination || !bytes.Equal(got.Data, u.Data) {
				t.Fatal(got, err)
			}
			if n > 0 {
				f.Payload[15] ^= 255
				if got.Data[0] != 7 {
					t.Fatal("UDP alias")
				}
			}
		}
	}
	for _, mutate := range []func(*UDPEnvelope){func(u *UDPEnvelope) { u.Kind = 99 }, func(u *UDPEnvelope) { u.Source = netip.AddrPort{} }, func(u *UDPEnvelope) { u.Destination = netip.MustParseAddrPort("[::1]:53") }, func(u *UDPEnvelope) { u.Data = make([]byte, 1471) }} {
		u := base
		mutate(&u)
		if _, err := u.MarshalBinary(); err == nil {
			t.Fatal("invalid UDP accepted")
		}
		if _, err := u.Frame(); err == nil {
			t.Fatal("invalid UDP frame accepted")
		}
	}
	for _, bad := range [][]byte{nil, make([]byte, 14), make([]byte, 1501), append([]byte{99}, b[1:]...), append(b, 0)} {
		if _, err := ParseUDPEnvelope(bad); err == nil {
			t.Fatal("malformed UDP")
		}
	}
	if _, err := ParseUDPFrame(Frame{Type: TypeData, Payload: b}); err == nil {
		t.Fatal("wrong type accepted")
	}
	// Recovered receiver's ceiling exceeds the normal producer's payload cap.
	large := make([]byte, 1500)
	copy(large, b)
	binary.LittleEndian.PutUint16(large[13:15], 1485)
	if _, err := ParseUDPEnvelope(large); err != nil {
		t.Fatal(err)
	}
}

func FuzzSocketParsers(f *testing.F) {
	f.Add(byte(16), []byte{1, 2, 3})
	f.Add(byte(8), make([]byte, 137))
	f.Fuzz(func(t *testing.T, typ byte, b []byte) {
		frame := Frame{Type: typ, Payload: b}
		_, _ = ParseSocketConnect(frame)
		_, _ = ParseSocketConnectResponse(frame)
		_, _ = ParseSocketClose(frame)
		_, _ = ParseSocketBuffer(frame)
		_, _ = ParseSocketReadClose(frame)
		_, _ = ParseDataChunk(frame)
		_, _ = ParseUDPFrame(frame)
		_, _ = ParseAddress(b)
	})
}
