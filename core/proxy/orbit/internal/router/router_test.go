package router

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"github.com/xtls/xray-core/proxy/orbit/internal/protocol"
	"os"
	"reflect"
	"strings"
	"testing"
)

func decodeHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestNativeRequestBuilderGoldens(t *testing.T) {
	b, err := os.ReadFile("testdata/native-requests.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Request Request
			Hex     string
		}
	}
	if err := json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, v := range fixture.Cases {
		got, err := ParseRequest(decodeHex(t, v.Hex))
		if err != nil || got != v.Request {
			t.Fatalf("decode %+v %v", got, err)
		}
		encoded, err := MarshalRequest(v.Request)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(encoded, decodeHex(t, v.Hex)) {
			t.Fatalf("native builder mismatch: got %x want %s", encoded, v.Hex)
		}
	}
}

func TestNativeResponseVerifierGoldens(t *testing.T) {
	b, err := os.ReadFile("testdata/native-verifier.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Name, Hex string
			Response  Response
			Accepted  bool
		}
	}
	if err := json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, v := range fixture.Cases {
		t.Run(v.Name, func(t *testing.T) {
			data := decodeHex(t, v.Hex)
			got, err := ParseResponse(data)
			if (err == nil) != v.Accepted {
				t.Fatalf("acceptance differs from native: %v", err)
			}
			if !v.Accepted {
				return
			}
			if !reflect.DeepEqual(got, v.Response) {
				t.Fatalf("response fields differ\ngot %+v\nwant %+v", got, v.Response)
			}
			encoded, err := MarshalResponse(got)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := ParseResponse(encoded)
			if err != nil || !reflect.DeepEqual(decoded, got) {
				t.Fatal("response did not round trip", err)
			}
		})
	}
}

func TestAddressNativeFixtures(t *testing.T) {
	b, err := os.ReadFile("../protocol/testdata/native-addresses.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Kind                 byte
			Port                 uint16
			ValueHex, AddressHex string
		}
	}
	if err := json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, v := range fixture.Cases {
		a := NetworkAddress{Kind: v.Kind, Port: v.Port, Address: decodeHex(t, v.ValueHex)}
		got, _ := a.ProtocolAddress().MarshalBinary()
		if !bytes.Equal(got, decodeHex(t, v.AddressHex)) {
			t.Fatal("native address copy differs")
		}
	}
	for _, host := range []string{"192.0.2.1", "2001:db8::1", "example.test"} {
		p, err := protocol.NewAddress(host, 443)
		if err != nil {
			t.Fatal(err)
		}
		a := NetworkAddressFromProtocol(p, 123)
		if a.Metadata != 123 || a.ProtocolAddress() != p {
			t.Fatal("protocol conversion")
		}
	}
	a := protocol.Address{Kind: 3}
	for i := range a.Storage {
		a.Storage[i] = 'a'
	}
	if len(NetworkAddressFromProtocol(a, 0).Address) != 128 {
		t.Fatal("raw nonterminated address preservation")
	}
}

func TestRequestAndResponseBoundsDefaultsOwnership(t *testing.T) {
	for _, req := range []Request{{}, {Attempt: -2147483648, Group: "nul\x00data", Metadata: ^uint32(0), Option: true}, {Attempt: 2147483647, Group: strings.Repeat("g", MaxBufferSize-64)}} {
		b, err := MarshalRequest(req)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseRequest(b)
		if err != nil || got != req {
			t.Fatal(got, err)
		}
	}
	if _, err := MarshalRequest(Request{Group: strings.Repeat("x", MaxBufferSize)}); err == nil {
		t.Fatal("request overflow")
	}
	a := NetworkAddress{Kind: 1, Port: 443, Address: []byte{192, 0, 2, 1}}
	r := Response{Status: 1, Addresses: []NetworkAddress{a}, TCPParams: []byte{1, 2}, AdPath: &AdPath{Addresses: []NetworkAddress{a}}, ExtraAddress: &a}
	b, err := MarshalResponse(r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseResponse(b)
	if err != nil {
		t.Fatal(err)
	}
	for i := range b {
		b[i] = 0
	}
	if !reflect.DeepEqual(got, r) {
		t.Fatal("response aliases source")
	}
	if err := r.ValidateUsable(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Response{{Status: 500}, {Status: 1}, {Status: 1, Addresses: []NetworkAddress{{Kind: 1}}}, {Status: 1, Addresses: []NetworkAddress{{Kind: 0, Port: 443}}}} {
		if err := bad.ValidateUsable(); err == nil {
			t.Fatal("unusable response accepted")
		}
	}
	for _, bad := range []Response{{TCPParams: make([]byte, MaxBufferSize+1)}, {Addresses: make([]NetworkAddress, MaxBufferSize)}, {Addresses: []NetworkAddress{{Address: make([]byte, MaxBufferSize)}}}, {PingPaths: make([]PingPathInfo, MaxBufferSize)}, {PingPaths: []PingPathInfo{{Info: &PingAddrInfo{Parameters: make([]byte, MaxBufferSize)}}}}, {AdPath: &AdPath{Addresses: make([]NetworkAddress, MaxBufferSize)}}, {AdPath: &AdPath{Field7: make([]byte, MaxBufferSize+1)}}, {ExtraAddress: &NetworkAddress{Address: make([]byte, MaxBufferSize+1)}}, {TCPParams: make([]byte, MaxBufferSize)}} {
		if _, err := MarshalResponse(bad); err == nil {
			t.Fatal("oversized response accepted")
		}
	}
}

func TestMalformedOffsetsLengthsAlignmentAndStrings(t *testing.T) {
	req, _ := MarshalRequest(Request{Attempt: 1, Group: "test", Metadata: 5, Option: true})
	_, tab := root(req)
	groupField := tab.field(1, 4)
	groupPos := groupField + int(binary.LittleEndian.Uint32(req[groupField:groupField+4]))
	rootPos := int(binary.LittleEndian.Uint32(req))
	vt := rootPos - int(int32(binary.LittleEndian.Uint32(req[rootPos:])))
	cases := [][]byte{nil, make([]byte, 7), make([]byte, MaxBufferSize+1)}
	for _, mutate := range []func([]byte){
		func(b []byte) { binary.LittleEndian.PutUint32(b, 0) }, func(b []byte) { binary.LittleEndian.PutUint32(b, 3) }, func(b []byte) { binary.LittleEndian.PutUint32(b, 0xffffffff) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[rootPos:], 0x7fffffff) }, func(b []byte) { binary.LittleEndian.PutUint16(b[vt:], 3) }, func(b []byte) { binary.LittleEndian.PutUint16(b[vt:], 0xffff) }, func(b []byte) { binary.LittleEndian.PutUint16(b[vt+2:], 3) },
		func(b []byte) { binary.LittleEndian.PutUint16(b[vt+4:], 1) }, func(b []byte) { binary.LittleEndian.PutUint16(b[vt+4:], 0xfffe) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[groupField:], 0) }, func(b []byte) { binary.LittleEndian.PutUint32(b[groupField:], 0xffffffff) }, func(b []byte) { binary.LittleEndian.PutUint32(b[groupPos:], 0xffffffff) }, func(b []byte) { b[groupPos+4+4] = 'x' },
	} {
		b := append([]byte(nil), req...)
		mutate(b)
		cases = append(cases, b)
	}
	for i, b := range cases {
		if _, err := ParseRequest(b); err == nil {
			t.Fatalf("bad request %d accepted", i)
		}
	}
	// Mutate vectors of tables, nested offsets, and a nested scalar's alignment.
	a := NetworkAddress{Kind: 1, Port: 443, Address: []byte{192, 0, 2, 1}}
	res, _ := MarshalResponse(Response{Status: 1, Addresses: []NetworkAddress{a}, PingPaths: []PingPathInfo{{Kind: 1, Info: &PingAddrInfo{Port: 53}}}, AdPath: &AdPath{TCPType: 1}, ExtraAddress: &a})
	_, rt := root(res)
	addrPtr, _ := rt.vector(1, 4)
	nested := rt.field(13, 4)
	for _, mutate := range []func([]byte){func(b []byte) { binary.LittleEndian.PutUint32(b[addrPtr:], 0) }, func(b []byte) { binary.LittleEndian.PutUint32(b[addrPtr:], 0xffffffff) }, func(b []byte) { binary.LittleEndian.PutUint32(b[nested:], 0xffffffff) }} {
		b := append([]byte(nil), res...)
		mutate(b)
		if _, err := ParseResponse(b); err == nil {
			t.Fatal("bad response pointer accepted")
		}
	}
}

func FuzzRouterParsers(f *testing.F) {
	b, _ := MarshalRequest(Request{Group: "test", Option: true})
	f.Add(b)
	b, _ = MarshalResponse(Response{Status: 1, Addresses: []NetworkAddress{{Port: 443, Kind: 1, Address: []byte{192, 0, 2, 1}}}})
	f.Add(b)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > MaxBufferSize+1 {
			return
		}
		if r, err := ParseRequest(b); err == nil {
			encoded, err := MarshalRequest(r)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ParseRequest(encoded)
			if err != nil || got != r {
				t.Fatal("request round trip")
			}
		}
		if r, err := ParseResponse(b); err == nil {
			encoded, err := MarshalResponse(r)
			if err != nil {
				return
			}
			got, err := ParseResponse(encoded)
			if err != nil || !reflect.DeepEqual(got, r) {
				t.Fatal("response round trip", err)
			}
		}
	})
}
