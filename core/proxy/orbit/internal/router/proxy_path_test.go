package router

import (
	"reflect"
	"testing"
)

func TestProxyPathRoundTripAndBounds(t *testing.T) {
	for _, p := range []ProxyPath{{}, {Nodes: []ProxyNodeInfo{}}, {Field1: 0xffffffff, Nodes: []ProxyNodeInfo{{Field0: 255, TransportType: 4, Addresses: []NetworkAddress{{Metadata: 0x12345678, Port: 443, Kind: 1, Address: []byte{192, 0, 2, 1}}, {Port: 80, Kind: 3, Address: []byte("second.test")}}, Parameters: []byte{0, 1, 2}, NestedProxy: []byte{9, 8, 7}}, {TransportType: 5, Addresses: []NetworkAddress{}}}}} {
		b, e := MarshalProxyPath(p)
		if e != nil {
			t.Fatal(e)
		}
		got, e := ParseProxyPath(b)
		if e != nil || !reflect.DeepEqual(got, p) {
			t.Fatalf("%#v %v", got, e)
		}
		if _, e = ParseProxyPath(b[:len(b)/2]); e == nil {
			t.Fatal("truncated accepted")
		}
	}
	for _, p := range []ProxyPath{{Nodes: make([]ProxyNodeInfo, MaxBufferSize)}, {Nodes: []ProxyNodeInfo{{Parameters: make([]byte, MaxBufferSize)}}}, {Nodes: []ProxyNodeInfo{{Addresses: make([]NetworkAddress, MaxBufferSize)}}}, {Nodes: []ProxyNodeInfo{{Addresses: []NetworkAddress{{Address: make([]byte, MaxBufferSize)}}}}}} {
		if _, e := MarshalProxyPath(p); e == nil {
			t.Fatal("oversize accepted")
		}
	}
}
func FuzzProxyPath(f *testing.F) {
	b, _ := MarshalProxyPath(ProxyPath{Nodes: []ProxyNodeInfo{{TransportType: 4, Addresses: []NetworkAddress{{Port: 443, Kind: 1, Address: []byte{192, 0, 2, 1}}}}}})
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) {
		p, e := ParseProxyPath(b)
		if e != nil {
			return
		}
		out, e := MarshalProxyPath(p)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = ParseProxyPath(out); e != nil {
			t.Fatal(e)
		}
	})
}
