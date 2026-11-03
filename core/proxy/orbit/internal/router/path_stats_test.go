package router

import (
	"reflect"
	"strings"
	"testing"
)

func TestPathStatRoundTrip(t *testing.T) {
	for _, p := range []PathStat{{}, {Kind: 1, Address: "127.0.0.1:8443", FromNode: 1, ToNode: 2, Protocols: []PathProtoStat{}}, {Kind: 255, Address: "owned\x00.test", FromNode: 0xffffffff, Protocols: []PathProtoStat{{4, 17, 0}, {5, 65535, 100}}}} {
		b, err := MarshalPathStat(p)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParsePathStat(b)
		if err != nil || !reflect.DeepEqual(p, got) {
			t.Fatalf("roundtrip %#v %#v %v", p, got, err)
		}
	}
}
func TestPathStatMalformed(t *testing.T) {
	for _, b := range [][]byte{nil, {1, 2, 3}, {0, 0, 0, 0}, {255, 255, 255, 255}, make([]byte, MaxBufferSize+1)} {
		if _, err := ParsePathStat(b); err == nil {
			t.Fatal("malformed accepted")
		}
	}
	for _, p := range []PathStat{{Address: strings.Repeat("a", MaxBufferSize)}, {Protocols: make([]PathProtoStat, MaxBufferSize)}} {
		if _, err := MarshalPathStat(p); err == nil {
			t.Fatal("oversize accepted")
		}
	}
}
func FuzzPathStat(f *testing.F) {
	b, _ := MarshalPathStat(PathStat{Kind: 1, Address: "owned.test", Protocols: []PathProtoStat{{4, 2, 0}}})
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := ParsePathStat(b)
		if err != nil {
			return
		}
		out, err := MarshalPathStat(p)
		if err != nil {
			t.Fatal(err)
		}
		q, err := ParsePathStat(out)
		if err != nil || !reflect.DeepEqual(p, q) {
			t.Fatal("roundtrip")
		}
	})
}
