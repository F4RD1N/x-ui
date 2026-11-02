package encoding_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vless"
	. "github.com/xtls/xray-core/proxy/vless/encoding"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func newID() []byte {
	id := uuid.New()
	return id.Bytes()
}

func TestClientVerRoundTrip(t *testing.T) {
	id := newID()
	for _, ver := range [][3]byte{{0, 0, 0}, {1, 8, 24}, {25, 3, 6}, {26, 3, 27}, {255, 255, 255}} {
		v := SealClientVer(id, ver)
		if len(v) != ClientVerLen || ClientVerLen > 16 {
			t.Fatalf("len %d, want %d (<= 16)", len(v), ClientVerLen)
		}
		got, ok := OpenClientVer(id, v)
		if !ok || got != ver {
			t.Fatalf("open(seal(%v)) = %v, %v", ver, got, ok)
		}
	}
}

func TestClientVerFreshPerConnection(t *testing.T) {
	id := newID()
	seen := map[string]bool{}
	sealed := map[string]bool{} // the 3 version bytes as sent
	for i := 0; i < 1000; i++ {
		v := SealClientVer(id, [3]byte{25, 3, 6})
		if seen[string(v)] {
			t.Fatal("same value twice")
		}
		seen[string(v)] = true
		sealed[string(v[8:11])] = true
	}
	// The version is not a fixed byte string: its sealed bytes change too.
	if len(sealed) < 900 {
		t.Fatalf("only %d distinct sealed versions in 1000", len(sealed))
	}
}

func TestClientVerWrongIDAndGarbage(t *testing.T) {
	id, other := newID(), newID()
	v := SealClientVer(id, [3]byte{25, 3, 6})
	if _, ok := OpenClientVer(other, v); ok {
		t.Fatal("opened under another user id")
	}
	for i := range v {
		w := append([]byte(nil), v...)
		w[i] ^= 0x01
		if _, ok := OpenClientVer(id, w); ok {
			t.Fatalf("opened with byte %d flipped", i)
		}
	}
	for _, g := range [][]byte{nil, {}, v[:14], append(append([]byte(nil), v...), 0), []byte("25.3.6")} {
		if _, ok := OpenClientVer(id, g); ok {
			t.Fatalf("opened %x", g)
		}
	}
	g := make([]byte, ClientVerLen)
	for i := 0; i < 20000; i++ {
		rand.Read(g)
		if _, ok := OpenClientVer(id, g); ok {
			t.Fatalf("opened random %x", g)
		}
	}
}

func TestClientVerAllowed(t *testing.T) {
	id := newID()
	v := SealClientVer(id, [3]byte{25, 3, 6})
	other := SealClientVer(newID(), [3]byte{25, 3, 6})
	b := func(x, y, z byte) []byte { return []byte{x, y, z} }
	cases := []struct {
		name     string
		v        []byte
		min, max []byte
		want     bool
	}{
		{"no limits", v, nil, nil, true},
		{"no limits, no version", nil, nil, nil, true},
		{"no limits, garbage", []byte("garbage"), nil, nil, true},
		{"min equal", v, b(25, 3, 6), nil, true},
		{"min lower", v, b(25, 2, 255), nil, true},
		{"min higher z", v, b(25, 3, 7), nil, false},
		{"min higher y", v, b(25, 4, 0), nil, false},
		{"min higher x", v, b(26, 0, 0), nil, false},
		{"max equal", v, nil, b(25, 3, 6), true},
		{"max higher", v, nil, b(26, 3, 27), true},
		{"max lower", v, nil, b(25, 3, 5), false},
		{"max lower x", v, nil, b(24, 9, 9), false},
		{"window in", v, b(25, 0, 0), b(25, 9, 0), true},
		{"window out", v, b(25, 4, 0), b(25, 9, 0), false},
		{"min, no version", nil, b(1, 0, 0), nil, false},
		{"min, wrong id", other, b(1, 0, 0), nil, false},
		{"max only, no version", nil, nil, b(25, 0, 0), true},
	}
	for _, c := range cases {
		if got, why := ClientVerAllowed(id, c.v, c.min, c.max); got != c.want {
			t.Errorf("%s: got %v (%s), want %v", c.name, got, why, c.want)
		}
	}
}

// fields lists the protobuf field numbers in an encoded Addons.
func fields(t *testing.T, b []byte) []protowire.Number {
	var out []protowire.Number
	for len(b) > 0 {
		n, typ, l := protowire.ConsumeTag(b)
		if l < 0 {
			t.Fatal("bad tag")
		}
		b = b[l:]
		l = protowire.ConsumeFieldValue(n, typ, b)
		if l < 0 {
			t.Fatal("bad value")
		}
		b = b[l:]
		out = append(out, n)
	}
	return out
}

func encodeAddons(t *testing.T, a *Addons) []byte {
	buffer := buf.New()
	defer buffer.Release()
	if err := EncodeHeaderAddons(buffer, a); err != nil {
		t.Fatal(err)
	}
	out := append([]byte(nil), buffer.Bytes()...)
	if int(out[0]) != len(out)-1 {
		t.Fatalf("length byte %d, body %d", out[0], len(out)-1)
	}
	return out
}

func TestEncodeHeaderAddonsClientVer(t *testing.T) {
	id := newID()
	cv := SealClientVer(id, [3]byte{25, 3, 6})

	// Unchanged without a ClientVer: nothing for no flow, Flow for Vision.
	if got := encodeAddons(t, &Addons{}); !bytes.Equal(got, []byte{0}) {
		t.Fatalf("empty addons = %x", got)
	}
	if got := encodeAddons(t, &Addons{Flow: "something"}); !bytes.Equal(got, []byte{0}) {
		t.Fatalf("non-vision flow = %x", got)
	}
	want, _ := proto.Marshal(&Addons{Flow: vless.XRV})
	if got := encodeAddons(t, &Addons{Flow: vless.XRV}); !bytes.Equal(got[1:], want) {
		t.Fatalf("vision = %x, want %x", got[1:], want)
	}

	// With a ClientVer: only field 1000 without Vision; 1 and 1000 with it.
	for _, c := range []struct {
		flow, wantFlow string
		fields         []protowire.Number
	}{
		{"", "", []protowire.Number{1000}},
		{"something", "", []protowire.Number{1000}},
		{vless.XRV, vless.XRV, []protowire.Number{1, 1000}},
	} {
		got := encodeAddons(t, &Addons{Flow: c.flow, ClientVer: cv})
		f := fields(t, got[1:])
		if len(f) != len(c.fields) {
			t.Fatalf("flow %q: fields %v, want %v", c.flow, f, c.fields)
		}
		for i := range f {
			if f[i] != c.fields[i] {
				t.Fatalf("flow %q: fields %v, want %v", c.flow, f, c.fields)
			}
		}
		r := buf.New()
		r.Write(got)
		dec, err := DecodeHeaderAddons(buf.New(), r)
		if err != nil {
			t.Fatal(err)
		}
		if dec.Flow != c.wantFlow || !bytes.Equal(dec.ClientVer, cv) {
			t.Fatalf("flow %q: decoded %q %x", c.flow, dec.Flow, dec.ClientVer)
		}
	}
}
