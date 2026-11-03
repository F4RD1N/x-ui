package router

import (
	"encoding/binary"
	"fmt"
)

// builder is the subset of the Go FlatBuffers Builder that VPN-Core's router
// encoder uses, written out here so the module needs no FlatBuffers
// dependency. It reproduces the library's layout byte for byte (back-to-front
// building, alignment padding, trailing-default vtable trimming and vtable
// sharing); the native request goldens in testdata pin that.
type builder struct {
	buf       []byte // filled from the end; data is buf[head:]
	head      int
	minalign  int
	vtable    []int
	objectEnd int
	vtables   []int
}

func newBuilder(size int) *builder {
	return &builder{buf: make([]byte, size), head: size, minalign: 1}
}

func (b *builder) offset() int { return len(b.buf) - b.head }

func (b *builder) grow(need int) {
	for b.head < need {
		size := len(b.buf) * 2
		if size == 0 {
			size = 64
		}
		next := make([]byte, size)
		copy(next[size-len(b.buf):], b.buf)
		b.head += size - len(b.buf)
		b.buf = next
	}
}

// prep aligns the next write of size bytes after additional bytes.
func (b *builder) prep(size, additional int) {
	if size > b.minalign {
		b.minalign = size
	}
	align := (^(len(b.buf) - b.head + additional) + 1) & (size - 1)
	b.grow(align + size + additional + 1)
	for i := 0; i < align; i++ {
		b.head--
		b.buf[b.head] = 0
	}
}

func (b *builder) placeByte(v byte) { b.head--; b.buf[b.head] = v }
func (b *builder) placeUint16(v uint16) {
	b.head -= 2
	binary.LittleEndian.PutUint16(b.buf[b.head:], v)
}
func (b *builder) placeUint32(v uint32) {
	b.head -= 4
	binary.LittleEndian.PutUint32(b.buf[b.head:], v)
}

func (b *builder) prependByte(v byte)     { b.prep(1, 0); b.placeByte(v) }
func (b *builder) prependUint16(v uint16) { b.prep(2, 0); b.placeUint16(v) }
func (b *builder) prependUint32(v uint32) { b.prep(4, 0); b.placeUint32(v) }
func (b *builder) prependUOffset(off int) {
	b.prep(4, 0)
	b.placeUint32(uint32(b.offset() - off + 4))
}

func (b *builder) startVector(elemSize, n, alignment int) {
	b.prep(4, elemSize*n)
	b.prep(alignment, elemSize*n)
}
func (b *builder) endVector(n int) int { b.placeUint32(uint32(n)); return b.offset() }

func (b *builder) createString(s string) int {
	b.prep(4, len(s)+1)
	b.placeByte(0)
	b.head -= len(s)
	copy(b.buf[b.head:], s)
	return b.endVector(len(s))
}

func (b *builder) createBytes(v []byte) int {
	b.prep(4, len(v))
	b.head -= len(v)
	copy(b.buf[b.head:], v)
	return b.endVector(len(v))
}

func (b *builder) startObject(fields int) {
	b.vtable = make([]int, fields)
	b.objectEnd = b.offset()
}
func (b *builder) slot(i int) { b.vtable[i] = b.offset() }

func (b *builder) uint16Slot(i int, v, d uint16) {
	if v != d {
		b.prependUint16(v)
		b.slot(i)
	}
}
func (b *builder) uint32Slot(i int, v, d uint32) {
	if v != d {
		b.prependUint32(v)
		b.slot(i)
	}
}
func (b *builder) byteSlot(i int, v, d byte) {
	if v != d {
		b.prependByte(v)
		b.slot(i)
	}
}
func (b *builder) boolSlot(i int, v bool) {
	if v {
		b.byteSlot(i, 1, 0)
	}
}
func (b *builder) offsetSlot(i, off int) {
	if off != 0 {
		b.prependUOffset(off)
		b.slot(i)
	}
}

func (b *builder) endObject() int {
	b.prep(4, 0)
	b.placeUint32(0) // the vtable soffset, written below
	object := b.offset()
	n := len(b.vtable)
	for n > 0 && b.vtable[n-1] == 0 {
		n--
	}
	entries := make([]uint16, n)
	for i := 0; i < n; i++ {
		if b.vtable[i] != 0 {
			entries[i] = uint16(object - b.vtable[i])
		}
	}
	size := uint16(object - b.objectEnd)
	existing := 0
	for i := len(b.vtables) - 1; i >= 0 && existing == 0; i-- {
		start := len(b.buf) - b.vtables[i]
		length := int(binary.LittleEndian.Uint16(b.buf[start:]))
		// Like the library, only the field entries are compared.
		if length != (n+2)*2 {
			continue
		}
		same := true
		for j, e := range entries {
			if binary.LittleEndian.Uint16(b.buf[start+4+2*j:]) != e {
				same = false
				break
			}
		}
		if same {
			existing = b.vtables[i]
		}
	}
	if existing == 0 {
		for i := n - 1; i >= 0; i-- {
			b.prependUint16(entries[i])
		}
		b.prependUint16(size)
		b.prependUint16(uint16((n + 2) * 2))
		start := len(b.buf) - object
		binary.LittleEndian.PutUint32(b.buf[start:], uint32(int32(b.offset()-object)))
		b.vtables = append(b.vtables, b.offset())
	} else {
		start := len(b.buf) - object
		b.head = start
		binary.LittleEndian.PutUint32(b.buf[start:], uint32(int32(existing-object)))
	}
	b.vtable = nil
	return object
}

func (b *builder) finish(root int) ([]byte, error) {
	b.prep(b.minalign, 4)
	b.prependUOffset(root)
	out := b.buf[b.head:]
	if len(out) > MaxBufferSize {
		return nil, fmt.Errorf("%w: buffer exceeds %d bytes", ErrMalformed, MaxBufferSize)
	}
	return append([]byte(nil), out...), nil
}

// MarshalRequest builds the RouteReq table in the native CreateRouteReq
// field order (VPN-Core router/encode.go).
func MarshalRequest(r Request) ([]byte, error) {
	if len(r.Group) > MaxBufferSize-64 {
		return nil, fmt.Errorf("%w: group too large", ErrMalformed)
	}
	b := newBuilder(256)
	group := b.createString(r.Group)
	b.startObject(4)
	b.uint32Slot(2, r.Metadata, 0)
	b.offsetSlot(1, group)
	b.uint32Slot(0, uint32(r.Attempt), 0)
	b.boolSlot(3, r.Option)
	return b.finish(b.endObject())
}
