package router

import "encoding/binary"

// The Go FlatBuffers runtime's generated accessors assume trusted bounds. This
// reader validates offsets, lengths, alignments and table count before access.
type reader struct {
	b      []byte
	err    error
	tables int
}
type table struct {
	r                      *reader
	pos, vt, vtlen, objlen int
}

func (r *reader) bad() { r.err = ErrMalformed }
func (r *reader) bounds(pos, n int) bool {
	if r.err != nil {
		return false
	}
	if pos < 0 || n < 0 || pos > len(r.b) || n > len(r.b)-pos {
		r.bad()
		return false
	}
	return true
}
func (r *reader) u16(pos int) uint16 {
	if !r.bounds(pos, 2) {
		return 0
	}
	return binary.LittleEndian.Uint16(r.b[pos : pos+2])
}
func (r *reader) u32(pos int) uint32 {
	if !r.bounds(pos, 4) {
		return 0
	}
	return binary.LittleEndian.Uint32(r.b[pos : pos+4])
}
func (r *reader) offset(pos int) int {
	if pos%4 != 0 || !r.bounds(pos, 4) {
		r.bad()
		return 0
	}
	delta := uint64(r.u32(pos))
	dest := uint64(pos) + delta
	if delta == 0 || dest >= uint64(len(r.b)) {
		r.bad()
		return 0
	}
	return int(dest)
}
func (r *reader) readTable(pos int) table {
	t := table{r: r, pos: pos}
	r.tables++
	if r.tables > 4096 || pos%4 != 0 || !r.bounds(pos, 4) {
		r.bad()
		return t
	}
	vt := int64(pos) - int64(int32(r.u32(pos)))
	if vt < 0 || vt > int64(len(r.b)-4) || vt%2 != 0 {
		r.bad()
		return t
	}
	t.vt = int(vt)
	t.vtlen = int(r.u16(t.vt))
	t.objlen = int(r.u16(t.vt + 2))
	if t.vtlen < 4 || t.vtlen%2 != 0 || t.objlen < 4 || !r.bounds(t.vt, t.vtlen) || !r.bounds(pos, t.objlen) {
		r.bad()
	}
	return t
}
func root(b []byte) (*reader, table) {
	r := &reader{b: b}
	if len(b) < 8 || len(b) > MaxBufferSize {
		r.bad()
		return r, table{r: r}
	}
	pos := r.offset(0)
	if pos < 4 {
		r.bad()
	}
	return r, r.readTable(pos)
}

func (t table) field(slot, width int) int {
	if t.r.err != nil {
		return 0
	}
	entry := 4 + slot*2
	if entry+2 > t.vtlen {
		return 0
	}
	offset := int(t.r.u16(t.vt + entry))
	if offset == 0 {
		return 0
	}
	pos := t.pos + offset
	if offset < 4 || offset > t.objlen-width || pos%width != 0 || !t.r.bounds(pos, width) {
		t.r.bad()
		return 0
	}
	return pos
}
func (t table) u16(slot int) uint16 {
	p := t.field(slot, 2)
	if p == 0 {
		return 0
	}
	return t.r.u16(p)
}
func (t table) u32(slot int) uint32 {
	p := t.field(slot, 4)
	if p == 0 {
		return 0
	}
	return t.r.u32(p)
}
func (t table) u8(slot int) byte {
	p := t.field(slot, 1)
	if p == 0 {
		return 0
	}
	return t.r.b[p]
}
func (t table) vector(slot, width int) (int, int) {
	p := t.field(slot, 4)
	if p == 0 {
		return 0, 0
	}
	v := t.r.offset(p)
	if v%4 != 0 || !t.r.bounds(v, 4) {
		t.r.bad()
		return 0, 0
	}
	n := uint64(t.r.u32(v))
	size := n * uint64(width)
	if size > uint64(len(t.r.b)) || !t.r.bounds(v+4, int(size)) {
		t.r.bad()
		return 0, 0
	}
	return v + 4, int(n)
}
func (t table) bytes(slot int) []byte {
	p, n := t.vector(slot, 1)
	if p == 0 {
		return nil
	}
	out := make([]byte, n)
	copy(out, t.r.b[p:p+n])
	return out
}
func (t table) text(slot int) string {
	p, n := t.vector(slot, 1)
	if p == 0 {
		return ""
	}
	if !t.r.bounds(p+n, 1) || t.r.b[p+n] != 0 {
		t.r.bad()
		return ""
	}
	return string(t.r.b[p : p+n])
}
func (t table) nested(slot int) *table {
	p := t.field(slot, 4)
	if p == 0 {
		return nil
	}
	out := t.r.readTable(t.r.offset(p))
	return &out
}
func (t table) tables(slot int) []table {
	p, n := t.vector(slot, 4)
	if p == 0 {
		return nil
	}
	if n > 4096 {
		t.r.bad()
		return nil
	}
	out := make([]table, n)
	for i := range out {
		out[i] = t.r.readTable(t.r.offset(p + 4*i))
		if t.r.err != nil {
			return nil
		}
	}
	return out
}

func ParseRequest(b []byte) (Request, error) {
	r, t := root(b)
	out := Request{Attempt: int32(t.u32(0)), Group: t.text(1), Metadata: t.u32(2), Option: t.u8(3) != 0}
	if r.err != nil {
		return Request{}, r.err
	}
	return out, nil
}

func decodeAddress(t table) NetworkAddress {
	return NetworkAddress{Metadata: t.u32(0), Port: t.u16(1), Kind: t.u8(2), Address: t.bytes(3)}
}
func decodeAddresses(t table, slot int) []NetworkAddress {
	tables := t.tables(slot)
	if tables == nil {
		return nil
	}
	as := make([]NetworkAddress, len(tables))
	for i, t := range tables {
		as[i] = decodeAddress(t)
	}
	return as
}
func decodePing(t table) PingPathInfo {
	p := PingPathInfo{Kind: t.u8(0)}
	if info := t.nested(1); info != nil {
		p.Info = &PingAddrInfo{Port: info.u16(0), Kind: info.u8(1), Address: info.bytes(2), Parameters: info.bytes(3)}
	}
	return p
}
func decodeAd(t table) AdPath {
	return AdPath{Addresses: decodeAddresses(t, 0), TCPType: t.u16(1), UDPType: t.u16(2), TCPParams: t.bytes(3), UDPParams: t.bytes(4), Field5: t.u16(5), Field6: t.u16(6), Field7: t.bytes(7), Field8: t.bytes(8), Flag9: t.u8(9) != 0}
}

func ParseResponse(b []byte) (Response, error) {
	r, t := root(b)
	out := Response{Status: t.u16(0), Addresses: decodeAddresses(t, 1), TCPType: t.u16(2), UDPType: t.u16(3), TCPParams: t.bytes(4), UDPParams: t.bytes(5), Field6: t.u16(6), Field7: t.u16(7), Field8: t.bytes(8), Field9: t.bytes(9), Flag11: t.u8(11) != 0, Field12: t.u16(12)}
	if pings := t.tables(10); pings != nil {
		out.PingPaths = make([]PingPathInfo, len(pings))
		for i, p := range pings {
			out.PingPaths[i] = decodePing(p)
		}
	}
	if ad := t.nested(13); ad != nil {
		a := decodeAd(*ad)
		out.AdPath = &a
	}
	if extra := t.nested(14); extra != nil {
		a := decodeAddress(*extra)
		out.ExtraAddress = &a
	}
	if r.err != nil {
		return Response{}, r.err
	}
	return out, nil
}
