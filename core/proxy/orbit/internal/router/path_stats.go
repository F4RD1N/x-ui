package router

// PathStat is the application type-4 response table. An empty Protocols vector
// reports no samples; it must not be replaced by fabricated telemetry.
type PathStat struct {
	Kind             byte
	Address          string
	FromNode, ToNode uint32
	Protocols        []PathProtoStat
}
type PathProtoStat struct {
	TransportType, RTT uint16
	LossPercent        byte
}

func MarshalPathStat(p PathStat) ([]byte, error) {
	if len(p.Protocols) > MaxBufferSize/16 || len(p.Address) > MaxBufferSize-64-len(p.Protocols)*16 {
		return nil, ErrMalformed
	}
	b := newBuilder(128)
	address := b.createString(p.Address)
	var protocols int
	if p.Protocols != nil {
		offsets := make([]int, len(p.Protocols))
		for i, p := range p.Protocols {
			b.startObject(3)
			b.uint16Slot(0, p.TransportType, 0)
			b.uint16Slot(1, p.RTT, 0)
			b.byteSlot(2, p.LossPercent, 0)
			offsets[i] = b.endObject()
		}
		protocols = tableVector(b, offsets)
	}
	b.startObject(5)
	b.byteSlot(0, p.Kind, 0)
	b.offsetSlot(1, address)
	b.uint32Slot(2, p.FromNode, 0)
	b.uint32Slot(3, p.ToNode, 0)
	b.offsetSlot(4, protocols)
	return b.finish(b.endObject())
}
func ParsePathStat(b []byte) (PathStat, error) {
	r, t := root(b)
	out := PathStat{Kind: t.u8(0), Address: t.text(1), FromNode: t.u32(2), ToNode: t.u32(3)}
	if ps := t.tables(4); ps != nil {
		out.Protocols = make([]PathProtoStat, len(ps))
		for i, p := range ps {
			out.Protocols[i] = PathProtoStat{TransportType: p.u16(0), RTT: p.u16(1), LossPercent: p.u8(2)}
		}
	}
	if r.err != nil {
		return PathStat{}, r.err
	}
	return out, nil
}
