package router

// ProxyNodeInfo preserves the five recovered relay-node slots. Field0 has no
// established policy meaning; Parameters and NestedProxy remain opaque bytes.
type ProxyNodeInfo struct {
	Field0                  byte
	TransportType           uint16
	Addresses               []NetworkAddress
	Parameters, NestedProxy []byte
}
type ProxyPath struct {
	Nodes  []ProxyNodeInfo
	Field1 uint32
}

func MarshalProxyPath(p ProxyPath) ([]byte, error) {
	if len(p.Nodes) > MaxBufferSize/32 {
		return nil, ErrMalformed
	}
	budget := MaxBufferSize
	for _, n := range p.Nodes {
		if len(n.Addresses) > MaxBufferSize/16 {
			return nil, ErrMalformed
		}
		budget -= 32
		for _, v := range [][]byte{n.Parameters, n.NestedProxy} {
			if len(v) > budget {
				return nil, ErrMalformed
			}
			budget -= len(v)
		}
		for _, a := range n.Addresses {
			if len(a.Address) > budget-16 {
				return nil, ErrMalformed
			}
			budget -= 16 + len(a.Address)
		}
	}
	b := newBuilder(256)
	var nodes int
	if p.Nodes != nil {
		offsets := make([]int, len(p.Nodes))
		for i, n := range p.Nodes {
			addresses := addressVector(b, n.Addresses)
			parameters := byteVector(b, n.Parameters)
			nested := byteVector(b, n.NestedProxy)
			b.startObject(5)
			b.byteSlot(0, n.Field0, 0)
			b.uint16Slot(1, n.TransportType, 0)
			b.offsetSlot(2, addresses)
			b.offsetSlot(3, parameters)
			b.offsetSlot(4, nested)
			offsets[i] = b.endObject()
		}
		nodes = tableVector(b, offsets)
	}
	b.startObject(2)
	b.offsetSlot(0, nodes)
	b.uint32Slot(1, p.Field1, 0)
	return b.finish(b.endObject())
}
func ParseProxyPath(b []byte) (ProxyPath, error) {
	r, t := root(b)
	out := ProxyPath{Field1: t.u32(1)}
	if ns := t.tables(0); ns != nil {
		out.Nodes = make([]ProxyNodeInfo, len(ns))
		for i, n := range ns {
			out.Nodes[i] = ProxyNodeInfo{Field0: n.u8(0), TransportType: n.u16(1), Addresses: decodeAddresses(n, 2), Parameters: n.bytes(3), NestedProxy: n.bytes(4)}
		}
	}
	if r.err != nil {
		return ProxyPath{}, r.err
	}
	return out, nil
}
