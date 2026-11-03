package router

// VPN-Core router/encode.go MarshalResponse and MarshalHTTPHeader on the
// local builder. A client only parses these tables; the encoders are the
// counterpart the native-golden round trips and the provider tests' local
// routers use. They hold no state.

func byteVector(b *builder, v []byte) int {
	if v == nil {
		return 0
	}
	return b.createBytes(v)
}
func addressTable(b *builder, a NetworkAddress) int {
	v := byteVector(b, a.Address)
	b.startObject(4)
	b.uint32Slot(0, a.Metadata, 0)
	b.uint16Slot(1, a.Port, 0)
	b.byteSlot(2, a.Kind, 0)
	b.offsetSlot(3, v)
	return b.endObject()
}
func tableVector(b *builder, offsets []int) int {
	if offsets == nil {
		return 0
	}
	b.startVector(4, len(offsets), 4)
	for i := len(offsets) - 1; i >= 0; i-- {
		b.prependUOffset(offsets[i])
	}
	return b.endVector(len(offsets))
}
func addressVector(b *builder, as []NetworkAddress) int {
	if as == nil {
		return 0
	}
	offsets := make([]int, len(as))
	for i, a := range as {
		offsets[i] = addressTable(b, a)
	}
	return tableVector(b, offsets)
}
func pingTable(b *builder, p PingPathInfo) int {
	var info int
	if p.Info != nil {
		a := byteVector(b, p.Info.Address)
		param := byteVector(b, p.Info.Parameters)
		b.startObject(4)
		b.uint16Slot(0, p.Info.Port, 0)
		b.byteSlot(1, p.Info.Kind, 0)
		b.offsetSlot(2, a)
		b.offsetSlot(3, param)
		info = b.endObject()
	}
	b.startObject(2)
	b.byteSlot(0, p.Kind, 0)
	b.offsetSlot(1, info)
	return b.endObject()
}
func adTable(b *builder, a AdPath) int {
	as := addressVector(b, a.Addresses)
	tcp, udp, f7, f8 := byteVector(b, a.TCPParams), byteVector(b, a.UDPParams), byteVector(b, a.Field7), byteVector(b, a.Field8)
	b.startObject(10)
	b.offsetSlot(0, as)
	b.uint16Slot(1, a.TCPType, 0)
	b.uint16Slot(2, a.UDPType, 0)
	b.offsetSlot(3, tcp)
	b.offsetSlot(4, udp)
	b.uint16Slot(5, a.Field5, 0)
	b.uint16Slot(6, a.Field6, 0)
	b.offsetSlot(7, f7)
	b.offsetSlot(8, f8)
	b.boolSlot(9, a.Flag9)
	return b.endObject()
}

func MarshalResponse(r Response) ([]byte, error) {
	if err := checkBudget(r); err != nil {
		return nil, err
	}
	b := newBuilder(512)
	as := addressVector(b, r.Addresses)
	tcp, udp, f8, f9 := byteVector(b, r.TCPParams), byteVector(b, r.UDPParams), byteVector(b, r.Field8), byteVector(b, r.Field9)
	var ping, ad, extra int
	if r.PingPaths != nil {
		offsets := make([]int, len(r.PingPaths))
		for i, p := range r.PingPaths {
			offsets[i] = pingTable(b, p)
		}
		ping = tableVector(b, offsets)
	}
	if r.AdPath != nil {
		ad = adTable(b, *r.AdPath)
	}
	if r.ExtraAddress != nil {
		extra = addressTable(b, *r.ExtraAddress)
	}
	b.startObject(15)
	b.uint16Slot(0, r.Status, 0)
	b.offsetSlot(1, as)
	b.uint16Slot(2, r.TCPType, 0)
	b.uint16Slot(3, r.UDPType, 0)
	b.offsetSlot(4, tcp)
	b.offsetSlot(5, udp)
	b.uint16Slot(6, r.Field6, 0)
	b.uint16Slot(7, r.Field7, 0)
	b.offsetSlot(8, f8)
	b.offsetSlot(9, f9)
	b.offsetSlot(10, ping)
	b.boolSlot(11, r.Flag11)
	b.uint16Slot(12, r.Field12, 0)
	b.offsetSlot(13, ad)
	b.offsetSlot(14, extra)
	return b.finish(b.endObject())
}

// Bound work before handing caller-owned vectors to the allocating builder.
func checkBudget(r Response) error {
	remaining := MaxBufferSize
	charge := func(n int) bool {
		if n > remaining {
			return false
		}
		remaining -= n
		return true
	}
	addresses := func(as []NetworkAddress) bool {
		if len(as) > MaxBufferSize/16 {
			return false
		}
		for _, a := range as {
			if !charge(16) || !charge(len(a.Address)) {
				return false
			}
		}
		return true
	}
	if !addresses(r.Addresses) {
		return ErrMalformed
	}
	for _, v := range [][]byte{r.TCPParams, r.UDPParams, r.Field8, r.Field9} {
		if !charge(len(v)) {
			return ErrMalformed
		}
	}
	if len(r.PingPaths) > MaxBufferSize/16 {
		return ErrMalformed
	}
	for _, p := range r.PingPaths {
		if !charge(16) {
			return ErrMalformed
		}
		if p.Info != nil {
			if !charge(len(p.Info.Address)) || !charge(len(p.Info.Parameters)) {
				return ErrMalformed
			}
		}
	}
	if a := r.AdPath; a != nil {
		if !addresses(a.Addresses) {
			return ErrMalformed
		}
		for _, v := range [][]byte{a.TCPParams, a.UDPParams, a.Field7, a.Field8} {
			if !charge(len(v)) {
				return ErrMalformed
			}
		}
	}
	if a := r.ExtraAddress; a != nil {
		if !charge(len(a.Address)) {
			return ErrMalformed
		}
	}
	return nil
}

// MarshalHTTPHeader is VPN-Core's HttpCheaterHeader builder (the router side
// of ParseHTTPHeader), kept beside the parser for the native verifier goldens.
func MarshalHTTPHeader(h HTTPHeader) ([]byte, error) {
	if len(h.Domain) > MaxBufferSize-64 || len(h.Extra) > MaxBufferSize-64-len(h.Domain) {
		return nil, ErrMalformed
	}
	b := newBuilder(128)
	domain, extra := b.createString(h.Domain), b.createString(h.Extra)
	b.startObject(4)
	b.uint16Slot(0, h.CheaterID, 0)
	b.uint16Slot(1, h.CustomID, 0)
	b.offsetSlot(2, domain)
	b.offsetSlot(3, extra)
	return b.finish(b.endObject())
}
