package openvpn

import (
	"io"
	"sync"

	"github.com/xtls/xray-core/common/buf"
)

// stackWriter writes a request's data into a TCP connection of the tunnel's
// stack with one Write per MultiBuffer (at most coalesceSize bytes each).
//
// The stack starts a new segment at every Write and never splits a queued
// write to top up the segment before it. Written buffer by buffer, as
// buf.NewWriter does, every 8 KiB buffer ends in a short segment: at MSS
// 1360, 8192 bytes go out as six full segments and one of 32 bytes. That
// short segment costs a whole packet on the link (seal, send, the server's
// work) and a whole slot of the congestion window, which the stack counts
// in packets: an upload sent 16% more packets than it needed and carried
// that much less per window. A request read with readv brings up to 64 KiB
// per MultiBuffer, so one Write per MultiBuffer leaves one short segment
// per read instead of one per buffer.
type stackWriter struct {
	w io.Writer
}

func newStackWriter(w io.Writer) buf.Writer { return &stackWriter{w: w} }

// coalesceSize bounds one coalesced Write (and the pooled scratch buffer).
const coalesceSize = 64 << 10

var coalescePool = sync.Pool{New: func() any {
	b := make([]byte, coalesceSize)
	return &b
}}

// WriteMultiBuffer implements buf.Writer.
func (s *stackWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	if len(mb) == 1 {
		return buf.WriteAllBytes(s.w, mb[0].Bytes(), nil)
	}
	var scratch *[]byte
	defer func() {
		if scratch != nil {
			coalescePool.Put(scratch)
		}
	}()
	for i := 0; i < len(mb); {
		b := mb[i].Bytes()
		if len(b) == 0 {
			i++
			continue
		}
		// A buffer that cannot share a Write with the next one goes as
		// it is.
		if i+1 == len(mb) || len(b)+int(mb[i+1].Len()) > coalesceSize {
			if err := buf.WriteAllBytes(s.w, b, nil); err != nil {
				return err
			}
			i++
			continue
		}
		if scratch == nil {
			scratch = coalescePool.Get().(*[]byte)
		}
		out := (*scratch)[:0]
		for ; i < len(mb) && len(out)+int(mb[i].Len()) <= coalesceSize; i++ {
			out = append(out, mb[i].Bytes()...)
		}
		if err := buf.WriteAllBytes(s.w, out, nil); err != nil {
			return err
		}
	}
	return nil
}
