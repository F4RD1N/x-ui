package singbridge

import (
	"context"
	stdnet "net"
	"sync"
	"time"

	B "github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport"
)

func CopyPacketConn(ctx context.Context, inboundConn net.Conn, link *transport.Link, destination net.Destination, serverConn net.PacketConn) error {
	conn := &PacketConnWrapper{
		Reader: link.Reader,
		Writer: link.Writer,
		Dest:   destination,
		Conn:   inboundConn,
	}
	return ReturnError(bufio.CopyPacketConn(ctx, conn, bufio.NewPacketConn(serverConn)))
}

type PacketConnWrapper struct {
	buf.Reader
	buf.Writer
	net.Conn
	Dest net.Destination

	readMu sync.Mutex
	mu     sync.Mutex
	cached buf.MultiBuffer
	done   chan struct{}
	closed bool
}

func (w *PacketConnWrapper) ReadPacket(buffer *B.Buffer) (M.Socksaddr, error) {
	return w.readPacket(buffer, 60*time.Second)
}

func (w *PacketConnWrapper) readPacket(buffer *B.Buffer, timeout time.Duration) (M.Socksaddr, error) {
	// Only one caller may read the underlying reader or consume the cached batch.
	// Close uses mu alone, so it can cancel a blocked read without waiting here.
	w.readMu.Lock()
	defer w.readMu.Unlock()

	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return M.Socksaddr{}, stdnet.ErrClosed
	}
	if w.done == nil {
		w.done = make(chan struct{})
	}
	done := w.done
	bb := w.takePacketLocked()
	w.mu.Unlock()

	if bb == nil {
		// The handoff is unbuffered: either this read owns the result, or the
		// worker releases it after cancellation. No packet can be orphaned in a
		// channel if the reader returns after Close or the timeout.
		results := make(chan packetReadResult)
		go readPacketBuffers(w.Reader, results, done)
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case <-done:
			return M.Socksaddr{}, stdnet.ErrClosed
		case <-timer.C:
			// A timed-out reader is interrupted and cannot safely be reused.
			// Closing also prevents another caller starting an overlapping read
			// if an underlying reader cannot be interrupted.
			w.Close()
			return M.Socksaddr{}, buf.ErrReadTimeout
		case result := <-results:
			if result.err != nil {
				buf.ReleaseMulti(result.mb)
				return M.Socksaddr{}, result.err
			}
			w.mu.Lock()
			if w.closed {
				w.mu.Unlock()
				buf.ReleaseMulti(result.mb)
				return M.Socksaddr{}, stdnet.ErrClosed
			}
			w.cached = result.mb
			bb = w.takePacketLocked()
			w.mu.Unlock()
		}
	}

	if bb == nil {
		return M.Socksaddr{}, nil
	}
	// bb has been detached from cached. Close can release the rest of the
	// batch, but this caller alone owns bb until the payload copy completes.
	defer bb.Release()
	buffer.Write(bb.Bytes())
	destination := w.Dest
	if bb.UDP != nil {
		destination = *bb.UDP
	}
	return ToSocksaddr(destination), nil
}

// takePacketLocked transfers one cached packet to the reader. Empty entries do
// not prevent later packets in a batch from being delivered or released.
func (w *PacketConnWrapper) takePacketLocked() *buf.Buffer {
	for len(w.cached) > 0 {
		var packet *buf.Buffer
		w.cached, packet = buf.SplitFirst(w.cached)
		if packet != nil {
			return packet
		}
	}
	w.cached = nil
	return nil
}

type packetReadResult struct {
	mb  buf.MultiBuffer
	err error
}

func readPacketBuffers(reader buf.Reader, results chan<- packetReadResult, done <-chan struct{}) {
	select {
	case <-done:
		return
	default:
	}
	mb, err := reader.ReadMultiBuffer()
	select {
	case results <- packetReadResult{mb: mb, err: err}:
	case <-done:
		buf.ReleaseMulti(mb)
	}
}

func (w *PacketConnWrapper) WritePacket(buffer *B.Buffer, destination M.Socksaddr) error {
	vBuf := buf.New()
	vBuf.Write(buffer.Bytes())
	endpoint := ToDestination(destination, net.Network_UDP)
	vBuf.UDP = &endpoint
	return w.Writer.WriteMultiBuffer(buf.MultiBuffer{vBuf})
}

func (w *PacketConnWrapper) Close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	if w.done != nil {
		close(w.done)
	}
	cached := w.cached
	w.cached = nil
	w.mu.Unlock()

	buf.ReleaseMulti(cached)
	// The wrapper owns the read cancellation, not the caller's Writer or Conn.
	// Interrupt also falls back to Close for readers that only implement that.
	common.Interrupt(w.Reader)
	return nil
}
