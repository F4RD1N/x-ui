package icmpecho

import (
	"io"
	"sync"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

// LinkWriter is the request side of a UDP link at an executor: every
// datagram to port 0 goes to Flow, everything else to Next.
type LinkWriter struct {
	// Flow executes the pings. nil means they are not executed here: the
	// link's socket (Next) carries them on as UDP to the link's own
	// destination, where an outbound further on executes them; a ping to any
	// other address cannot travel that way and is dropped.
	Flow *Flow
	// Target is the link's own destination: where a buffer without b.UDP is
	// addressed.
	Target net.Destination
	// Next takes the datagrams that are not pings; nil drops them.
	Next buf.Writer
}

// WriteMultiBuffer implements buf.Writer.
func (w *LinkWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	var rest buf.MultiBuffer
	for _, b := range mb {
		d := w.Target
		if b.UDP != nil {
			d = *b.UDP
		}
		if d.Port == 0 { // on a UDP link, port 0 is a ping and nothing else
			if w.Flow != nil {
				w.Flow.Send(d.Address, b.Bytes())
				b.Release()
				continue
			}
			if w.Next == nil || !IsMarker(w.Target) || d.Address.String() != w.Target.Address.String() {
				b.Release()
				continue
			}
		} else if w.Next == nil {
			b.Release()
			continue
		}
		rest = append(rest, b)
	}
	if rest.IsEmpty() {
		return nil
	}
	return w.Next.WriteMultiBuffer(rest)
}

// LazyNext is the Next of a LinkWriter on a link that a ping opened (whose
// own destination is port 0) and that therefore has no socket: the socket is
// opened for the link's first datagram that is not a ping, and it takes that
// datagram and every later one that is not a ping. A link that only pings
// never opens one. Its replies are read from Reader once Ready is closed.
type LazyNext struct {
	open  func(first net.Destination) (buf.Writer, buf.Reader, io.Closer, error)
	ready chan struct{}
	w     buf.Writer // the writer's own: only one goroutine writes

	mu     sync.Mutex
	closed bool
	r      buf.Reader
	c      io.Closer
}

// NewLazyNext returns a LazyNext that opens its socket with open, for a
// first datagram to first: w takes the datagrams, r reads what comes back
// and c closes the socket.
func NewLazyNext(open func(first net.Destination) (w buf.Writer, r buf.Reader, c io.Closer, err error)) *LazyNext {
	return &LazyNext{open: open, ready: make(chan struct{})}
}

// WriteMultiBuffer implements buf.Writer. A socket that cannot be opened
// fails the write, and with it the link, as a link that cannot dial fails.
func (l *LazyNext) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if l.w == nil {
		var first *net.Destination
		for _, b := range mb {
			if b.UDP != nil && b.UDP.Port != 0 {
				first = b.UDP
				break
			}
		}
		if first == nil {
			buf.ReleaseMulti(mb)
			return nil
		}
		dest := *first
		w, r, c, err := l.open(dest)
		if err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			c.Close()
			buf.ReleaseMulti(mb)
			return io.ErrClosedPipe
		}
		l.r, l.c = &labelReader{Reader: r, from: dest}, c
		l.mu.Unlock()
		l.w = w
		close(l.ready)
	}
	return l.w.WriteMultiBuffer(mb)
}

// Ready is closed once the socket is open.
func (l *LazyNext) Ready() <-chan struct{} { return l.ready }

// Reader reads the replies to the socket's datagrams; call it once Ready is
// closed. A reply that does not say where it comes from is from the first
// datagram's destination, never from the ping's port 0.
func (l *LazyNext) Reader() buf.Reader {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.r
}

// Close closes the socket, if one was opened, and keeps one from opening.
func (l *LazyNext) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	if l.c != nil {
		return l.c.Close()
	}
	return nil
}

// labelReader labels the datagrams that come without a source with from.
type labelReader struct {
	buf.Reader
	from net.Destination
}

func (r *labelReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBuffer()
	for _, b := range mb {
		if b.UDP == nil {
			d := r.from
			b.UDP = &d
		}
	}
	return mb, err
}

// Deliverer returns an Options.Deliver that writes each reply into w as one
// datagram from from:0. w must take concurrent writes (see SyncWriter).
func Deliverer(w buf.Writer) func(from net.Address, msg []byte) {
	return func(from net.Address, msg []byte) {
		var b *buf.Buffer
		if len(msg) <= buf.Size {
			b = buf.New()
		} else {
			b = buf.NewWithSize(int32(len(msg)))
		}
		b.Write(msg)
		b.UDP = &net.Destination{Network: net.Network_UDP, Address: from, Port: 0}
		_ = w.WriteMultiBuffer(buf.MultiBuffer{b})
	}
}

// SyncWriter serialises the writers of one link: the executor's own reply
// path and a Flow's replies.
type SyncWriter struct {
	mu sync.Mutex
	w  buf.Writer
}

// NewSyncWriter wraps w.
func NewSyncWriter(w buf.Writer) *SyncWriter { return &SyncWriter{w: w} }

// WriteMultiBuffer implements buf.Writer.
func (s *SyncWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.WriteMultiBuffer(mb)
}
