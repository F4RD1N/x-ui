package icmpecho

import (
	"context"
	goerrors "errors"
	"io"
	"math/rand/v2"
	stdnet "net"
	"net/netip"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

// Conn is one echo socket of one address family, as an executor opens it: a
// kernel ICMP socket, or an ICMP endpoint of a userspace netstack.
type Conn interface {
	// WriteEcho sends the echo request msg (an Echo message) to dst. The
	// socket may put its own identifier into it, as a datagram ICMP socket
	// does.
	WriteEcho(msg []byte, dst netip.Addr) error
	// ReadEcho reads into b the next echo reply addressed to this socket
	// (its identifier) and returns its size and its source. It returns
	// net.ErrClosed (or io.EOF) once the socket is closed.
	ReadEcho(b []byte) (n int, src netip.Addr, err error)
	Close() error
}

// Options configure a Flow.
type Options struct {
	// Open opens the echo socket of one family (v6: ICMPv6). It is called on
	// the first echo of that family; after a failure it is not called again
	// for openRetry, and the echoes of that family are dropped meanwhile.
	Open func(v6 bool) (Conn, error)
	// Resolve resolves a name to one address of the given family. nil means
	// echoes to names are dropped.
	Resolve func(ctx context.Context, domain string, v6 bool) (netip.Addr, error)
	// Redirect, when set, is where every echo goes instead of the address it
	// names (freedom's redirect). The reply still comes from the named one.
	Redirect net.Address
	// Deliver hands a reply -- an echo reply message to put on the link as
	// one datagram from from:0 -- to the link. It may be called from several
	// goroutines at once.
	Deliver func(from net.Address, msg []byte)
	// Timeout is how long an echo waits for its reply; 0 means EchoTimeout.
	Timeout time.Duration
	// Now is the rate limit's clock; nil means time.Now.
	Now func() time.Time
}

const (
	// openRetry is how long a family whose socket could not be opened stays
	// unavailable before Open is tried again.
	openRetry = 5 * time.Second
	// nameTTL is how long a flow keeps using the address a name resolved to.
	nameTTL = time.Minute
	// maxNames bounds the names one flow remembers.
	maxNames = 64
	// readSlack is what a socket's read buffer holds beyond the largest echo
	// request the flow sent (a reply is as long as its request): room for
	// the IP header a raw IPv4 socket reads into the buffer, at most 60
	// bytes, before Go strips it. The sockets hand over the ICMP message.
	readSlack = 64
)

// Flow executes the pings of one UDP link: it checks and rate-limits each
// echo request, resolves names, sends the echo from an echo socket per
// family (one identifier per flow and family; the flow numbers its echoes
// itself), and delivers each echo reply with the identifier and sequence of
// the request it answers. An echo without a reply within the timeout is
// forgotten; nothing is ever made up.
type Flow struct {
	ctx     context.Context
	opts    Options
	timeout time.Duration
	now     func() time.Time

	openMu sync.Mutex // serialises Open

	mu       sync.Mutex
	closed   bool
	conns    [2]Conn      // IPv4, IPv6
	openFail [2]time.Time // when Open last failed, per family
	inflight int          // echoes admitted and not yet answered, expired or dropped
	pending  map[wireKey]*pending
	npending [2]int    // pending, per family
	idleGen  [2]uint64 // bumped whenever a family's idle close is armed or called off
	maxLen   [2]int    // the longest echo request admitted, per family
	nextSeq  [2]uint16
	tokens   float64
	refilled time.Time
	names    map[nameKey]resolved
}

// wireKey names an echo on the wire: the flow's sockets carry their own
// identifier, so the family and the sequence the flow gave it are enough.
type wireKey struct {
	v6  bool
	seq uint16
}

// pending is an echo in flight.
type pending struct {
	id, seq uint16      // the request's own
	dst     netip.Addr  // where it went: the reply must come from there
	from    net.Address // the address pinged: the reply comes from it
	timer   *time.Timer
}

type nameKey struct {
	name string
	v6   bool
}

type resolved struct {
	addr  netip.Addr
	until time.Time
}

// NewFlow returns a flow; it opens no socket before the first echo. ctx is
// for logs and name resolution. Close it when the link ends.
func NewFlow(ctx context.Context, opts Options) *Flow {
	f := &Flow{
		ctx:     ctx,
		opts:    opts,
		timeout: opts.Timeout,
		now:     opts.Now,
		pending: map[wireKey]*pending{},
		names:   map[nameKey]resolved{},
		tokens:  MaxRate,
	}
	if f.timeout <= 0 {
		f.timeout = EchoTimeout
	}
	if f.now == nil {
		f.now = time.Now
	}
	f.nextSeq = [2]uint16{uint16(rand.Uint32()), uint16(rand.Uint32())}
	return f
}

// Send takes one marker datagram: payload addressed to addr, port 0. A valid
// echo request is pinged for real; anything else is dropped. It does not
// wait for the reply (and resolves a name in the background).
func (f *Flow) Send(addr net.Address, payload []byte) {
	e, ok := ParseRequest(payload)
	if !ok {
		errors.LogDebug(f.ctx, "icmp echo: dropping a datagram to port 0 that is not an echo request (", len(payload), " bytes)")
		return
	}
	if !FamilyMatches(addr, e.V6) {
		errors.LogDebug(f.ctx, "icmp echo: dropping an echo request of the wrong family for ", addr)
		return
	}
	target := addr
	if f.opts.Redirect != nil {
		target = f.opts.Redirect
		if !FamilyMatches(target, e.V6) {
			return
		}
	}
	if !f.admit() {
		errors.LogDebug(f.ctx, "icmp echo: dropping an echo request to ", addr, ": too many in flight or too fast")
		return
	}
	r := request{v6: e.V6, id: e.ID, seq: e.Seq, data: append([]byte(nil), e.Data...), from: addr}
	if target.Family().IsIP() {
		dst, ok := netip.AddrFromSlice(target.IP())
		if !ok {
			f.release()
			return
		}
		f.transmit(r, dst.Unmap())
		return
	}
	name := target.Domain()
	if dst, ok := f.cached(name, e.V6); ok {
		f.transmit(r, dst)
		return
	}
	if f.opts.Resolve == nil {
		f.release()
		return
	}
	go func() {
		dst, err := f.opts.Resolve(f.ctx, name, r.v6)
		dst = dst.Unmap()
		if err != nil || !dst.IsValid() || dst.Is6() != r.v6 {
			if err != nil {
				errors.LogInfoInner(f.ctx, err, "icmp echo: cannot resolve ", name)
			}
			f.release()
			return
		}
		f.remember(name, r.v6, dst)
		f.transmit(r, dst)
	}()
}

// request is an admitted echo request on its way out.
type request struct {
	v6      bool
	id, seq uint16
	data    []byte
	from    net.Address
}

// admit counts an echo in, unless the flow is closed, has MaxOutstanding
// echoes in flight or has used up its rate.
func (f *Flow) admit() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.inflight >= MaxOutstanding {
		return false
	}
	now := f.now()
	if !f.refilled.IsZero() {
		f.tokens = min(MaxRate, f.tokens+now.Sub(f.refilled).Seconds()*MaxRate)
	}
	f.refilled = now
	if f.tokens < 1 {
		return false
	}
	f.tokens--
	f.inflight++
	return true
}

// release counts out an admitted echo that was not sent.
func (f *Flow) release() {
	f.mu.Lock()
	if !f.closed { // Close already counted everything out
		f.inflight--
	}
	f.mu.Unlock()
}

func (f *Flow) cached(name string, v6 bool) (netip.Addr, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.names[nameKey{name, v6}]
	if !ok || f.now().After(r.until) {
		return netip.Addr{}, false
	}
	return r.addr, true
}

func (f *Flow) remember(name string, v6 bool, a netip.Addr) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.names) >= maxNames {
		clear(f.names)
	}
	f.names[nameKey{name, v6}] = resolved{addr: a, until: f.now().Add(nameTTL)}
}

// transmit sends an admitted echo to dst.
func (f *Flow) transmit(r request, dst netip.Addr) {
	fam := family(r.v6)
	f.mu.Lock() // before a socket opens: its reader sizes its buffer by this
	f.maxLen[fam] = max(f.maxLen[fam], HeaderLen+len(r.data))
	f.mu.Unlock()
	var c Conn
	for {
		if c = f.conn(r.v6); c == nil {
			f.release()
			return
		}
		f.mu.Lock()
		if f.closed {
			f.mu.Unlock()
			return
		}
		if f.conns[fam] == c {
			break // and f.mu stays locked
		}
		f.mu.Unlock() // closed for idleness meanwhile: open it again
	}
	seq := f.nextSeq[fam]
	for {
		if _, busy := f.pending[wireKey{r.v6, seq}]; !busy {
			break
		}
		seq++ // at most MaxOutstanding are taken
	}
	f.nextSeq[fam] = seq + 1
	k := wireKey{r.v6, seq}
	p := &pending{id: r.id, seq: r.seq, dst: dst, from: r.from}
	f.pending[k] = p
	f.npending[fam]++
	f.idleGen[fam]++ // busy: no idle close
	p.timer = time.AfterFunc(f.timeout, func() { f.forget(k, p) })
	f.mu.Unlock()

	msg := Echo{V6: r.v6, ID: r.id, Seq: seq, Data: r.data}.Marshal()
	if err := c.WriteEcho(msg, dst); err != nil {
		errors.LogDebugInner(f.ctx, err, "icmp echo: cannot send an echo request to ", dst)
		f.forget(k, p)
	}
}

// forget drops the echo k if it is still p.
func (f *Flow) forget(k wireKey, p *pending) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pending[k] == p {
		f.done(k, p)
	}
}

// done takes the echo k, which is p, out of the flow: answered, expired or
// not sent. With the family's last echo done, the family's socket is closed
// once it has stayed idle for the echo timeout, so that an idle flow -- a
// link that outlives its pings by minutes -- holds no socket, reader or
// buffer; the next echo opens it again. f.mu is held.
func (f *Flow) done(k wireKey, p *pending) {
	delete(f.pending, k)
	p.timer.Stop()
	f.inflight--
	fam := family(k.v6)
	if f.npending[fam]--; f.npending[fam] > 0 || f.conns[fam] == nil {
		return
	}
	f.idleGen[fam]++
	gen, c := f.idleGen[fam], f.conns[fam]
	time.AfterFunc(f.timeout, func() { f.closeIdle(fam, gen, c) })
}

// closeIdle closes the family's socket c if nothing used the family since
// the idle close gen was armed.
func (f *Flow) closeIdle(fam int, gen uint64, c Conn) {
	f.mu.Lock()
	if f.closed || f.idleGen[fam] != gen || f.npending[fam] > 0 || f.conns[fam] != c {
		f.mu.Unlock()
		return
	}
	f.conns[fam] = nil
	f.mu.Unlock()
	_ = c.Close()
}

func family(v6 bool) int {
	if v6 {
		return 1
	}
	return 0
}

// conn returns the family's socket, opening it (and its reader) on first use;
// nil when it cannot be opened or the flow is closed.
func (f *Flow) conn(v6 bool) Conn {
	fam := family(v6)
	f.mu.Lock()
	c, closed, failed := f.conns[fam], f.closed, f.openFail[fam]
	f.mu.Unlock()
	if c != nil || closed {
		return c
	}
	if !failed.IsZero() && f.now().Sub(failed) < openRetry {
		return nil
	}

	f.openMu.Lock()
	defer f.openMu.Unlock()
	f.mu.Lock()
	c, closed = f.conns[fam], f.closed
	f.mu.Unlock()
	if c != nil || closed {
		return c
	}
	if f.opts.Open == nil {
		return nil
	}
	c, err := f.opts.Open(v6)
	f.mu.Lock()
	if err != nil || c == nil {
		f.openFail[fam] = f.now()
		f.mu.Unlock()
		if err != nil {
			errors.LogInfoInner(f.ctx, err, "icmp echo: cannot open an echo socket")
		}
		return nil
	}
	if f.closed {
		f.mu.Unlock()
		_ = c.Close()
		return nil
	}
	f.conns[fam] = c
	f.mu.Unlock()
	go f.read(c, v6)
	return c
}

// readSize is how large a buffer the family's socket needs for the replies
// to the echoes sent so far: a pooled buffer's size for ordinary pings.
func (f *Flow) readSize(fam int) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return max(int(buf.Size), f.maxLen[fam]+readSlack)
}

// read delivers the replies c receives until it is closed.
func (f *Flow) read(c Conn, v6 bool) {
	fam := family(v6)
	pooled := buf.New()
	defer pooled.Release()
	b := pooled.Extend(buf.Size)
	for {
		if size := f.readSize(fam); size > len(b) {
			b = make([]byte, size)
		}
		n, src, err := c.ReadEcho(b)
		if err != nil {
			if goerrors.Is(err, stdnet.ErrClosed) || goerrors.Is(err, io.EOF) || !f.current(fam, c) {
				return
			}
			// An error the socket reports (an ICMP error that came back for
			// an earlier echo): the socket is still good.
			errors.LogDebugInner(f.ctx, err, "icmp echo: reading the echo socket")
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if n+readSlack > len(b) {
			// It (with a raw socket's IPv4 header) filled the buffer, so it
			// may have been cut short: the reply to a request larger than any
			// before, sent while this read was waiting. Never deliver a
			// truncated reply; that echo times out, and the next read has
			// room.
			continue
		}
		r, ok := ParseReply(b[:n])
		if !ok || r.V6 != v6 {
			continue
		}
		k := wireKey{v6, r.Seq}
		f.mu.Lock()
		p := f.pending[k]
		if p == nil || p.dst != src.Unmap() {
			f.mu.Unlock()
			continue // late, duplicate, or not ours
		}
		f.done(k, p)
		f.mu.Unlock()
		if f.opts.Deliver != nil {
			f.opts.Deliver(p.from, Echo{V6: v6, Reply: true, ID: p.id, Seq: p.seq, Data: r.Data}.Marshal())
		}
	}
}

// current reports whether c is still the family's socket of the open flow.
func (f *Flow) current(fam int, c Conn) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return !f.closed && f.conns[fam] == c
}

// Close closes the flow's sockets and forgets its echoes; replies that are
// still on their way are dropped. It does not wait for the readers.
func (f *Flow) Close() error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil
	}
	f.closed = true
	for k, p := range f.pending {
		p.timer.Stop()
		delete(f.pending, k)
	}
	f.inflight = 0
	f.npending = [2]int{}
	conns := f.conns
	f.conns = [2]Conn{}
	f.mu.Unlock()
	for _, c := range conns {
		if c != nil {
			_ = c.Close()
		}
	}
	return nil
}
