package icmpecho

import (
	"bytes"
	"context"
	goerrors "errors"
	"fmt"
	"io"
	stdnet "net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
)

const wait = 5 * time.Second

// fakeConn is an echo socket like a kernel datagram ICMP socket: it puts its
// own identifier on every request, and (when answering) the target answers
// each request with the same identifier, sequence and data.
type fakeConn struct {
	v6        bool
	id        uint16
	answer    func(dst netip.Addr) (netip.Addr, bool) // who answers a request to dst; nil: dst itself
	replies   chan fakeReply
	closed    chan struct{}
	closeOnce sync.Once

	mu   sync.Mutex
	sent []sentEcho
}

type fakeReply struct {
	src netip.Addr
	msg []byte
}

type sentEcho struct {
	dst netip.Addr
	e   Echo
}

func newFakeConn(v6 bool, id uint16) *fakeConn {
	return &fakeConn{v6: v6, id: id, replies: make(chan fakeReply, 1024), closed: make(chan struct{})}
}

func (c *fakeConn) WriteEcho(msg []byte, dst netip.Addr) error {
	select {
	case <-c.closed:
		return stdnet.ErrClosed
	default:
	}
	e, ok := ParseRequest(msg)
	if !ok || e.V6 != c.v6 || dst.Is6() != c.v6 {
		return fmt.Errorf("bad echo request % x to %v", msg, dst)
	}
	e.Data = bytes.Clone(e.Data)
	c.mu.Lock()
	c.sent = append(c.sent, sentEcho{dst, e})
	c.mu.Unlock()
	src, ok := dst, true
	if c.answer != nil {
		src, ok = c.answer(dst)
	}
	if ok {
		c.replies <- fakeReply{src, Echo{V6: c.v6, Reply: true, ID: c.id, Seq: e.Seq, Data: e.Data}.Marshal()}
	}
	return nil
}

func (c *fakeConn) ReadEcho(b []byte) (int, netip.Addr, error) {
	select {
	case r := <-c.replies:
		return copy(b, r.msg), r.src, nil
	case <-c.closed:
		return 0, netip.Addr{}, stdnet.ErrClosed
	}
}

func (c *fakeConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *fakeConn) sentEchoes() []sentEcho {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]sentEcho(nil), c.sent...)
}

func (c *fakeConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

// delivered is one reply a flow handed back.
type delivered struct {
	from xnet.Address
	e    Echo
}

type harness struct {
	t      *testing.T
	flow   *Flow
	conns  [2]*fakeConn
	opens  atomic.Int32
	out    chan delivered
	failV6 bool
}

func newHarness(t *testing.T, mod func(*Options, *harness)) *harness {
	h := &harness{t: t, out: make(chan delivered, 1024)}
	h.conns[0], h.conns[1] = newFakeConn(false, 0x4242), newFakeConn(true, 0x6666)
	opts := Options{
		Open: func(v6 bool) (Conn, error) {
			h.opens.Add(1)
			if v6 && h.failV6 {
				return nil, goerrors.New("no IPv6 here")
			}
			return h.conns[family(v6)], nil
		},
		Deliver: func(from xnet.Address, msg []byte) {
			e, ok := ParseReply(msg)
			if !ok {
				t.Errorf("delivered a message that is not an echo reply: % x", msg)
				return
			}
			e.Data = bytes.Clone(e.Data)
			if !e.V6 && Checksum(msg, 0) != 0 {
				t.Errorf("delivered an ICMPv4 reply with a bad checksum: % x", msg)
			}
			h.out <- delivered{from, e}
		},
	}
	if mod != nil {
		mod(&opts, h)
	}
	h.flow = NewFlow(context.Background(), opts)
	t.Cleanup(func() { h.flow.Close() })
	return h
}

func (h *harness) send(addr string, e Echo) {
	h.flow.Send(xnet.ParseAddress(addr), e.Marshal())
}

func (h *harness) expect(from string, e Echo) {
	h.t.Helper()
	select {
	case d := <-h.out:
		want := Echo{V6: e.V6, Reply: true, ID: e.ID, Seq: e.Seq, Data: e.Data}
		if d.from.String() != xnet.ParseAddress(from).String() || d.e.V6 != want.V6 || d.e.ID != want.ID ||
			d.e.Seq != want.Seq || !bytes.Equal(d.e.Data, want.Data) {
			h.t.Fatalf("reply %+v from %v, want %+v from %v", d.e, d.from, want, from)
		}
	case <-time.After(wait):
		h.t.Fatalf("no reply for %+v from %s", e, from)
	}
}

func (h *harness) expectNothing(d time.Duration) {
	h.t.Helper()
	select {
	case r := <-h.out:
		h.t.Fatalf("unexpected reply %+v from %v", r.e, r.from)
	case <-time.After(d):
	}
}

func (h *harness) inflight() int {
	h.flow.mu.Lock()
	defer h.flow.mu.Unlock()
	return h.flow.inflight
}

func TestFlowEcho(t *testing.T) {
	h := newHarness(t, nil)
	e4 := Echo{ID: 0x1234, Seq: 1, Data: []byte("hello, ping")}
	h.send("192.0.2.1", e4)
	h.expect("192.0.2.1", e4)

	e6 := Echo{V6: true, ID: 0x1234, Seq: 1, Data: []byte("hello, ping6")}
	h.send("2001:db8::1", e6)
	h.expect("2001:db8::1", e6)

	// The kernel's identifier went on the wire, never the request's; the
	// flow numbered the echoes itself.
	if s := h.conns[0].sentEchoes(); len(s) != 1 || s[0].dst != netip.MustParseAddr("192.0.2.1") || !bytes.Equal(s[0].e.Data, e4.Data) {
		t.Fatalf("IPv4 socket sent %+v", s)
	}
	if s := h.conns[1].sentEchoes(); len(s) != 1 || s[0].dst != netip.MustParseAddr("2001:db8::1") {
		t.Fatalf("IPv6 socket sent %+v", s)
	}
	if n := h.opens.Load(); n != 2 {
		t.Fatalf("opened %d sockets, want one per family", n)
	}
	if n := h.inflight(); n != 0 {
		t.Fatalf("%d echoes in flight after their replies", n)
	}
}

// Two pings with the same sequence (two ping processes) to the same host
// share the flow's socket and still get their own replies.
func TestFlowSameSequenceDifferentIdentifiers(t *testing.T) {
	h := newHarness(t, nil)
	a := Echo{ID: 100, Seq: 1, Data: []byte("first")}
	b := Echo{ID: 200, Seq: 1, Data: []byte("second")}
	h.send("192.0.2.1", a)
	h.send("192.0.2.1", b)
	got := map[uint16]Echo{}
	for range 2 {
		select {
		case d := <-h.out:
			got[d.e.ID] = d.e
		case <-time.After(wait):
			t.Fatal("missing reply")
		}
	}
	if got[100].Seq != 1 || string(got[100].Data) != "first" || got[200].Seq != 1 || string(got[200].Data) != "second" {
		t.Fatalf("replies %+v", got)
	}
	s := h.conns[0].sentEchoes()
	if len(s) != 2 || s[0].e.Seq == s[1].e.Seq {
		t.Fatalf("both went out with the same sequence: %+v", s)
	}
}

func TestFlowDrops(t *testing.T) {
	h := newHarness(t, nil)
	h.flow.Send(xnet.ParseAddress("192.0.2.1"), Echo{V6: true, ID: 1}.Marshal())    // ICMPv6 to an IPv4 address
	h.flow.Send(xnet.ParseAddress("2001:db8::1"), Echo{ID: 1}.Marshal())            // ICMPv4 to an IPv6 address
	h.flow.Send(xnet.ParseAddress("192.0.2.1"), Echo{Reply: true, ID: 1}.Marshal()) // a reply
	h.flow.Send(xnet.ParseAddress("192.0.2.1"), []byte{8, 0, 0})                    // short
	h.flow.Send(xnet.ParseAddress("192.0.2.1"), []byte("GET / HTTP/1.1\r\n\r\n"))   // not ICMP
	h.flow.Send(nil, Echo{ID: 1}.Marshal())
	h.flow.Send(xnet.DomainAddress("example.com"), Echo{ID: 1}.Marshal()) // no resolver
	h.expectNothing(200 * time.Millisecond)
	if s := h.conns[0].sentEchoes(); len(s) != 0 {
		t.Fatalf("sent %+v", s)
	}
	if n := h.inflight(); n != 0 {
		t.Fatalf("%d echoes counted in flight", n)
	}
}

// A reply from another address, a duplicate and one nobody asked for are
// not delivered.
func TestFlowIgnoresStrayReplies(t *testing.T) {
	h := newHarness(t, func(o *Options, h *harness) {
		h.conns[0].answer = func(dst netip.Addr) (netip.Addr, bool) {
			return netip.MustParseAddr("198.51.100.9"), true // someone else answers
		}
	})
	h.send("192.0.2.1", Echo{ID: 1, Seq: 1})
	h.expectNothing(200 * time.Millisecond)

	h.conns[0].answer = nil
	e := Echo{ID: 1, Seq: 2, Data: []byte("x")}
	h.send("192.0.2.1", e)
	h.expect("192.0.2.1", e)
	s := h.conns[0].sentEchoes()
	last := s[len(s)-1]
	dup := Echo{Reply: true, ID: h.conns[0].id, Seq: last.e.Seq, Data: last.e.Data}.Marshal()
	h.conns[0].replies <- fakeReply{last.dst, dup}
	h.conns[0].replies <- fakeReply{last.dst, Echo{Reply: true, ID: h.conns[0].id, Seq: last.e.Seq + 100}.Marshal()}
	h.conns[0].replies <- fakeReply{last.dst, Echo{ID: h.conns[0].id, Seq: last.e.Seq}.Marshal()} // a request
	h.expectNothing(200 * time.Millisecond)
}

func TestFlowTimeout(t *testing.T) {
	h := newHarness(t, func(o *Options, h *harness) {
		o.Timeout = 50 * time.Millisecond
		h.conns[0].answer = func(netip.Addr) (netip.Addr, bool) { return netip.Addr{}, false }
	})
	h.send("192.0.2.1", Echo{ID: 1, Seq: 1})
	deadline := time.Now().Add(wait)
	for h.inflight() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the echo never expired")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// A reply after the timeout is not delivered.
	s := h.conns[0].sentEchoes()
	h.conns[0].replies <- fakeReply{s[0].dst, Echo{Reply: true, ID: h.conns[0].id, Seq: s[0].e.Seq}.Marshal()}
	h.expectNothing(200 * time.Millisecond)
}

func TestFlowOutstandingLimit(t *testing.T) {
	h := newHarness(t, func(o *Options, h *harness) {
		h.conns[0].answer = func(netip.Addr) (netip.Addr, bool) { return netip.Addr{}, false }
		var now time.Time
		var mu sync.Mutex
		o.Now = func() time.Time { // a second per call: the rate never limits
			mu.Lock()
			defer mu.Unlock()
			now = now.Add(time.Second)
			return now
		}
	})
	for i := range MaxOutstanding + 10 {
		h.send("192.0.2.1", Echo{ID: 1, Seq: uint16(i)})
	}
	if n := len(h.conns[0].sentEchoes()); n != MaxOutstanding {
		t.Fatalf("sent %d echoes, want %d", n, MaxOutstanding)
	}
	// Once one is answered there is room for one more.
	s := h.conns[0].sentEchoes()
	h.conns[0].replies <- fakeReply{s[0].dst, Echo{Reply: true, ID: h.conns[0].id, Seq: s[0].e.Seq}.Marshal()}
	h.expect("192.0.2.1", Echo{ID: 1, Seq: 0})
	h.send("192.0.2.1", Echo{ID: 1, Seq: 999})
	if n := len(h.conns[0].sentEchoes()); n != MaxOutstanding+1 {
		t.Fatalf("sent %d echoes after one reply, want %d", n, MaxOutstanding+1)
	}
}

func TestFlowRateLimit(t *testing.T) {
	var mu sync.Mutex
	now := time.Unix(1000, 0)
	h := newHarness(t, func(o *Options, h *harness) {
		o.Now = func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			return now
		}
	})
	advance := func(d time.Duration) {
		mu.Lock()
		now = now.Add(d)
		mu.Unlock()
	}
	drain := func(n int) {
		for range n {
			select {
			case <-h.out:
			case <-time.After(wait):
				t.Fatal("missing reply")
			}
		}
	}
	// A burst: MaxRate go out at once; the rest of the second's requests are
	// dropped (each reply frees its slot, so only the rate limits here).
	for i := range MaxRate + 50 {
		h.send("192.0.2.1", Echo{ID: 1, Seq: uint16(i)})
		if i%10 == 9 {
			drain(min(10, max(0, MaxRate-(i-9))))
		}
	}
	if n := len(h.conns[0].sentEchoes()); n != MaxRate {
		t.Fatalf("a burst sent %d echoes, want %d", n, MaxRate)
	}
	h.expectNothing(50 * time.Millisecond)
	// 100 ms later there are 10 more.
	advance(100 * time.Millisecond)
	for i := range 20 {
		h.send("192.0.2.1", Echo{ID: 2, Seq: uint16(i)})
	}
	drain(10)
	if n := len(h.conns[0].sentEchoes()); n != MaxRate+10 {
		t.Fatalf("sent %d echoes, want %d", n, MaxRate+10)
	}
}

func TestFlowNames(t *testing.T) {
	var lookups atomic.Int32
	h := newHarness(t, func(o *Options, h *harness) {
		o.Resolve = func(ctx context.Context, name string, v6 bool) (netip.Addr, error) {
			lookups.Add(1)
			switch {
			case name == "ping.test" && !v6:
				return netip.MustParseAddr("192.0.2.7"), nil
			case name == "ping.test" && v6:
				return netip.MustParseAddr("2001:db8::7"), nil
			case name == "wrong.test":
				return netip.MustParseAddr("2001:db8::8"), nil // the wrong family
			}
			return netip.Addr{}, goerrors.New("no such host")
		}
	})
	e := Echo{ID: 9, Seq: 1, Data: []byte("by name")}
	h.send("ping.test", e)
	h.expect("ping.test", e) // labelled with the name it was sent to
	e.Seq = 2
	h.send("ping.test", e)
	h.expect("ping.test", e)
	if n := lookups.Load(); n != 1 {
		t.Fatalf("%d lookups, want the second echo to use the first's answer", n)
	}
	e6 := Echo{V6: true, ID: 9, Seq: 3}
	h.send("ping.test", e6)
	h.expect("ping.test", e6)
	if s := h.conns[1].sentEchoes(); len(s) != 1 || s[0].dst != netip.MustParseAddr("2001:db8::7") {
		t.Fatalf("IPv6 echo went to %+v", s)
	}

	h.send("nxdomain.test", Echo{ID: 9, Seq: 4})
	h.send("wrong.test", Echo{ID: 9, Seq: 5})
	h.expectNothing(200 * time.Millisecond)
	if n := h.inflight(); n != 0 {
		t.Fatalf("%d echoes in flight after failed lookups", n)
	}
}

func TestFlowRedirect(t *testing.T) {
	h := newHarness(t, func(o *Options, h *harness) {
		o.Redirect = xnet.ParseAddress("192.0.2.99")
	})
	e := Echo{ID: 3, Seq: 3}
	h.send("198.51.100.1", e)
	h.expect("198.51.100.1", e)
	if s := h.conns[0].sentEchoes(); len(s) != 1 || s[0].dst != netip.MustParseAddr("192.0.2.99") {
		t.Fatalf("sent %+v", s)
	}
	h.send("2001:db8::1", Echo{V6: true}) // the redirect has no IPv6
	h.expectNothing(100 * time.Millisecond)
}

func TestFlowOpenFailure(t *testing.T) {
	h := newHarness(t, func(o *Options, h *harness) { h.failV6 = true })
	h.send("2001:db8::1", Echo{V6: true, ID: 1})
	h.send("2001:db8::1", Echo{V6: true, ID: 2})
	h.expectNothing(100 * time.Millisecond)
	if n := h.opens.Load(); n != 1 {
		t.Fatalf("Open called %d times, want once within the retry hold-off", n)
	}
	if n := h.inflight(); n != 0 {
		t.Fatalf("%d echoes in flight", n)
	}
	e := Echo{ID: 1, Seq: 1}
	h.send("192.0.2.1", e) // IPv4 is unaffected
	h.expect("192.0.2.1", e)
}

func TestFlowClose(t *testing.T) {
	h := newHarness(t, func(o *Options, h *harness) {
		h.conns[0].answer = func(netip.Addr) (netip.Addr, bool) { return netip.Addr{}, false }
	})
	h.send("192.0.2.1", Echo{ID: 1, Seq: 1})
	h.flow.Close()
	if !h.conns[0].isClosed() {
		t.Fatal("Close left the socket open")
	}
	h.send("192.0.2.1", Echo{ID: 1, Seq: 2})
	if n := len(h.conns[0].sentEchoes()); n != 1 {
		t.Fatalf("sent %d echoes, the closed flow sent more", n)
	}
	h.flow.Close() // twice is fine
}

type collectWriter struct {
	mu sync.Mutex
	mb buf.MultiBuffer
}

func (w *collectWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.mb = append(w.mb, mb...)
	return nil
}

func TestLinkWriter(t *testing.T) {
	h := newHarness(t, nil)
	next := &collectWriter{}
	target := xnet.UDPDestination(xnet.ParseAddress("192.0.2.53"), 53)
	w := &LinkWriter{Flow: h.flow, Target: target, Next: next}

	mk := func(dest *xnet.Destination, payload []byte) *buf.Buffer {
		b := buf.New()
		b.Write(payload)
		b.UDP = dest
		return b
	}
	ping := Echo{ID: 5, Seq: 6, Data: []byte("through the link")}
	pingDest := xnet.UDPDestination(xnet.ParseAddress("192.0.2.1"), 0)
	other := xnet.UDPDestination(xnet.ParseAddress("192.0.2.2"), 123)
	if err := w.WriteMultiBuffer(buf.MultiBuffer{
		mk(nil, []byte("dns query")),
		mk(&pingDest, ping.Marshal()),
		mk(&other, []byte("ntp")),
		mk(&pingDest, []byte("junk to port 0")),
	}); err != nil {
		t.Fatal(err)
	}
	h.expect("192.0.2.1", ping)
	if len(next.mb) != 2 || next.mb[0].String() != "dns query" || next.mb[1].String() != "ntp" {
		t.Fatalf("passed on %v", next.mb)
	}
	buf.ReleaseMulti(next.mb)

	// A link whose own destination is port 0 carries pings without b.UDP; with
	// no Next, everything else is dropped.
	w = &LinkWriter{Flow: h.flow, Target: pingDest}
	ping.Seq = 7
	if err := w.WriteMultiBuffer(buf.MultiBuffer{mk(nil, ping.Marshal()), mk(&other, []byte("dropped"))}); err != nil {
		t.Fatal(err)
	}
	h.expect("192.0.2.1", ping)
}

func TestDeliverer(t *testing.T) {
	out := &collectWriter{}
	d := Deliverer(NewSyncWriter(out))
	small := Echo{Reply: true, ID: 1, Seq: 2, Data: []byte("abc")}.Marshal()
	big := Echo{Reply: true, ID: 1, Seq: 3, Data: make([]byte, 20000)}.Marshal()
	d(xnet.DomainAddress("ping.test"), small)
	d(xnet.ParseAddress("2001:db8::1"), big)
	if len(out.mb) != 2 {
		t.Fatalf("%d buffers", len(out.mb))
	}
	for i, want := range [][]byte{small, big} {
		b := out.mb[i]
		if !bytes.Equal(b.Bytes(), want) || b.UDP == nil || b.UDP.Port != 0 || b.UDP.Network != xnet.Network_UDP {
			t.Fatalf("buffer %d: %d bytes, UDP %v", i, b.Len(), b.UDP)
		}
	}
	if out.mb[0].UDP.Address.String() != "ping.test" {
		t.Fatalf("labelled %v", out.mb[0].UDP)
	}
	buf.ReleaseMulti(out.mb)
}

// FuzzFlowSend: any datagram to port 0 is safe to hand to a flow.
func FuzzFlowSend(f *testing.F) {
	f.Add(Echo{ID: 1, Seq: 2, Data: []byte("x")}.Marshal(), false)
	f.Add(Echo{V6: true, ID: 1, Seq: 2}.Marshal(), true)
	f.Add([]byte{0, 0, 0}, false)
	f.Fuzz(func(t *testing.T, payload []byte, v6 bool) {
		c := newFakeConn(v6, 77)
		flow := NewFlow(context.Background(), Options{
			Open:    func(bool) (Conn, error) { return c, nil },
			Deliver: func(xnet.Address, []byte) {},
		})
		defer flow.Close()
		addr := "192.0.2.1"
		if v6 {
			addr = "2001:db8::1"
		}
		flow.Send(xnet.ParseAddress(addr), payload)
		e, ok := ParseRequest(payload)
		sent := c.sentEchoes()
		if ok && e.V6 == v6 {
			if len(sent) != 1 || !bytes.Equal(sent[0].e.Data, e.Data) {
				t.Fatalf("a valid request went out as %+v", sent)
			}
		} else if len(sent) != 0 {
			t.Fatalf("an invalid request went out: %+v", sent)
		}
	})
}

// A family's socket is closed once no echo has been in flight on it for the
// echo timeout, and opened again for the next echo: an idle flow -- a link
// that outlives its pings by minutes -- holds no socket, reader or buffer.
func TestFlowIdleClose(t *testing.T) {
	const timeout = 150 * time.Millisecond
	var mu sync.Mutex
	var conns []*fakeConn
	h := newHarness(t, func(o *Options, h *harness) {
		o.Timeout = timeout
		o.Open = func(v6 bool) (Conn, error) {
			h.opens.Add(1)
			c := newFakeConn(v6, 0x4242)
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			return c, nil
		}
	})
	opened := func() []*fakeConn {
		mu.Lock()
		defer mu.Unlock()
		return append([]*fakeConn(nil), conns...)
	}

	// Pings that keep coming keep the socket.
	for seq := range uint16(8) {
		h.send("192.0.2.1", Echo{ID: 1, Seq: seq})
		h.expect("192.0.2.1", Echo{ID: 1, Seq: seq})
		time.Sleep(timeout / 3)
	}
	if n := h.opens.Load(); n != 1 {
		t.Fatalf("opened %d sockets for a steady run of pings, want 1", n)
	}

	// An echo in flight keeps it too, up to its own timeout.
	opened()[0].answer = func(netip.Addr) (netip.Addr, bool) { return netip.Addr{}, false }
	h.send("192.0.2.1", Echo{ID: 1, Seq: 100})
	time.Sleep(timeout * 3 / 4)
	if opened()[0].isClosed() {
		t.Fatal("the socket was closed with an echo in flight")
	}

	// Idle for the timeout after that: closed.
	deadline := time.Now().Add(wait)
	for !opened()[0].isClosed() {
		if time.Now().After(deadline) {
			t.Fatal("the idle socket was never closed")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// The next echo opens a new one.
	h.send("192.0.2.1", Echo{ID: 1, Seq: 200})
	h.expect("192.0.2.1", Echo{ID: 1, Seq: 200})
	if n := h.opens.Load(); n != 2 {
		t.Fatalf("%d sockets opened, want 2", n)
	}
	if opened()[1].isClosed() {
		t.Fatal("the new socket is closed")
	}
}

// truncatingConn hands over a reply cut to the reader's buffer, as a
// datagram socket does, and says so only by filling the buffer.
type truncatingConn struct{ *fakeConn }

func (c truncatingConn) ReadEcho(b []byte) (int, netip.Addr, error) {
	select {
	case r := <-c.replies:
		return copy(b, r.msg), r.src, nil
	case <-c.closed:
		return 0, netip.Addr{}, stdnet.ErrClosed
	}
}

// The reader's buffer is a pooled one for ordinary pings and grows for large
// ones; a reply is never delivered cut short.
func TestFlowReadBuffer(t *testing.T) {
	h := newHarness(t, func(o *Options, h *harness) {
		o.Open = func(v6 bool) (Conn, error) { return truncatingConn{h.conns[family(v6)]}, nil }
	})
	big := bytes.Repeat([]byte("0123456789abcdef"), 2000) // 32000 bytes of data

	// The first echo of the socket is large: the reader starts large.
	h.send("192.0.2.1", Echo{ID: 1, Seq: 1, Data: big})
	h.expect("192.0.2.1", Echo{ID: 1, Seq: 1, Data: big})

	h6 := newHarness(t, func(o *Options, h *harness) {
		o.Open = func(v6 bool) (Conn, error) { return truncatingConn{h.conns[family(v6)]}, nil }
	})
	// A small echo first: the reader waits with a pooled buffer, so the
	// reply to the large echo that follows may be cut -- and is then dropped,
	// not delivered short. The next large one has room.
	h6.send("2001:db8::1", Echo{V6: true, ID: 2, Seq: 1, Data: []byte("small")})
	h6.expect("2001:db8::1", Echo{V6: true, ID: 2, Seq: 1, Data: []byte("small")})
	h6.send("2001:db8::1", Echo{V6: true, ID: 2, Seq: 2, Data: big})
	select {
	case d := <-h6.out:
		if !bytes.Equal(d.e.Data, big) {
			t.Fatalf("delivered a reply with %d bytes of data, want %d", len(d.e.Data), len(big))
		}
	case <-time.After(300 * time.Millisecond):
	}
	h6.send("2001:db8::1", Echo{V6: true, ID: 2, Seq: 3, Data: big})
	h6.expect("2001:db8::1", Echo{V6: true, ID: 2, Seq: 3, Data: big})
}

// Without a Flow (the pings are executed further on), a ping to the link's
// own destination goes on as a datagram; a ping to another address cannot,
// and is dropped; everything else goes on as before.
func TestLinkWriterWithoutFlow(t *testing.T) {
	mk := func(dest *xnet.Destination, payload string) *buf.Buffer {
		b := buf.New()
		b.WriteString(payload)
		b.UDP = dest
		return b
	}
	own := xnet.UDPDestination(xnet.ParseAddress("192.0.2.1"), 0)
	other := xnet.UDPDestination(xnet.ParseAddress("192.0.2.2"), 0)
	udp := xnet.UDPDestination(xnet.ParseAddress("192.0.2.3"), 53)

	next := &collectWriter{}
	w := &LinkWriter{Target: own, Next: next}
	if err := w.WriteMultiBuffer(buf.MultiBuffer{
		mk(nil, "ping 1"), mk(&own, "ping 2"), mk(&other, "ping elsewhere"), mk(&udp, "dns"),
	}); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, b := range next.mb {
		got = append(got, b.String())
	}
	if fmt.Sprint(got) != "[ping 1 ping 2 dns]" {
		t.Fatalf("passed on %q", got)
	}
	buf.ReleaseMulti(next.mb)

	// A link to a real destination: its pings cannot travel on its socket.
	next = &collectWriter{}
	w = &LinkWriter{Target: udp, Next: next}
	if err := w.WriteMultiBuffer(buf.MultiBuffer{mk(&own, "ping"), mk(nil, "dns")}); err != nil {
		t.Fatal(err)
	}
	if len(next.mb) != 1 || next.mb[0].String() != "dns" {
		t.Fatalf("passed on %v", next.mb)
	}
	buf.ReleaseMulti(next.mb)
}

type fakeSocket struct {
	collectWriter
	replies chan buf.MultiBuffer
	closed  atomic.Bool
}

func (s *fakeSocket) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, ok := <-s.replies
	if !ok {
		return nil, io.EOF
	}
	return mb, nil
}

func (s *fakeSocket) Close() error {
	s.closed.Store(true)
	return nil
}

// LazyNext opens its socket for the first datagram that is not a ping and
// sends every later one through it; replies without a source are labelled
// with the first datagram's destination, never with a ping's port 0.
func TestLazyNext(t *testing.T) {
	var opens []xnet.Destination
	sock := &fakeSocket{replies: make(chan buf.MultiBuffer, 4)}
	l := NewLazyNext(func(first xnet.Destination) (buf.Writer, buf.Reader, io.Closer, error) {
		opens = append(opens, first)
		return sock, sock, sock, nil
	})
	select {
	case <-l.Ready():
		t.Fatal("ready before any datagram")
	default:
	}
	dns := xnet.UDPDestination(xnet.ParseAddress("192.0.2.53"), 53)
	ntp := xnet.UDPDestination(xnet.ParseAddress("192.0.2.123"), 123)
	for _, d := range []*xnet.Destination{&dns, &ntp} {
		b := buf.New()
		b.WriteString(d.String())
		b.UDP = d
		if err := l.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
			t.Fatal(err)
		}
	}
	if len(opens) != 1 || opens[0] != dns {
		t.Fatalf("opened for %v, want once for %v", opens, dns)
	}
	if len(sock.mb) != 2 {
		t.Fatalf("the socket got %d datagrams", len(sock.mb))
	}
	buf.ReleaseMulti(sock.mb)
	<-l.Ready()

	labelled, unlabelled := buf.New(), buf.New()
	labelled.UDP = &ntp
	sock.replies <- buf.MultiBuffer{labelled, unlabelled}
	mb, err := l.Reader().ReadMultiBuffer()
	if err != nil || len(mb) != 2 {
		t.Fatal(mb, err)
	}
	if *mb[0].UDP != ntp || *mb[1].UDP != dns {
		t.Fatalf("replies labelled %v and %v", mb[0].UDP, mb[1].UDP)
	}
	buf.ReleaseMulti(mb)
	l.Close()
	if !sock.closed.Load() {
		t.Fatal("Close left the socket open")
	}

	// Closed before the first datagram: nothing stays open.
	sock2 := &fakeSocket{}
	l2 := NewLazyNext(func(xnet.Destination) (buf.Writer, buf.Reader, io.Closer, error) { return sock2, sock2, sock2, nil })
	l2.Close()
	b := buf.New()
	b.UDP = &dns
	if err := l2.WriteMultiBuffer(buf.MultiBuffer{b}); err == nil || !sock2.closed.Load() {
		t.Fatalf("a socket opened after Close: %v, closed %v", err, sock2.closed.Load())
	}

	// A socket that cannot be opened fails the write.
	l3 := NewLazyNext(func(xnet.Destination) (buf.Writer, buf.Reader, io.Closer, error) {
		return nil, nil, nil, goerrors.New("no route")
	})
	b = buf.New()
	b.UDP = &dns
	if err := l3.WriteMultiBuffer(buf.MultiBuffer{b}); err == nil {
		t.Fatal("no error")
	}
}
