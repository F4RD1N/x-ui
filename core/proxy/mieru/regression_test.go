package mieru

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/xtls/xray-core/transport/internet"
)

// fakeUDP is a small Mieru UDP server: it accepts client data in order and
// acknowledges it (optionally late or lossy), pushes its own data with
// go-back-N retransmission, and answers closeRequest.
type fakeUDP struct {
	t        *testing.T
	ln       net.PacketConn
	w        *wire
	ackDelay time.Duration
	lossy    int             // drop every lossy-th client data segment
	dropOnce map[uint32]bool // drop the first copy of these client segments
	out      [][]byte

	mu        sync.Mutex
	sid       uint32
	got       bytes.Buffer
	expected  uint32
	ooo       map[uint32][]byte
	acked     uint32
	window    uint16         // receive window in the client's last ACK
	acks      map[uint32]int // client ACKs by their unack value
	count     int
	closeSeen chan struct{}
	closeOnce sync.Once
}

func startFakeUDP(t *testing.T, f *fakeUDP) (*Conn, net.PacketConn) {
	ln, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	pc, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { ln.Close(); pc.Close() })
	f.t, f.ln, f.expected, f.acked, f.closeSeen, f.ooo = t, ln, 1, 1, make(chan struct{}), map[uint32][]byte{}
	f.w, _ = newWire(&internet.PacketConnWrapper{PacketConn: ln, Dest: pc.LocalAddr()}, "user", "pass", true, false)
	go f.serve()
	w, _ := newWire(&internet.PacketConnWrapper{PacketConn: pc, Dest: ln.LocalAddr()}, "user", "pass", true, false)
	c, e := Open(w)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.abort(net.ErrClosed) })
	return c, pc
}

func (f *fakeUDP) serve() {
	for {
		s, e := f.w.read()
		if e != nil {
			return
		}
		switch s.kind {
		case openRequest:
			f.mu.Lock()
			f.sid = s.session
			f.mu.Unlock()
			_ = f.w.write(segment{kind: openResponse, session: s.session})
			if len(f.out) > 0 {
				go f.push()
			}
		case dataClient:
			f.mu.Lock()
			f.count++
			if f.lossy > 0 && f.count%f.lossy == 0 || f.dropOnce[s.seq] {
				delete(f.dropOnce, s.seq)
				f.mu.Unlock()
				continue
			}
			// Like mita, keep out-of-order segments and acknowledge
			// cumulatively.
			if s.seq >= f.expected {
				f.ooo[s.seq] = s.payload
			}
			for p, ok := f.ooo[f.expected]; ok; p, ok = f.ooo[f.expected] {
				delete(f.ooo, f.expected)
				f.got.Write(p)
				f.expected++
			}
			ack := segment{kind: ackServer, session: s.session, unack: f.expected}
			f.mu.Unlock()
			if f.ackDelay > 0 {
				go func() { time.Sleep(f.ackDelay); _ = f.w.write(ack) }()
			} else {
				_ = f.w.write(ack)
			}
		case ackClient:
			f.mu.Lock()
			if s.unack > f.acked {
				f.acked = s.unack
			}
			f.window = s.window
			if f.acks == nil {
				f.acks = map[uint32]int{}
			}
			f.acks[s.unack]++
			f.mu.Unlock()
		case closeRequest:
			f.closeOnce.Do(func() { close(f.closeSeen) })
			_ = f.w.write(segment{kind: closeResponse, session: s.session, seq: s.seq})
		}
	}
}

// push sends f.out as data seq 1.., resending everything unacknowledged.
func (f *fakeUDP) push() {
	for {
		f.mu.Lock()
		from, sid, unack := int(f.acked), f.sid, f.expected
		f.mu.Unlock()
		if from > len(f.out) {
			return
		}
		for i := from; i <= len(f.out) && i < from+64; i++ {
			if f.w.write(segment{kind: dataServer, session: sid, seq: uint32(i), unack: unack, payload: f.out[i-1]}) != nil {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (f *fakeUDP) received() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]byte(nil), f.got.Bytes()...)
}

// rawDatagram is a server datagram with an arbitrary metadata timestamp.
func (f *fakeUDP) rawDatagram(s segment, minute int64) []byte {
	n, _ := f.w.nonce()
	m := metadata(s)
	binary.BigEndian.PutUint32(m[2:6], uint32(minute))
	return append(n, f.w.send.Seal(nil, n, m, nil)...)
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func TestUDPBadDatagramsDoNotEndSession(t *testing.T) {
	f := &fakeUDP{}
	c, pc := startFakeUDP(t, f)
	junk, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer junk.Close()
	f.mu.Lock()
	sid := f.sid
	f.mu.Unlock()
	valid := f.rawDatagram(segment{kind: dataServer, session: sid, seq: 1, unack: 1}, time.Now().Unix()/60)
	for _, d := range []struct {
		from net.PacketConn
		b    []byte
	}{
		{junk, randomBytes(100)}, // off-path host
		{junk, valid},            // a valid segment, but not from the server
		{f.ln, randomBytes(100)}, // corrupted
		{f.ln, valid[:30]},       // truncated
		{f.ln, f.rawDatagram(segment{kind: dataServer, session: sid, seq: 1, unack: 1}, time.Now().Unix()/60-10)}, // stale
		{f.ln, f.rawDatagram(segment{kind: openRequest, session: sid}, time.Now().Unix()/60)},                     // unexpected kind
	} {
		if _, e := d.from.WriteTo(d.b, pc.LocalAddr()); e != nil {
			t.Fatal(e)
		}
	}
	time.Sleep(300 * time.Millisecond)
	if c.ended() {
		t.Fatalf("session ended by a bad datagram: %v", c.error())
	}
	_ = f.w.write(segment{kind: dataServer, session: sid, seq: 1, unack: 1, payload: []byte("still-alive")})
	got := make([]byte, 11)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, e := io.ReadFull(c, got); e != nil || string(got) != "still-alive" {
		t.Fatalf("valid data after bad datagrams: %q %v", got, e)
	}
}

// An unread download must not stop acknowledgement processing.
func TestUDPUnreadDownlinkKeepsAcksFlowing(t *testing.T) {
	f := &fakeUDP{out: [][]byte{[]byte("0123456789")}}
	c, _ := startFakeUDP(t, f)
	time.Sleep(200 * time.Millisecond) // the server's data arrives; nobody reads it
	start := time.Now()
	if _, e := c.Write([]byte{1}); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(time.Second)
	for len(f.received()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	c.mu.Lock()
	inflight := len(c.inflight)
	c.mu.Unlock()
	if len(f.received()) != 1 || inflight != 0 || time.Since(start) > time.Second {
		t.Fatalf("uplink not acknowledged while the downlink is unread (inflight %d, %v)", inflight, time.Since(start))
	}
}

// A full receive queue drops segments unacknowledged; the server's
// retransmissions then deliver every byte in order once the reader drains.
func TestUDPFullQueueDropsThenDeliversInOrder(t *testing.T) {
	const n = recvCapacity + 500
	var want []byte
	for i := 0; i < n; i++ {
		want = append(want, bytes.Repeat([]byte{byte(i)}, 1000)...)
	}
	out := make([][]byte, n)
	for i := range out {
		out[i] = want[i*1000 : (i+1)*1000]
	}
	f := &fakeUDP{out: out}
	c, _ := startFakeUDP(t, f)
	time.Sleep(time.Second)
	c.mu.Lock()
	buffered := len(c.queue) + len(c.ooo)
	c.mu.Unlock()
	if buffered > recvCapacity {
		t.Fatalf("receive buffer grew past its bound: %d segments", buffered)
	}
	f.mu.Lock()
	window := f.window
	f.mu.Unlock()
	if window != 0 {
		t.Fatalf("full receive buffer advertised window %d, want 0", window)
	}
	got := make([]byte, len(want))
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, e := io.ReadFull(c, got); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("download corrupted or reordered after queue-full drops")
	}
}

// The UDP uplink keeps a window in flight instead of one segment per RTT.
func TestUDPUploadUsesSendWindow(t *testing.T) {
	f := &fakeUDP{ackDelay: 50 * time.Millisecond}
	c, _ := startFakeUDP(t, f)
	data := randomBytes(512 << 10)
	start := time.Now()
	if _, e := c.Write(data); e != nil {
		t.Fatal(e)
	}
	for !bytes.Equal(f.received(), data) && time.Since(start) < 10*time.Second {
		time.Sleep(5 * time.Millisecond)
	}
	el := time.Since(start)
	if !bytes.Equal(f.received(), data) {
		t.Fatal("upload incomplete")
	}
	t.Logf("512 KiB at 50 ms acknowledgement delay took %v", el)
	if el > 2*time.Second {
		t.Fatalf("upload took %v: still stop-and-wait", el)
	}
}

func TestUDPLossyUploadArrivesInOrder(t *testing.T) {
	f := &fakeUDP{lossy: 10}
	c, _ := startFakeUDP(t, f)
	data := randomBytes(100 << 10)
	if _, e := c.Write(data); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(15 * time.Second)
	for !bytes.Equal(f.received(), data) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !bytes.Equal(f.received(), data) {
		t.Fatalf("lossy upload: server has %d of %d bytes", len(f.received()), len(data))
	}
}

// Without acknowledgements a segment fails the session after udpAttempts
// sends.
func TestUDPUnacknowledgedSegmentFailsSession(t *testing.T) {
	f := &fakeUDP{lossy: 1}
	c, _ := startFakeUDP(t, f)
	if _, e := c.Write([]byte("x")); e != nil {
		t.Fatal(e)
	}
	select {
	case <-c.done:
		if e := c.error(); e == nil || e.Error() != "Mieru session acknowledgement timed out" {
			t.Fatalf("wrong failure: %v", e)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("session did not fail")
	}
}

// Over UDP the server cannot see the socket close, so Close sends
// closeRequest after in-flight data is acknowledged.
func TestUDPCloseTellsServer(t *testing.T) {
	f := &fakeUDP{ackDelay: 100 * time.Millisecond}
	c, _ := startFakeUDP(t, f)
	if _, e := c.Write([]byte("tail")); e != nil {
		t.Fatal(e)
	}
	start := time.Now()
	c.Close()
	select {
	case <-f.closeSeen:
	default:
		t.Fatal("no closeRequest reached the server")
	}
	if string(f.received()) != "tail" {
		t.Fatalf("unacknowledged tail lost on close: %q", f.received())
	}
	if el := time.Since(start); el > time.Second {
		t.Fatalf("Close took %v", el)
	}
}

// The receive key is derived once per time window, not per datagram, and a
// server one window ahead is still accepted.
func TestUDPReceiveKeyCache(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	server, _ := newWire(a, "user", "pass", true, false)
	server.send, _ = chacha20poly1305.NewX(Key("user", "pass", time.Now().Add(120*time.Second)))
	client, _ := newWire(b, "user", "pass", true, false)
	go func() {
		for i := 0; i < 50; i++ {
			_ = server.write(segment{kind: dataServer, session: 1, seq: uint32(i), payload: []byte{byte(i)}})
		}
	}()
	for i := 0; i < 50; i++ {
		s, e := client.read()
		if e != nil || s.seq != uint32(i) || !bytes.Equal(s.payload, []byte{byte(i)}) {
			t.Fatalf("datagram %d: %v", i, e)
		}
	}
	if len(client.keys) > 3 {
		t.Fatalf("%d receive keys derived for one server window", len(client.keys))
	}
}

// sendServer writes raw server segments for the gap and close tests.
func (f *fakeUDP) sendServer(t *testing.T, segs ...segment) {
	f.mu.Lock()
	sid := f.sid
	f.mu.Unlock()
	for _, s := range segs {
		s.session = sid
		if e := f.w.write(s); e != nil {
			t.Fatal(e)
		}
	}
}

func data(seq uint32, p string) segment {
	return segment{kind: dataServer, seq: seq, unack: 1, payload: []byte(p)}
}

// Segments that arrive ahead of a gap are kept, not dropped: once the gap is
// filled everything is delivered in order without being sent again.
func TestUDPReorderedSegmentsAreKept(t *testing.T) {
	f := &fakeUDP{}
	c, _ := startFakeUDP(t, f)
	f.sendServer(t, data(2, "b"), data(4, "d"), data(3, "c"))
	time.Sleep(100 * time.Millisecond)
	c.mu.Lock()
	kept := len(c.ooo)
	c.mu.Unlock()
	if kept != 3 {
		t.Fatalf("%d of 3 segments after the gap kept", kept)
	}
	f.sendServer(t, data(1, "a"))
	got := make([]byte, 4)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, e := io.ReadFull(c, got); e != nil || string(got) != "abcd" {
		t.Fatalf("reordered download: %q %v", got, e)
	}
	deadline := time.Now().Add(time.Second)
	for {
		f.mu.Lock()
		acked := f.acked
		f.mu.Unlock()
		if acked == 5 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("client acknowledged up to %d, want 5", acked)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The server's close waits for the data before it: a close that overtakes
// a lost segment must not cut the download short.
func TestUDPCloseWaitsForMissingData(t *testing.T) {
	f := &fakeUDP{}
	c, _ := startFakeUDP(t, f)
	f.sendServer(t, data(1, "a"), data(3, "c"), segment{kind: closeRequest, seq: 4})
	time.Sleep(100 * time.Millisecond)
	if c.ended() {
		t.Fatal("close acted on while segment 2 was missing")
	}
	f.sendServer(t, data(2, "b"))
	got, e := io.ReadAll(c)
	if e != nil || string(got) != "abc" {
		t.Fatalf("download before a reordered close: %q %v", got, e)
	}
}

// A gap that is never filled ends the read with an error, not a short EOF.
func TestUDPCloseWithLostDataIsAnError(t *testing.T) {
	f := &fakeUDP{}
	c, _ := startFakeUDP(t, f)
	f.sendServer(t, data(1, "a"), data(3, "c"), segment{kind: closeRequest, seq: 4})
	start := time.Now()
	got, e := io.ReadAll(c)
	if e != io.ErrUnexpectedEOF || string(got) != "a" {
		t.Fatalf("lost data before close: %q %v, want \"a\" and io.ErrUnexpectedEOF", got, e)
	}
	if el := time.Since(start); el < closeGapWait/2 || el > closeGapWait+time.Second {
		t.Fatalf("gave up after %v", el)
	}
}

// ACKs advertise the free receive capacity, and reading reopens the window.
func TestUDPAdvertisesReceiveWindow(t *testing.T) {
	f := &fakeUDP{}
	startFakeUDP(t, f)
	var segs []segment
	for i := 1; i <= 8; i++ {
		segs = append(segs, data(uint32(i), "x"))
	}
	f.sendServer(t, segs...)
	time.Sleep(100 * time.Millisecond)
	f.mu.Lock()
	window := f.window
	f.mu.Unlock()
	if window != recvCapacity-8 {
		t.Fatalf("window %d after 8 unread segments, want %d", window, recvCapacity-8)
	}
}

// Three duplicate ACKs resend the missing segment at once, well before its
// retransmission timeout.
func TestUDPFastRetransmit(t *testing.T) {
	f := &fakeUDP{dropOnce: map[uint32]bool{5: true, 15: true}}
	c, _ := startFakeUDP(t, f)
	c.mu.Lock()
	c.srtt, c.rttvar = time.Second, time.Second // timeout far above the test's limit
	c.mu.Unlock()
	data := randomBytes(30 * udpSegment)
	start := time.Now()
	if _, e := c.Write(data); e != nil {
		t.Fatal(e)
	}
	for !bytes.Equal(f.received(), data) && time.Since(start) < 5*time.Second {
		time.Sleep(5 * time.Millisecond)
	}
	if !bytes.Equal(f.received(), data) {
		t.Fatal("lossy upload incomplete")
	}
	if el := time.Since(start); el > 1500*time.Millisecond {
		t.Fatalf("lost segments took %v: resent only on timeout", el)
	}
}

// When a resend fills one gap and reveals the next (a burst loss), the client
// sends the three duplicate ACKs the server needs to resend that one too,
// since no later data may arrive to produce them.
func TestUDPNextGapGetsDuplicateAcks(t *testing.T) {
	f := &fakeUDP{}
	c, _ := startFakeUDP(t, f)
	f.sendServer(t, data(1, "a"), data(3, "c"), data(5, "e"))
	time.Sleep(100 * time.Millisecond)
	f.mu.Lock()
	before := f.acks[4]
	f.mu.Unlock()
	f.sendServer(t, data(2, "b"))
	time.Sleep(100 * time.Millisecond)
	f.mu.Lock()
	after := f.acks[4]
	f.mu.Unlock()
	if before != 0 || after < 3 {
		t.Fatalf("ACKs asking for segment 4: %d before the fill, %d after, want 0 and at least 3", before, after)
	}
	got := make([]byte, 3)
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if _, e := io.ReadFull(c, got); e != nil || string(got) != "abc" {
		t.Fatalf("%q %v", got, e)
	}
}
