package mieru

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func resourceSession(t *testing.T, budget *atomic.Int64, slots int) *inboundSession {
	t.Helper()
	_, cancel := context.WithCancel(context.Background())
	s := &inboundSession{done: make(chan struct{}), incoming: make(chan segment, slots), cancel: cancel, budget: budget}
	t.Cleanup(s.close)
	return s
}

func resourceSegment(size int) segment {
	return segment{kind: dataClient, session: 1, seq: 1, payload: bytes.Repeat([]byte{0x5a}, size)}
}

func TestReviewSessionPendingByteBoundAndWireDequeue(t *testing.T) {
	budget := new(atomic.Int64)
	s := resourceSession(t, budget, 256)
	seg := resourceSegment(32768)
	want := int64(0)
	accepted := 0
	for s.enqueue(seg) {
		accepted++
		want += segmentCost(seg)
		if accepted > 256 {
			t.Fatal("session byte cap did not stop admission")
		}
	}
	if accepted != 7 || s.bytes.Load() != want || budget.Load() != want {
		t.Fatalf("large-frame admission/accounting: accepted=%d session=%d shared=%d want=%d", accepted, s.bytes.Load(), budget.Load(), want)
	}
	// A failed large reservation must leave room for smaller legal frames.
	remaining := serverSessionPendingBytes - int(want)
	small := resourceSegment(remaining - 64)
	if !s.enqueue(small) || s.bytes.Load() != serverSessionPendingBytes || s.enqueue(resourceSegment(0)) {
		t.Fatal("exact byte boundary or failed reservation rollback is incorrect")
	}
	w := &wire{incoming: s.incoming, sessionDone: s.done, dequeue: s.dequeue}
	for i := 0; i < accepted+1; i++ {
		got, err := w.read()
		if err != nil {
			t.Fatal(err)
		}
		expect := seg
		if i == accepted {
			expect = small
		}
		if !bytes.Equal(got.payload, expect.payload) {
			t.Fatal("queue consumption changed the authenticated payload")
		}
		want = serverSessionPendingBytes
		if i < accepted {
			want -= int64(i+1) * segmentCost(seg)
		} else {
			want = 0
		}
		if s.bytes.Load() != want || budget.Load() != want {
			t.Fatalf("wire.read did not release reservation: session=%d shared=%d want=%d", s.bytes.Load(), budget.Load(), want)
		}
	}
	if !s.enqueue(seg) {
		t.Fatal("consumed capacity was not reusable")
	}
	s.close()
	if s.bytes.Load() != 0 || budget.Load() != 0 || len(s.incoming) != 0 || s.enqueue(seg) {
		t.Fatal("close leaked reservations or admitted more frames")
	}
}

func TestReviewChannelFullReleasesByteReservation(t *testing.T) {
	budget := new(atomic.Int64)
	s := resourceSession(t, budget, 1)
	seg := resourceSegment(32768)
	if !s.enqueue(seg) || s.enqueue(seg) {
		t.Fatal("unexpected one-slot queue admission")
	}
	if s.bytes.Load() != segmentCost(seg) || budget.Load() != segmentCost(seg) {
		t.Fatal("channel-full rejection leaked reserved bytes")
	}
	s.close()
	if s.bytes.Load() != 0 || budget.Load() != 0 {
		t.Fatal("close did not release pending frame")
	}
}

func TestReviewSharedUnderlayByteBoundAndSiblingRecovery(t *testing.T) {
	budget := new(atomic.Int64)
	seg := resourceSegment(32768)
	sessions := make([]*inboundSession, 12)
	for i := range sessions {
		sessions[i] = resourceSession(t, budget, 256)
	}
	// One stalled session reaches its own bound but leaves room for siblings.
	for sessions[0].enqueue(seg) {
	}
	if !sessions[1].enqueue(seg) {
		t.Fatal("one slow session consumed healthy sibling's admission capacity")
	}
	for _, s := range sessions[1:] {
		for s.enqueue(seg) {
		}
	}
	var sum int64
	for _, s := range sessions {
		if n := s.bytes.Load(); n > serverSessionPendingBytes || n < 0 {
			t.Fatalf("session reservation out of bounds: %d", n)
		} else {
			sum += n
		}
	}
	if sum != budget.Load() || sum > serverUnderlayPendingBytes || sum+segmentCost(seg) <= serverUnderlayPendingBytes {
		t.Fatalf("shared budget did not bound aggregate memory: sum=%d shared=%d", sum, budget.Load())
	}
	if sessions[11].enqueue(seg) {
		t.Fatal("shared byte cap admitted another large frame")
	}
	freed := sessions[0].bytes.Load()
	sessions[0].close()
	if budget.Load() != sum-freed || !sessions[11].enqueue(seg) {
		t.Fatal("closing a stalled session did not free capacity for a sibling")
	}
	for _, s := range sessions {
		s.close()
	}
	if budget.Load() != 0 {
		t.Fatalf("underlay cleanup retained %d bytes", budget.Load())
	}
}

func TestReviewConcurrentQueueDrainAndClose(t *testing.T) {
	budget := new(atomic.Int64)
	var wg sync.WaitGroup
	start := make(chan struct{})
	sessions := make([]*inboundSession, 8)
	for i := range sessions {
		s := resourceSession(t, budget, 256)
		sessions[i] = s
		seg := resourceSegment(32768)
		for j := 0; j < 2; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				for k := 0; k < 500; k++ {
					s.enqueue(seg)
				}
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for {
				select {
				case frame := <-s.incoming:
					s.dequeue(frame)
				case <-s.done:
					return
				}
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			// Compete with both producers and the wire-reader's dequeue path.
			for k := 0; k < 25; k++ {
				s.enqueue(seg)
			}
			s.close()
		}()
	}
	close(start)
	wg.Wait()
	for _, s := range sessions {
		if s.bytes.Load() != 0 || len(s.incoming) != 0 {
			t.Fatalf("concurrent close leaked or double-released session bytes: %d", s.bytes.Load())
		}
	}
	if budget.Load() != 0 {
		t.Fatalf("concurrent underlay teardown retained %d bytes", budget.Load())
	}
}

type resourceDiscardConn struct{ net.Conn }

func (resourceDiscardConn) Write(p []byte) (int, error) { return len(p), nil }
func (resourceDiscardConn) Close() error                { return nil }

func resourceUDPConn(t *testing.T, server bool) *Conn {
	t.Helper()
	w, err := newWire(resourceDiscardConn{}, "resource-user", "resource-password", true, false)
	if err != nil {
		t.Fatal(err)
	}
	w.server = server
	c := &Conn{wire: w, sid: 1, next: 1, expected: 1, ooo: make(map[uint32][]byte), done: make(chan struct{}), opened: make(chan struct{}), kick: make(chan struct{}, 1), peerWindow: 128, cwnd: 32, ssthresh: 128, ackArmed: true}
	c.cond = sync.NewCond(&c.mu)
	t.Cleanup(func() { c.abort(net.ErrClosed) })
	return c
}

func TestReviewUDPReceiveByteAccountingAndOrderedDrain(t *testing.T) {
	c := resourceUDPConn(t, true)
	push := func(seq uint32, size int, fill byte) {
		t.Helper()
		if c.receiveUDP(segment{kind: dataClient, session: 1, seq: seq, payload: bytes.Repeat([]byte{fill}, size)}) {
			t.Fatal("healthy session ended while admitting bounded data")
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.queued+c.oooBytes > serverUDPReceiveBytes || c.queued < 0 || c.oooBytes < 0 {
			t.Fatalf("receive byte accounting out of bounds: queued=%d out-of-order=%d", c.queued, c.oooBytes)
		}
	}
	push(1, 24<<10, 1)
	push(4, 16<<10, 4)
	push(4, 32<<10, 99) // A retransmission cannot replace/reserve the same OOO frame twice.
	push(7, 32<<10, 7)
	push(9, 32<<10, 9) // Keep enough room for the missing sequence.
	func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.oooBytes != 48<<10 || len(c.ooo) != 2 || c.oooBytes+c.queued > 96<<10 {
			t.Fatalf("out-of-order accounting/reserve failed: queued=%d out-of-order=%d frames=%d", c.queued, c.oooBytes, len(c.ooo))
		}
	}()
	push(2, 32<<10, 2)
	push(3, 24<<10, 3) // Promotes frame4 without allocating its byte budget twice.
	func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.expected != 5 || c.queued != 96<<10 || c.oooBytes != 32<<10 || c.windowLocked() != 0 {
			t.Fatalf("promotion/window mismatch: expected=%d queued=%d out-of-order=%d window=%d", c.expected, c.queued, c.oooBytes, c.windowLocked())
		}
	}()
	push(5, 1000, 5) // The full queue must leave this unacknowledged for retry.
	push(3, 24<<10, 99)
	part := make([]byte, 4096)
	if _, err := io.ReadFull(c, part); err != nil || !bytes.Equal(part, bytes.Repeat([]byte{1}, len(part))) {
		t.Fatal("partial read changed byte order or failed", err)
	}
	push(5, 1000, 5)
	push(6, 3096, 6) // Fills the remaining space and promotes frame7.
	func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.expected != 8 || c.oooBytes != 0 || c.queued != serverUDPReceiveBytes {
			t.Fatalf("partial-read reuse/promotion accounting: expected=%d queued=%d out-of-order=%d", c.expected, c.queued, c.oooBytes)
		}
	}()
	want := bytes.Repeat([]byte{1}, (24<<10)-len(part))
	for _, chunk := range []struct {
		size int
		fill byte
	}{{32 << 10, 2}, {24 << 10, 3}, {16 << 10, 4}, {1000, 5}, {3096, 6}, {32 << 10, 7}} {
		want = append(want, bytes.Repeat([]byte{chunk.fill}, chunk.size)...)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, want) {
		t.Fatal("bounded receiver corrupted ordered stream", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.queued != 0 || c.oooBytes != 0 || int(c.windowLocked()) != c.maxReceiveSegments() {
		t.Fatal("reading all accepted bytes did not restore the receive window")
	}
}

func TestReviewServerReceiveCapLeavesClientBehaviorUnchanged(t *testing.T) {
	c := resourceUDPConn(t, false)
	for seq := uint32(1); seq <= 5; seq++ {
		c.receiveUDP(segment{kind: dataServer, session: 1, seq: seq, payload: make([]byte, 32768)})
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.expected != 6 || c.queued != 5*32768 || c.maxReceiveSegments() != recvCapacity {
		t.Fatal("server-only memory policy changed the existing outbound client")
	}
}

type resourcePartialWriteConn struct {
	net.Conn
	closed  atomic.Bool
	calls   atomic.Int32
	failure error
}

func (c *resourcePartialWriteConn) Write(p []byte) (int, error) {
	c.calls.Add(1)
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	return min(len(p), 7), c.failure
}
func (c *resourcePartialWriteConn) Close() error                   { c.closed.Store(true); return nil }
func (*resourcePartialWriteConn) SetWriteDeadline(time.Time) error { return nil }

func TestReviewPartialServerTCPRecordClosesSharedUnderlay(t *testing.T) {
	failure := errors.New("injected partial record write")
	raw := &resourcePartialWriteConn{failure: failure}
	parent, err := newWire(raw, "resource-user", "resource-password", false, false)
	if err != nil {
		t.Fatal(err)
	}
	parent.server = true
	first := &wire{parent: parent, sessionDone: make(chan struct{})}
	second := &wire{parent: parent, sessionDone: make(chan struct{})}
	if err := first.write(segment{kind: dataServer, session: 1, seq: 1, payload: []byte("first")}); !errors.Is(err, failure) {
		t.Fatal("partial record failure was not propagated", err)
	}
	if !raw.closed.Load() {
		t.Fatal("shared TCP stream remained open after implicit nonce/framing desynchronization")
	}
	done := make(chan error, 1)
	go func() {
		done <- second.write(segment{kind: dataServer, session: 2, seq: 1, payload: []byte("sibling")})
	}()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal("sibling kept writing to a damaged TCP underlay", err)
		}
	case <-time.After(time.Second):
		t.Fatal("sibling remained blocked after shared TCP failure")
	}
}

func TestReviewPartialWritePolicyPreservesUDPAndClientScope(t *testing.T) {
	for _, tc := range []struct {
		name        string
		udp, server bool
	}{{"server-udp", true, true}, {"client-tcp", false, false}} {
		t.Run(tc.name, func(t *testing.T) {
			failure := errors.New("injected write error")
			raw := &resourcePartialWriteConn{failure: failure}
			w, err := newWire(raw, "resource-user", "resource-password", tc.udp, false)
			if err != nil {
				t.Fatal(err)
			}
			w.server = tc.server
			if err = w.write(resourceSegment(100)); !errors.Is(err, failure) {
				t.Fatal("write error was not preserved", err)
			}
			if raw.closed.Load() {
				t.Fatal("TCP-server-only close policy affected another transport scope")
			}
		})
	}
}
