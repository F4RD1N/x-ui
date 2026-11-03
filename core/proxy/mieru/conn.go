package mieru

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	mrand "math/rand/v2"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/proxy/nativebridge"
	"github.com/xtls/xray-core/transport/internet"
)

// Conn is one reliable Mieru session. Each outbound link owns its underlay,
// avoiding cross-request credentials, routes, cancellation or sequence state.
//
// Reading the underlay never waits for the local reader: received payloads go
// to a bounded queue, so acknowledgements keep flowing while the app is slow.
// Over TCP, writes go out once and segments arrive in order.
//
// Over UDP the session is a small reliable transport of its own:
//   - Receive: segments that arrive ahead of a gap are kept until the gap is
//     filled, and every ACK advertises the real free receive capacity, so the
//     server neither resends what already arrived nor overruns the client.
//     The server's close is acted on only once every segment before it has
//     arrived; a gap that is never filled ends the read with an error instead
//     of a silent short read.
//   - Send: a congestion window (slow start, halved on loss) bounded by the
//     server's advertised window; the retransmission timeout follows the
//     measured round trip, and three duplicate ACKs resend the missing
//     segment at once.
type Conn struct {
	wire           *wire
	sid            uint32
	writeMu        sync.Mutex
	mu             sync.Mutex
	cond           *sync.Cond // queue, window, deadline or done changed
	next, expected uint32
	opened         chan struct{}
	openOnce       sync.Once
	ack            uint32    // the server's next expected sequence
	inflight       []*flight // UDP: sent, unacknowledged data, ascending seq
	queue          [][]byte  // received payloads not yet read
	queued         int       // bytes in queue
	rdeadline      time.Time
	rtimer         *time.Timer
	done           chan struct{}
	once           sync.Once
	err            error

	// UDP receive side.
	oooBytes   int               // payload bytes retained ahead of a UDP gap
	ooo        map[uint32][]byte // segments received ahead of a gap, by seq
	closeSeq   uint32            // seq of a server close waiting for that gap; 0 = none
	ackOwed    int               // in-order segments not acknowledged yet
	ackArmed   bool              // a delayed acknowledgement is scheduled
	advertised int               // receive window last sent to the server

	// UDP send side.
	srtt, rttvar   time.Duration // 0 until the first sample
	cwnd, ssthresh float64       // congestion window, in segments
	peerWindow     int           // the server's last advertised window
	dupAcks        int
	recovering     bool          // repairing losses after a fast retransmit or timeout
	recoverSeq     uint32        // last seq sent when the loss was found
	kick           chan struct{} // wakes the retransmit worker
	wakeAt         time.Time     // when that worker next wakes; zero while idle
	paceAt         time.Time     // when the next new segment may go out

	// UDP liveness.
	live      liveness
	heartbeat time.Duration // silence after which an idle session sends an ACK
	lastRecv  atomic.Int64  // monoNow() when the last segment of this session was received
}

type flight struct {
	s     segment
	sent  time.Time
	tries int
	fast  bool // already resent by fast retransmit
	// retimed: its timer was restarted without a resend, so its ACK gives
	// no round-trip sample.
	retimed bool
}

const (
	udpSegment     = 1000
	udpInitWindow  = 32   // initial congestion window, in segments
	udpMinWindow   = 8    // congestion window floor after a loss
	udpMaxWindow   = 128  // congestion window ceiling: more overruns a default server socket buffer
	udpAttempts    = 8    // sends per segment before the session fails
	recvCapacity   = 1024 // UDP: segments received but not yet read, gap or not
	udpReadBuffer  = 4 << 20
	ackEvery       = 4 // in-order segments per acknowledgement
	ackDelay       = 2 * time.Millisecond
	initialRTO     = 500 * time.Millisecond
	minRTO         = 200 * time.Millisecond
	maxRTO         = 3200 * time.Millisecond
	closeGapWait   = time.Second
	closeDrainWait = 2 * time.Second
	closeAttempts  = 3
	closeWait      = 200 * time.Millisecond
)

// UDP liveness, as in the reference. Both ends of a UDP session send an ACK
// as a heartbeat whenever they have sent nothing for interval (give or take
// jitter, drawn afresh after each heartbeat so the rhythm is not periodic),
// and both drop a session they have heard nothing from for idle. Without the
// heartbeat the server forgets an idle client after a minute without telling
// it; without the idle limit a client whose server or path died (a NAT
// mapping lost in a Wi-Fi to mobile switch) would wait on a silent socket.
// Each session copies udpLiveness when it opens, so tests can shorten it.
type liveness struct{ interval, jitter, idle time.Duration }

var udpLiveness = liveness{interval: 5 * time.Second, jitter: time.Second, idle: time.Minute}

// next draws the silence after which the next heartbeat is sent.
func (l liveness) next() time.Duration {
	return l.interval - l.jitter + time.Duration(mrand.Int64N(int64(2*l.jitter)+1))
}

// backoff is the open request's retry delay before any round trip is known.
func backoff(attempt int) time.Duration {
	return time.Duration(400*(1<<min(attempt, 3))) * time.Millisecond
}

// growReadBuffer asks for a larger socket receive buffer, so bursts from the
// server's congestion window are not dropped by the kernel. Best effort: the
// kernel caps it, and some wrapped sockets don't expose it.
func growReadBuffer(c net.Conn) {
	var x interface{} = c
	if w, ok := c.(*internet.PacketConnWrapper); ok {
		x = w.PacketConn
	}
	if b, ok := x.(interface{ SetReadBuffer(int) error }); ok {
		_ = b.SetReadBuffer(udpReadBuffer)
	}
}

func Open(w *wire) (*Conn, error) {
	var id [4]byte
	if _, e := rand.Read(id[:]); e != nil {
		return nil, e
	}
	sid := binary.BigEndian.Uint32(id[:])
	if sid == 0 {
		sid = 1
	}
	c := &Conn{wire: w, sid: sid, next: 1, expected: 1, opened: make(chan struct{}), done: make(chan struct{})}
	c.cond = sync.NewCond(&c.mu)
	if w.udp {
		growReadBuffer(w.conn)
		c.ooo = make(map[uint32][]byte)
		c.cwnd, c.ssthresh = udpInitWindow, udpMaxWindow
		c.peerWindow = udpMaxWindow
		c.advertised = recvCapacity
		c.kick = make(chan struct{}, 1)
		c.live = udpLiveness
		c.heartbeat = c.live.next()
		c.lastRecv.Store(monoNow())
	}
	go c.receive()
	if e := c.openSession(); e != nil {
		c.abort(e)
		return nil, e
	}
	if w.udp {
		go c.retransmit()
	}
	return c, nil
}

func (c *Conn) openSession() error {
	s := segment{kind: openRequest, session: c.sid, seq: 0}
	attempts := 1
	if c.wire.udp {
		attempts = udpAttempts
	}
	for attempt := 0; attempt < attempts; attempt++ {
		sent := time.Now()
		if e := c.wire.write(s); e != nil {
			return e
		}
		wait := backoff(attempt)
		if !c.wire.udp {
			wait = 10 * time.Second
		}
		t := time.NewTimer(wait)
		select {
		case <-c.opened:
			t.Stop()
			if c.wire.udp && attempt == 0 {
				c.mu.Lock()
				c.sampleRTTLocked(time.Since(sent))
				c.mu.Unlock()
			}
			return nil
		case <-c.done:
			t.Stop()
			return c.error()
		case <-t.C:
		}
	}
	return errors.New("Mieru session acknowledgement timed out")
}

// retransmit runs the retransmission timer, which follows the oldest
// unacknowledged segment, as in TCP: on expiry only that segment is resent and
// the others' timers restart; any further holes are then repaired one round
// trip apart by partial ACKs instead of resending the whole window. It sleeps
// until the deadline.
//
// While nothing is in flight the session is idle: the worker then wakes only
// to send a heartbeat ACK once nothing at all has been sent for the heartbeat
// interval, and to end a session the server has been silent on for the
// idle timeout. Those wakeups leave wakeAt zero, so Write still kicks it.
func (c *Conn) retransmit() {
	defer nativebridge.RecoverWorker(c.abort)
	for {
		var resend, heartbeat *segment
		failed := false
		wait := time.Duration(-1)
		idle := time.Duration(0)
		now := time.Now()
		silent := time.Duration(monoNow() - c.lastRecv.Load())
		if silent > c.live.idle {
			c.abort(errIdle)
			return
		}
		c.mu.Lock()
		if len(c.inflight) == 0 {
			sinceSent := c.wire.sinceSent()
			if sinceSent >= c.heartbeat {
				a := c.ackLocked()
				heartbeat = &a
				c.heartbeat = c.live.next()
				sinceSent = 0
			}
			idle = min(c.heartbeat-sinceSent, c.live.idle-silent)
		} else {
			rto := c.rtoLocked()
			f := c.inflight[0]
			if due := f.sent.Add(f.timeout(rto)); now.Before(due) {
				wait = due.Sub(now)
			} else if f.tries >= udpAttempts {
				failed = true
			} else {
				s := c.resendLocked(f, now)
				resend = &s
				for _, o := range c.inflight[1:] {
					o.sent, o.retimed = now, true
				}
				c.onLossLocked(true)
				c.recovering, c.recoverSeq = true, c.next-1
				wait = f.timeout(rto)
			}
		}
		c.wakeAt = time.Time{}
		if wait >= 0 {
			c.wakeAt = now.Add(max(wait, 5*time.Millisecond))
		}
		c.mu.Unlock()
		if failed {
			c.abort(errors.New("Mieru session acknowledgement timed out"))
			return
		}
		if resend != nil {
			if e := c.wire.write(*resend); e != nil {
				c.abort(e)
				return
			}
		}
		if heartbeat != nil {
			// Like any ACK, best effort: a lost one is covered by the next,
			// and a dead path by the idle timeout.
			_ = c.wire.write(*heartbeat)
		}
		if wait < 0 {
			t := time.NewTimer(max(idle, 5*time.Millisecond))
			select {
			case <-c.done:
				t.Stop()
				return
			case <-c.kick:
			case <-t.C:
			}
			t.Stop()
			continue
		}
		t := time.NewTimer(max(wait, 5*time.Millisecond))
		select {
		case <-c.done:
			t.Stop()
			return
		case <-c.kick:
		case <-t.C:
		}
		t.Stop()
	}
}

func (f *flight) timeout(rto time.Duration) time.Duration {
	return min(rto<<min(f.tries-1, 5), maxRTO)
}

func (c *Conn) rtoLocked() time.Duration {
	if c.srtt == 0 {
		return initialRTO
	}
	return min(max(c.srtt+4*c.rttvar, minRTO), maxRTO)
}

// sampleRTTLocked folds one round-trip sample in, as TCP does (RFC 6298).
func (c *Conn) sampleRTTLocked(r time.Duration) {
	if r <= 0 {
		r = time.Millisecond
	}
	if c.srtt == 0 {
		c.srtt, c.rttvar = r, r/2
		return
	}
	d := c.srtt - r
	if d < 0 {
		d = -d
	}
	c.rttvar = (3*c.rttvar + d) / 4
	c.srtt = (7*c.srtt + r) / 8
}

// onLossLocked shrinks the congestion window: by 30% after a fast
// retransmit (CUBIC's factor, gentler than halving on lossy mobile paths),
// back to the floor after a timeout.
func (c *Conn) onLossLocked(timeout bool) {
	c.ssthresh = max(c.cwnd*0.7, udpMinWindow)
	if timeout {
		c.cwnd = udpMinWindow
	} else {
		c.cwnd = c.ssthresh
	}
}

// sendLimitLocked is how many data segments may be in flight: the congestion
// window, bounded by the server's window but never below one, so a closed
// window is still probed.
func (c *Conn) sendLimitLocked() int {
	return max(1, min(int(c.cwnd), c.peerWindow))
}

// windowLocked is the receive window advertised to the server: the free
// receive capacity, counting segments held ahead of a gap. It is never closed
// just because a segment is missing: the reference server gives a close only
// about a second to drain its queue (within this window) before it sends the
// close anyway and discards what is left, so a throttled window near the end
// of a transfer would cut it shorter, not save it.
func (c *Conn) windowLocked() uint16 {
	if !c.wire.udp {
		return 65535
	}
	room := max(recvCapacity-len(c.queue)-len(c.ooo), 0)
	if c.wire.server {
		room = min(room, max(serverUDPReceiveBytes-c.queued-c.oooBytes, 0)/udpSegment)
	}
	return uint16(min(room, 65535))
}

// overdueLocked reports whether f should have been acknowledged by now: it was
// sent more than a quarter round trip (plus 5 ms of jitter) longer ago than
// the smoothed round trip.
func (c *Conn) overdueLocked(f *flight, now time.Time) bool {
	return c.srtt > 0 && now.Sub(f.sent) > c.srtt*5/4+5*time.Millisecond
}

// paceLocked spreads new UDP segments over the round trip instead of sending
// a window in one burst: a burst of hundreds of datagrams overflows the
// server's socket buffer (212 KB on a default Linux, which mita cannot raise),
// and every dropped datagram costs a resend and a smaller window. The rate is
// 1.25 windows per smoothed round trip (2 in slow start), as Linux paces TCP;
// up to 2 ms of segments may still go out back to back. It returns how long
// to wait before sending the next segment.
func (c *Conn) paceLocked(now time.Time) time.Duration {
	if c.srtt == 0 || c.cwnd <= 0 {
		return 0
	}
	gain := 1.25
	if c.cwnd < c.ssthresh {
		gain = 2
	}
	interval := time.Duration(float64(c.srtt) / (gain * c.cwnd))
	if floor := now.Add(-2 * time.Millisecond); c.paceAt.Before(floor) {
		c.paceAt = floor
	}
	c.paceAt = c.paceAt.Add(interval)
	if wait := c.paceAt.Sub(now); wait > time.Millisecond {
		return wait
	}
	return 0
}

// resendLocked marks f as sent again now and returns the copy to write.
func (c *Conn) resendLocked(f *flight, now time.Time) segment {
	f.tries++
	f.sent = now
	f.s.unack, f.s.window, f.s.windowSet = c.expected, c.windowLocked(), true
	return f.s
}

// ackLocked builds an acknowledgement of everything received in order.
func (c *Conn) ackLocked() segment {
	w := c.windowLocked()
	c.ackOwed = 0
	c.advertised = int(w)
	return segment{kind: c.sendACKKind(), session: c.sid, unack: c.expected, window: w, windowSet: true}
}

// flushAck sends a delayed acknowledgement if one is still owed.
func (c *Conn) flushAck() {
	defer nativebridge.RecoverWorker(c.abort)
	c.mu.Lock()
	c.ackArmed = false
	if c.ackOwed == 0 || c.ended() {
		c.mu.Unlock()
		return
	}
	a := c.ackLocked()
	c.mu.Unlock()
	_ = c.wire.write(a)
}

func (c *Conn) receive() {
	defer nativebridge.RecoverWorker(c.abort)
	for {
		s, e := c.wire.read()
		if e != nil {
			c.abort(e)
			return
		}
		if s.session != c.sid {
			continue
		}
		c.lastRecv.Store(monoNow())
		if c.wire.server && s.kind == openRequest {
			// Retransmitted UDP opens must receive the same acknowledgement.
			if err := c.wire.write(segment{kind: openResponse, session: c.sid}); err != nil {
				c.abort(err)
				return
			}
			continue
		}
		if !c.wire.server && s.kind == openResponse {
			first := false
			c.openOnce.Do(func() { close(c.opened); first = true })
			if c.wire.udp {
				c.mu.Lock()
				a := c.ackLocked()
				c.mu.Unlock()
				_ = c.wire.write(a)
			}
			if first && len(s.payload) > 0 && !c.deliver(s.payload) {
				return
			}
			continue
		}
		if s.kind == closeRequest || s.kind == closeResponse {
			if s.kind == closeRequest {
				_ = c.wire.write(segment{kind: closeResponse, session: c.sid, seq: s.seq})
			}
			if s.kind == closeRequest && c.wire.udp && !c.closeInOrder(s.seq) {
				continue // data before the close is still missing
			}
			c.abort(io.EOF)
			return
		}
		if s.kind != c.receiveDataKind() && s.kind != c.receiveACKKind() {
			if c.wire.udp {
				continue // a stray datagram must not end the session
			}
			c.abort(errors.New("unexpected Mieru server segment"))
			return
		}
		if c.wire.udp {
			if done := c.receiveUDP(s); done {
				return
			}
			continue
		}
		c.mu.Lock()
		if s.unack > c.ack {
			c.ack = s.unack
		}
		c.mu.Unlock()
		if s.kind == c.receiveACKKind() {
			continue
		}
		c.mu.Lock()
		c.expected = s.seq + 1
		c.mu.Unlock()
		if !c.deliver(s.payload) {
			return
		}
	}
}

// receiveUDP handles a UDP data or ACK segment. It reports true when the
// session has ended.
func (c *Conn) receiveUDP(s segment) bool {
	now := time.Now()
	var resend []segment
	var ack *segment
	dupAcks := 1
	finished := false
	c.mu.Lock()
	if s.windowSet {
		if int(s.window) > c.peerWindow {
			c.cond.Broadcast() // the server's window opened
		}
		c.peerWindow = int(s.window)
	}
	if s.unack > c.ack {
		c.ack = s.unack
		kept := c.inflight[:0]
		acked := 0
		var sample time.Duration
		for _, f := range c.inflight {
			if f.s.seq >= s.unack {
				kept = append(kept, f)
				continue
			}
			acked++
			if f.tries == 1 && !f.retimed { // Karn: only segments sent once give a sample
				sample = now.Sub(f.sent)
			}
		}
		clear(c.inflight[len(kept):])
		c.inflight = kept
		if sample > 0 {
			c.sampleRTTLocked(sample)
		}
		c.dupAcks = 0
		switch {
		case c.recovering && s.unack <= c.recoverSeq && len(c.inflight) > 0:
			// A partial ACK. If the next segment is overdue it is another
			// hole from the same loss: resend it now rather than after a
			// timeout. If not, it is still on its way; resending it on
			// every partial ACK would resend much of the window.
			if f := c.inflight[0]; c.overdueLocked(f, now) && f.tries < udpAttempts {
				f.fast = true
				resend = append(resend, c.resendLocked(f, now))
			}
		case c.recovering:
			c.recovering = false
		case c.cwnd < c.ssthresh:
			c.cwnd += float64(acked)
		default:
			c.cwnd += float64(acked) / c.cwnd
		}
		c.cwnd = min(c.cwnd, udpMaxWindow)
		c.cond.Broadcast()
		if len(c.inflight) > 0 {
			// The timer follows the oldest segment, which just changed.
			select {
			case c.kick <- struct{}{}:
			default:
			}
		}
	} else if s.kind == c.receiveACKKind() && s.unack == c.ack && len(c.inflight) > 0 && c.inflight[0].s.seq == s.unack {
		// A duplicate ACK: later data reached the server, the oldest
		// segment did not. The server ACKs at most once per tick (1 ms),
		// so a burst yields a single duplicate and three may never come.
		// Besides three duplicates, a duplicate that arrives once the
		// oldest segment is a quarter round trip overdue marks it lost, as
		// TCP's RACK does; that also catches a lost resend.
		c.dupAcks++
		f := c.inflight[0]
		if f.tries < udpAttempts && (c.overdueLocked(f, now) || c.dupAcks >= 3 && !f.fast) {
			if !c.recovering {
				c.onLossLocked(false)
				c.recovering, c.recoverSeq = true, c.next-1
			}
			f.fast = true
			c.dupAcks = 0
			resend = append(resend, c.resendLocked(f, now))
		}
	}
	if s.kind == c.receiveDataKind() {
		switch {
		case s.seq < c.expected: // a resend of what already arrived: the ACK was lost
			a := c.ackLocked()
			ack = &a
		case s.seq == c.expected:
			if len(c.queue) >= recvCapacity || !c.receiveByteRoomLocked(len(s.payload)) {
				a := c.ackLocked() // no room: leave it for the server to resend
				ack = &a
				break
			}
			c.pushLocked(s.payload)
			c.expected++
			for p, ok := c.ooo[c.expected]; ok; p, ok = c.ooo[c.expected] {
				delete(c.ooo, c.expected)
				c.oooBytes -= len(p)
				c.pushLocked(p)
				c.expected++
			}
			if c.closeSeq != 0 && c.expected >= c.closeSeq {
				finished = true
			}
			c.ackOwed++
			if len(c.ooo) > 0 {
				// The resend filled one gap but the next segment is
				// missing too (a burst loss). Nothing else may arrive
				// to produce duplicate ACKs, so send the three the
				// server needs to resend it now instead of on timeout.
				a := c.ackLocked()
				ack = &a
				dupAcks = 3
			} else if c.ackOwed >= ackEvery || c.advertised < c.maxReceiveSegments()/4 {
				a := c.ackLocked()
				ack = &a
			} else if !c.ackArmed {
				c.ackArmed = true
				time.AfterFunc(ackDelay, c.flushAck)
			}
		default: // ahead of a gap: keep it, and tell the server what is missing
			if int(s.seq-c.expected) < recvCapacity-len(c.queue) {
				if _, ok := c.ooo[s.seq]; !ok && c.receiveByteRoomLocked(len(s.payload)+c.missingFrameReserve()) {
					c.ooo[s.seq] = s.payload
					c.oooBytes += len(s.payload)
				}
			}
			a := c.ackLocked()
			ack = &a
		}
	}
	c.mu.Unlock()
	for _, r := range resend {
		if e := c.wire.write(r); e != nil {
			c.abort(e)
			return true
		}
	}
	for i := 0; ack != nil && i < dupAcks; i++ {
		_ = c.wire.write(*ack)
	}
	if finished {
		c.abort(io.EOF)
		return true
	}
	return false
}

// closeInOrder reports whether every server segment before the close at seq
// has arrived. If not, the close waits for the gap to be filled; should the
// gap outlast closeGapWait, the session ends with io.ErrUnexpectedEOF so the
// reader sees a broken transfer rather than a short one.
func (c *Conn) closeInOrder(seq uint32) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if seq <= c.expected {
		return true
	}
	if c.closeSeq == 0 {
		c.closeSeq = seq
		time.AfterFunc(closeGapWait, func() { c.abort(io.ErrUnexpectedEOF) })
	}
	return false
}

func (c *Conn) pushLocked(p []byte) {
	if len(p) > 0 {
		c.queue = append(c.queue, p)
		c.queued += len(p)
		c.cond.Broadcast()
	}
}

// deliver queues a TCP payload (or the opening payload) for Read. TCP needs no
// acknowledgements, so it waits until the previous payload was read, the
// backpressure the old pipe gave. It reports false when the session ended.
func (c *Conn) deliver(p []byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for c.queued > 0 && !c.ended() {
		c.cond.Wait()
	}
	if c.ended() {
		return false
	}
	c.pushLocked(p)
	return true
}

func (c *Conn) ended() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	total := 0
	for len(p) > 0 {
		n := len(p)
		limit := 32768
		if c.wire.udp {
			limit = udpSegment
		}
		if n > limit {
			n = limit
		}
		c.mu.Lock()
		for c.wire.udp && len(c.inflight) >= c.sendLimitLocked() && !c.ended() {
			c.cond.Wait()
		}
		if c.ended() {
			c.mu.Unlock()
			return total, c.error()
		}
		s := segment{kind: c.sendDataKind(), session: c.sid, seq: c.next, unack: c.expected, payload: p[:n]}
		c.next++
		if c.wire.udp {
			// The segment stays in flight for retransmission, so it keeps
			// its own copy of the caller's bytes.
			s.payload = append([]byte(nil), p[:n]...)
			s.window, s.windowSet = c.windowLocked(), true
			c.advertised = int(s.window)
			c.ackOwed = 0 // the data carries the acknowledgement
			now := time.Now()
			if wait := c.paceLocked(now); wait > 0 {
				// Pacing: sleep without the lock, then stamp the
				// segment with the time it really leaves.
				c.mu.Unlock()
				time.Sleep(wait)
				c.mu.Lock()
				now = time.Now()
			}
			c.inflight = append(c.inflight, &flight{s: s, sent: now, tries: 1})
			// Wake the retransmit worker if it is idle.
			if c.wakeAt.IsZero() {
				select {
				case c.kick <- struct{}{}:
				default:
				}
			}
		}
		c.mu.Unlock()
		if e := c.wire.write(s); e != nil {
			c.abort(e)
			return total, e
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		if len(c.queue) > 0 {
			n := copy(p, c.queue[0])
			if n == len(c.queue[0]) {
				c.queue[0] = nil
				c.queue = c.queue[1:]
			} else {
				c.queue[0] = c.queue[0][n:]
			}
			c.queued -= n
			c.cond.Broadcast()
			// The server stops sending while the advertised window is
			// nearly closed; once reading has freed half the capacity,
			// tell it so instead of waiting for its next segment.
			if c.wire.udp && c.advertised < c.maxReceiveSegments()/4 && int(c.windowLocked()) >= c.maxReceiveSegments()/2 && !c.ended() {
				a := c.ackLocked()
				go func() {
					defer nativebridge.RecoverWorker(c.abort)
					_ = c.wire.write(a)
				}()
			}
			return n, nil
		}
		if c.ended() {
			if c.err == io.EOF {
				return 0, io.EOF
			}
			return 0, c.errorLocked()
		}
		if !c.rdeadline.IsZero() && !time.Now().Before(c.rdeadline) {
			return 0, os.ErrDeadlineExceeded
		}
		c.cond.Wait()
	}
}

var errIdle = errors.New("Mieru session timed out: nothing received from the server")

func (c *Conn) error() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.errorLocked()
}

func (c *Conn) errorLocked() error {
	if c.err != nil {
		return c.err
	}
	return net.ErrClosed
}

func (c *Conn) abort(e error) {
	c.once.Do(func() {
		c.mu.Lock()
		c.err = e
		close(c.done)
		if c.rtimer != nil {
			c.rtimer.Stop()
		}
		c.cond.Broadcast()
		c.mu.Unlock()
		c.wire.conn.Close()
	})
}

// Close ends the session. Over UDP the server cannot see the socket close, so
// the client first lets in-flight data be acknowledged (bounded), then sends
// closeRequest, retried briefly until the server answers; otherwise the
// server would keep the session and its destination open until it times out.
func (c *Conn) Close() error {
	if (c.wire.udp || c.wire.parent != nil) && !c.ended() {
		select {
		case <-c.opened:
			c.closeGracefully()
		default:
		}
	}
	c.abort(net.ErrClosed)
	return nil
}

func (c *Conn) closeGracefully() {
	deadline := time.Now().Add(closeDrainWait)
	t := time.AfterFunc(closeDrainWait, func() {
		c.mu.Lock()
		c.cond.Broadcast()
		c.mu.Unlock()
	})
	c.mu.Lock()
	for len(c.inflight) > 0 && !c.ended() && time.Now().Before(deadline) {
		c.cond.Wait()
	}
	s := segment{kind: closeRequest, session: c.sid, seq: c.next, unack: c.expected}
	c.next++
	c.mu.Unlock()
	t.Stop()
	for i := 0; i < closeAttempts && !c.ended(); i++ {
		if c.wire.write(s) != nil {
			return
		}
		w := time.NewTimer(closeWait)
		select {
		case <-c.done:
		case <-w.C:
		}
		w.Stop()
	}
}

func (c *Conn) LocalAddr() net.Addr  { return c.wire.conn.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr { return c.wire.conn.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.wire.conn.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rdeadline = t
	if c.rtimer != nil {
		c.rtimer.Stop()
		c.rtimer = nil
	}
	if !t.IsZero() {
		c.rtimer = time.AfterFunc(time.Until(t), func() {
			c.mu.Lock()
			c.cond.Broadcast()
			c.mu.Unlock()
		})
	}
	c.cond.Broadcast()
	return nil
}
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.wire.conn.SetWriteDeadline(t) }

// Mieru carries the SOCKS5 request directly: method negotiation is omitted
// because the encrypted underlay already authenticated the user.
func socksRequest(c net.Conn, cmd byte, addr []byte) error {
	if e := nativebridge.WriteFull(c, append([]byte{5, cmd, 0}, addr...)); e != nil {
		return e
	}
	var h [3]byte
	if _, e := io.ReadFull(c, h[:]); e != nil {
		return e
	}
	if h[0] != 5 || h[1] != 0 || h[2] != 0 {
		return errors.New("Mieru destination rejected")
	}
	_, e := nativebridge.ReadAddress(c)
	return e
}

// Role helpers leave the existing outbound's segment values unchanged.
func (c *Conn) sendDataKind() byte {
	if c.wire.server {
		return dataServer
	}
	return dataClient
}
func (c *Conn) sendACKKind() byte {
	if c.wire.server {
		return ackServer
	}
	return ackClient
}
func (c *Conn) receiveDataKind() byte {
	if c.wire.server {
		return dataClient
	}
	return dataServer
}
func (c *Conn) receiveACKKind() byte {
	if c.wire.server {
		return ackClient
	}
	return ackServer
}

// Server receive limits count bytes as well as records: authenticated peers may
// legally choose records much larger than this implementation's 1000-byte sends.
const serverUDPReceiveBytes = 128 << 10

func (c *Conn) receiveByteRoomLocked(n int) bool {
	return !c.wire.server || n <= serverUDPReceiveBytes-c.queued-c.oooBytes
}
func (c *Conn) maxReceiveSegments() int {
	if c.wire.server {
		return min(recvCapacity, serverUDPReceiveBytes/udpSegment)
	}
	return recvCapacity
}

func (c *Conn) missingFrameReserve() int {
	// A full OOO budget cannot be consumed by the application. Reserve room
	// for the largest legal missing frame, otherwise a gap could deadlock it.
	if c.wire.server {
		return 32768
	}
	return 0
}
