package client

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/datachan"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/wire"
)

// maxTransientErrors is how many transient UDP read errors in a row (ICMP
// port unreachable and the like) the reader tolerates.
const maxTransientErrors = 1000

// writeRaw puts one packet on the link: as a datagram over UDP, framed over
// TCP. Writes are serialised so TCP frames never interleave. A TCP write
// error ends the session. A failed UDP send is only returned: it loses that
// datagram, as when the network drops it (EPERM from a firewall during a
// network change, ICMP errors on a connected socket); OpenVPN logs it and
// carries on, and ping-restart decides whether the server is gone. Only a
// closed UDP socket ends the session.
func (c *Client) writeRaw(pkt []byte) error {
	c.writeMu.Lock()
	err := c.writeLocked(pkt)
	c.writeMu.Unlock()
	return c.afterWrite(pkt, err)
}

// tryWriteRaw is writeRaw for a packet that need not go out while another
// write is in progress (a keepalive: that write carries something). It
// never waits for the transport lock, which a write blocked on a stalled
// TCP connection may hold; sent reports whether it wrote.
func (c *Client) tryWriteRaw(pkt []byte) (sent bool, err error) {
	if !c.writeMu.TryLock() {
		return false, nil
	}
	err = c.writeLocked(pkt)
	c.writeMu.Unlock()
	return err == nil, c.afterWrite(pkt, err)
}

func (c *Client) writeLocked(pkt []byte) error {
	if !c.tcp {
		_, err := c.conn.Write(pkt)
		return err
	}
	var err error
	c.frame, err = wire.AppendFrame(c.frame[:0], pkt)
	if err == nil {
		_, err = c.conn.Write(c.frame)
	}
	if cap(c.frame) > 128<<10 {
		c.frame = nil
	}
	return err
}

func (c *Client) afterWrite(pkt []byte, err error) error {
	if err == nil {
		c.markSend(time.Now())
		if c.writeFailing.Load() {
			c.writeFailing.Store(false)
			c.log.Debugf("openvpn: sending to the server works again")
		}
		return nil
	}
	if c.isDone() {
		if e := c.Err(); e != nil {
			return e
		}
		return err
	}
	if errors.Is(err, wire.ErrTooLarge) {
		c.dropLog("openvpn: write of %d bytes failed: %v", len(pkt), err)
		return err
	}
	if !c.tcp && !errors.Is(err, net.ErrClosed) {
		if c.writeFailing.CompareAndSwap(false, true) {
			c.log.Warnf("openvpn: sending to the server failed (the session goes on): %v", err)
		} else {
			c.dropLog("openvpn: write of %d bytes failed: %v", len(pkt), err)
		}
		return err
	}
	err = fmt.Errorf("openvpn: writing to the server: %w", err)
	c.fail(err)
	return err
}

// isTransientUDP reports errors a connected UDP socket returns after an
// ICMP error or for one oversized datagram; the next one may well work.
func isTransientUDP(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EMSGSIZE) ||
		errors.Is(err, syscall.ENOBUFS)
}

// tcpReadBuffer is the read buffer of a TCP transport: room for a burst of
// full-size frames.
const tcpReadBuffer = 64 << 10

// Receive coalescing, on a UDP transport. While a download streams in over
// a slow link (a phone's radio), its packets arrive one at a time, and a
// reader woken for each one costs a thread wake-up per packet -- here and in
// every goroutine downstream: the stack's TCP processor, the ACK it sends
// back, the reader of the connection and the app's socket. That was most of
// the CPU such a download took. So when a read had to wait (the batch that
// was waiting is drained) while packets stream in slowly, the loop pauses
// before reading again: the packets that arrive meanwhile wait in the
// socket, are then read back to back, and everything downstream wakes once
// for the batch (the stack ACKs the batch once).
//
// The pause is sized to collect about rxBatch packets at the stream's rate,
// and at most rxCoalesce. A fast stream needs none (packets pile up while
// the last ones are handled, so batches form by themselves) and would only
// lose throughput to ACKs held back in bunches, so streams faster than one
// packet per rxSlowGap get no pause. A packet that comes after a quiet
// spell -- a ping, a game's update, the start of a reply -- is read the
// moment it arrives. A TCP transport needs none of this: the kernel hands
// over what one read finds as a batch.
var (
	rxCoalesce    = 2 * time.Millisecond
	rxBatch       = 4
	rxSlowGap     = 300 * time.Microsecond // ~37 Mbit/s of 1400-byte packets
	rxStreamGap   = 3 * rxCoalesce         // a longer silence ends a stream
	rxReadBlocked = 100 * time.Microsecond // a read this long had to wait
)

// rxPacer decides when, and for how long, the reader pauses (see
// rxCoalesce).
type rxPacer struct {
	last    time.Time     // when the previous packet was read
	batchAt time.Time     // when the current batch began: the last read that waited
	packets int           // packets read since batchAt
	gap     time.Duration // the stream's time per packet, smoothed; 0: unknown
}

// read accounts for a packet whose read started at start and ended at end,
// and returns how long to pause before the next read (0: none).
func (p *rxPacer) read(start, end time.Time) time.Duration {
	if p.last.IsZero() || end.Sub(p.last) >= rxStreamGap {
		// The first packet of a stream: nothing to go by yet.
		*p = rxPacer{last: end, batchAt: end}
		return 0
	}
	p.last = end
	p.packets++
	if end.Sub(start) <= rxReadBlocked {
		return 0 // it was waiting in the socket: still within a batch
	}
	// This read waited: the batch since batchAt is drained, and its packets
	// arrived over end-batchAt.
	per := end.Sub(p.batchAt) / time.Duration(p.packets)
	if p.gap == 0 {
		p.gap = per
	} else {
		p.gap += (per - p.gap) / 4
	}
	p.batchAt, p.packets = end, 0
	if p.gap < rxSlowGap {
		return 0
	}
	return min(time.Duration(rxBatch)*p.gap, rxCoalesce)
}

// readLoop reads the transport and dispatches every packet until the
// session ends.
func (c *Client) readLoop() {
	defer c.wg.Done()
	buf := make([]byte, wire.MaxPacketSize)
	var fr *wire.FrameReader
	if c.tcp {
		// Buffered: a frame is a 2-byte length and then the packet, and
		// read straight from the socket that is two reads per packet. This
		// reader is the connection's only reader.
		fr = wire.NewFrameReader(bufio.NewReaderSize(c.conn, tcpReadBuffer))
	}
	var pacer *rxPacer
	if !c.tcp && rxCoalesce > 0 {
		pacer = &rxPacer{}
	}
	transient := 0
	for {
		var (
			n     int
			err   error
			start time.Time
		)
		if pacer != nil {
			start = time.Now()
		}
		if fr != nil {
			n, err = fr.ReadPacket(buf)
		} else {
			n, err = c.conn.Read(buf)
		}
		if err != nil {
			if c.isDone() {
				return
			}
			if !c.tcp && isTransientUDP(err) && transient < maxTransientErrors {
				transient++
				c.dropLog("openvpn: transient read error: %v", err)
				continue
			}
			c.transportFailed(fmt.Errorf("openvpn: reading from the server: %w", err))
			return
		}
		transient = 0
		if n > 0 {
			c.dispatch(buf[:n])
		}
		if pacer != nil {
			if d := pacer.read(start, time.Now()); d > 0 {
				time.Sleep(d)
			}
		}
	}
}

// maxDataOverhead bounds what a data packet adds to its IP packet (header,
// packet id, IV, HMAC or tag, padding, compression byte).
const maxDataOverhead = 256

// dispatch routes one received packet: data packets are opened here and
// queued for ReadPacket, control packets are authenticated here and handed
// to the control loop. Bad packets are dropped.
func (c *Client) dispatch(pkt []byte) {
	op, keyID := wire.SplitHeader(pkt[0])
	switch {
	case op.IsData():
		ch := c.data.Load()
		if ch == nil {
			c.dropLog("openvpn: dropping %v before the data channel is up", op)
			return
		}
		if int64(len(pkt)) > c.maxPacket.Load()+maxDataOverhead {
			// Cannot hold an IP packet the tunnel allows (compression only
			// makes the wire packet smaller than its IP packet).
			c.dropPacket("openvpn: dropping a %d-byte data packet, larger than the tunnel MTU allows", len(pkt))
			return
		}
		bp := rxPool.Get().(*[]byte)
		out, kind, err := ch.Open((*bp)[:0], pkt)
		if err != nil {
			rxPool.Put(bp)
			c.dropLog("openvpn: dropping %v key %d: %v", op, keyID, err)
			return
		}
		now := c.stampAt(time.Now())
		c.lastRecv.store(now)
		c.pingOverdue(now)
		switch kind {
		case datachan.KindPacket:
			c.queuePacket(out, bp)
		case datachan.KindOCC:
			c.handleOCC(out)
			rxPool.Put(bp)
		default:
			rxPool.Put(bp)
		}
	case op.IsControl():
		p, err := c.wrapper.Unwrap(pkt)
		if err != nil {
			c.dropLog("openvpn: dropping %v key %d: %v", op, keyID, err)
			return
		}
		cp := copyControlPacket(p)
		if c.tcp {
			// TCP control messages are never retransmitted: do not drop.
			select {
			case c.ctlIn <- cp:
			case <-c.done:
			}
			return
		}
		select {
		case c.ctlIn <- cp:
		default:
			c.dropLog("openvpn: control queue full, dropping %v", op)
		}
	default:
		c.dropLog("openvpn: dropping packet with opcode %v", op)
	}
}

// queuePacket hands an opened IP packet to ReadPacket. out was opened into
// *bp; it lives there unless Open needed a larger buffer. The queue is
// bounded in packets and in bytes, and a packet larger than the tunnel MTU
// allows is no IP packet a server sends: those are dropped.
func (c *Client) queuePacket(out []byte, bp *[]byte) {
	n := int64(len(out))
	switch {
	case n == 0:
		rxPool.Put(bp)
		return
	case n > c.maxPacket.Load():
		rxPool.Put(bp)
		c.dropPacket("openvpn: dropping a %d-byte packet, larger than the tunnel MTU allows", n)
		return
	}
	p := rxPacket{data: out}
	if cap(out) > 0 && &out[:1][0] == &(*bp)[:1][0] {
		p.buf = bp
	} else {
		rxPool.Put(bp)
	}
	if c.queued.Add(n) <= maxQueuedBytes {
		select {
		case c.packets <- p:
			return
		default:
		}
	}
	c.queued.Add(-n)
	p.release()
	c.dropPacket("openvpn: receive queue full")
}

// dropPacket counts a received IP packet that was discarded and logs
// (rarely) why.
func (c *Client) dropPacket(format string, args ...any) {
	if n := c.dropped.Add(1); n&(n-1) == 0 {
		c.log.Debugf(format+" (%d packets dropped so far)", append(args, n)...)
	}
}

// transportFailed hands a dead transport to the control loop, which first
// finishes what already arrived (an AUTH_FAILED or RESTART just before the
// server closed a TCP connection says more than the EOF does).
func (c *Client) transportFailed(err error) {
	select {
	case c.readErr <- err:
	default:
		c.fail(err)
	}
}

// handleOCC acts on an OCC message from the server: an exit notification
// ends the session the way RESTART would; others are not needed.
func (c *Client) handleOCC(msg []byte) {
	if len(msg) == 0 {
		return
	}
	if msg[0] == datachan.OCCExit {
		c.log.Infof("openvpn: the server sent an exit notification")
		c.fail(fmt.Errorf("%w (explicit-exit-notify)", ErrServerRestart))
		return
	}
	c.log.Debugf("openvpn: ignoring OCC message %d", msg[0])
}

// copyControlPacket detaches p from the reader's buffer.
func copyControlPacket(p *wire.ControlPacket) *wire.ControlPacket {
	cp := *p
	if len(p.Acks) > 0 {
		cp.Acks = append([]wire.PacketID(nil), p.Acks...)
	}
	if len(p.Payload) > 0 {
		cp.Payload = append([]byte(nil), p.Payload...)
	} else {
		cp.Payload = nil
	}
	return &cp
}

// dropLog logs at debug level at most once a second, so a flood of bad
// packets cannot flood the log.
func (c *Client) dropLog(format string, args ...any) {
	now := c.mono(time.Now())
	last := c.dropLogAt.Load()
	if last != 0 && now-last < int64(time.Second) {
		return
	}
	if !c.dropLogAt.CompareAndSwap(last, now) {
		return
	}
	c.log.Debugf(format, args...)
}
