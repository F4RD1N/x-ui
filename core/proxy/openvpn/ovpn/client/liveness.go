package client

import (
	"fmt"
	"sync/atomic"
	"time"
)

// Liveness timing (keepalive pings, ping-restart, the OCC probe).
//
// Go's monotonic clock (CLOCK_MONOTONIC on Linux and Android) stops while
// the device is suspended; the wall clock does not. OpenVPN keeps these
// timers in wall-clock time, so a phone that wakes up pings at once and sees
// that ping-restart has long passed. A stamp records both readings, and the
// time since a stamp is the larger of the two differences: the wall clock
// counts a suspend, the monotonic clock stays right when the wall clock is
// stepped backward.
type stamp struct{ mono, wall int64 }

// since is how long before now then was.
func since(now, then stamp) time.Duration {
	return time.Duration(max(now.mono-then.mono, now.wall-then.wall, 0))
}

// atomicStamp is a stamp one goroutine stores and others load. The halves
// are not read as one; a torn read mixes two recent stamps, which only blurs
// the reading by the time between them.
type atomicStamp struct{ mono, wall atomic.Int64 }

func (a *atomicStamp) store(s stamp) { a.mono.Store(s.mono); a.wall.Store(s.wall) }
func (a *atomicStamp) load() stamp   { return stamp{a.mono.Load(), a.wall.Load()} }

// stampAt reads the liveness clock at t, a time.Now() reading.
func (c *Client) stampAt(t time.Time) stamp {
	s := stamp{mono: int64(t.Sub(c.epoch)), wall: t.UnixNano()}
	if c.wallSkew != nil {
		s.wall += int64(c.wallSkew())
	}
	return s
}

func (c *Client) markRecv(now time.Time) { c.lastRecv.store(c.stampAt(now)) }

func (c *Client) markSend(now time.Time) { c.lastSend.store(c.stampAt(now)) }

// sinceRecv is how long ago the last authenticated packet arrived.
func (c *Client) sinceRecv(now time.Time) time.Duration {
	return since(c.stampAt(now), c.lastRecv.load())
}

// sinceSendAt is how long ago a packet last went out, or a keepalive ping
// was last tried (one that could not be sent while another write was in
// progress counts: that write carries something).
func (c *Client) sinceSendAt(now stamp) time.Duration {
	return min(since(now, c.lastSend.load()), since(now, c.pingTried.load()))
}

// pingOverdue wakes the control loop when a keepalive ping is due. The
// reader calls it for every authenticated packet, so a device woken by the
// server's packet pings at once rather than when its monotonic timer
// (which did not run while it slept) fires.
func (c *Client) pingOverdue(now stamp) {
	if p := c.pingNs.Load(); p > 0 && c.sinceSendAt(now) >= time.Duration(p) {
		c.signalWake()
	}
}

// setHandshakeDeadline moves the deadline steps 1-6 must meet.
func (c *Client) setHandshakeDeadline(t time.Time) {
	c.loop.hsDeadline = t
	c.hsDeadlineNs.Store(int64(t.Sub(c.epoch)))
}

// watchdogGrace is how long after the handshake deadline the watchdog ends
// a session whose control loop has not (it reports the stage itself).
const watchdogGrace = time.Second

// watchdog enforces ping-restart, and backs up the handshake deadline, on
// a goroutine of its own: the control loop writes to the transport itself,
// and a TCP write blocks for as long as the server takes no bytes (a
// stopped or overloaded server, a black-holed path), which would freeze the
// loop's timers. Ending the session closes the transport, and that releases
// every write blocked in it. The control loop kicks it when the session
// comes up, so that it starts timing ping-restart.
func (c *Client) watchdog() {
	defer c.wg.Done()
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
		case <-c.kick:
		}
		wait, err := c.watch(time.Now())
		if err != nil {
			c.fail(err)
			return
		}
		t.Reset(max(wait, time.Millisecond))
	}
}

// kickWatchdog makes the watchdog look at the session again.
func (c *Client) kickWatchdog() {
	select {
	case c.kick <- struct{}{}:
	default:
	}
}

// watch checks the session at now: the error that ends it, or how long
// until the next check.
func (c *Client) watch(now time.Time) (time.Duration, error) {
	wait := c.maxSleep
	select {
	case <-c.closing:
		return wait, nil // Close ends the session within its own grace
	default:
	}
	if !c.established.Load() {
		left := time.Duration(c.hsDeadlineNs.Load()-int64(now.Sub(c.epoch))) + watchdogGrace
		if left <= 0 {
			return 0, fmt.Errorf("%w (the session stalled)", ErrHandshakeTimeout)
		}
		return min(wait, left), nil
	}
	if pr := time.Duration(c.pingRestartNs.Load()); pr > 0 {
		left := pr - c.sinceRecv(now)
		if left <= 0 {
			return 0, ErrPingTimeout
		}
		wait = min(wait, left)
	}
	return wait, nil
}
