package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/datachan"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/handshake"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/options"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/reliable"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/wire"
)

// keyState is one key id's control-channel state. The control loop owns
// every field; the key's TLS goroutine only uses id, adapter, tls and
// source, which are set before it starts and never change, and sets
// tlsDone.
type keyState struct {
	id      uint8
	layer   *reliable.Layer
	adapter *tlsAdapter
	tls     *tls.Conn
	cancel  context.CancelFunc
	source  *handshake.ClientKeySource

	peerReset  bool // the server's reset message (its message 0) arrived
	tlsStarted bool
	tlsIn      int         // TLS bytes the server sent on this key
	tlsDone    atomic.Bool // the TLS handshake finished
	exchanged  bool        // key-method 2 exchange done
	dropped    bool

	server *handshake.ServerMessage
	cs     tls.ConnectionState
	canEKM bool

	deadline    time.Time // a renegotiation must finish by then
	established time.Time // became the sending key
	expires     time.Time // lame duck: dropped then
}

// loopState is the control loop's state.
type loopState struct {
	ourSID, serverSID wire.SessionID
	haveServerSID     bool

	keys        []*keyState
	primary     *keyState // the key data is sealed with (key 0 during setup)
	lame        *keyState // the previous key, kept for opening
	negotiating *keyState // a renegotiation in progress
	lastKeyID   uint8

	start           time.Time
	hsDeadline      time.Time
	connectDeadline time.Time

	pushed   *options.Pushed
	pushing  bool // key 0 exchanged; asking for PUSH_REPLY
	gotPush  bool // a PUSH_REPLY arrived (continuations may follow)
	pushNext time.Time
	pending  bool // AUTH_PENDING seen
	up       bool

	cipher, digest, keyDerivation string
	ping, pingRestart             time.Duration
	// probe: pingRestart is the client-mode default, so the server sends
	// no keepalive; a silent server is asked for an OCC reply.
	probe      bool
	probeTried stamp
	ccExit     bool
	exitNotify int

	authUserPass             bool
	username, password       string
	authToken, authTokenUser string

	closing       bool
	closeDeadline time.Time
	exitSent      bool

	// readErr is the transport's failure, reported once the TLS sessions
	// had readErrDeadline to deliver what arrived before it.
	readErr         error
	readErrDeadline time.Time
}

// Kinds of keyEvent.
const (
	evExchanged = iota // key-method 2 done: server, cs, canEKM set
	evMessage          // a control message: msg
	evError            // the key's TLS failed: err
)

// keyEvent is what a key's TLS goroutine reports to the control loop.
type keyEvent struct {
	ks     *keyState
	kind   int
	server *handshake.ServerMessage
	cs     tls.ConnectionState
	canEKM bool
	msg    string
	err    error
}

func nextKeyID(id uint8) uint8 {
	id = (id + 1) & wire.KeyIDMask
	if id == 0 {
		id = 1
	}
	return id
}

// newKeyState makes a key state and queues its reset message (message 0).
func (c *Client) newKeyState(id uint8, resetOp wire.Opcode, now time.Time) (*keyState, error) {
	src, err := handshake.NewClientKeySource(c.d.rand)
	if err != nil {
		return nil, fmt.Errorf("openvpn: key source: %w", err)
	}
	ks := &keyState{
		id:      id,
		layer:   reliable.New(c.relOptions()),
		adapter: newTLSAdapter(c.chunk, c.signalWake, c.conn.LocalAddr(), c.conn.RemoteAddr()),
		source:  src,
	}
	ks.layer.Send(resetOp, nil)
	s := &c.loop
	s.keys = append(s.keys, ks)
	s.lastKeyID = id
	return ks, nil
}

func (c *Client) keyByID(id uint8) *keyState {
	for _, ks := range c.loop.keys {
		if ks.id == id {
			return ks
		}
	}
	return nil
}

// dropKey forgets a key state: its data key, its TLS session, its timers.
func (c *Client) dropKey(ks *keyState) {
	if ks == nil || ks.dropped {
		return
	}
	ks.dropped = true
	if ks.exchanged {
		if ch := c.data.Load(); ch != nil {
			ch.DropKey(ks.id)
		}
	}
	ks.adapter.Close()
	if ks.cancel != nil {
		ks.cancel()
	}
	s := &c.loop
	for i, k := range s.keys {
		if k == ks {
			s.keys = append(s.keys[:i], s.keys[i+1:]...)
			break
		}
	}
	if s.lame == ks {
		s.lame = nil
	}
	if s.negotiating == ks {
		s.negotiating = nil
	}
}

// closeKeys shuts every key state's TLS down when the loop ends.
func (c *Client) closeKeys() {
	for _, ks := range c.loop.keys {
		ks.adapter.Close()
		if ks.cancel != nil {
			ks.cancel()
		}
	}
}

// controlLoop owns the key states and all timers.
func (c *Client) controlLoop() {
	defer c.wg.Done()
	defer c.closeKeys()
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	closing := c.closing
	for {
		now := time.Now()
		if err := c.tick(now); err != nil {
			c.fail(err)
			return
		}
		c.flush(now)
		if c.isDone() {
			return
		}
		d := max(c.nextDeadline(now).Sub(time.Now()), time.Millisecond)
		timer.Reset(d)

		var err error
		select {
		case <-c.done:
			return
		case p := <-c.ctlIn:
			err = c.handleControlPacket(p, time.Now())
		case ev := <-c.events:
			err = c.handleKeyEvent(ev, time.Now())
		case <-c.wake:
		case <-closing:
			closing = nil
			err = c.beginClose(time.Now())
		case rerr := <-c.readErr:
			err = c.transportDown(rerr, time.Now())
		case <-timer.C:
		}
		if err != nil {
			c.flush(time.Now()) // the acks and messages already queued
			c.fail(err)
			return
		}
	}
}

// transportDown takes the reader's fatal error: the packets it queued
// before are processed, then the session ends after a short grace period
// unless one of them ends it first with a better reason.
func (c *Client) transportDown(err error, now time.Time) error {
	s := &c.loop
	for {
		select {
		case p := <-c.ctlIn:
			if herr := c.handleControlPacket(p, now); herr != nil {
				return herr
			}
			continue
		default:
		}
		break
	}
	s.readErr = err
	s.readErrDeadline = now.Add(closeGrace)
	return nil
}

// tick runs the timers that are due.
func (c *Client) tick(now time.Time) error {
	s := &c.loop
	if s.readErr != nil {
		if !now.Before(s.readErrDeadline) {
			if !s.up && c.noTLSReply() {
				return fmt.Errorf("%w (%s)", s.readErr, noTLSReplyHint)
			}
			return s.readErr
		}
		return nil
	}
	if !s.up {
		if !now.Before(s.hsDeadline) {
			return fmt.Errorf("%w (%s)", ErrHandshakeTimeout, c.stage())
		}
		if !s.haveServerSID && !now.Before(s.connectDeadline) {
			return fmt.Errorf("%w: no reply from the server", ErrHandshakeTimeout)
		}
		if s.pushing && !s.gotPush && !now.Before(s.pushNext) {
			c.sendControlMessage(s.primary, "PUSH_REQUEST")
			s.pushNext = now.Add(c.d.pushInterval)
		}
		return nil
	}
	if s.closing {
		if !now.Before(s.closeDeadline) {
			return ErrClosed
		}
		if p := s.primary; s.exitSent && p != nil && p.adapter.pendingOut() == 0 && p.layer.Unacked() == 0 {
			return ErrClosed
		}
		return nil
	}
	if s.pingRestart > 0 && c.sinceRecv(now) >= s.pingRestart {
		return ErrPingTimeout
	}
	if s.ping > 0 && c.pingWait(now) <= 0 {
		c.pingTried.store(c.stampAt(now))
		c.sendKeepalive(func(ch *datachan.Channel, dst []byte) ([]byte, error) { return ch.SealPing(dst) })
	}
	if s.probe && c.probeWait(now) <= 0 {
		s.probeTried = c.stampAt(now)
		c.sendKeepalive(func(ch *datachan.Channel, dst []byte) ([]byte, error) { return ch.SealOCC(dst, occRequest) })
	}
	if s.lame != nil && !now.Before(s.lame.expires) {
		c.log.Debugf("openvpn: transition window over, dropping key %d", s.lame.id)
		c.dropKey(s.lame)
	}
	if ks := s.negotiating; ks != nil {
		if !now.Before(ks.deadline) {
			return fmt.Errorf("%w: renegotiation of key %d did not finish", ErrHandshakeTimeout, ks.id)
		}
	} else if c.renegotiationDue(now) {
		return c.startRenegotiation(now)
	}
	return nil
}

// noTLSReplyHint is what a TLS handshake the server never answered most
// likely means: the server dropped it for want of a common TLS version or
// cipher suite (crypto/tls has no finite-field DHE).
const noTLSReplyHint = "the server sent no TLS reply: likely no TLS version or cipher suite in common (this client cannot use DHE-only cipher suites)"

// noTLSReply reports that key 0's TLS handshake started and the server has
// not sent a single TLS byte.
func (c *Client) noTLSReply() bool {
	ks := c.loop.primary
	return ks != nil && ks.tlsStarted && ks.tlsIn == 0 && !ks.tlsDone.Load()
}

// stage names how far the handshake got, for a timeout error.
func (c *Client) stage() string {
	s := &c.loop
	ks := s.primary
	switch {
	case !s.haveServerSID:
		return "no reply from the server"
	case ks == nil || !ks.tlsStarted:
		return "waiting for the server's reset"
	case c.noTLSReply():
		return "TLS handshake: " + noTLSReplyHint
	case !ks.tlsDone.Load():
		return "the TLS handshake did not finish"
	case !ks.exchanged:
		return "the key exchange did not finish (no key-method 2 message from the server)"
	case s.pending:
		return "authentication still pending"
	default:
		return "no PUSH_REPLY"
	}
}

// pingWait is how long until a keepalive ping is due.
func (c *Client) pingWait(now time.Time) time.Duration {
	return c.loop.ping - c.sinceSendAt(c.stampAt(now))
}

// probeWait is how long until an OCC request is due: once the server has
// been silent for a quarter of ping-restart, then every twelfth of it.
func (c *Client) probeWait(now time.Time) time.Duration {
	s := &c.loop
	st := c.stampAt(now)
	return max(s.pingRestart/4-since(st, c.lastRecv.load()), s.pingRestart/12-since(st, s.probeTried))
}

func (c *Client) renegotiationDue(now time.Time) bool {
	s := &c.loop
	if s.primary == nil {
		return false
	}
	if r := c.d.opts.RenegSec; r > 0 && !now.Before(s.primary.established.Add(r)) {
		return true
	}
	if ch := c.data.Load(); ch != nil && ch.NeedsRenegotiation() {
		return true
	}
	return false
}

// nextDeadline is when the loop must wake up next.
func (c *Client) nextDeadline(now time.Time) time.Time {
	s := &c.loop
	next := now.Add(c.maxSleep)
	consider := func(t time.Time) {
		if !t.IsZero() && t.Before(next) {
			next = t
		}
	}
	if s.readErr != nil {
		consider(s.readErrDeadline)
		return next
	}
	for _, ks := range s.keys {
		consider(ks.layer.NextDeadline())
	}
	if !s.up {
		consider(s.hsDeadline)
		if !s.haveServerSID {
			consider(s.connectDeadline)
		}
		if s.pushing && !s.gotPush {
			consider(s.pushNext)
		}
		return next
	}
	if s.closing {
		consider(s.closeDeadline)
		return next
	}
	if s.pingRestart > 0 {
		consider(now.Add(s.pingRestart - c.sinceRecv(now)))
	}
	if s.ping > 0 {
		consider(now.Add(c.pingWait(now)))
	}
	if s.probe {
		consider(now.Add(c.probeWait(now)))
	}
	if s.lame != nil {
		consider(s.lame.expires)
	}
	if s.negotiating != nil {
		consider(s.negotiating.deadline)
	} else if r := c.d.opts.RenegSec; r > 0 && s.primary != nil {
		consider(s.primary.established.Add(r))
	}
	return next
}

// flush hands the TLS bytes written since the last flush to each key's
// reliability layer and puts whatever is due on the wire.
func (c *Client) flush(now time.Time) {
	s := &c.loop
	if s.readErr != nil {
		return // the transport is gone
	}
	for _, ks := range s.keys {
		for _, chunk := range ks.adapter.takeOut() {
			ks.layer.Send(wire.ControlV1, chunk)
		}
		for _, p := range ks.layer.Poll(now) {
			p.KeyID = ks.id
			p.SessionID = s.ourSID
			p.RemoteSessionID = s.serverSID
			b, err := c.wrapper.Wrap(p)
			if err != nil {
				c.log.Warnf("openvpn: wrapping %v: %v", p.Opcode, err)
				continue
			}
			if c.writeRaw(b) != nil && c.isDone() {
				return
			}
		}
	}
}

// handleControlPacket takes one authenticated control packet from the
// reader: it checks the session ids, finds (or, for a server soft reset,
// makes) the key state and feeds its reliability layer.
func (c *Client) handleControlPacket(p *wire.ControlPacket, now time.Time) error {
	s := &c.loop
	if !s.haveServerSID {
		if p.KeyID != 0 || p.Opcode != wire.ControlHardResetServerV2 {
			c.dropLog("openvpn: dropping %v key %d before the server's reset", p.Opcode, p.KeyID)
			return nil
		}
		if len(p.Acks) > 0 && p.RemoteSessionID != s.ourSID {
			c.dropLog("openvpn: dropping server reset for another session")
			return nil
		}
		s.serverSID = p.SessionID
		s.haveServerSID = true
		c.log.Debugf("openvpn: server session %x", s.serverSID[:])
	} else {
		if p.SessionID != s.serverSID {
			c.dropLog("openvpn: dropping %v from unknown session %x", p.Opcode, p.SessionID[:])
			return nil
		}
		if len(p.Acks) > 0 && p.RemoteSessionID != s.ourSID {
			c.dropLog("openvpn: dropping %v acknowledging another session", p.Opcode)
			return nil
		}
	}
	ks := c.keyByID(p.KeyID)
	if ks == nil {
		if p.Opcode != wire.ControlSoftResetV1 || !s.up || s.closing {
			c.dropLog("openvpn: dropping %v for unknown key %d", p.Opcode, p.KeyID)
			return nil
		}
		var err error
		if ks, err = c.serverRenegotiation(p.KeyID, now); err != nil {
			return err
		}
	}
	c.markRecv(now)
	for _, m := range ks.layer.Receive(p, now) {
		switch {
		case m.Opcode == wire.ControlV1:
			ks.tlsIn += len(m.Payload)
			ks.adapter.deliver(m.Payload)
		case m.Opcode.IsReset():
			if m.ID == 0 {
				ks.peerReset = true
			}
		}
	}
	c.maybeStartTLS(ks)
	return nil
}

// serverRenegotiation starts the key state for a server soft reset.
func (c *Client) serverRenegotiation(id uint8, now time.Time) (*keyState, error) {
	s := &c.loop
	if old := s.negotiating; old != nil {
		c.log.Debugf("openvpn: server renegotiates key %d, abandoning key %d", id, old.id)
		c.dropKey(old)
	}
	c.log.Infof("openvpn: server renegotiates, key %d", id)
	ks, err := c.newKeyState(id, wire.ControlSoftResetV1, now)
	if err != nil {
		return nil, err
	}
	ks.deadline = now.Add(c.d.timeout)
	s.negotiating = ks
	return ks, nil
}

// startRenegotiation soft-resets to the next key id.
func (c *Client) startRenegotiation(now time.Time) error {
	s := &c.loop
	id := nextKeyID(s.lastKeyID)
	if old := c.keyByID(id); old != nil {
		c.dropKey(old)
	}
	c.log.Infof("openvpn: renegotiating, key %d", id)
	ks, err := c.newKeyState(id, wire.ControlSoftResetV1, now)
	if err != nil {
		return err
	}
	ks.deadline = now.Add(c.d.timeout)
	s.negotiating = ks
	return nil
}

// maybeStartTLS starts the key's TLS client once the server is ready for
// it: key 0 when the server's hard reset arrived; a renegotiated key when
// the server's soft reset arrived or it acknowledged ours.
func (c *Client) maybeStartTLS(ks *keyState) {
	if ks.tlsStarted || ks.dropped {
		return
	}
	if !ks.peerReset && (ks.id == 0 || ks.layer.Unacked() != 0) {
		return
	}
	ks.tlsStarted = true
	ctx, cancel := context.WithCancel(c.ctx)
	ks.cancel = cancel
	ks.tls = tls.Client(ks.adapter, c.d.tlsConf)
	user, pass := c.credentials()
	c.wg.Add(1)
	go c.runKeyTLS(ks, ctx, user, pass)
}

// credentials are the username and password for the next key-method 2
// message: the pushed auth-token replaces the password once there is one.
func (c *Client) credentials() (user, pass string) {
	s := &c.loop
	if !s.authUserPass {
		return "", ""
	}
	if s.authToken != "" {
		user = s.username
		if s.authTokenUser != "" {
			user = s.authTokenUser
		}
		return user, s.authToken
	}
	return s.username, s.password
}

// handleKeyEvent processes what a key's TLS goroutine reports.
func (c *Client) handleKeyEvent(ev keyEvent, now time.Time) error {
	s := &c.loop
	ks := ev.ks
	if ks.dropped {
		return nil
	}
	switch ev.kind {
	case evError:
		switch {
		case !s.up || ks == s.primary:
			return fmt.Errorf("openvpn: TLS on key %d: %w", ks.id, ev.err)
		case ks == s.negotiating:
			return fmt.Errorf("openvpn: renegotiation of key %d: %w", ks.id, ev.err)
		}
		c.log.Debugf("openvpn: TLS on retiring key %d ended: %v", ks.id, ev.err)
		return nil
	case evExchanged:
		ks.exchanged = true
		ks.server, ks.cs, ks.canEKM = ev.server, ev.cs, ev.canEKM
		c.log.Debugf("openvpn: key %d exchanged (%s), server options %q", ks.id, tls.VersionName(ev.cs.Version), ev.server.Options)
		if !s.up {
			s.pushing = true
			c.sendControlMessage(ks, "PUSH_REQUEST")
			s.pushNext = now.Add(c.d.pushInterval)
			return nil
		}
		return c.activateKey(ks, now)
	case evMessage:
		return c.handleControlMessage(ev.msg, now)
	}
	return nil
}

// activateKey makes a renegotiated key the sending key; the old one is kept
// for opening during the transition window.
func (c *Client) activateKey(ks *keyState, now time.Time) error {
	s := &c.loop
	dk, err := c.dataKey(ks)
	if err != nil {
		return err
	}
	ch := c.data.Load()
	ch.SetPrimary(dk)
	if s.lame != nil {
		c.dropKey(s.lame)
	}
	old := s.primary
	old.expires = now.Add(c.d.transition)
	s.lame = old
	s.primary = ks
	s.negotiating = nil
	ks.established = now
	c.log.Infof("openvpn: key %d active (%s)", ks.id, tls.VersionName(ks.cs.Version))
	return nil
}

// sendControlMessage writes a NUL-terminated control message on a key's
// TLS session. Only called once that key's handshake is complete, so the
// write never waits for the control loop.
func (c *Client) sendControlMessage(ks *keyState, msg string) {
	if ks == nil || ks.tls == nil || !ks.exchanged {
		return
	}
	b := make([]byte, len(msg)+1)
	copy(b, msg)
	if _, err := ks.tls.Write(b); err != nil {
		c.log.Debugf("openvpn: sending %s on key %d: %v", msg, ks.id, err)
	}
}

// occRequest is the OCC_REQUEST opcode: the server answers OCC_REPLY.
const occRequest = 0

// sendKeepalive seals and sends a keepalive ping or OCC request, unless a
// write is in progress (it carries something, and may be blocked on a
// stalled TCP connection).
func (c *Client) sendKeepalive(seal func(ch *datachan.Channel, dst []byte) ([]byte, error)) {
	ch := c.data.Load()
	if ch == nil {
		return
	}
	bp := sealPool.Get().(*[]byte)
	defer sealPool.Put(bp)
	pkt, err := seal(ch, (*bp)[:0])
	if err != nil {
		c.log.Debugf("openvpn: sealing a keepalive: %v", err)
		return
	}
	_, _ = c.tryWriteRaw(pkt)
	*bp = pkt[:0]
}

// beginClose tells the server the client is leaving, if it can, and lets
// the loop wait briefly for that to be delivered.
func (c *Client) beginClose(now time.Time) error {
	s := &c.loop
	if !s.up {
		return ErrClosed
	}
	s.closing = true
	s.closeDeadline = now.Add(closeGrace)
	if s.ccExit && s.primary != nil && s.primary.exchanged {
		c.sendControlMessage(s.primary, "EXIT")
		s.exitSent = true
		return nil
	}
	if !c.tcp && s.exitNotify > 0 {
		if ch := c.data.Load(); ch != nil {
			var buf []byte
			for range min(s.exitNotify, maxExitNotify) {
				pkt, err := ch.SealOCC(buf[:0], datachan.OCCExit)
				if err != nil {
					break
				}
				buf = pkt
				if c.writeRaw(pkt) != nil && c.isDone() {
					break
				}
			}
		}
	}
	return ErrClosed
}
