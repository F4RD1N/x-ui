package openvpn

import (
	"context"
	goerrors "errors"
	gonet "net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/transport"
)

// errTunnelGone ends a TCP relay whose stream ended because the tunnel went
// away under it, not because the far end said so.
var errTunnelGone = goerrors.New("the OpenVPN tunnel closed")

// tcpRelay carries one TCP connection between an Xray link and a connection
// inside the tunnel, each direction ending on its own, as on the plain IP
// link a stock OpenVPN client gives:
//
//   - The client ends its side first (the link's reader ends without an
//     error): the destination is sent a FIN and its reply keeps flowing to
//     the client until it ends its side too. That wait is held to the
//     connection-idle timeout, not DownlinkOnly: a destination learns that
//     the request is complete only from the FIN, and may take any time to
//     answer it. The inbound's own timer, which the inbound set to
//     DownlinkOnly before it ended the link, is raised back to the inbound's
//     connection-idle timeout (as splicing outbounds adjust it): otherwise
//     the inbound would drop the reply after DownlinkOnly anyway. The
//     inbound ends the link, and sets DownlinkOnly, as soon as the last of
//     the request is in the link, which may be long before that data is in
//     the stack: a destination slow to read holds it in the link and in a
//     blocked stack write. Until the FIN goes out, every write into the
//     stack therefore counts as activity on the inbound's timer, and so does
//     every half DownlinkOnly that one write stays blocked (inboundFeeder).
//     Waiting for more of the request does not: an idle client still ends
//     on the inbound's own timeouts.
//   - The destination ends its side first (FIN): the link's writer is closed
//     and the client's data keeps going to the destination until the client
//     ends its side. An inbound which dispatches socket links directly
//     delegates its UplinkOnly idle policy to this relay; an inbound with
//     its own timer continues to enforce that policy itself.
//   - A connection that cannot be half-closed ends as before: DownlinkOnly
//     once the client's side ended. So does a mux stream (noHalfClose): the
//     end of its request is a mux End or the end of the mux connection,
//     either of which also closes the stream's reply direction, so no reply
//     could reach the client after a FIN.
//
// An error in either direction, the idle timeout, cancellation or the end of
// the tunnel ends the whole connection (Process).
type tcpRelay struct {
	conn         gonet.Conn
	link         *transport.Link
	timer        *signal.ActivityTimer // the connection's idle timer
	tun          *tunnel
	downlinkOnly time.Duration
	// noHalfClose: the end of the link's reader closes both directions (a
	// mux stream), and is not passed on as a FIN.
	noHalfClose       bool
	ownHalfCloseTimer bool
	uplinkOnly        time.Duration

	// inTimer is the inbound's timer, nil when there is none to hold, inIdle
	// its connection-idle timeout and inTick how often a blocked write into
	// the stack feeds it (half the inbound's DownlinkOnly; 0: never).
	inTimer *signal.ActivityTimer
	inIdle  time.Duration
	inTick  time.Duration

	mu sync.Mutex
	// downDone is set once the link's writer is about to be closed or
	// interrupted: from then on the inbound sets its own final timeout, and
	// its timer is no longer touched.
	downDone bool
}

// uplink copies the client's data to the destination; on the client's end
// it half-closes the connection.
func (r *tcpRelay) uplink() error {
	w := newStackWriter(r.conn)
	if r.inTimer != nil && r.inTick > 0 {
		w = &inboundFeeder{w: w, r: r}
	}
	if err := buf.Copy(r.link.Reader, w, buf.UpdateActivity(r.timer)); err != nil {
		return err
	}
	if !r.tun.alive() {
		return errTunnelGone
	}
	cw, ok := r.conn.(interface{ CloseWrite() error })
	if r.noHalfClose || !ok || cw.CloseWrite() != nil {
		r.timer.SetTimeout(r.downlinkOnly)
		return nil
	}
	// The FIN is on its way. Our own timer stays at the connection-idle
	// timeout; the inbound's comes back to its own.
	r.mu.Lock()
	if !r.downDone && r.inTimer != nil {
		r.inTimer.SetTimeout(r.inIdle)
	}
	r.mu.Unlock()
	return nil
}

// feedInbound counts as activity on the inbound's timer, until the link's
// writer ends.
func (r *tcpRelay) feedInbound() {
	r.mu.Lock()
	if !r.downDone && r.inTimer != nil {
		r.inTimer.Update()
	}
	r.mu.Unlock()
}

// inboundFeeder writes the request into the stack and feeds the inbound's
// timer meanwhile: before and after every write, and every inTick while one
// write is blocked (the destination is not reading). The tick runs only
// while a write is in progress, so an idle connection has none.
type inboundFeeder struct {
	w buf.Writer
	r *tcpRelay

	mu      sync.Mutex
	writing bool
	tick    *time.Timer
}

// WriteMultiBuffer implements buf.Writer.
func (f *inboundFeeder) WriteMultiBuffer(mb buf.MultiBuffer) error {
	f.r.feedInbound()
	f.mu.Lock()
	f.writing = true
	if f.tick == nil {
		f.tick = time.AfterFunc(f.r.inTick, f.onTick)
	} else {
		f.tick.Reset(f.r.inTick)
	}
	f.mu.Unlock()

	err := f.w.WriteMultiBuffer(mb)

	f.mu.Lock()
	f.writing = false
	f.tick.Stop()
	f.mu.Unlock()
	f.r.feedInbound()
	return err
}

func (f *inboundFeeder) onTick() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.writing {
		return
	}
	f.r.feedInbound()
	f.tick.Reset(f.r.inTick)
}

// downlink copies the destination's data to the client until the
// destination ends its side. The caller closes the link's writer after it.
func (r *tcpRelay) downlink() error {
	defer r.endDownlink()
	if err := buf.Copy(buf.NewReader(r.conn), r.link.Writer, buf.UpdateActivity(r.timer)); err != nil {
		return err
	}
	if !r.tun.alive() {
		return errTunnelGone
	}
	if r.ownHalfCloseTimer {
		r.timer.SetTimeout(r.uplinkOnly)
	}
	return nil
}

// endDownlink marks the link's writer as ending. It must come before the
// writer is closed or interrupted.
func (r *tcpRelay) endDownlink() {
	r.mu.Lock()
	r.downDone = true
	r.mu.Unlock()
}

// inboundTimer is the timer of the inbound whose link Process carries, with
// the inbound's connection-idle and DownlinkOnly timeouts; nil when there is
// none of its own: no inbound timer, a request chained through another
// outbound (the link is that outbound's, not the inbound's), or a mux stream
// (the timer is the whole mux connection's; the mux server marks every
// stream, and sets TimeoutOnly on XUDP ones).
func (h *Handler) inboundTimer(ctx context.Context) (timer *signal.ActivityTimer, idle, downlinkOnly time.Duration) {
	in := session.InboundFromContext(ctx)
	if in == nil || in.Timer == nil || session.TimeoutOnlyFromContext(ctx) || session.MuxStreamFromContext(ctx) || len(session.OutboundsFromContext(ctx)) != 1 {
		return nil, 0, 0
	}
	var level uint32
	if in.User != nil {
		level = in.User.Level
	}
	t := h.policyManager.ForLevel(level).Timeouts
	return in.Timer, t.ConnectionIdle, t.DownlinkOnly
}

// feedInterval is how often a blocked write feeds a timer that runs out
// after downlinkOnly without activity: twice within it. 0 when nothing can
// keep that timer (it ends the connection at once).
func feedInterval(downlinkOnly time.Duration) time.Duration {
	if downlinkOnly <= 0 {
		return 0
	}
	return max(downlinkOnly/2, 10*time.Millisecond)
}
