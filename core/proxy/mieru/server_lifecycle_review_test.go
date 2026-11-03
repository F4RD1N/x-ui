package mieru

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/nativebridge"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestReviewActiveRevocationAndReadd(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			s := nativeTestServer(t, network, nativeTestUser("review-user", "review-password", "review@test", false))
			d := &nativeEchoDispatcher{}
			c, _, done := nativeConnect(t, s, network, "review-user", "review-password", false, d, nil)
			addr, _ := nativebridge.Address(xnet.TCPDestination(xnet.DomainAddress("before-revoke.invalid"), 443))
			if e := socksRequest(c, 1, addr); e != nil {
				t.Fatal(e)
			}
			if e := s.RemoveUser(context.Background(), "review@test"); e != nil {
				t.Fatal(e)
			}
			replacement, e := nativeTestUser("review-user", "review-password", "review@test", false).ToMemoryUser()
			if e != nil {
				t.Fatal(e)
			}
			if e = s.AddUser(context.Background(), replacement); e != nil {
				t.Fatal(e)
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("revoked underlay remained active after same-credential re-add")
			}
			// A re-added account is a new generation. The old transport cannot use it
			// to open another destination, even though its password has the same bytes.
			_ = c.wire.write(segment{kind: openRequest, session: c.sid + 1})
			request := append([]byte{5, 1, 0}, addr...)
			_ = c.wire.write(segment{kind: dataClient, session: c.sid + 1, seq: 1, payload: request})
			if len(d.snapshot()) != 1 {
				t.Fatal("revoked underlay reached another route")
			}
			fresh, _, _ := nativeConnect(t, s, network, "review-user", "review-password", false, d, nil)
			if e = socksRequest(fresh, 1, addr); e != nil {
				t.Fatal("fresh account generation could not connect", e)
			}
			if len(d.snapshot()) != 2 {
				t.Fatal("fresh generation route missing")
			}
		})
	}
}

// suffixGate pauses after the initial authenticated 72-byte envelope, when the
// server has selected a user but has not validated the complete opening frame.
type suffixGate struct {
	net.Conn
	bytes                  int
	ready, release, closed chan struct{}
	readyOnce, closeOnce   sync.Once
}

func (g *suffixGate) Read(p []byte) (int, error) {
	if g.bytes >= 72 {
		g.readyOnce.Do(func() { close(g.ready) })
		select {
		case <-g.release:
		case <-g.closed:
			return 0, net.ErrClosed
		}
	}
	if g.bytes < 72 && len(p) > 72-g.bytes {
		p = p[:72-g.bytes]
	}
	n, e := g.Conn.Read(p)
	g.bytes += n
	return n, e
}
func (g *suffixGate) Close() error {
	var e error
	g.closeOnce.Do(func() { close(g.closed); e = g.Conn.Close() })
	return e
}
func TestReviewRemovalDuringOpeningCannotAdmitOldGeneration(t *testing.T) {
	s := nativeTestServer(t, "tcp", nativeTestUser("review-user", "review-password", "review@test", false))
	raw, server := nativeUnderlay(t, "tcp")
	gate := &suffixGate{Conn: server, ready: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
	d := &nativeEchoDispatcher{}
	_, done := nativeRunProcess(t, s, "tcp", gate, d)
	w, e := newWire(raw, "review-user", "review-password", false, false)
	if e != nil {
		t.Fatal(e)
	}
	if e = w.write(segment{kind: openRequest, session: 123}); e != nil {
		t.Fatal(e)
	}
	select {
	case <-gate.ready:
	case <-time.After(time.Second):
		t.Fatal("opening did not reach admission gate")
	}
	if e = s.RemoveUser(context.Background(), "review@test"); e != nil {
		t.Fatal(e)
	}
	u, e := nativeTestUser("review-user", "review-password", "review@test", false).ToMemoryUser()
	if e != nil {
		t.Fatal(e)
	}
	if e = s.AddUser(context.Background(), u); e != nil {
		t.Fatal(e)
	}
	close(gate.release)
	select {
	case e = <-done:
		if e == nil {
			t.Fatal("revoked in-flight generation authenticated")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("revoked opening did not terminate")
	}
	if len(d.snapshot()) != 0 {
		t.Fatal("revoked in-flight account reached routing")
	}
}

// reviewStreamDispatcher sends a response stream independently of client input.
// A TCP transfer has no Mieru-level acknowledgements to hide one-way idleness.
type reviewStreamDispatcher struct {
	nativeEchoDispatcher
	interval time.Duration
	count    int
	wg       sync.WaitGroup
}

func (d *reviewStreamDispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
	if e := d.record(ctx, dest); e != nil {
		return nil, e
	}
	upR, upW := pipe.New()
	downR, downW := pipe.New()
	context.AfterFunc(ctx, func() { common.Interrupt(upR); common.Interrupt(upW); common.Interrupt(downR); common.Interrupt(downW) })
	d.wg.Add(2)
	go func() {
		defer d.wg.Done()
		for {
			mb, e := upR.ReadMultiBuffer()
			buf.ReleaseMulti(mb)
			if e != nil {
				return
			}
		}
	}()
	go func() {
		defer d.wg.Done()
		defer common.Close(downW)
		ticker := time.NewTicker(d.interval)
		defer ticker.Stop()
		for i := 0; i < d.count; i++ {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			b := buf.FromBytes([]byte{byte(i)})
			if dest.Network == xnet.Network_UDP {
				target := dest
				b.UDP = &target
			}
			if e := downW.WriteMultiBuffer(buf.MultiBuffer{b}); e != nil {
				return
			}
		}
	}()
	return &transport.Link{Reader: downR, Writer: upW}, nil
}
func TestReviewOneWayTCPDownloadKeepsUnderlayAlive(t *testing.T) {
	s := nativeTestServer(t, "tcp", nativeTestUser("review-user", "review-password", "review@test", false))
	s.underlayIdle = 100 * time.Millisecond
	d := &reviewStreamDispatcher{interval: 30 * time.Millisecond, count: 20}
	c, cancel, _ := nativeConnect(t, s, "tcp", "review-user", "review-password", false, d, nil)
	defer func() { cancel(); c.abort(net.ErrClosed); d.wg.Wait() }()
	addr, _ := nativebridge.Address(xnet.TCPDestination(xnet.DomainAddress("one-way.invalid"), 443))
	if e := socksRequest(c, 1, addr); e != nil {
		t.Fatal(e)
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, d.count)
	if _, e := io.ReadFull(c, got); e != nil {
		t.Fatalf("active one-way download terminated: %v", e)
	}
	want := make([]byte, d.count)
	for i := range want {
		want[i] = byte(i)
	}
	if !bytes.Equal(want, got) {
		t.Fatal("download corrupted")
	}
}

type reviewShortPolicy struct{ policy.DefaultManager }

func (reviewShortPolicy) ForLevel(uint32) policy.Session {
	p := policy.DefaultManager{}.ForLevel(0)
	p.Timeouts.ConnectionIdle = 100 * time.Millisecond
	return p
}
func TestReviewUDPResponsesKeepAssociationAndRouteAlive(t *testing.T) {
	s := nativeTestServer(t, "tcp", nativeTestUser("review-user", "review-password", "review@test", false))
	s.underlayIdle = 120 * time.Millisecond
	s.policy = reviewShortPolicy{}
	d := &reviewStreamDispatcher{interval: 30 * time.Millisecond, count: 20}
	c, cancel, _ := nativeConnect(t, s, "tcp", "review-user", "review-password", false, d, nil)
	defer func() { cancel(); c.abort(net.ErrClosed); d.wg.Wait() }()
	addr, _ := nativebridge.Address(xnet.UDPDestination(xnet.AnyIP, 0))
	if e := socksRequest(c, 3, addr); e != nil {
		t.Fatal(e)
	}
	packets := &packetConn{Conn: c}
	target := xnet.UDPDestination(xnet.DomainAddress("one-way-udp.invalid"), 5353)
	if e := packets.WritePacket([]byte("start"), target); e != nil {
		t.Fatal(e)
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	for i := 0; i < 20; i++ {
		data, from, e := packets.ReadPacket()
		if e != nil {
			t.Fatalf("UDP response %d: %v", i, e)
		}
		if len(data) != 1 || data[0] != byte(i) || from.String() != target.String() {
			t.Fatal("UDP response corrupted")
		}
		if i == 10 {
			if e = packets.WritePacket([]byte("keep same destination"), target); e != nil {
				t.Fatal(e)
			}
		}
	}
	if got := len(d.snapshot()); got != 1 {
		t.Fatalf("active response route was evicted/reopened (%d dispatches)", got)
	}
}

var _ routing.Dispatcher = (*reviewStreamDispatcher)(nil)

type reviewDiscardConn struct{ net.Conn }

func (reviewDiscardConn) Write(p []byte) (int, error) { return len(p), nil }
func (reviewDiscardConn) Close() error                { return nil }
func TestReviewUDPByteBudgetReservesMissingGap(t *testing.T) {
	w, e := newWire(reviewDiscardConn{}, "review-user", "review-password", true, false)
	if e != nil {
		t.Fatal(e)
	}
	w.server = true
	c := &Conn{wire: w, sid: 1, next: 1, expected: 1, ooo: map[uint32][]byte{}, done: make(chan struct{}), opened: make(chan struct{}), kick: make(chan struct{}, 1), peerWindow: 128, cwnd: 32, ssthresh: 128}
	c.cond = sync.NewCond(&c.mu)
	defer c.abort(net.ErrClosed)
	// Four legal 32KiB out-of-order records can consume the whole byte budget.
	// At least one must be left unacknowledged so sequence1 can fill the gap.
	for seq := uint32(2); seq <= 5; seq++ {
		c.receiveUDP(segment{kind: dataClient, session: 1, seq: seq, payload: make([]byte, 32768)})
	}
	c.receiveUDP(segment{kind: dataClient, session: 1, seq: 1, payload: make([]byte, 32768)})
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.expected == 1 {
		t.Fatalf("missing packet cannot enter full OOO budget: queued=%d out-of-order=%d", c.queued, c.oooBytes)
	}
	if c.queued+c.oooBytes > serverUDPReceiveBytes {
		t.Fatal("byte budget exceeded while filling gap")
	}
}
