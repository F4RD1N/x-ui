package mieru

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/nativebridge"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/pipe"
)

type nativeDispatchRecord struct {
	destination xnet.Destination
	email       string
	level       uint32
	inbound     *session.Inbound
	content     *session.Content
	outbound    *session.Outbound
}

// The echo dispatcher deliberately does not dial: successful transfers prove
// the inbound handed traffic to Xray's configured dispatcher, including each
// UDP destination, instead of opening an unaccounted direct socket.
type nativeEchoDispatcher struct {
	mu      sync.Mutex
	records []nativeDispatchRecord
	deny    bool
}

func (*nativeEchoDispatcher) Type() interface{} { return routing.DispatcherType() }
func (*nativeEchoDispatcher) Start() error      { return nil }
func (*nativeEchoDispatcher) Close() error      { return nil }
func (d *nativeEchoDispatcher) record(ctx context.Context, dest xnet.Destination) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	r := nativeDispatchRecord{destination: dest, inbound: session.InboundFromContext(ctx), content: session.ContentFromContext(ctx)}
	if outs := session.OutboundsFromContext(ctx); len(outs) > 0 {
		r.outbound = outs[0]
	}
	if in := session.InboundFromContext(ctx); in != nil && in.User != nil {
		r.email, r.level = in.User.Email, in.User.Level
	}
	d.records = append(d.records, r)
	if d.deny {
		return errors.New("synthetic routing rejection")
	}
	return nil
}
func (d *nativeEchoDispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
	if err := d.record(ctx, dest); err != nil {
		return nil, err
	}
	r, w := pipe.New()
	return &transport.Link{Reader: r, Writer: w}, nil
}
func (d *nativeEchoDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	if err := d.record(ctx, dest); err != nil {
		return err
	}
	return buf.Copy(link.Reader, link.Writer)
}
func (d *nativeEchoDispatcher) snapshot() []nativeDispatchRecord {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]nativeDispatchRecord(nil), d.records...)
}

func nativeTestUser(username, password, email string, custom bool) *protocol.User {
	return &protocol.User{Email: email, Level: 7, Account: serial.ToTypedMessage(&Account{Username: username, Password: password, UuidMetadataTrailer: custom})}
}
func nativeTestServer(t *testing.T, network string, users ...*protocol.User) *Server {
	t.Helper()
	v := new(core.Instance)
	if err := v.AddFeature(policy.DefaultManager{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Close() })
	ctx := context.WithValue(context.Background(), core.XrayKey(1), v)
	s, err := NewServer(ctx, &ServerConfig{Users: users, Transport: network, HandshakeTimeout: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closer, ok := interface{}(s).(interface{ Close() error }); ok {
			_ = closer.Close()
		}
	})
	return s
}

// Xray's actual UDP worker has a Read method that panics and exposes packet
// buffers through ReadMultiBuffer. Its deadlines are no-ops. Reproduce that
// contract so a superficially passing plain-UDPConn test cannot hide a runtime
// incompatibility in the native inbound.
type nativeWorkerUDP struct{ net.Conn }

func (*nativeWorkerUDP) Read([]byte) (int, error) { panic("Xray UDP worker Read must not be called") }
func (c *nativeWorkerUDP) ReadMultiBuffer() (buf.MultiBuffer, error) {
	p := make([]byte, 65535)
	n, err := c.Conn.Read(p)
	if err != nil {
		return nil, err
	}
	return buf.MultiBuffer{buf.FromBytes(p[:n])}, nil
}
func (*nativeWorkerUDP) SetDeadline(time.Time) error      { return nil }
func (*nativeWorkerUDP) SetReadDeadline(time.Time) error  { return nil }
func (*nativeWorkerUDP) SetWriteDeadline(time.Time) error { return nil }

func nativeUnderlay(t *testing.T, network string) (net.Conn, net.Conn) {
	t.Helper()
	if network == "tcp" {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		client, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		server, err := ln.Accept()
		if err != nil {
			client.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
		return client, server
	}
	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	c := &internet.PacketConnWrapper{PacketConn: client, Dest: server.LocalAddr()}
	s := &internet.PacketConnWrapper{PacketConn: server, Dest: client.LocalAddr()}
	return c, &nativeWorkerUDP{Conn: s}
}

func nativeRunProcess(t *testing.T, s *Server, network string, raw net.Conn, d routing.Dispatcher) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Tag: "native-test", Source: xnet.DestinationFromAddr(raw.RemoteAddr()), Gateway: xnet.DestinationFromAddr(raw.LocalAddr())})
	ctx = session.ContextWithContent(ctx, &session.Content{Protocol: "seed", Attributes: map[string]string{"original": "untouched"}})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Tag: "seed"}})
	done := make(chan error, 1)
	n := xnet.Network_TCP
	if network == "udp" {
		n = xnet.Network_UDP
	}
	go func() { defer close(done); done <- s.Process(ctx, n, raw, d) }()
	t.Cleanup(func() {
		cancel()
		_ = raw.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("native server Process did not stop")
		}
	})
	return cancel, done
}

func nativeConnect(t *testing.T, s *Server, network, username, password string, custom bool, d routing.Dispatcher, wrap func(net.Conn) net.Conn) (*Conn, context.CancelFunc, <-chan error) {
	t.Helper()
	raw, server := nativeUnderlay(t, network)
	cancel, done := nativeRunProcess(t, s, network, server, d)
	_ = raw.SetDeadline(time.Now().Add(8 * time.Second))
	if wrap != nil {
		raw = wrap(raw)
	}
	w, err := newWire(raw, username, password, network == "udp", custom)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Open(w)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.abort(net.ErrClosed) })
	return c, cancel, done
}

func TestNativeServerTCPAndUDPRouting(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		for _, custom := range []bool{false, true} {
			for _, inner := range []string{"tcp", "udp"} {
				t.Run(fmt.Sprintf("%s/%s/custom=%v", network, inner, custom), func(t *testing.T) {
					username := "synthetic-user"
					if custom {
						username = "a3ac6533-7c27-45c4-93f2-9192745e218b"
					}
					s := nativeTestServer(t, network, nativeTestUser("unused", "different-password", "other@test", false), nativeTestUser(username, "synthetic-password", "selected@test", custom))
					d := &nativeEchoDispatcher{}
					c, _, _ := nativeConnect(t, s, network, username, "synthetic-password", custom, d, nil)
					target := xnet.TCPDestination(xnet.DomainAddress("route-target.invalid"), 443)
					if inner == "tcp" {
						addr, _ := nativebridge.Address(target)
						if err := socksRequest(c, 1, addr); err != nil {
							t.Fatal(err)
						}
						want := bytes.Repeat([]byte("native routed TCP payload\x00"), 1600)
						written := make(chan error, 1)
						go func() { _, err := c.Write(want); written <- err }()
						got := make([]byte, len(want))
						if _, err := io.ReadFull(c, got); err != nil {
							t.Fatal(err)
						}
						if err := <-written; err != nil {
							t.Fatal(err)
						}
						if !bytes.Equal(got, want) {
							t.Fatal("TCP payload corrupted")
						}
					} else {
						addr, _ := nativebridge.Address(xnet.UDPDestination(xnet.AnyIP, 0))
						if err := socksRequest(c, 3, addr); err != nil {
							t.Fatal(err)
						}
						pc := &packetConn{Conn: c}
						for _, a := range []xnet.Address{xnet.DomainAddress("first.invalid"), xnet.ParseAddress("192.0.2.18"), xnet.ParseAddress("2001:db8::12")} {
							target = xnet.UDPDestination(a, 5353)
							want := []byte("UDP must follow the selected destination: " + a.String())
							if err := pc.WritePacket(want, target); err != nil {
								t.Fatal(err)
							}
							got, reply, err := pc.ReadPacket()
							if err != nil {
								t.Fatal(err)
							}
							if !bytes.Equal(want, got) || reply.Address.String() != target.Address.String() || reply.Port != target.Port {
								t.Fatalf("UDP response mismatch %q %v", got, reply)
							}
						}
					}
					records := d.snapshot()
					wantRecords := 1
					if inner == "udp" {
						wantRecords = 3
					}
					if len(records) != wantRecords {
						t.Fatalf("dispatch count=%d want=%d", len(records), wantRecords)
					}
					if inner == "udp" {
						for i := 1; i < len(records); i++ {
							if records[i].inbound == records[0].inbound || records[i].content == records[0].content || records[i].outbound == records[0].outbound {
								t.Fatal("UDP destinations share mutable routing context")
							}
						}
						records[0].content.Attributes["original"] = "changed"
						if records[1].content.Attributes["original"] != "untouched" {
							t.Fatal("UDP destinations share content attributes")
						}
					}
					for _, r := range records {
						if r.email != "selected@test" || r.level != 7 {
							t.Fatalf("missing authenticated user context: %+v", r)
						}
					}
				})
			}
		}
	}
}

func TestNativeServerRejectsWrongAuth(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		for _, tc := range []struct {
			name, user, password      string
			requireCustom, sendCustom bool
		}{
			{"password", "synthetic-user", "wrong-password", false, false},
			{"username", "unknown-user", "synthetic-password", false, false},
			{"missing-trailer", "a3ac6533-7c27-45c4-93f2-9192745e218b", "synthetic-password", true, false},
			{"unexpected-trailer", "a3ac6533-7c27-45c4-93f2-9192745e218b", "synthetic-password", false, true},
		} {
			t.Run(network+"/"+tc.name, func(t *testing.T) {
				user := "synthetic-user"
				if tc.name == "missing-trailer" || tc.name == "unexpected-trailer" {
					user = tc.user
				}
				s := nativeTestServer(t, network, nativeTestUser(user, "synthetic-password", "auth@test", tc.requireCustom))
				d := &nativeEchoDispatcher{}
				raw, server := nativeUnderlay(t, network)
				nativeRunProcess(t, s, network, server, d)
				_ = raw.SetDeadline(time.Now().Add(500 * time.Millisecond))
				w, err := newWire(raw, tc.user, tc.password, network == "udp", tc.sendCustom)
				if err != nil {
					t.Fatal(err)
				}
				c, err := Open(w)
				if err == nil {
					defer c.abort(net.ErrClosed)
					addr, _ := nativebridge.Address(xnet.TCPDestination(xnet.DomainAddress("forbidden.invalid"), 443))
					err = socksRequest(c, 1, addr)
				}
				if err == nil {
					t.Fatal("invalid authentication was accepted")
				}
				if got := d.snapshot(); len(got) != 0 {
					t.Fatalf("unauthenticated client reached routing: %+v", got)
				}
			})
		}
	}
}

func TestNativeServerCancellationStopsBlockedRead(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		for _, connected := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/established=%v", network, connected), func(t *testing.T) {
				s := nativeTestServer(t, network, nativeTestUser("synthetic-user", "synthetic-password", "cancel@test", false))
				d := &nativeEchoDispatcher{}
				var cancel context.CancelFunc
				var done <-chan error
				if connected {
					var c *Conn
					c, cancel, done = nativeConnect(t, s, network, "synthetic-user", "synthetic-password", false, d, nil)
					addr, _ := nativebridge.Address(xnet.TCPDestination(xnet.DomainAddress("cancel.invalid"), 80))
					if err := socksRequest(c, 1, addr); err != nil {
						t.Fatal(err)
					}
				} else {
					_, raw := nativeUnderlay(t, network)
					cancel, done = nativeRunProcess(t, s, network, raw, d)
				}
				cancel()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("cancellation did not end server Process")
				}
			})
		}
	}
}

// Each fault is deterministic and applied once. Reordering sends the next
// packet before the held one; a later retransmit also releases a final held
// packet. The reliable session must repair this without duplicating bytes.
type nativeFaultConn struct {
	net.Conn
	mu     sync.Mutex
	writes int
	held   []byte
}

func (c *nativeFaultConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	if c.writes == 3 || c.writes == 7 {
		return len(p), nil
	}
	if c.writes == 9 {
		c.held = append([]byte(nil), p...)
		return len(p), nil
	}
	n, err := c.Conn.Write(p)
	if err == nil && c.writes == 11 {
		_, err = c.Conn.Write(p)
	}
	if err == nil && c.held != nil {
		_, err = c.Conn.Write(c.held)
		c.held = nil
	}
	return n, err
}
func TestNativeServerUDPLossReorderDuplicateBulk(t *testing.T) {
	s := nativeTestServer(t, "udp", nativeTestUser("synthetic-user", "synthetic-password", "loss@test", false))
	d := &nativeEchoDispatcher{}
	c, _, _ := nativeConnect(t, s, "udp", "synthetic-user", "synthetic-password", false, d, func(raw net.Conn) net.Conn { return &nativeFaultConn{Conn: raw} })
	addr, _ := nativebridge.Address(xnet.TCPDestination(xnet.DomainAddress("loss.invalid"), 443))
	if err := socksRequest(c, 1, addr); err != nil {
		t.Fatal(err)
	}
	want := randomBytes(256 * 1024)
	written := make(chan error, 1)
	go func() { _, err := c.Write(want); written <- err }()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, got) {
		t.Fatal("loss/reorder transfer corrupted")
	}
}

// downlinkDispatcher hands back a link whose downlink the test drives directly
// and whose uplink it ignores, so a test can push data the mieru client never
// reads and observe whether the wire reader keeps draining the underlay.
type downlinkDispatcher struct{ ready chan buf.Writer }

func (*downlinkDispatcher) Type() interface{} { return routing.DispatcherType() }
func (*downlinkDispatcher) Start() error      { return nil }
func (*downlinkDispatcher) Close() error      { return nil }
func (d *downlinkDispatcher) Dispatch(context.Context, xnet.Destination) (*transport.Link, error) {
	downR, downW := pipe.New()
	_, upW := pipe.New()
	d.ready <- downW
	return &transport.Link{Reader: downR, Writer: upW}, nil
}
func (*downlinkDispatcher) DispatchLink(context.Context, xnet.Destination, *transport.Link) error {
	return errors.New("downlinkDispatcher does not dial")
}

// On the TCP underlay the sole wire reader must keep draining into a bounded
// buffer even while the application is not reading, so a transiently slow
// consumer on one direction cannot stall the other and truncate a full-duplex
// stream. The old code required the receive queue to fully empty before the
// next segment was delivered, so the reader stopped after the first segment
// and left the rest stuck in the underlay.
func TestNativeServerTCPReaderKeepsDrainingWhileAppIsSlow(t *testing.T) {
	s := nativeTestServer(t, "tcp", nativeTestUser("synthetic-user", "synthetic-password", "drain@test", false))
	d := &downlinkDispatcher{ready: make(chan buf.Writer, 1)}
	c, _, _ := nativeConnect(t, s, "tcp", "synthetic-user", "synthetic-password", false, d, nil)
	addr, _ := nativebridge.Address(xnet.TCPDestination(xnet.DomainAddress("drain.invalid"), 443))
	if err := socksRequest(c, 1, addr); err != nil {
		t.Fatal(err)
	}
	var downW buf.Writer
	select {
	case downW = <-d.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("dispatcher was not invoked")
	}
	// Push many distinct downlink segments the application never reads; each
	// small write with a gap becomes its own mieru segment.
	const seg = 2 << 10
	const count = 32
	const total = seg * count
	go func() {
		for i := 0; i < count; i++ {
			b := buf.New()
			_, _ = b.Write(randomBytes(seg))
			if downW.WriteMultiBuffer(buf.MultiBuffer{b}) != nil {
				return
			}
			time.Sleep(3 * time.Millisecond)
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	var queued int
	for time.Now().Before(deadline) {
		c.mu.Lock()
		queued = c.queued
		c.mu.Unlock()
		if queued >= total {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if queued < total {
		t.Fatalf("wire reader stalled with the app not reading: buffered %d of %d bytes", queued, total)
	}
}

// When a TCP session's pending receive budget is full, the shared underlay
// reader must backpressure (pause) until the session drains, never abort the
// session. Aborting left the client hung waiting for a reply the underlay
// never delivered, truncating a full-duplex transfer.
func TestInboundSessionBackpressuresInsteadOfAborting(t *testing.T) {
	s := &inboundSession{done: make(chan struct{}), incoming: make(chan segment, 256), room: make(chan struct{}, 1), budget: new(atomic.Int64)}
	payload := make([]byte, 1000)
	for s.enqueue(segment{payload: payload}) {
	}
	// A further segment must block, not drop or abort.
	blocked := make(chan bool, 1)
	go func() { blocked <- s.enqueueBlocking(segment{payload: payload}, nil) }()
	select {
	case <-blocked:
		t.Fatal("enqueueBlocking returned while full; it must backpressure")
	case <-time.After(150 * time.Millisecond):
	}
	// Draining one segment frees capacity; the blocked enqueue must resume.
	s.dequeue(<-s.incoming)
	select {
	case ok := <-blocked:
		if !ok {
			t.Fatal("enqueueBlocking failed after capacity was freed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("enqueueBlocking did not resume after a dequeue")
	}
	// A full-queue enqueueBlocking must give up once the session ends.
	for s.enqueue(segment{payload: payload}) {
	}
	ended := make(chan bool, 1)
	go func() { ended <- s.enqueueBlocking(segment{payload: payload}, nil) }()
	time.Sleep(50 * time.Millisecond)
	close(s.done)
	select {
	case ok := <-ended:
		if ok {
			t.Fatal("enqueueBlocking reported success for an ended session")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("enqueueBlocking did not return after the session ended")
	}
}

// Reaching the per-session UDP destination cap must evict only the coldest
// flow, never tear down the whole session. Fanning out past the cap once
// returned an error whose deferred cleanup closed the session and dropped
// every working destination with it.
func TestNativeServerUDPDestinationCapEvictsLRU(t *testing.T) {
	s := nativeTestServer(t, "udp", nativeTestUser("synthetic-user", "synthetic-password", "fanout@test", false))
	d := &nativeEchoDispatcher{}
	c, _, _ := nativeConnect(t, s, "udp", "synthetic-user", "synthetic-password", false, d, nil)
	addr, _ := nativebridge.Address(xnet.UDPDestination(xnet.AnyIP, 0))
	if err := socksRequest(c, 3, addr); err != nil {
		t.Fatal(err)
	}
	pc := &packetConn{Conn: c}
	_ = c.SetReadDeadline(time.Now().Add(20 * time.Second))
	const dests = maxUDPDestinations + 6
	for i := 0; i < dests; i++ {
		target := xnet.UDPDestination(xnet.ParseAddress(fmt.Sprintf("192.0.2.%d", i+1)), 5353)
		want := []byte(fmt.Sprintf("fan-out datagram %d", i))
		if err := pc.WritePacket(want, target); err != nil {
			t.Fatalf("write to destination %d: %v", i, err)
		}
		got, reply, err := pc.ReadPacket()
		if err != nil {
			t.Fatalf("destination %d past the cap tore down the session: %v", i, err)
		}
		if !bytes.Equal(want, got) || reply.Address.String() != target.Address.String() || reply.Port != target.Port {
			t.Fatalf("destination %d echo mismatch: %q from %v", i, got, reply)
		}
	}
	if got := len(d.snapshot()); got != dests {
		t.Fatalf("dispatched %d destinations, want %d", got, dests)
	}
	if c.ended() {
		t.Fatalf("session ended after fan-out: %v", c.error())
	}
}

func TestNativeServerRoutingRejection(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			s := nativeTestServer(t, network, nativeTestUser("synthetic-user", "synthetic-password", "deny@test", false))
			d := &nativeEchoDispatcher{deny: true}
			c, _, _ := nativeConnect(t, s, network, "synthetic-user", "synthetic-password", false, d, nil)
			addr, _ := nativebridge.Address(xnet.TCPDestination(xnet.DomainAddress("blocked.invalid"), 443))
			if err := socksRequest(c, 1, addr); err == nil {
				t.Fatal("SOCKS success returned for routing rejection")
			}
			if len(d.snapshot()) != 1 {
				t.Fatal("destination did not reach dispatcher exactly once")
			}
		})
	}
}

func TestNativeServerUserManagement(t *testing.T) {
	s := nativeTestServer(t, "tcp", nativeTestUser("initial", "initial-secret", "initial@test", false))
	ctx := context.Background()
	if got := s.GetUsersCount(ctx); got != 1 {
		t.Fatalf("initial count=%d", got)
	}
	user, err := nativeTestUser("second", "second-secret", "second@test", false).ToMemoryUser()
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AddUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	if err = s.AddUser(ctx, user); err == nil {
		t.Fatal("duplicate user accepted")
	}
	if s.GetUsersCount(ctx) != 2 || len(s.GetUsers(ctx)) != 2 || s.GetUser(ctx, "second@test") == nil {
		t.Fatal("added user not visible")
	}
	if err = s.RemoveUser(ctx, "second@test"); err != nil {
		t.Fatal(err)
	}
	if s.GetUser(ctx, "second@test") != nil || s.GetUsersCount(ctx) != 1 {
		t.Fatal("removed user still visible")
	}
	if err = s.RemoveUser(ctx, "absent@test"); err == nil {
		t.Fatal("missing removal was not reported")
	}
}

func TestNativeServerConcurrentUserManagement(t *testing.T) {
	s := nativeTestServer(t, "udp", nativeTestUser("initial", "initial-secret", "initial@test", false))
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("parallel-%d", i)
			user, err := nativeTestUser(name, "synthetic-password", name+"@test", false).ToMemoryUser()
			if err != nil {
				t.Error(err)
				return
			}
			if err = s.AddUser(ctx, user); err != nil {
				t.Error(err)
				return
			}
			_ = s.GetUsers(ctx)
			_ = s.GetUsersCount(ctx)
			if got := s.GetUser(ctx, name+"@test"); got == nil {
				t.Error("missing concurrent user")
			}
			if err = s.RemoveUser(ctx, name+"@test"); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if s.GetUsersCount(ctx) != 1 {
		t.Fatal("concurrent user operations lost original user")
	}
}

func TestNativeServerHandshakeTimeoutWithWorkerUDP(t *testing.T) {
	s := nativeTestServer(t, "udp", nativeTestUser("synthetic-user", "synthetic-password", "timeout@test", false))
	_, raw := nativeUnderlay(t, "udp")
	d := &nativeEchoDispatcher{}
	_, done := nativeRunProcess(t, s, "udp", raw, d)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("silent preauth peer succeeded")
		}
	case <-time.After(2500 * time.Millisecond):
		t.Fatal("handshake timeout did not close worker with no-op deadlines")
	}
	if len(d.snapshot()) != 0 {
		t.Fatal("silent peer reached routing")
	}
}

func TestNativeServerMalformedTCPDoesNotDispatch(t *testing.T) {
	for _, payload := range [][]byte{{}, {1}, bytes.Repeat([]byte{0}, 72), bytes.Repeat([]byte{0xff}, 256)} {
		t.Run(fmt.Sprintf("bytes=%d", len(payload)), func(t *testing.T) {
			s := nativeTestServer(t, "tcp", nativeTestUser("synthetic-user", "synthetic-password", "malformed@test", false))
			raw, server := nativeUnderlay(t, "tcp")
			d := &nativeEchoDispatcher{}
			_, done := nativeRunProcess(t, s, "tcp", server, d)
			_ = raw.SetWriteDeadline(time.Now().Add(time.Second))
			_, _ = raw.Write(payload)
			_ = raw.Close()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("malformed peer succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("malformed peer did not stop")
			}
			if len(d.snapshot()) != 0 {
				t.Fatal("malformed peer reached routing")
			}
		})
	}
}

type nativeCaptureFirstConn struct {
	net.Conn
	mu    sync.Mutex
	first []byte
}

func (c *nativeCaptureFirstConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if c.first == nil {
		c.first = append([]byte(nil), p...)
	}
	c.mu.Unlock()
	return c.Conn.Write(p)
}
func (c *nativeCaptureFirstConn) opening() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.first...)
}

func TestNativeServerRejectsOpeningReplayOnAnotherConnection(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		for _, custom := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/custom=%v", network, custom), func(t *testing.T) {
				username := "synthetic-user"
				if custom {
					username = "a3ac6533-7c27-45c4-93f2-9192745e218b"
				}
				s := nativeTestServer(t, network, nativeTestUser(username, "synthetic-password", "replay@test", custom))
				d := &nativeEchoDispatcher{}
				var capture *nativeCaptureFirstConn
				_, _, _ = nativeConnect(t, s, network, username, "synthetic-password", custom, d, func(raw net.Conn) net.Conn { capture = &nativeCaptureFirstConn{Conn: raw}; return capture })
				raw, server := nativeUnderlay(t, network)
				_, done := nativeRunProcess(t, s, network, server, d)
				_ = raw.SetWriteDeadline(time.Now().Add(time.Second))
				if _, err := raw.Write(capture.opening()); err != nil {
					t.Fatal(err)
				}
				select {
				case err := <-done:
					if err == nil || !strings.Contains(err.Error(), "replay") {
						t.Fatalf("expected immediate replay rejection, got %v", err)
					}
				case <-time.After(750 * time.Millisecond):
					t.Fatal("opening replay was not rejected before handshake timeout")
				}
				if len(d.snapshot()) != 0 {
					t.Fatal("opening replay reached routing")
				}
			})
		}
	}
}

func TestNativeServerAuthenticatedSOCKSTimeout(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			s := nativeTestServer(t, network, nativeTestUser("synthetic-user", "synthetic-password", "timeout@test", false))
			d := &nativeEchoDispatcher{}
			c, _, _ := nativeConnect(t, s, network, "synthetic-user", "synthetic-password", false, d, nil)
			_ = c.SetReadDeadline(time.Now().Add(2500 * time.Millisecond))
			started := time.Now()
			if _, err := c.Read(make([]byte, 1)); err == nil {
				t.Fatal("missing SOCKS request accepted")
			}
			if time.Since(started) > 2*time.Second {
				t.Fatal("authenticated peer without SOCKS request was not closed promptly")
			}
			if len(d.snapshot()) != 0 {
				t.Fatal("incomplete request reached routing")
			}
		})
	}
}

// Use wire-level records here rather than a second copy of the server's mux:
// session 1 intentionally never sends SOCKS; session 2 must remain usable after
// session 1's deadline. This also verifies standard multiplexed framing over a
// single nonce sequence (TCP) and a single peer address (UDP).
func TestNativeServerMultiplexSessionTimeoutIsolation(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			s := nativeTestServer(t, network, nativeTestUser("synthetic-user", "synthetic-password", "mux@test", false))
			d := &nativeEchoDispatcher{}
			raw, server := nativeUnderlay(t, network)
			nativeRunProcess(t, s, network, server, d)
			_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
			w, err := newWire(raw, "synthetic-user", "synthetic-password", network == "udp", false)
			if err != nil {
				t.Fatal(err)
			}
			closed := false
			read := func() segment {
				seg, err := w.read()
				if err != nil {
					t.Fatal(err)
				}
				if seg.kind == closeRequest {
					_ = w.write(segment{kind: closeResponse, session: seg.session, seq: seg.seq})
					if seg.session == 1 {
						closed = true
					}
				}
				if seg.kind == dataServer {
					_ = w.write(segment{kind: ackClient, session: seg.session, unack: seg.seq + 1, window: 128, windowSet: true})
				}
				return seg
			}
			for _, sid := range []uint32{1, 2} {
				if err := w.write(segment{kind: openRequest, session: sid}); err != nil {
					t.Fatal(err)
				}
				for {
					seg := read()
					if seg.kind == openResponse && seg.session == sid {
						break
					}
				}
			}
			addr, _ := nativebridge.Address(xnet.TCPDestination(xnet.DomainAddress("mux.invalid"), 443))
			request := append([]byte{5, 1, 0}, addr...)
			if err := w.write(segment{kind: dataClient, session: 2, seq: 1, unack: 1, payload: request}); err != nil {
				t.Fatal(err)
			}
			var reply []byte
			for len(reply) < 10 {
				seg := read()
				if seg.kind == dataServer && seg.session == 2 {
					reply = append(reply, seg.payload...)
				}
			}
			if !bytes.Equal(reply[:3], []byte{5, 0, 0}) {
				t.Fatalf("SOCKS reply %x", reply)
			}
			for !closed {
				read()
			}
			want := []byte("healthy multiplexed session after sibling timeout")
			if err := w.write(segment{kind: dataClient, session: 2, seq: 2, unack: 2, payload: want}); err != nil {
				t.Fatal(err)
			}
			var got []byte
			for len(got) < len(want) {
				seg := read()
				if seg.kind == closeRequest && seg.session == 2 {
					t.Fatal("healthy session closed with timed-out sibling")
				}
				if seg.kind == dataServer && seg.session == 2 {
					got = append(got, seg.payload...)
				}
			}
			if !bytes.Equal(want, got) {
				t.Fatalf("healthy session corrupted: %q", got)
			}
			if records := d.snapshot(); len(records) != 1 || records[0].destination.Address.String() != "mux.invalid" {
				t.Fatalf("unexpected dispatches: %+v", records)
			}
		})
	}
}

type nativePanicReadConn struct{ net.Conn }

func (nativePanicReadConn) Read([]byte) (int, error) { panic("synthetic read panic") }
func TestNativeServerPanicDoesNotConsumeHandshakeCapacity(t *testing.T) {
	s := nativeTestServer(t, "tcp", nativeTestUser("synthetic-user", "synthetic-password", "panic@test", false))
	for i := 0; i < 70; i++ {
		left, right := net.Pipe()
		err := s.Process(context.Background(), xnet.Network_TCP, nativePanicReadConn{Conn: left}, &nativeEchoDispatcher{})
		_ = right.Close()
		if err == nil {
			t.Fatal("synthetic panic was not contained as an error")
		}
		if n := len(s.handshakes); n != 0 {
			t.Fatalf("panic leaked handshake slot %d: %d retained", i, n)
		}
		s.mu.RLock()
		active := len(s.active)
		s.mu.RUnlock()
		if active != 0 {
			t.Fatalf("panic leaked active underlay: %d", active)
		}
	}
}

type nativeMutateFirstConn struct {
	net.Conn
	once   sync.Once
	mutate func([]byte)
}

func (c *nativeMutateFirstConn) Write(p []byte) (int, error) {
	copyP := append([]byte(nil), p...)
	c.once.Do(func() { c.mutate(copyP) })
	return c.Conn.Write(copyP)
}
func TestNativeServerRejectsCorruptedOrStaleOpening(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		for _, variant := range []string{"metadata-tag", "uuid-trailer", "stale-timestamp"} {
			t.Run(network+"/"+variant, func(t *testing.T) {
				custom := variant == "uuid-trailer"
				username := "synthetic-user"
				if custom {
					username = "a3ac6533-7c27-45c4-93f2-9192745e218b"
				}
				s := nativeTestServer(t, network, nativeTestUser(username, "synthetic-password", "corrupt@test", custom))
				raw, server := nativeUnderlay(t, network)
				d := &nativeEchoDispatcher{}
				_, done := nativeRunProcess(t, s, network, server, d)
				_ = raw.SetDeadline(time.Now().Add(600 * time.Millisecond))
				w, err := newWire(raw, username, "synthetic-password", network == "udp", custom)
				if err != nil {
					t.Fatal(err)
				}
				w.conn = &nativeMutateFirstConn{Conn: raw, mutate: func(p []byte) {
					switch variant {
					case "metadata-tag":
						p[24] ^= 1
					case "uuid-trailer":
						p[72] ^= 1
					case "stale-timestamp":
						m, err := w.send.Open(nil, p[:24], p[24:72], nil)
						if err != nil {
							panic(err)
						}
						binary.BigEndian.PutUint32(m[2:6], uint32(time.Now().Unix()/60-10))
						copy(p[24:72], w.send.Seal(nil, p[:24], m, nil))
					}
				}}
				if err := w.write(segment{kind: openRequest, session: 23}); err != nil {
					t.Fatal(err)
				}
				select {
				case err := <-done:
					if err == nil {
						t.Fatal("corrupt/stale opening accepted")
					}
				case <-time.After(750 * time.Millisecond):
					t.Fatal("invalid opening not rejected promptly")
				}
				if len(d.snapshot()) != 0 {
					t.Fatal("invalid opening reached routing")
				}
			})
		}
	}
}
