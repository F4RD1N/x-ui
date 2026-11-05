package anytls

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type anyTLSDispatchCall struct {
	target  xnet.Destination
	inbound session.Inbound
}
type anyTLSEchoDispatcher struct {
	calls                 chan anyTLSDispatchCall
	panicRead, panicWrite bool
}

func (d *anyTLSEchoDispatcher) Type() interface{} { return routing.DispatcherType() }
func (d *anyTLSEchoDispatcher) Start() error      { return nil }
func (d *anyTLSEchoDispatcher) Close() error      { return nil }
func (d *anyTLSEchoDispatcher) DispatchLink(context.Context, xnet.Destination, *transport.Link) error {
	return errors.New("not used")
}
func (d *anyTLSEchoDispatcher) Dispatch(ctx context.Context, target xnet.Destination) (*transport.Link, error) {
	in := session.InboundFromContext(ctx)
	d.calls <- anyTLSDispatchCall{target, *in}
	if target.Address.String() == "block.example" {
		return nil, errors.New("blocked by test route")
	}
	ur, uw := pipe.New(pipe.WithSizeLimit(1024 * 1024))
	dr, dw := pipe.New(pipe.WithSizeLimit(1024 * 1024))
	stop := context.AfterFunc(ctx, func() { common.Interrupt(ur); common.Interrupt(uw); common.Interrupt(dr); common.Interrupt(dw) })
	if d.panicRead || d.panicWrite {
		link := &transport.Link{Reader: dr, Writer: uw}
		if d.panicRead {
			link.Reader = anyTLSPanicReader{}
		}
		if d.panicWrite {
			link.Writer = anyTLSPanicWriter{}
		}
		go func() {
			<-ctx.Done()
			stop()
			common.Interrupt(ur)
			common.Interrupt(uw)
			common.Interrupt(dr)
			common.Interrupt(dw)
		}()
		return link, nil
	}
	go func() {
		defer stop()
		defer dw.Close()
		for {
			mb, e := ur.ReadMultiBuffer()
			if len(mb) > 0 {
				if e := dw.WriteMultiBuffer(mb); e != nil {
					return
				}
			}
			if e != nil {
				return
			}
		}
	}()
	return &transport.Link{Reader: dr, Writer: uw}, nil
}

type anyTLSPanicReader struct{}

func (anyTLSPanicReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	panic("fixture failure must not escape copy worker")
}

type anyTLSPanicWriter struct{}

func (anyTLSPanicWriter) WriteMultiBuffer(b buf.MultiBuffer) error {
	buf.ReleaseMulti(b)
	panic("fixture failure must not escape copy worker")
}
func anyTLSNewTestServer(t *testing.T, password string, custom bool) (*Server, *anyTLSEchoDispatcher) {
	t.Helper()
	s := &Server{users: make(map[[32]byte]*protocol.MemoryUser), emails: make(map[string][32]byte), sessions: make(map[*serverSession]struct{}), timeout: time.Second, maxStreams: 8, streamSlots: make(chan struct{}, maxServerStreams), policy: policy.DefaultManager{}}
	a, e := (&Account{Password: password, UuidHashMiddle: custom}).AsAccount()
	if e != nil {
		t.Fatal(e)
	}
	if e = s.AddUser(context.Background(), &protocol.MemoryUser{Account: a, Email: "user@example.test", Level: 3}); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s, &anyTLSEchoDispatcher{calls: make(chan anyTLSDispatchCall, 128)}
}
func anyTLSWireFrame(command byte, id uint32, p []byte) []byte {
	b := make([]byte, 7+len(p))
	b[0] = command
	binary.BigEndian.PutUint32(b[1:5], id)
	binary.BigEndian.PutUint16(b[5:7], uint16(len(p)))
	copy(b[7:], p)
	return b
}
func anyTLSWrite(t *testing.T, c net.Conn, b []byte) {
	t.Helper()
	if _, e := c.Write(b); e != nil {
		t.Fatal(e)
	}
}
func anyTLSRead(t *testing.T, c net.Conn) (byte, uint32, []byte) {
	t.Helper()
	var h [7]byte
	if _, e := io.ReadFull(c, h[:]); e != nil {
		t.Fatal(e)
	}
	p := make([]byte, binary.BigEndian.Uint16(h[5:]))
	if _, e := io.ReadFull(c, p); e != nil {
		t.Fatal(e)
	}
	return h[0], binary.BigEndian.Uint32(h[1:5]), p
}
func anyTLSAddress(host string, port uint16) []byte {
	p := append([]byte{3, byte(len(host))}, []byte(host)...)
	return binary.BigEndian.AppendUint16(p, port)
}
func anyTLSWireAuth(password string, custom bool) []byte {
	h := sha256.Sum256([]byte(password))
	if custom {
		copy(h[8:24], []byte{0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	}
	return append(append([]byte{}, h[:]...), 0, 3, 0, 1, 2)
}
func anyTLSPeer(t *testing.T, s *Server, d *anyTLSEchoDispatcher) (net.Conn, chan error) {
	t.Helper()
	client, server := net.Pipe()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan error, 1)
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: "native-anytls", Source: xnet.TCPDestination(xnet.LocalHostIP, 30001)})
	go func() { done <- s.Process(ctx, xnet.Network_TCP, server, d) }()
	t.Cleanup(func() {
		client.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("AnyTLS Process leaked after closing carrier")
		}
	})
	return client, done
}
func anyTLSLogin(t *testing.T, c net.Conn, password string, custom bool) {
	t.Helper()
	auth := anyTLSWireAuth(password, custom)
	// Fragment authentication and padding deliberately: no first-read assumption.
	for _, b := range auth {
		anyTLSWrite(t, c, []byte{b})
	}
	anyTLSWrite(t, c, anyTLSWireFrame(4, 0, []byte("v=2\nclient=independent-test")))
	cmd, id, p := anyTLSRead(t, c)
	if cmd != 10 || id != 0 || string(p) != "v=2" {
		t.Fatalf("bad server settings: %d %d %q", cmd, id, p)
	}
}
func anyTLSOpen(t *testing.T, c net.Conn, id uint32, target []byte) {
	t.Helper()
	anyTLSWrite(t, c, anyTLSWireFrame(1, id, nil))
	anyTLSWrite(t, c, anyTLSWireFrame(2, id, target))
	cmd, got, p := anyTLSRead(t, c)
	if cmd != 7 || got != id || len(p) != 0 {
		t.Fatalf("bad SYNACK: %d %d %q", cmd, got, p)
	}
}

func TestAnyTLSNativeInboundTCPAuthenticationRoutingAndReuse(t *testing.T) {
	for _, custom := range []bool{false, true} {
		t.Run(map[bool]string{false: "standard", true: "uuid-middle"}[custom], func(t *testing.T) {
			pass := "00112233-4455-6677-8899-aabbccddeeff"
			s, d := anyTLSNewTestServer(t, pass, custom)
			c, _ := anyTLSPeer(t, s, d)
			anyTLSLogin(t, c, pass, custom)
			for id := uint32(1); id <= 3; id++ {
				anyTLSOpen(t, c, id, anyTLSAddress("echo.example", 443))
				call := <-d.calls
				if call.target.Network != xnet.Network_TCP || call.inbound.Name != "anytls" || call.inbound.Tag != "native-anytls" || call.inbound.User.Email != "user@example.test" || call.inbound.User.Level != 3 {
					t.Fatalf("dispatcher lost destination/auth context: %+v", call)
				}
				payload := bytes.Repeat([]byte("payload-"), 4096)
				anyTLSWrite(t, c, anyTLSWireFrame(2, id, payload))
				var actual []byte
				for len(actual) < len(payload) {
					cmd, got, p := anyTLSRead(t, c)
					if cmd != 2 || got != id {
						t.Fatalf("unexpected frame %d/%d", cmd, got)
					}
					actual = append(actual, p...)
				}
				if !bytes.Equal(actual, payload) {
					t.Fatal("TCP payload corruption")
				}
				anyTLSWrite(t, c, anyTLSWireFrame(3, id, nil))
			}
			anyTLSWrite(t, c, anyTLSWireFrame(8, 0, nil))
			cmd, _, p := anyTLSRead(t, c)
			if cmd != 9 || len(p) != 0 {
				t.Fatal("idle carrier heartbeat failed")
			}
		})
	}
}

func TestAnyTLSNativeInboundUDPBothModesAndPerDestinationRouting(t *testing.T) {
	for _, connected := range []bool{false, true} {
		t.Run(map[bool]string{false: "per-packet", true: "connected"}[connected], func(t *testing.T) {
			s, d := anyTLSNewTestServer(t, "test-password", false)
			c, _ := anyTLSPeer(t, s, d)
			anyTLSLogin(t, c, "test-password", false)
			anyTLSWrite(t, c, anyTLSWireFrame(1, 1, nil))
			target := anyTLSAddress("sp.v2.udp-over-tcp.arpa", 0)
			mode := byte(0)
			if connected {
				mode = 1
			}
			target = append(target, mode)
			target = append(target, anyTLSAddress("dns-one.example", 53)...)
			anyTLSWrite(t, c, anyTLSWireFrame(2, 1, target))
			cmd, _, p := anyTLSRead(t, c)
			if cmd != 7 || len(p) != 0 {
				t.Fatal("UDP SYNACK failed")
			}
			for _, host := range []string{"dns-one.example", "dns-two.example"} {
				data := []byte("datagram:" + host)
				var wire []byte
				if !connected {
					wire = anyTLSAddress(host, 53)
					wire[0] = 2
				}
				wire = binary.BigEndian.AppendUint16(wire, uint16(len(data)))
				wire = append(wire, data...)
				anyTLSWrite(t, c, anyTLSWireFrame(2, 1, wire))
				cmd, _, p = anyTLSRead(t, c)
				if cmd != 2 || !bytes.Equal(wire, p) {
					t.Fatalf("UDP framing mismatch %d %x != %x", cmd, p, wire)
				}
			}
			first := <-d.calls
			if first.target.Network != xnet.Network_UDP || first.target.Address.String() != "dns-one.example" {
				t.Fatalf("bad first UDP dispatch: %+v", first)
			}
			if !connected {
				second := <-d.calls
				if second.target.Address.String() != "dns-two.example" {
					t.Fatal("second UDP destination bypassed route lookup")
				}
			} else {
				select {
				case call := <-d.calls:
					t.Fatalf("unexpected second connected dispatch: %+v", call)
				default:
				}
			}
		})
	}
}

func TestAnyTLSNativeInboundRejectsAuthAndMalformedFrames(t *testing.T) {
	cases := []struct {
		name     string
		wire     []byte
		settings bool
	}{
		{"missing-settings", anyTLSWireFrame(1, 1, nil), false},
		{"zero-stream-id", anyTLSWireFrame(1, 0, nil), true},
		{"syn-payload", anyTLSWireFrame(1, 1, []byte{1}), true},
		{"unknown-command", anyTLSWireFrame(255, 0, nil), true},
		{"heartbeat-payload", anyTLSWireFrame(8, 0, []byte{1}), true},
		{"fin-payload", anyTLSWireFrame(3, 1, []byte{1}), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, d := anyTLSNewTestServer(t, "test-password", false)
			c, done := anyTLSPeer(t, s, d)
			if tc.settings {
				anyTLSLogin(t, c, "test-password", false)
			} else {
				anyTLSWrite(t, c, anyTLSWireAuth("test-password", false))
			}
			anyTLSWrite(t, c, tc.wire)
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("invalid request accepted")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("malformed carrier not closed")
			}
			done <- errors.New("consumed")
		})
	}
	t.Run("wrong-password", func(t *testing.T) {
		s, d := anyTLSNewTestServer(t, "right", false)
		c, done := anyTLSPeer(t, s, d)
		_, _ = c.Write(anyTLSWireAuth("wrong", false))
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("wrong auth accepted")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("wrong auth not closed")
		}
		done <- errors.New("consumed")
	})
	t.Run("wrong-custom-mode", func(t *testing.T) {
		s, d := anyTLSNewTestServer(t, "00112233-4455-6677-8899-aabbccddeeff", true)
		c, done := anyTLSPeer(t, s, d)
		_, _ = c.Write(anyTLSWireAuth("00112233-4455-6677-8899-aabbccddeeff", false))
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("standard mode accepted for custom-only user")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("wrong mode not closed")
		}
		done <- errors.New("consumed")
	})
}

func TestAnyTLSNativeInboundRouteDenialAndUserRevocation(t *testing.T) {
	s, d := anyTLSNewTestServer(t, "test-password", false)
	c, done := anyTLSPeer(t, s, d)
	anyTLSLogin(t, c, "test-password", false)
	anyTLSWrite(t, c, anyTLSWireFrame(1, 1, nil))
	anyTLSWrite(t, c, anyTLSWireFrame(2, 1, anyTLSAddress("block.example", 443)))
	cmd, id, p := anyTLSRead(t, c)
	if cmd != 7 || id != 1 || len(p) == 0 {
		t.Fatal("route failure was not rejected")
	}
	cmd, id, _ = anyTLSRead(t, c)
	if cmd != 3 || id != 1 {
		t.Fatal("failed stream not closed")
	}
	if e := s.RemoveUser(context.Background(), "user@example.test"); e != nil {
		t.Fatal(e)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("revoked user retained pooled carrier")
	}
	done <- errors.New("consumed")
	if s.GetUsersCount(context.Background()) != 0 {
		t.Fatal("user not removed")
	}
}

func TestAnyTLSNativeInboundCloseCancelsUnauthenticatedAndBlockedStreams(t *testing.T) {
	s, d := anyTLSNewTestServer(t, "test-password", false)
	c, done := anyTLSPeer(t, s, d)
	anyTLSLogin(t, c, "test-password", false)
	anyTLSWrite(t, c, anyTLSWireFrame(1, 1, nil))
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("server close leaked destination parser")
	}
	done <- errors.New("consumed")
}

func TestAnyTLSUserManagerConcurrencyAndCopies(t *testing.T) {
	s, _ := anyTLSNewTestServer(t, "p", false)
	ctx := context.Background()
	u := s.GetUser(ctx, "user@example.test")
	u.Email = "mutated"
	u.Account.(*MemoryAccount).Password = "mutated"
	if s.GetUser(ctx, "user@example.test").Account.(*MemoryAccount).Password != "p" {
		t.Fatal("GetUser exposed mutable account")
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = s.GetUsers(ctx)
				_ = s.GetUsersCount(ctx)
				_ = s.GetUser(ctx, "user@example.test")
			}
		}()
	}
	wg.Wait()
}

func TestAnyTLSNativeInboundVersionOneAndLimits(t *testing.T) {
	t.Run("v1-no-v2-controls", func(t *testing.T) {
		s, d := anyTLSNewTestServer(t, "p", false)
		c, _ := anyTLSPeer(t, s, d)
		anyTLSWrite(t, c, anyTLSWireAuth("p", false))
		anyTLSWrite(t, c, anyTLSWireFrame(4, 0, []byte("v=1")))
		anyTLSWrite(t, c, anyTLSWireFrame(1, 1, nil))
		anyTLSWrite(t, c, anyTLSWireFrame(2, 1, append(anyTLSAddress("echo.example", 80), []byte("v1-echo")...)))
		cmd, id, payload := anyTLSRead(t, c)
		if cmd != 2 || id != 1 || string(payload) != "v1-echo" {
			t.Fatalf("v1 received v2 controls or corrupt payload: %d/%d/%q", cmd, id, payload)
		}
	})
	t.Run("stream-limit", func(t *testing.T) {
		s, d := anyTLSNewTestServer(t, "p", false)
		s.maxStreams = 1
		c, done := anyTLSPeer(t, s, d)
		anyTLSLogin(t, c, "p", false)
		anyTLSWrite(t, c, anyTLSWireFrame(1, 1, nil))
		anyTLSWrite(t, c, anyTLSWireFrame(1, 2, nil))
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("stream capacity not enforced")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("capacity violation did not close carrier")
		}
		done <- errors.New("consumed")
		if len(s.streamSlots) != 0 {
			t.Fatal("stream slot leaked")
		}
	})
	t.Run("authentication-timeout", func(t *testing.T) {
		s, d := anyTLSNewTestServer(t, "p", false)
		s.timeout = 30 * time.Millisecond
		_, done := anyTLSPeer(t, s, d)
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("empty authentication accepted")
			}
		case <-time.After(time.Second):
			t.Fatal("handshake deadline not enforced")
		}
		done <- errors.New("consumed")
	})
}

func TestAnyTLSNativeInboundIPv6AddressAndInvalidUDPMode(t *testing.T) {
	s, d := anyTLSNewTestServer(t, "p", false)
	c, _ := anyTLSPeer(t, s, d)
	anyTLSLogin(t, c, "p", false)
	address := append([]byte{4}, net.ParseIP("::1").To16()...)
	address = binary.BigEndian.AppendUint16(address, 443)
	anyTLSOpen(t, c, 1, address)
	call := <-d.calls
	if call.target.Address.Family() != xnet.AddressFamilyIPv6 || !call.target.Address.IP().Equal(net.ParseIP("::1")) {
		t.Fatal("IPv6 destination corrupted")
	}
	anyTLSWrite(t, c, anyTLSWireFrame(3, 1, nil))
	anyTLSWrite(t, c, anyTLSWireFrame(1, 2, nil))
	request := append(anyTLSAddress("sp.v2.udp-over-tcp.arpa", 0), 2)
	anyTLSWrite(t, c, anyTLSWireFrame(2, 2, request))
	cmd, id, _ := anyTLSRead(t, c)
	if cmd != 3 || id != 2 {
		t.Fatal("invalid UOT connected mode was accepted")
	}
	select {
	case call := <-d.calls:
		t.Fatalf("invalid UOT caused destination dispatch: %+v", call)
	default:
	}
}

func TestAnyTLSNativeInboundAdmissionIncludesBlockedFIN(t *testing.T) {
	s, d := anyTLSNewTestServer(t, "p", false)
	s.maxStreams = 2
	// Logical streams close before their workers necessarily exit. The global
	// worker bound must still include both blocked FIN writers below.
	s.streamSlots = make(chan struct{}, 2)
	reader, writer := net.Pipe()
	defer reader.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &serverSession{owner: s, ctx: ctx, cancel: cancel, conn: writer, dispatcher: d, streams: make(map[uint32]*serverStream), user: s.GetUser(ctx, "user@example.test")}
	defer func() { c.close(); c.wg.Wait() }()
	for id := uint32(1); id <= 2; id++ {
		if err := c.open(id); err != nil {
			t.Fatal(err)
		}
		c.mu.Lock()
		st := c.streams[id]
		c.mu.Unlock()
		if !st.enqueue([]byte{255}) {
			t.Fatal("fixture destination queue failed")
		}
	}
	// Neither FIN can finish: the peer deliberately never reads from reader.
	// A closed logical stream still occupies global admission until worker exit.
	until := time.Now().Add(time.Second)
	for {
		closed := 0
		c.mu.Lock()
		for _, st := range c.streams {
			st.mu.Lock()
			if st.closed {
				closed++
			}
			st.mu.Unlock()
		}
		c.mu.Unlock()
		if closed == 2 {
			break
		}
		if time.Now().After(until) {
			t.Fatal("fixture did not reach closed blocked writers")
		}
		time.Sleep(time.Millisecond)
	}
	if err := c.open(3); err == nil {
		t.Fatal("closed but blocked FIN writers bypassed stream capacity")
	}
	if len(s.streamSlots) != 2 {
		t.Fatal("global admission released before FIN worker exit")
	}
	c.close()
	c.wg.Wait()
	if len(s.streamSlots) != 0 {
		t.Fatal("shutdown did not release held worker admission")
	}
}

func TestAnyTLSNativeInboundCopyWorkerPanicsAreContained(t *testing.T) {
	for _, direction := range []string{"reader", "writer"} {
		t.Run(direction, func(t *testing.T) {
			s, d := anyTLSNewTestServer(t, "p", false)
			d.panicRead = direction == "reader"
			d.panicWrite = direction == "writer"
			c, _ := anyTLSPeer(t, s, d)
			anyTLSLogin(t, c, "p", false)
			anyTLSOpen(t, c, 1, anyTLSAddress("echo.example", 80))
			if d.panicWrite {
				anyTLSWrite(t, c, anyTLSWireFrame(2, 1, []byte("request")))
			}
			command, id, _ := anyTLSRead(t, c)
			if command != 3 || id != 1 {
				t.Fatalf("panicking copy worker did not close only its stream: %d/%d", command, id)
			}
			anyTLSWrite(t, c, anyTLSWireFrame(8, 0, nil))
			command, _, _ = anyTLSRead(t, c)
			if command != 9 {
				t.Fatal("copy failure broke unrelated carrier heartbeat")
			}
		})
	}
}
