package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/orbit/internal/protocol"
)

func pair(t *testing.T, o Options, allocator ...func() (uint32, error)) (*Session, *Session) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	a, b := net.Pipe()
	t.Cleanup(func() { cancel(); a.Close(); b.Close() })
	type result struct {
		session *Session
		err     error
	}
	ready := make(chan result, 1)
	go func() {
		s, err := Server(ctx, b, ServerOptions{Options: o, Authenticate: func(_ context.Context, user protocol.UserInfo) error {
			if user.UID != "owned-test" || user.Token != "local-token" {
				return ErrAuthentication
			}
			return nil
		}})
		ready <- result{s, err}
	}()
	var allocate func() (uint32, error)
	if len(allocator) != 0 {
		allocate = allocator[0]
	}
	client, err := Client(ctx, a, ClientOptions{Options: o, User: protocol.UserInfo{UID: "owned-test", Token: "local-token", DeviceID: "synthetic-device"}, ConnectionID: 17, AllocateSocketID: allocate})
	if err != nil {
		t.Fatal(err)
	}
	r := <-ready
	if r.err != nil {
		t.Fatal(r.err)
	}
	t.Cleanup(func() { client.Close(); r.session.Close() })
	return client, r.session
}

func openPair(t *testing.T, c, s *Session) (*Stream, *Stream) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	type result struct {
		stream *Stream
		err    error
	}
	ready := make(chan result, 1)
	go func() { stream, err := c.Open(ctx, "192.0.2.10", 443); ready <- result{stream, err} }()
	in, err := s.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := in.Accept(); err != nil {
		t.Fatal(err)
	}
	r := <-ready
	if r.err != nil {
		t.Fatal(r.err)
	}
	return r.stream, in
}

func eventually(t *testing.T, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestHandshakeIdentityAndChannel(t *testing.T) {
	c, s := pair(t, Options{})
	if c.ChannelID() != s.ChannelID() || c.ChannelID() == [16]byte{} || s.ConnectionID() != 17 {
		t.Fatal("channel identity mismatch")
	}
	if s.User().UID != "owned-test" || s.User().DeviceID != "synthetic-device" {
		t.Fatal("identity mismatch")
	}
}

func TestAuthenticationRejected(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ready := make(chan error, 1)
	go func() {
		_, err := Server(ctx, b, ServerOptions{Authenticate: func(context.Context, protocol.UserInfo) error { return errors.New("revoked") }})
		ready <- err
	}()
	_, err := Client(ctx, a, ClientOptions{})
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("client: %v", err)
	}
	if err := <-ready; !errors.Is(err, ErrAuthentication) {
		t.Fatalf("server: %v", err)
	}
}

func TestHandshakeTimeoutCancellationAndMissingAuthenticator(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Client(ctx, a, ClientOptions{}); !errors.Is(err, context.Canceled) && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("cancelled: %v", err)
	}
	a, b = net.Pipe()
	defer a.Close()
	defer b.Close()
	if _, err := Server(context.Background(), a, ServerOptions{}); err == nil {
		t.Fatal("missing authenticator accepted")
	}
	_, err := Client(context.Background(), a, ClientOptions{Options: Options{HandshakeTimeout: 10 * time.Millisecond}})
	if e, ok := err.(net.Error); !ok || !e.Timeout() {
		t.Fatalf("timeout: %v", err)
	}
}

func TestBidirectionalDataAndWholeSocketFIN(t *testing.T) {
	c, s := pair(t, Options{})
	client, server := openPair(t, c, s)
	payload := bytes.Repeat([]byte("chunk-data"), 2000)
	writeDone := make(chan error, 1)
	go func() { _, err := client.Write(payload); writeDone <- err }()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("write %v dataequal%v", err, bytes.Equal(got, payload))
	}
	go func() { _, err := server.Write([]byte("reply")); writeDone <- err }()
	got = make([]byte, 5)
	if _, err := io.ReadFull(client, got); err != nil || string(got) != "reply" {
		t.Fatalf("reply %q %v", got, err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("peer FIN %v", err)
	}
	if _, err := server.Write([]byte("cannot half close")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("whole-socket behavior %v", err)
	}
}

func TestCloseReadStopsOppositeWritesOnly(t *testing.T) {
	c, s := pair(t, Options{})
	client, server := openPair(t, c, s)
	if err := server.CloseRead(); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { client.mu.Lock(); defer client.mu.Unlock(); return client.remoteReadClosed })
	if _, err := client.Write([]byte("blocked")); !errors.Is(err, ErrPeerReadClosed) {
		t.Fatal(err)
	}
	ready := make(chan error, 1)
	go func() { _, err := server.Write([]byte("reverse")); ready <- err }()
	b := make([]byte, 7)
	if _, err := io.ReadFull(client, b); err != nil || string(b) != "reverse" {
		t.Fatalf("reverse %q %v", b, err)
	}
	if err := <-ready; err != nil {
		t.Fatal(err)
	}
}

func TestDeadlineUpdatesWakeBlockedIO(t *testing.T) {
	c, s := pair(t, Options{})
	client, server := openPair(t, c, s)
	read := make(chan error, 1)
	go func() { _, err := client.Read(make([]byte, 1)); read <- err }()
	if err := client.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := <-read; !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	client.SetReadDeadline(time.Time{})
	client.peerBuffer(0, true)
	write := make(chan error, 1)
	go func() { _, err := client.Write([]byte("wait")); write <- err }()
	client.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
	if err := <-write; !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	client.SetWriteDeadline(time.Time{})
	client.peerBuffer(0, false)
	go func() { _, err := client.Write([]byte("ok")); write <- err }()
	buf := make([]byte, 2)
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Fatal(err)
	}
	if err := <-write; err != nil {
		t.Fatal(err)
	}
}

func TestFlowPauseAndResumeAfterNativeNodeThresholds(t *testing.T) {
	c, s := pair(t, Options{})
	client, server := openPair(t, c, s)
	data := bytes.Repeat([]byte("x"), 2<<20)
	write := make(chan error, 1)
	go func() { _, err := client.Write(data); write <- err }()
	eventually(t, func() bool { client.mu.Lock(); defer client.mu.Unlock(); return client.remoteFull })
	select {
	case err := <-write:
		t.Fatalf("write passed pause: %v", err)
	default:
	}
	got := make([]byte, len(data))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatal(err)
	}
	if err := <-write; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, got) {
		t.Fatal("payload corrupted")
	}
	if s.BufferedBytes() != 0 {
		t.Fatalf("buffer accounting %d", s.BufferedBytes())
	}
}

func TestOldPauseUpdatesIgnored(t *testing.T) {
	c, s := pair(t, Options{})
	client, _ := openPair(t, c, s)
	client.peerBuffer(20, true)
	client.peerBuffer(19, false)
	client.mu.Lock()
	if !client.remoteFull || client.remoteFullOffset != 20 {
		t.Fatal("stale update accepted")
	}
	client.mu.Unlock()
	client.peerBuffer(20, false)
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.remoteFull {
		t.Fatal("equal offset update rejected")
	}
}

func TestConnectRejectCancelAndFlowLimit(t *testing.T) {
	c, s := pair(t, Options{MaxFlows: 1})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	opened := make(chan error, 1)
	go func() { _, err := c.Open(ctx, "example.test", 80); opened <- err }()
	server, err := s.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Open(ctx, "example.test", 80); !errors.Is(err, ErrFlowLimit) {
		t.Fatalf("limit %v", err)
	}
	server.Reject()
	if err := <-opened; !errors.Is(err, ErrConnect) {
		t.Fatalf("reject %v", err)
	}
	eventually(t, func() bool { c.mu.Lock(); defer c.mu.Unlock(); return len(c.streams) == 0 })
	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel2()
	if _, err := c.Open(ctx2, "example.test", 80); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancel %v", err)
	}
}

func TestUDPExchangeAndBoundedDropQueue(t *testing.T) {
	c, s := pair(t, Options{UDPQueue: 1})
	u := protocol.UDPEnvelope{Kind: protocol.UDPKindData, Source: netip.MustParseAddrPort("192.0.2.1:1234"), Destination: netip.MustParseAddrPort("198.51.100.2:53"), Data: []byte("dns")}
	if err := c.SendUDP(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	if err := c.SendUDP(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { return s.DroppedUDP() == 1 })
	v, err := s.ReceiveUDP(context.Background())
	if err != nil || v.Source != u.Source || !bytes.Equal(v.Data, u.Data) {
		t.Fatalf("UDP %+v %v", v, err)
	}
	u.Source, u.Destination = u.Destination, u.Source
	u.Data = nil
	if err := s.SendUDP(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	v, err = c.ReceiveUDP(context.Background())
	if err != nil || v.Source != u.Source || len(v.Data) != 0 {
		t.Fatalf("emptyUDP %+v %v", v, err)
	}
}

func TestMalformedOffsetTerminatesSession(t *testing.T) {
	c, s := pair(t, Options{})
	client, _ := openPair(t, c, s)
	f, _ := (protocol.DataChunk{SocketID: client.ID(), Sequence: 0, Offset: 1, Data: []byte("x")}).Frame()
	// The peer can reject and close before the local write acknowledgement is
	// observed; the server error is the authoritative validation result.
	_ = c.send(context.Background(), f)
	select {
	case <-s.Done():
	case <-time.After(time.Second):
		t.Fatal("bad offset accepted")
	}
	if !errors.Is(s.Err(), ErrOffset) {
		t.Fatal(s.Err())
	}
}

func TestConcurrentStreamsAndClose(t *testing.T) {
	c, s := pair(t, Options{})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		client, server := openPair(t, c, s)
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, err := client.Write([]byte("abc"))
			if err != nil {
				t.Error(err)
			}
		}()
		go func() {
			defer wg.Done()
			b := make([]byte, 3)
			_, err := io.ReadFull(server, b)
			if err != nil || string(b) != "abc" {
				t.Errorf("read %q %v", b, err)
			}
		}()
	}
	wg.Wait()
	var closing sync.WaitGroup
	for i := 0; i < 8; i++ {
		closing.Add(1)
		go func() { defer closing.Done(); c.Close(); s.Close() }()
	}
	closing.Wait()
	if s.BufferedBytes() != 0 || c.BufferedBytes() != 0 {
		t.Fatal("buffer leak")
	}
}

func TestOptionsAndUnsupportedFrames(t *testing.T) {
	for _, o := range []Options{{MaxFlows: -1}, {UDPQueue: -1}, {MaxBufferedBytes: 1}, {HandshakeTimeout: -1}, {WriteTimeout: -1}, {IdleTimeout: -1}, {HeartbeatInterval: -1}, {CloseTimeout: -1}} {
		if _, err := o.normalized(); err == nil {
			t.Fatalf("accepted %+v", o)
		}
	}
	c, s := pair(t, Options{})
	_ = c.send(context.Background(), protocol.Frame{Type: 255})
	select {
	case <-s.Done():
	case <-time.After(time.Second):
		t.Fatal("unknown frame accepted")
	}
	if !errors.Is(s.Err(), protocol.ErrUnsupported) {
		t.Fatal(s.Err())
	}
}

func TestBufferedEOFDrainsAndOwnerCloseReleasesAccounting(t *testing.T) {
	c, s := pair(t, Options{CloseTimeout: 30 * time.Millisecond})
	client, server := openPair(t, c, s)
	if _, err := client.Write([]byte("buffered")); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { return s.BufferedBytes() == 8 })
	client.Close()
	got := make([]byte, 8)
	if _, err := io.ReadFull(server, got); err != nil || string(got) != "buffered" {
		t.Fatalf("buffered EOF %q %v", got, err)
	}
	if _, err := server.Read(make([]byte, 1)); err != io.EOF {
		t.Fatal(err)
	}
	if s.BufferedBytes() != 0 {
		t.Fatal("drained accounting")
	}

	client2, server2 := openPair(t, c, s)
	if _, err := client2.Write([]byte("abandoned")); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { return s.BufferedBytes() == 9 })
	client2.Close()
	// Peer-closed state has no native expiry: its owner must consume or close.
	time.Sleep(40 * time.Millisecond)
	if s.BufferedBytes() != 9 {
		t.Fatal("peer FIN discarded unread payload")
	}
	server2.Close()
	eventually(t, func() bool { return s.BufferedBytes() == 0 })
	if _, err := server2.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expired %v", err)
	}
}

func TestReceiveBudgetAndZeroLengthSequenceSemantics(t *testing.T) {
	c, s := pair(t, Options{MaxBufferedBytes: 4096})
	client, server := openPair(t, c, s)
	f, _ := (protocol.DataChunk{SocketID: client.ID(), Sequence: 999999, Offset: 0, Data: nil}).Frame()
	if err := c.send(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(bytes.Repeat([]byte("x"), 4096)); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { return s.BufferedBytes() == 4096 })
	_, _ = client.Write([]byte("overflow"))
	select {
	case <-s.Done():
	case <-time.After(time.Second):
		t.Fatal("receive budget ignored")
	}
	if !errors.Is(s.Err(), ErrBufferLimit) {
		t.Fatal(s.Err())
	}
	eventually(t, func() bool { return s.BufferedBytes() == 0 })
	if _, err := server.Read(make([]byte, 1)); err == nil {
		t.Fatal("closed read succeeded")
	}
}

func TestQueuePressureDeadlineAndCloseWake(t *testing.T) {
	// A synthetic full writer queue exercises admission without involving a
	// blocking kernel socket or changing the wire protocol.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &Session{ctx: ctx, done: make(chan struct{}), out: make(chan writeRequest, 1), space: make(chan struct{}, 1)}
	s.out <- writeRequest{}
	stream := newStream(s, 1, 0, protocol.Address{}, false)
	stream.state = 3
	ready := make(chan error, 1)
	go func() { _, err := stream.queueData(ctx, protocol.Frame{Type: protocol.TypeData}); ready <- err }()
	stream.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
	if err := <-ready; !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("queue deadline %v", err)
	}
	stream.SetWriteDeadline(time.Time{})
	go func() { _, err := stream.queueData(ctx, protocol.Frame{Type: protocol.TypeData}); ready <- err }()
	stream.mu.Lock()
	stream.localClosed = true
	stream.signalLocked()
	stream.mu.Unlock()
	if err := <-ready; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("queue close %v", err)
	}
}

func rawPeerClient(t *testing.T, o Options) (*Session, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(func() { cancel(); a.Close(); b.Close() })
	ready := make(chan error, 1)
	go func() {
		_, err := protocol.ReadFrame(b)
		if err == nil {
			err = protocol.WriteFrame(b, protocol.Frame{Type: protocol.TypeConnectResponse})
		}
		ready <- err
	}()
	c, err := Client(ctx, a, ClientOptions{Options: o})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-ready; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, b
}

func TestIdleAndWriteTimeoutBoundTransportStalls(t *testing.T) {
	c, _ := rawPeerClient(t, Options{IdleTimeout: 30 * time.Millisecond, HeartbeatInterval: 10 * time.Millisecond, WriteTimeout: time.Second})
	select {
	case <-c.Done():
	case <-time.After(time.Second):
		t.Fatal("idle peer did not close")
	}
	if !strings.Contains(c.Err().Error(), "idle timeout") {
		t.Fatal(c.Err())
	}
	c, _ = rawPeerClient(t, Options{WriteTimeout: 10 * time.Millisecond})
	err := c.send(context.Background(), protocol.Frame{Type: protocol.TypeHeartbeat})
	if e, ok := err.(net.Error); !ok || !e.Timeout() {
		t.Fatalf("write timeout %v", err)
	}
}

func TestNilContextsAndRoleMisuse(t *testing.T) {
	c, s := pair(t, Options{})
	if _, err := c.Open(nil, "example.test", 80); err == nil {
		t.Fatal("nil open")
	}
	if _, err := s.Accept(nil); err == nil {
		t.Fatal("nil accept")
	}
	if _, err := s.ReceiveUDP(nil); err == nil {
		t.Fatal("nil UDP")
	}
	if _, err := c.Accept(context.Background()); err == nil {
		t.Fatal("client accepts")
	}
	if _, err := s.Open(context.Background(), "example.test", 80); err == nil {
		t.Fatal("server opens")
	}
	if _, err := c.Open(context.Background(), "example.test", 0); err == nil {
		t.Fatal("zero port")
	}
	if _, err := c.Open(context.Background(), "http://invalid", 80); err == nil {
		t.Fatal("invalid host")
	}
	if _, err := c.queue(nil, protocol.Frame{}); err == nil {
		t.Fatal("nil queue")
	}
	if err := c.SendUDP(context.Background(), protocol.UDPEnvelope{}); err == nil {
		t.Fatal("invalid UDP")
	}
	client, server := openPair(t, c, s)
	if err := client.Accept(); err == nil {
		t.Fatal("outgoing accept")
	}
	if server.RemoteAddr().String() != "192.0.2.10:443" || server.RemoteAddr().Network() != "tcp" || server.LocalAddr() == nil {
		t.Fatal("addresses")
	}
	if server.Destination().Port != 443 {
		t.Fatal("destination")
	}
	server.SetDeadline(time.Now().Add(time.Second))
	server.SetDeadline(time.Time{})
	if n, err := server.Read(nil); n != 0 || err != nil {
		t.Fatal("empty read")
	}
	if n, err := server.Write(nil); n != 0 || err != nil {
		t.Fatal("empty write")
	}
}
