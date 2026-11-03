package transport

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/orbit/internal/protocol"
)

// deadlineDeafConn is a packet socket whose reads ignore deadlines, as the
// chained connections of Xray's dialerProxy (pipe based) do.
type deadlineDeafConn struct{ net.PacketConn }

func (deadlineDeafConn) SetReadDeadline(time.Time) error { return nil }
func (deadlineDeafConn) SetDeadline(time.Time) error     { return nil }

// TestQUICCloseOverADeadlineDeafSocket: quic-go's Transport.Close stops its
// read loop by setting a read deadline on a socket it did not create, and
// waits for it. Over a chained connection that ignores deadlines that wait
// never ended, and closing the session (Xray shutdown, reload, a network
// change, a retired session) hung forever.
func TestQUICCloseOverADeadlineDeafSocket(t *testing.T) {
	serverTLS, clientTLS := testTLS(t)
	srv := listenTestQUIC(t, serverTLS, QUICServerOptions{}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	user := protocol.UserInfo{UID: "quic-test", Token: "token", DeviceID: "device"}
	q, err := DialQUIC(ctx, srv.addr, clientTLS, QUICInitialOptions{ConnectionID: 9, ChannelID: [16]byte{4},
		EncodeUserInfo: func(r io.Reader) ([128]byte, error) { return protocol.EncodeUserInfo(user, r) },
		PacketConnFactory: func(context.Context) (net.PacketConn, error) {
			pc, err := net.ListenPacket("udp", "127.0.0.1:0")
			return deadlineDeafConn{pc}, err
		}})
	if err != nil {
		t.Fatal(err)
	}
	if err = q.waitReady(ctx); err != nil {
		t.Fatal(err)
	}
	st, err := q.Open(ctx, "127.0.0.1", 80)
	if err != nil {
		t.Fatal(err)
	}
	if err = echoOnce(st, "before close"); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { q.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("QUICSession.Close hung on a socket that ignores read deadlines")
	}
}

// The inbound uses an Xray-owned packet adapter. A listener must stop even if
// that adapter cannot interrupt a pending read with a deadline.
func TestQUICListenerCloseOverADeadlineDeafSocket(t *testing.T) {
	serverTLS, clientTLS := testTLS(t)
	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l, err := ListenQUIC(deadlineDeafConn{raw}, serverTLS, testVerify)
	if err != nil {
		raw.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := DialQUIC(ctx, l.Addr().String(), clientTLS, testInitial())
	if err != nil {
		l.Close()
		t.Fatal(err)
	}
	defer c.Close()
	s, err := l.Accept(ctx)
	if err != nil {
		l.Close()
		t.Fatal(err)
	}
	defer s.Close()
	done := make(chan struct{})
	go func() { l.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("QUIC listener Close hung on a packet adapter without deadlines")
	}
	// Close is safe after completion and cannot leave a newly accepted session.
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Accept(ctx); err == nil {
		t.Fatal("closed QUIC listener accepted a session")
	}
}

func TestQUICListenerFailedTLSInitializationClosesPacketAdapter(t *testing.T) {
	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	done := make(chan error, 1)
	go func() {
		l, err := ListenQUIC(deadlineDeafConn{raw}, &tls.Config{}, testVerify)
		if l != nil {
			l.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("QUIC listener accepted TLS settings without server certificate")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("failed listener initialization hung on a deadline-ignoring socket")
	}
	if _, err := raw.WriteTo([]byte("closed"), raw.LocalAddr()); err == nil {
		t.Fatal("failed listener initialization retained packet socket")
	}
}
