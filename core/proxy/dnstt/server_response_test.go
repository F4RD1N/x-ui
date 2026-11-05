package dnstt

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	xlog "github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

type responseTestDispatcher struct {
	routing.Dispatcher
	handle func(context.Context, xnet.Destination, *transport.Link) error
}

func (d *responseTestDispatcher) DispatchLink(ctx context.Context, target xnet.Destination, link *transport.Link) error {
	return d.handle(ctx, target, link)
}

func responseTestServer(t *testing.T) *Server {
	t.Helper()
	// No listeners are configured or started. The existing private VLESS
	// handler runs over net.Pipe so these regressions need no network access.
	instance, err := core.New(&core.Config{App: []*serial.TypedMessage{
		serial.ToTypedMessage(&xlog.Config{}), serial.ToTypedMessage(&dispatcher.Config{}),
		serial.ToTypedMessage(&proxyman.InboundConfig{}), serial.ToTypedMessage(&proxyman.OutboundConfig{}),
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	object, err := core.CreateObject(instance, nativeServerConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	server := object.(*Server)
	t.Cleanup(func() { _ = server.Close() })
	return server
}

func TestNativeServerVLESSResponsePrecedesSlowTarget(t *testing.T) {
	for _, udp := range []bool{false, true} {
		t.Run(map[bool]string{false: "tcp", true: "udp"}[udp], func(t *testing.T) {
			server := responseTestServer(t)
			clientSide, serverSide := net.Pipe()
			defer clientSide.Close()
			defer serverSide.Close()
			_ = clientSide.SetDeadline(time.Now().Add(5 * time.Second))
			_ = serverSide.SetDeadline(time.Now().Add(5 * time.Second))
			destination := xnet.TCPDestination(xnet.LocalHostIP, 8080)
			if udp {
				destination.Network = xnet.Network_UDP
			}
			finished := make(chan error, 1)
			dispatch := &responseTestDispatcher{handle: func(_ context.Context, target xnet.Destination, link *transport.Link) error {
				if target != destination {
					return errors.New("inner destination changed")
				}
				// Model an HTTP target which does not answer until the full upload
				// arrives, beyond the unchanged client's one-second header timeout.
				reader := &buf.BufferedReader{Reader: link.Reader}
				got := make([]byte, 5)
				if _, err := io.ReadFull(reader, got); err != nil {
					return err
				}
				if !bytes.Equal(got, []byte("abcde")) {
					return errors.New("upload bytes changed")
				}
				return link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("ok"))})
			}}
			go func() {
				defer serverSide.Close()
				ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: "dnstt"})
				finished <- server.inner.Process(ctx, xnet.Network_TCP, serverSide, &authenticatedDispatcher{
					Dispatcher: dispatch, promote: func() bool { return true }, eagerVLESSResponse: true,
				})
			}()
			cfg := normalizedTestConfig(t)
			cfg.HandshakeTimeout = 1
			conn, packets, err := innerConnection(context.Background(), clientSide, destination, cfg)
			if err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() {
				var got []byte
				var err error
				if udp {
					got, _, err = packets.ReadPacket()
				} else {
					got = make([]byte, 2)
					_, err = io.ReadFull(conn, got)
				}
				if err == nil && !bytes.Equal(got, []byte("ok")) {
					err = errors.New("early header duplicated into payload")
				}
				result <- err
			}()
			for _, b := range []byte("abcde") {
				time.Sleep(250 * time.Millisecond)
				if udp {
					err = packets.WritePacket([]byte{b}, destination)
				} else {
					_, err = conn.Write([]byte{b})
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			select {
			case err = <-result:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("response did not complete")
			}
			if err = <-finished; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNativeServerVLESSEarlyResponseRequiresAuthenticationAndCapacity(t *testing.T) {
	for _, tc := range []struct {
		name                string
		validUser, capacity bool
	}{
		{"wrong_uuid", false, true}, {"capacity_denied", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := responseTestServer(t)
			clientSide, serverSide := net.Pipe()
			defer clientSide.Close()
			defer serverSide.Close()
			_ = clientSide.SetDeadline(time.Now().Add(3 * time.Second))
			var called atomic.Bool
			dispatch := &responseTestDispatcher{handle: func(context.Context, xnet.Destination, *transport.Link) error { called.Store(true); return nil }}
			finished := make(chan error, 1)
			go func() {
				defer serverSide.Close()
				ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: "dnstt"})
				finished <- server.inner.Process(ctx, xnet.Network_TCP, serverSide, &authenticatedDispatcher{Dispatcher: dispatch, promote: func() bool { return tc.capacity }, eagerVLESSResponse: true})
			}()
			cfg := normalizedTestConfig(t)
			if !tc.validUser {
				cfg.Inner.Uuid = "00112233-4455-6677-8899-aabbccddeeff"
			}
			_, _, err := innerConnection(context.Background(), clientSide, xnet.TCPDestination(xnet.LocalHostIP, 8080), cfg)
			if err != nil {
				t.Fatal(err)
			}
			var one [1]byte
			if n, err := clientSide.Read(one[:]); n != 0 || err == nil {
				t.Fatal("rejected request received a success header")
			}
			if err := <-finished; err == nil {
				t.Fatal("rejected request returned success")
			}
			if called.Load() {
				t.Fatal("rejected request reached target dispatcher")
			}
		})
	}
}

func TestNativeServerVLESSEarlyResponseRejectsInvalidDestination(t *testing.T) {
	var output bytes.Buffer
	writer := buf.NewBufferedWriter(buf.NewWriter(&output))
	_, _ = writer.Write([]byte{0, 0})
	called := false
	d := &authenticatedDispatcher{Dispatcher: &responseTestDispatcher{handle: func(context.Context, xnet.Destination, *transport.Link) error { called = true; return nil }}, promote: func() bool { return true }, eagerVLESSResponse: true}
	if err := d.DispatchLink(context.Background(), xnet.Destination{}, &transport.Link{Writer: writer}); err == nil {
		t.Fatal("invalid destination accepted")
	}
	if output.Len() != 0 || called {
		t.Fatal("invalid destination received success or dispatch")
	}
}
