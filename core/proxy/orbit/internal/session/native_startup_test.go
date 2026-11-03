package session

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/orbit/internal/protocol"
)

func TestNativeStartupControlsRequireConnectionAndFreshReach(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		if _, err := protocol.ReadFrame(server); err != nil {
			done <- err
			return
		}
		stale, _ := (protocol.AppMessage{Type: 2, Data: []byte(`{"node_id":123,"ip":"192.0.2.1"}`)}).Frame()
		for _, f := range []protocol.Frame{stale, {Type: protocol.TypeHeartbeat}, {Type: protocol.TypeConnectResponse, Payload: []byte{1, 2, 3}}} {
			if err := protocol.WriteFrame(server, f); err != nil {
				done <- err
				return
			}
		}
		f, err := protocol.ReadFrame(server)
		if err != nil {
			done <- err
			return
		}
		request, err := protocol.ParseAppMessage(f)
		if err != nil || request.Type != 1 || request.RequestID != 42 {
			done <- protocol.ErrMalformed
			return
		}
		ack, _ := (protocol.AppMessage{Type: 2, RequestID: 42, Data: []byte(`{"node_id":456}`)}).Frame()
		done <- protocol.WriteFrame(server, ack)
	}()
	s, err := Client(ctx, client, ClientOptions{NativeCompatibility: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// The earlier zero-ID reach notification must not enter the session queue.
	check, stop := context.WithTimeout(ctx, 10*time.Millisecond)
	if _, err := s.ReceiveApp(check); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("stale startup ACK leaked into readiness", err)
	}
	stop()
	if err := s.SendApp(ctx, protocol.AppMessage{Type: 1, RequestID: 42}); err != nil {
		t.Fatal(err)
	}
	ack, err := s.ReceiveApp(ctx)
	if err != nil || ack.RequestID != 42 {
		t.Fatal("fresh reach response missing", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestNativeStartupNotificationsCannotAuthorizeAndStayBounded(t *testing.T) {
	app, _ := (protocol.AppMessage{Type: 2}).Frame()
	for _, test := range []struct {
		name      string
		native    bool
		frames    []protocol.Frame
		authError bool
	}{
		{"owned-notification-rejected", false, []protocol.Frame{app}, false},
		{"owned-extension-rejected", false, []protocol.Frame{{Type: protocol.TypeConnectResponse, Payload: []byte{1}}}, false},
		{"native-notification-only", true, []protocol.Frame{app}, false},
		{"native-kickout-after-notification", true, []protocol.Frame{app, protocol.KickOut(1)}, true},
		{"native-invalid-notification", true, []protocol.Frame{{Type: protocol.TypeApp, Payload: []byte{1}}}, false},
		{"native-data-before-reply", true, []protocol.Frame{{Type: protocol.TypeData}}, false},
		{"native-control-flood", true, make([]protocol.Frame, 17), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer b.Close()
				if _, err := protocol.ReadFrame(b); err != nil {
					return
				}
				for _, f := range test.frames {
					if test.name == "native-control-flood" {
						f = protocol.Frame{Type: protocol.TypeHeartbeat}
					}
					if protocol.WriteFrame(b, f) != nil {
						return
					}
				}
			}()
			s, err := Client(ctx, a, ClientOptions{NativeCompatibility: test.native})
			if s != nil {
				s.Close()
				t.Fatal("missing valid connection response authorized")
			}
			if err == nil || test.authError && !errors.Is(err, ErrAuthentication) {
				t.Fatal("unexpected startup result", err)
			}
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.ErrNoProgress) {
				t.Fatal("unbounded startup", err)
			}
			<-done
		})
	}
}
