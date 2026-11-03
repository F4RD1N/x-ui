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

func startupOptions() ClientOptions {
	return ClientOptions{User: protocol.UserInfo{UID: "owned-test", Token: "local-token", DeviceID: "synthetic-device"}, InitialReachID: 42}
}

func TestPipelinedReachArrivesBeforeAuthenticationReply(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	type result struct {
		session *Session
		err     error
	}
	done := make(chan result, 1)
	go func() { s, err := Client(ctx, client, startupOptions()); done <- result{s, err} }()
	server.SetDeadline(time.Now().Add(time.Second))
	first, err := protocol.ReadFrame(server)
	if err != nil || first.Type != protocol.TypeConnect {
		t.Fatal("missing initial connect request", err)
	}
	second, err := protocol.ReadFrame(server)
	if err != nil {
		t.Fatal("reach request waited for authentication reply", err)
	}
	reach, err := protocol.ParseAppMessage(second)
	if err != nil || reach.Type != 1 || reach.RequestID != 42 || len(reach.Data) != 0 {
		t.Fatal("unexpected pipelined application bytes", err)
	}
	select {
	case <-done:
		t.Fatal("session became ready without authentication reply")
	default:
	}
	if err = protocol.WriteFrame(server, protocol.Frame{Type: protocol.TypeConnectResponse}); err != nil {
		t.Fatal(err)
	}
	r := <-done
	if r.err != nil {
		t.Fatal(r.err)
	}
	defer r.session.Close()
}

func TestPipelinedReachWorksWithUnmodifiedServerAndUnbufferedConn(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	releaseServer := make(chan struct{})
	defer close(releaseServer)
	done := make(chan error, 1)
	go func() {
		s, err := Server(ctx, server, ServerOptions{Authenticate: func(context.Context, protocol.UserInfo) error { return nil }})
		if err != nil {
			done <- err
			return
		}
		defer s.Close()
		m, err := s.ReceiveApp(ctx)
		if err == nil && (m.Type != 1 || m.RequestID != 42 || len(m.Data) != 0) {
			err = errors.New("invalid reach message")
		}
		done <- err
		// Receiving reach bytes does not mean the client's writer goroutine
		// has joined or that its handshake deadline has been cleared. Keep the
		// fixture alive until the client completes those startup assertions.
		<-releaseServer
	}()
	s, err := Client(ctx, client, startupOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPipelinedReachDoesNotReplaceAuthentication(t *testing.T) {
	for _, reply := range []protocol.Frame{protocol.KickOut(500), {Type: protocol.TypeApp}, {Type: protocol.TypeConnectResponse, Payload: []byte{1}}} {
		client, server := net.Pipe()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		done := make(chan error, 1)
		go func() {
			defer server.Close()
			if _, err := protocol.ReadFrame(server); err != nil {
				done <- err
				return
			}
			// Reject before reading the pipelined reach. The client must close
			// and reap its blocked writer instead of deadlocking or succeeding.
			done <- protocol.WriteFrame(server, reply)
		}()
		s, err := Client(ctx, client, startupOptions())
		cancel()
		client.Close()
		if err == nil || s != nil {
			t.Fatal("invalid authentication reply accepted")
		}
		if reply.Type == protocol.TypeKickOut && !errors.Is(err, ErrAuthentication) {
			t.Fatal("authentication rejection lost", err)
		}
		if err = <-done; err != nil {
			t.Fatal(err)
		}
	}
}

func TestPipelinedReachCancellationClosesReaderAndWriter(t *testing.T) {
	for _, readConnect := range []bool{false, true} {
		client, server := net.Pipe()
		defer server.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
		done := make(chan error, 1)
		go func() {
			s, err := Client(ctx, client, startupOptions())
			if s != nil {
				s.Close()
			}
			done <- err
		}()
		if readConnect {
			server.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := protocol.ReadFrame(server); err != nil {
				t.Fatal(err)
			}
			cancel()
		}
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("stalled pipelined handshake succeeded")
			}
		case <-time.After(time.Second):
			t.Fatal("pipelined handshake leaked a blocked writer")
		}
		cancel()
		server.SetReadDeadline(time.Now().Add(time.Second))
		_, err := io.Copy(io.Discard, server)
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Fatal("failed handshake left socket open")
		}
	}
}
