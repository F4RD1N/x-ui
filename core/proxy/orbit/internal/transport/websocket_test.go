package transport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestWebSocketBinaryStreamChunkingAndLifetime(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(finished)
		stream, err := AcceptWebSocket(ctx, w, r)
		if err != nil {
			return
		}
		defer stream.Close()
		_, _ = io.Copy(stream, stream)
	}))
	defer server.Close()
	dialer := new(net.Dialer)
	clientCtx, clientCancel := context.WithCancel(ctx)
	defer clientCancel()
	stream, err := DialWebSocket(clientCtx, WebSocketDialOptions{Address: server.Listener.Addr().String(), Host: "owned.test", Path: "/core", DialContext: dialer.DialContext, Timeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	// A successful stream outlives the separate WebSocket handshake deadline.
	time.Sleep(250 * time.Millisecond)
	stream.SetDeadline(time.Now().Add(3 * time.Second))
	payload := bytes.Repeat([]byte("chunked binary tunnel\x00"), 15000)
	writeDone := make(chan error, 1)
	go func() { _, err := stream.Write(payload); writeDone <- err }()
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(stream, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatal("large stream failed bounded message chunking", err)
	}
	if err = <-writeDone; err != nil {
		t.Fatal(err)
	}
	clientCancel()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("idle canceled socket remained open")
	}
}

func TestWebSocketRejectsTextAndOversizedMessages(t *testing.T) {
	for _, kind := range []string{"text", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			result := make(chan error, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				stream, err := AcceptWebSocket(context.Background(), w, r)
				if err != nil {
					result <- err
					return
				}
				defer stream.Close()
				_, err = io.Copy(io.Discard, stream)
				result <- err
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			client, _, err := websocket.DefaultDialer.DialContext(ctx, "ws://"+server.Listener.Addr().String(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			messageType := websocket.TextMessage
			payload := []byte("not a binary tunnel")
			if kind == "oversized" {
				messageType = websocket.BinaryMessage
				payload = make([]byte, WebSocketMessageLimit+1)
			}
			_ = client.WriteMessage(messageType, payload)
			// A reader lets the close handshake finish promptly.
			_ = client.SetReadDeadline(time.Now().Add(time.Second))
			_, _, _ = client.ReadMessage()
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("invalid WebSocket message was accepted")
				}
			case <-ctx.Done():
				t.Fatal("invalid message did not terminate the stream")
			}
		})
	}
}

func TestWebSocketNoRedirectsAndDialCancellation(t *testing.T) {
	var unexpected atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		unexpected.Add(1)
		http.Error(w, "unexpected", 500)
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	dialer := new(net.Dialer)
	opts := WebSocketDialOptions{Address: redirect.Listener.Addr().String(), Host: "owned.test", Path: "/core", DialContext: dialer.DialContext}
	stream, err := DialWebSocket(context.Background(), opts)
	if err == nil {
		stream.Close()
		t.Fatal("redirect accepted")
	}
	if unexpected.Load() != 0 {
		t.Fatal("redirect was followed")
	}
	opts.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = DialWebSocket(ctx, opts)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("canceled dial did not retain cancellation", err)
	}
}

func TestWebSocketStreamReadDeadline(t *testing.T) {
	serverCtx, cancelServer := context.WithCancel(context.Background())
	defer cancelServer()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stream, err := AcceptWebSocket(serverCtx, w, r)
		if err != nil {
			return
		}
		defer stream.Close()
		_, _ = io.Copy(io.Discard, stream)
	}))
	defer server.Close()
	dialer := new(net.Dialer)
	stream, err := DialWebSocket(serverCtx, WebSocketDialOptions{Address: server.Listener.Addr().String(), Host: "owned.test", Path: "/core", DialContext: dialer.DialContext})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	started := time.Now()
	stream.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	_, err = stream.Read(make([]byte, 1))
	// The deadline ends the blocked read; the lifetime context is unaffected.
	if err == nil || time.Since(started) > time.Second || serverCtx.Err() != nil {
		t.Fatal("blocked read ignored its deadline", err)
	}
}
