package transport

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestWebSocketWriteDeadlineConcurrentWithWrites: gorilla's SetWriteDeadline
// stores a plain field that WriteMessage reads, and the session sets it from
// its writer while shutdown's tls.Conn.Close (closeNotify) sets it from
// another goroutine. Under -race this fails unless the stream serializes
// deadline changes with writes.
func TestWebSocketWriteDeadlineConcurrentWithWrites(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stream, err := AcceptWebSocket(ctx, w, r)
		if err != nil {
			return
		}
		defer stream.Close()
		_, _ = io.Copy(io.Discard, stream)
	}))
	defer server.Close()
	stream, err := DialWebSocket(ctx, WebSocketDialOptions{Address: server.Listener.Addr().String(), Host: "owned.test", Path: "/core", DialContext: new(net.Dialer).DialContext})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	payload := bytes.Repeat([]byte("x"), 1024)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // Session.writeLoop
		defer wg.Done()
		for i := 0; i < 300; i++ {
			_ = stream.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := stream.Write(payload); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	go func() { // tls.Conn.closeNotify, and SetDeadline users
		defer wg.Done()
		for i := 0; i < 300; i++ {
			_ = stream.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
		}
	}()
	wg.Wait()
}

// TestWebSocketStreamOnDoneContext: a stream built on a context that is
// already done (an outbound closed or reset just as a dial finished) closes
// itself from the context callback while the constructor still stores the
// callback's stop function. -race catches an unsynchronized store.
func TestWebSocketStreamOnDoneContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		// The context callback is the only Close here.
		if _, err := AcceptWebSocket(ctx, w, r); err == nil {
			time.Sleep(20 * time.Millisecond)
		}
	}))
	defer server.Close()
	for i := 0; i < 20; i++ {
		stream, err := DialWebSocket(context.Background(), WebSocketDialOptions{Address: server.Listener.Addr().String(), Host: "owned.test", Path: "/core", DialContext: new(net.Dialer).DialContext})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = stream.Read(make([]byte, 1))
		stream.Close()
	}
}
