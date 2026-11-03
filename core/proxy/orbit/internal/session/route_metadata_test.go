package session

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/orbit/internal/protocol"
)

func TestTerminalRouteMetadataOwnership(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	route := []byte{0, 1, 2, 3, 0xff}
	type result struct {
		s   *Session
		err error
	}
	ready := make(chan result, 1)
	go func() {
		s, e := Server(ctx, b, ServerOptions{RouteMetadata: route, Authenticate: func(context.Context, protocol.UserInfo) error { return nil }})
		ready <- result{s, e}
	}()
	c, e := Client(ctx, a, ClientOptions{User: protocol.UserInfo{UID: "local", Token: "test", DeviceID: "test"}})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	r := <-ready
	if r.err != nil {
		t.Fatal(r.err)
	}
	defer r.s.Close()
	want := append([]byte(nil), route...)
	route[0] = 99
	if !bytes.Equal(r.s.RouteMetadata(), want) {
		t.Fatal("source mutation changed retained route")
	}
	copy := r.s.RouteMetadata()
	copy[1] = 99
	if !bytes.Equal(r.s.RouteMetadata(), want) {
		t.Fatal("accessor exposed owned route storage")
	}
	if len(c.RouteMetadata()) != 0 {
		t.Fatal("opaque server route was put on session wire")
	}
}
