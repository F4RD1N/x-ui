package websocket_test

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	. "github.com/xtls/xray-core/transport/internet/websocket"
)

// listenEcho starts a WebSocket server with this path that answers
// "Response:" and what it read.
func listenEcho(t *testing.T, path string) net.Port {
	t.Helper()
	port := tcp.PickPort()
	ln, err := ListenWS(context.Background(), net.LocalHostIP, port, &internet.MemoryStreamConfig{
		ProtocolName:     "websocket",
		ProtocolSettings: &Config{Path: path},
	}, func(conn stat.Connection) {
		go func(c stat.Connection) {
			defer c.Close()
			var b [1024]byte
			c.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := c.Read(b[:])
			if err != nil {
				return
			}
			c.Write(append([]byte("Response:"), b[:n]...))
		}(conn)
	})
	common.Must(err)
	t.Cleanup(func() { ln.Close() })
	return port
}

// roundTrip dials with this client config and returns the answer, or the error.
func roundTrip(port net.Port, client *Config) (string, error) {
	conn, err := Dial(context.Background(), net.TCPDestination(net.DomainAddress("localhost"), port),
		&internet.MemoryStreamConfig{ProtocolName: "websocket", ProtocolSettings: client})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("hi")); err != nil {
		return "", err
	}
	// a read may return nothing yet (HTTPUpgrade with early data first takes
	// in the upgrade reply)
	var b [1024]byte
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		n, err := conn.Read(b[:])
		if n > 0 || err != nil {
			return string(b[:n]), err
		}
	}
}

func TestAnyPath(t *testing.T) {
	for _, server := range []string{"*", "/*"} {
		port := listenEcho(t, server)
		for _, client := range []*Config{
			{Path: "/feed/966695/assets/recent/media"},
			{Path: "random"},
			{Path: "/a/b?id=1"},
			{Path: "/"},
			{Path: "*"},
			{Path: "/early/data", Ed: 2560}, // first bytes ride in Sec-WebSocket-Protocol
		} {
			got, err := roundTrip(port, client)
			if err != nil || got != "Response:hi" {
				t.Errorf("server %q, client %q (ed %d): %q, %v", server, client.Path, client.Ed, got, err)
			}
		}
	}
}

func TestExactPathStillRequired(t *testing.T) {
	port := listenEcho(t, "/ws")
	if got, err := roundTrip(port, &Config{Path: "/ws"}); err != nil || got != "Response:hi" {
		t.Errorf("the right path: %q, %v", got, err)
	}
	for _, path := range []string{"/other", "/ws/more", "/*", "*"} {
		if got, err := roundTrip(port, &Config{Path: path}); err == nil {
			t.Errorf("path %q taken by a /ws server: %q", path, got)
		}
	}
}

func TestAnyPathOnlyForStar(t *testing.T) {
	for path, want := range map[string]bool{"*": true, "/*": true, "": false, "/": false, "/ws": false, "/*/x": false, "**": false} {
		if got := (&Config{Path: path}).AnyPath(); got != want {
			t.Errorf("AnyPath(%q) = %v, want %v", path, got, want)
		}
	}
}
