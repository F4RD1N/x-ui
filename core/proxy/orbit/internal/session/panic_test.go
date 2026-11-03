package session

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/orbit/internal/protocol"
)

// panicCloseConn is a carrier whose Close panics: a stand-in for any bug
// reached while a session shuts down.
type panicCloseConn struct{ net.Conn }

func (panicCloseConn) Close() error { panic("injected close failure") }

// TestShutdownOnCancelPanicIsContained: a session ends when its context is
// cancelled, on a goroutine of its own. A panic there must stop in that
// goroutine (the session is still marked done) instead of ending the process
// and with it every other outbound of the Xray instance.
func TestShutdownOnCancelPanicIsContained(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	defer a.Close()
	o, err := (Options{}).normalized()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := newSession(ctx, panicCloseConn{a}, o, protocol.UserInfo{}, protocol.ConnectRequest{}, false, nil)
	cancel()
	select {
	case <-s.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("the cancelled session never ended")
	}
	// Give the shutdown goroutine time to reach the panicking Close.
	time.Sleep(200 * time.Millisecond)
}
