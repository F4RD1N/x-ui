package transport

import (
	"sync/atomic"
	"testing"
	"time"
)

// shortHeartbeat makes the native timer tick every 10 ms: the heartbeat
// request goes out at tick 30 (300 ms) and an unacknowledged session
// expires at tick 38 (380 ms). It must run before the test server starts.
func shortHeartbeat(t *testing.T) {
	old := heartbeatPeriod
	heartbeatPeriod = 10 * time.Millisecond
	t.Cleanup(func() { heartbeatPeriod = old })
}

// TestQUICHeartbeatKeepsAnIdleSessionAlive: an idle QUIC session sends its
// heartbeat at tick 30, the server acknowledges it, and the session lives
// through many expiry periods. Without the heartbeat it would expire at
// tick 38, since only an acknowledgement resets the counter.
func TestQUICHeartbeatKeepsAnIdleSessionAlive(t *testing.T) {
	shortHeartbeat(t)
	serverTLS, clientTLS := testTLS(t)
	srv := listenTestQUIC(t, serverTLS, QUICServerOptions{}, nil)
	q := dialTestQUIC(t, srv, clientTLS)
	select {
	case <-q.Done():
		t.Fatal("an idle session with an answering server expired:", q.Err())
	case <-time.After(1500 * time.Millisecond): // about four heartbeat cycles
	}
}

// TestQUICHeartbeatExpiresWithoutAcknowledgement: when the server stops
// answering, the session closes itself at tick 38, long before QUIC's 20 s
// idle timeout.
func TestQUICHeartbeatExpiresWithoutAcknowledgement(t *testing.T) {
	shortHeartbeat(t)
	serverTLS, clientTLS := testTLS(t)
	var silent atomic.Bool
	srv := listenTestQUIC(t, serverTLS, QUICServerOptions{}, silent.Load)
	q := dialTestQUIC(t, srv, clientTLS)
	silent.Store(true)
	select {
	case <-q.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("a session whose heartbeat went unanswered did not expire")
	}
}
