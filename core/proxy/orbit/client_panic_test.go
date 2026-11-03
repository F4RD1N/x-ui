package orbit

import (
	"context"
	"testing"
	"time"
)

// TestPanickingProbeIsContained: the heartbeat probe runs on a timer
// goroutine of its own. A panic there must end only that session (it is
// retired and the next request dials anew), never the process and with it
// every other outbound of the instance.
func TestPanickingProbeIsContained(t *testing.T) {
	shortTimers(t, 2*time.Second, 50*time.Millisecond, 200*time.Millisecond)
	port, _ := silentServer(t)
	c := testClient(t, port, 1)
	defer c.Close()
	p := &probingStuckPeer{stuckPeer: newStuckPeer(), probe: func(context.Context) error { panic("injected probe failure") }}
	g := withGeneration(c, p, "quic")
	if err := processTCP(c, 5*time.Second); err == nil {
		t.Fatal("a request over a session whose probe panicked succeeded")
	}
	if p.probes.Load() == 0 {
		t.Fatal("the probe never ran")
	}
	deadline := time.Now().Add(2 * time.Second)
	for g.alive() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if g.alive() || p.closes.Load() == 0 {
		t.Fatal("a session whose probe panicked was kept")
	}
}
