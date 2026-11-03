package client

import (
	"testing"
	"time"
)

// TestRxPacer: the reader pauses only in a slow stream, after a read that
// had to wait, for about rxBatch packets' worth of the stream, and at most
// rxCoalesce; a fast stream, packets already waiting and a packet after a
// quiet spell get no pause.
func TestRxPacer(t *testing.T) {
	us := time.Microsecond
	ms := time.Millisecond
	// stream feeds n packets arriving every gap, each read waiting for its
	// packet, and returns the pauses asked for.
	stream := func(p *rxPacer, at time.Time, gap time.Duration, n int) ([]time.Duration, time.Time) {
		var pauses []time.Duration
		for i := 0; i < n; i++ {
			start := at
			at = at.Add(gap)
			pauses = append(pauses, p.read(start, at))
		}
		return pauses, at
	}
	base := time.Unix(1000, 0)

	t.Run("slow stream", func(t *testing.T) {
		var p rxPacer
		if d := p.read(base, base); d != 0 {
			t.Fatalf("first packet: pause %v", d)
		}
		pauses, _ := stream(&p, base, 550*us, 5) // ~20 Mbit/s
		for i, d := range pauses {
			if d != rxCoalesce {
				t.Errorf("packet %d: pause %v, want %v", i, d, rxCoalesce)
			}
		}
	})
	t.Run("pause scales with the rate", func(t *testing.T) {
		var p rxPacer
		p.read(base, base)
		pauses, _ := stream(&p, base, 400*us, 3)
		if want := time.Duration(rxBatch) * 400 * us; pauses[2] != want {
			t.Errorf("pause %v, want %v", pauses[2], want)
		}
	})
	t.Run("fast stream", func(t *testing.T) {
		var p rxPacer
		p.read(base, base)
		pauses, _ := stream(&p, base, 100*us, 20) // ~110 Mbit/s
		for i, d := range pauses {
			if d != 0 {
				t.Errorf("packet %d: pause %v, want none", i, d)
			}
		}
	})
	t.Run("batch after a pause", func(t *testing.T) {
		var p rxPacer
		p.read(base, base)
		_, at := stream(&p, base, 550*us, 3)
		// After the pause four packets were waiting: read at once, no pause.
		at = at.Add(rxCoalesce)
		for i := 0; i < 4; i++ {
			if d := p.read(at, at.Add(5*us)); d != 0 {
				t.Errorf("queued packet %d: pause %v", i, d)
			}
			at = at.Add(5 * us)
		}
		// The next read waits: the rate over the cycle is still ~0.5 ms a packet.
		start := at
		at = at.Add(200 * us)
		if d := p.read(start, at); d != rxCoalesce {
			t.Errorf("after the batch: pause %v, want %v", d, rxCoalesce)
		}
	})
	t.Run("quiet spell", func(t *testing.T) {
		var p rxPacer
		p.read(base, base)
		_, at := stream(&p, base, 550*us, 3)
		start := at
		at = at.Add(50 * ms)
		if d := p.read(start, at); d != 0 {
			t.Errorf("a packet after 50 ms: pause %v", d)
		}
		if p.gap != 0 {
			t.Errorf("the stream's rate was kept across a quiet spell: %v", p.gap)
		}
	})
}
