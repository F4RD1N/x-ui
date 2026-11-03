package mieru

// Padding and UDP liveness: segments must not have fixed lengths, padding
// must stay inside the UDP MTU and round-trip through the parser, an idle UDP
// session must send heartbeats, and a session the server has gone silent on
// must end instead of waiting forever.

import (
	"bytes"
	"io"
	"math/bits"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// recordConn keeps every write; over UDP each write is one datagram.
type recordConn struct {
	net.Conn
	writes [][]byte
}

func (r *recordConn) Write(p []byte) (int, error) {
	r.writes = append(r.writes, append([]byte(nil), p...))
	return len(p), nil
}

func printableRun(b []byte) int {
	best, run := 0, 0
	for _, c := range b {
		if c >= '!' && c <= '~' {
			run++
			best = max(best, run)
		} else {
			run = 0
		}
	}
	return best
}

func rareBitShare(b []byte) float64 {
	ones := 0
	for _, c := range b {
		ones += bits.OnesCount8(c)
	}
	return float64(min(ones, len(b)*8-ones)) / float64(len(b)*8)
}

func TestPaddingVariesLengthsAndRoundTrips(t *testing.T) {
	kinds := []struct {
		name    string
		kind    byte
		payload int
	}{
		{"open", openRequest, 0},
		{"close", closeRequest, 0},
		{"ack", ackClient, 0},
		{"data", dataClient, 100},
		{"full-udp-data", dataClient, udpSegment},
		{"oversized-data", dataClient, udpMTU - packetOverhead}, // no room left for padding
	}
	for _, udp := range []bool{true, false} {
		for _, custom := range []bool{false, true} {
			for _, ascii := range []bool{true, false} {
				for _, k := range kinds {
					name := map[bool]string{true: "udp", false: "tcp"}[udp] + "-" + k.name
					if custom {
						name += "-trailer"
					}
					name += map[bool]string{true: "-ascii", false: "-entropy"}[ascii]
					t.Run(name, func(t *testing.T) {
						user := "user"
						if custom {
							user = "00112233-4455-6677-8899-aabbccddeeff"
						}
						rc := &recordConn{}
						w, _ := newWire(rc, user, "pass", udp, custom)
						w.asciiPadding = ascii
						r, _ := newWire(nil, user, "pass", udp, custom)
						payload := randomBytes(k.payload)
						const n = 200
						for i := 0; i < n; i++ {
							if e := w.write(segment{kind: k.kind, session: 7, seq: uint32(i), payload: payload}); e != nil {
								t.Fatal(e)
							}
						}
						lengths := map[int]bool{}
						limit := udpMTU
						if custom {
							limit += 16
						}
						var stream []byte
						for i, d := range rc.writes {
							lengths[len(d)] = true
							if udp && len(d) > limit {
								t.Fatalf("datagram of %d bytes exceeds the MTU", len(d))
							}
							if k.kind < dataClient {
								if ascii && printableRun(d) < 24 {
									t.Fatalf("segment %d: no printable run of 24 bytes", i)
								}
								if !ascii && rareBitShare(d) > 0.36 {
									t.Fatalf("segment %d: rarer bit is %.3f of the segment", i, rareBitShare(d))
								}
							}
							stream = append(stream, d...)
						}
						// The receiver must find every segment back, consuming
						// exactly the padding the metadata announced.
						var src io.Reader = bytes.NewReader(stream)
						for i := 0; i < n; i++ {
							if udp {
								src = &sliceReader{p: rc.writes[i]}
							}
							if custom {
								// The UUID trailer is the adapter's to strip.
								src = &trailerSkipper{r: src, noNonce: !udp && i > 0}
							}
							s, e := r.parse(src)
							if e != nil {
								t.Fatalf("segment %d: %v", i, e)
							}
							if s.kind != k.kind || s.seq != uint32(i) || !bytes.Equal(s.payload, payload) {
								t.Fatalf("segment %d came back wrong", i)
							}
							if sr, ok := src.(*sliceReader); ok && len(sr.p) != 0 {
								t.Fatalf("segment %d: %d bytes left after parsing", i, len(sr.p))
							}
						}
						if k.payload == udpMTU-packetOverhead && udp {
							return // padding has no room at all here
						}
						if len(lengths) < 20 {
							t.Fatalf("only %d distinct lengths in %d segments", len(lengths), n)
						}
					})
				}
			}
		}
	}
}

// trailerSkipper drops the 16-byte UUID trailer that follows the sealed
// metadata (and the nonce, when present), as the metadata adapter does.
type trailerSkipper struct {
	r       io.Reader
	noNonce bool // a TCP segment after the first carries no nonce
	read    int
}

func (s *trailerSkipper) Read(p []byte) (int, error) {
	head := 24 + 48
	if s.noNonce {
		head = 48
	}
	if s.read == head {
		var t [16]byte
		if _, e := io.ReadFull(s.r, t[:]); e != nil {
			return 0, e
		}
		s.read += 16
	}
	if s.read < head {
		p = p[:min(len(p), head-s.read)]
	}
	n, e := s.r.Read(p)
	s.read += n
	return n, e
}

func shortLiveness(t *testing.T, l liveness) {
	saved := udpLiveness
	udpLiveness = l
	t.Cleanup(func() { udpLiveness = saved })
}

func (f *fakeUDP) ackCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.acks {
		n += c
	}
	return n
}

// An idle UDP session must keep telling the server it is alive.
func TestUDPIdleSessionSendsHeartbeats(t *testing.T) {
	shortLiveness(t, liveness{interval: 200 * time.Millisecond, jitter: 50 * time.Millisecond, idle: time.Minute})
	f := &fakeUDP{}
	c, _ := startFakeUDP(t, f)
	time.Sleep(100 * time.Millisecond)
	before := f.ackCount() // the ACK of the open response
	time.Sleep(1200 * time.Millisecond)
	if got := f.ackCount() - before; got < 4 {
		t.Fatalf("%d heartbeats in 1.2 s of idling, want at least 4", got)
	}
	if c.ended() {
		t.Fatal(c.error())
	}
}

// A session the server has gone silent on must end with an error, not hang.
func TestUDPSilentServerEndsSession(t *testing.T) {
	shortLiveness(t, liveness{interval: 200 * time.Millisecond, jitter: 50 * time.Millisecond, idle: 700 * time.Millisecond})
	f := &fakeUDP{}
	c, _ := startFakeUDP(t, f)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	_, e := c.Read(make([]byte, 16))
	if e != errIdle || time.Since(start) > 2*time.Second {
		t.Fatalf("read on a silent session: %v after %v", e, time.Since(start))
	}
}

// Server heartbeats alone keep an idle session open.
func TestUDPServerHeartbeatsKeepSessionAlive(t *testing.T) {
	shortLiveness(t, liveness{interval: 200 * time.Millisecond, jitter: 50 * time.Millisecond, idle: 700 * time.Millisecond})
	f := &fakeUDP{}
	c, _ := startFakeUDP(t, f)
	f.mu.Lock()
	sid := f.sid
	f.mu.Unlock()
	for i := 0; i < 10; i++ {
		_ = f.w.write(segment{kind: ackServer, session: sid, unack: 1})
		time.Sleep(200 * time.Millisecond)
	}
	if c.ended() {
		t.Fatalf("session with a heartbeating server ended: %v", c.error())
	}
}

// Against real mita: a UDP session left idle past mita's one-minute idle
// limit must still carry data both ways. Slow (80 s), so it runs only when
// MIERU_IDLE_TEST is set, besides NATIVE_MITA; run it under the interop lock.
func TestUpstreamMitaIdleUDP(t *testing.T) {
	if os.Getenv("MIERU_IDLE_TEST") == "" {
		t.Skip("MIERU_IDLE_TEST not set")
	}
	for _, bin := range mitaServers(t) {
		t.Run(filepath.Base(filepath.Dir(bin)), func(t *testing.T) {
			t.Parallel()
			addr := startMita(t, bin, "udp")
			dst, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer dst.Close()
			c := dialMita(t, "udp", addr, dst.Addr())
			defer c.Close()
			if _, e = c.Write([]byte("hi")); e != nil {
				t.Fatal(e)
			}
			d, e := dst.Accept()
			if e != nil {
				t.Fatal(e)
			}
			defer d.Close()
			got := make([]byte, 2)
			_ = d.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, e = io.ReadFull(d, got); e != nil || string(got) != "hi" {
				t.Fatalf("destination: %q %v", got, e)
			}
			time.Sleep(75 * time.Second)
			// mita sweeps idle sessions only when its socket receives
			// something, so another client's session triggers the sweep, as
			// any busy server's traffic would.
			other := dialMita(t, "udp", addr, dst.Addr())
			if o, e := dst.Accept(); e == nil {
				o.Close()
			}
			other.Close()
			time.Sleep(time.Second)
			// Server-pushed data after the idle period: lost if mita
			// dropped the session.
			if _, e = d.Write([]byte("pong")); e != nil {
				t.Fatal(e)
			}
			got = make([]byte, 4)
			_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
			if _, e = io.ReadFull(c, got); e != nil || string(got) != "pong" {
				t.Fatalf("client after 75 s idle: %q %v", got, e)
			}
			if _, e = c.Write([]byte("back")); e != nil {
				t.Fatal(e)
			}
			_ = d.SetReadDeadline(time.Now().Add(10 * time.Second))
			if _, e = io.ReadFull(d, got); e != nil || string(got) != "back" {
				t.Fatalf("destination after 75 s idle: %q %v", got, e)
			}
		})
	}
}

// Over UDP a bulk data segment is padded by a few bytes only, so bulk
// transfers do not pay a fifth of their bytes for padding; a small one keeps
// the full range. TCP is not capped.
func TestUDPBulkPaddingIsCapped(t *testing.T) {
	udp := &wire{udp: true}
	for _, payload := range []int{udpBulkPayload, 1000} {
		for used := 0; used <= udpBulkPadding+8; used += 8 {
			want := min(max(udpBulkPadding-used, 0), max(udpMTU-packetOverhead-payload-used, 0))
			if got := udp.paddingRoom(payload, used); got != want {
				t.Fatalf("UDP payload %d, %d used: room %d, want %d", payload, used, got, want)
			}
		}
	}
	if got := udp.paddingRoom(udpBulkPayload-1, 0); got != maxPadding {
		t.Fatalf("UDP small payload: room %d, want %d", got, maxPadding)
	}
	if got := (&wire{}).paddingRoom(1000, 0); got != maxPadding {
		t.Fatalf("TCP bulk payload: room %d, want %d", got, maxPadding)
	}
}

// Liveness timestamps are monotonic: they do not move when the wall clock is
// set, so a clock change cannot make a session look idle.
func TestLivenessClockIsMonotonic(t *testing.T) {
	w := &wire{}
	w.lastWrite.Store(monoNow())
	if d := w.sinceSent(); d < 0 || d > time.Second {
		t.Fatalf("sinceSent right after a write: %v", d)
	}
}
