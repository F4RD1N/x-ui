package client

import (
	"testing"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/datachan"
)

// serverChannel seals packets the way the fuzz client's peer would.
func serverChannel(t testing.TB) *datachan.Channel {
	t.Helper()
	k2 := fuzzKey2()
	ks, err := datachan.NewKeyState(0, "AES-256-GCM", "SHA1", k2.ServerSend(), k2.ServerRecv())
	if err != nil {
		t.Fatal(err)
	}
	ch := datachan.New(datachan.Options{PeerID: 3})
	ch.SetPrimary(ks)
	return ch
}

// TestReceiveQueueBounded: what the session queues for ReadPacket is
// bounded in bytes, not just in packets, and packets larger than the tunnel
// allows are dropped; MTU-sized packets still fill the whole queue.
func TestReceiveQueueBounded(t *testing.T) {
	for _, tc := range []struct {
		name      string
		size, n   int
		maxQueued int // bytes
		wantQueue int // packets; -1: don't care
	}{
		{"oversized", 60000, 1100, 2 << 20, -1},
		{"mtu-sized", 1400, 1100, 2 << 20, packetQueueLen},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := fuzzClient(t, fuzzDialer(t), true)
			defer stopFuzzClient(c)
			srv := serverChannel(t)
			payload := testPacket(1, tc.size)
			var buf []byte
			for i := 0; i < tc.n; i++ {
				pkt, err := srv.Seal(buf[:0], payload)
				if err != nil {
					t.Fatal(err)
				}
				buf = pkt
				c.dispatch(pkt)
			}
			queued := len(c.packets)
			if queued*tc.size > tc.maxQueued {
				t.Errorf("%d packets of %d bytes queued (%d KiB), want at most %d KiB", queued, tc.size, queued*tc.size>>10, tc.maxQueued>>10)
			}
			if tc.wantQueue >= 0 && queued != tc.wantQueue {
				t.Errorf("%d packets queued, want %d", queued, tc.wantQueue)
			}
			if d := c.DroppedPackets(); int(d)+queued != tc.n {
				t.Errorf("%d queued + %d dropped != %d sent", queued, d, tc.n)
			}
		})
	}
}

// TestReceivePathAllocs: opening and handing over a received packet
// allocates nothing in the steady state.
func TestReceivePathAllocs(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts are not meaningful under the race detector")
	}
	c := fuzzClient(t, fuzzDialer(t), true)
	defer stopFuzzClient(c)
	srv := serverChannel(t)
	payload := testPacket(7, 1400)
	sealed := make([]byte, 0, 2048)
	out := make([]byte, 2048)
	allocs := testing.AllocsPerRun(500, func() {
		pkt, err := srv.Seal(sealed[:0], payload)
		if err != nil {
			t.Fatal(err)
		}
		c.dispatch(pkt)
		n, err := c.ReadPacket(out)
		if err != nil || n != len(payload) {
			t.Fatalf("ReadPacket = %d, %v", n, err)
		}
	})
	if allocs >= 1 {
		t.Errorf("%.1f allocations per received packet, want 0", allocs)
	}
}

func BenchmarkReceive(b *testing.B) {
	c := fuzzClient(b, fuzzDialer(b), true)
	defer stopFuzzClient(c)
	srv := serverChannel(b)
	payload := testPacket(7, 1400)
	sealed := make([]byte, 0, 2048)
	out := make([]byte, 65536)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		pkt, _ := srv.Seal(sealed[:0], payload)
		c.dispatch(pkt)
		if _, err := c.ReadPacket(out); err != nil {
			b.Fatal(err)
		}
	}
}
