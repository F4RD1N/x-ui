package datachan

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/wire"
)

// TestSealOpenAllocs: sealing and opening a packet allocate nothing in the
// steady state, for AEAD and CBC alike (no per-packet nonce, BlockMode or
// IV read).
func TestSealOpenAllocs(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts are not meaningful under the race detector")
	}
	for _, s := range []suite{{"AES-256-GCM", ""}, {"CHACHA20-POLY1305", ""}, {"AES-256-CBC", "SHA1"}, {"AES-128-CBC", "SHA512"}, {"BF-CBC", "SHA1"}} {
		t.Run(s.cipher+"/"+s.digest, func(t *testing.T) {
			p := newPair(t, s, 1, Options{PeerID: 5})
			payload := bytes.Repeat([]byte{0x45, 1, 2, 3}, 350)
			sealed := make([]byte, 0, 2048)
			opened := make([]byte, 0, 2048)
			allocs := testing.AllocsPerRun(1000, func() {
				pkt, err := p.client.Seal(sealed[:0], payload)
				if err != nil {
					t.Fatal(err)
				}
				out, _, err := p.server.Open(opened[:0], pkt)
				if err != nil || !bytes.Equal(out, payload) {
					t.Fatalf("Open: %v", err)
				}
			})
			if allocs >= 1 {
				t.Errorf("%.1f allocations per sealed and opened packet, want 0", allocs)
			}
		})
	}
}

// TestCBCIVsDistinct: IVs drawn in batches are still fresh for every
// packet, across batch refills.
func TestCBCIVsDistinct(t *testing.T) {
	p := newPair(t, suite{"AES-128-CBC", "SHA1"}, 0, Options{PeerID: wire.NoPeerID})
	seen := map[[16]byte]bool{}
	macSize := 20
	for i := 0; i < 3*ivBatch/16; i++ {
		pkt, err := p.client.Seal(nil, []byte{0x45, byte(i)})
		if err != nil {
			t.Fatal(err)
		}
		iv := [16]byte(pkt[1+macSize : 1+macSize+16])
		if seen[iv] {
			t.Fatalf("packet %d reuses an IV", i)
		}
		seen[iv] = true
		if _, _, err := p.server.Open(nil, pkt); err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
	}
}

func BenchmarkSealCBC(b *testing.B) {
	p := newPair(b, suite{"AES-256-CBC", "SHA1"}, 0, Options{PeerID: 5})
	payload := make([]byte, 64)
	payload[0] = 0x45
	buf := make([]byte, 0, 2048)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := p.client.Seal(buf[:0], payload); err != nil {
			b.Fatal(err)
		}
	}
}
