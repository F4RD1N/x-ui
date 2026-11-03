package ctlwrap

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math"
	"math/rand/v2"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/wire"
)

// testKey returns a deterministic pseudo-random static key.
func testKey(seed uint64) *StaticKey {
	var k StaticKey
	r := rand.New(rand.NewChaCha8([32]byte{byte(seed), byte(seed >> 8), 'k', 'e', 'y'}))
	for i := range k {
		k[i] = byte(r.Uint32())
	}
	return &k
}

// testWKc returns a fake wrapped client key of n bytes with a valid trailer.
func testWKc(n int) []byte {
	w := make([]byte, n)
	for i := range w {
		w[i] = byte(i*7 + 3)
	}
	binary.BigEndian.PutUint16(w[n-2:], uint16(n))
	return w
}

// keyText renders k as an OpenVPN static key file with the given line
// ending.
func keyText(k *StaticKey, eol string) string {
	var b strings.Builder
	b.WriteString("#" + eol + "# 2048 bit OpenVPN static key" + eol + "#" + eol)
	b.WriteString(staticKeyBegin + eol)
	h := hex.EncodeToString(k[:])
	for i := 0; i < len(h); i += 32 {
		b.WriteString(h[i:i+32] + eol)
	}
	b.WriteString(staticKeyEnd + eol)
	return b.String()
}

// withClock makes new wrappers read t as the current time.
func withClock(t *testing.T, at time.Time) {
	t.Helper()
	old := timeNow
	timeNow = func() time.Time { return at }
	t.Cleanup(func() { timeNow = old })
}

func mustTLSAuth(t testing.TB, k *StaticKey, dir Direction, digest string) Wrapper {
	t.Helper()
	w, err := NewTLSAuth(k, dir, digest)
	if err != nil {
		t.Fatalf("NewTLSAuth(%v, %q): %v", dir, digest, err)
	}
	return w
}

func mustTLSCrypt(t testing.TB, k *StaticKey, client bool) Wrapper {
	t.Helper()
	w, err := NewTLSCrypt(k, client)
	if err != nil {
		t.Fatalf("NewTLSCrypt(client=%v): %v", client, err)
	}
	return w
}

func mustV2(t testing.TB, k *StaticKey, wkc []byte) Wrapper {
	t.Helper()
	w, err := NewTLSCryptV2Client(k, wkc)
	if err != nil {
		t.Fatalf("NewTLSCryptV2Client: %v", err)
	}
	return w
}

// v2Server is the server side of tls-crypt-v2 once it has unwrapped Kc: plain
// tls-crypt in the server direction, after cutting the WKc off client
// packets that carry one.
type v2Server struct {
	Wrapper
	lastWKc []byte
}

func (s *v2Server) Unwrap(b []byte) (*wire.ControlPacket, error) {
	s.lastWKc = nil
	if len(b) > 2 {
		if op, _ := wire.SplitHeader(b[0]); carriesWKc(op) {
			n := int(binary.BigEndian.Uint16(b[len(b)-2:]))
			if n > len(b) {
				return nil, wire.ErrShort
			}
			b, s.lastWKc = b[:len(b)-n], b[len(b)-n:]
		}
	}
	return s.Wrapper.Unwrap(b)
}

type wrapPair struct {
	name           string
	client, server Wrapper
	overhead       int // exact bytes added to a packet without WKc
}

func wrapPairs(t *testing.T) []wrapPair {
	k := testKey(1)
	pairs := []wrapPair{{name: "plain", client: NewPlain(), server: NewPlain()}}
	for _, d := range []struct {
		name string
		size int
	}{{"MD5", 16}, {"SHA1", 20}, {"SHA224", 28}, {"SHA256", 32}, {"SHA384", 48}, {"SHA512", 64}} {
		pairs = append(pairs,
			wrapPair{"tls-auth-" + d.name + "-1/0", mustTLSAuth(t, k, Inverse, d.name), mustTLSAuth(t, k, Normal, d.name), d.size + 8},
			wrapPair{"tls-auth-" + d.name + "-0/1", mustTLSAuth(t, k, Normal, d.name), mustTLSAuth(t, k, Inverse, d.name), d.size + 8},
			wrapPair{"tls-auth-" + d.name + "-bidir", mustTLSAuth(t, k, Bidirectional, d.name), mustTLSAuth(t, k, Bidirectional, d.name), d.size + 8},
		)
	}
	pairs = append(pairs,
		wrapPair{"tls-crypt", mustTLSCrypt(t, k, true), mustTLSCrypt(t, k, false), 40},
		wrapPair{"tls-crypt-v2", mustV2(t, k, testWKc(299)), &v2Server{Wrapper: mustTLSCrypt(t, k, false)}, 40},
	)
	return pairs
}

var (
	sidA = wire.SessionID{1, 2, 3, 4, 5, 6, 7, 8}
	sidB = wire.SessionID{0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8}
)

func testPackets() []*wire.ControlPacket {
	big := bytes.Repeat([]byte("0123456789abcdef"), 80)
	return []*wire.ControlPacket{
		{Opcode: wire.ControlHardResetClientV2, SessionID: sidA},
		{Opcode: wire.ControlHardResetClientV3, SessionID: sidA, Payload: []byte{0x00, 0x0f, 0x00, 0x02, 0x00, 0x01}},
		{Opcode: wire.ControlHardResetServerV2, SessionID: sidB, Acks: []wire.PacketID{0}, RemoteSessionID: sidA},
		{Opcode: wire.ControlV1, KeyID: 3, SessionID: sidA, Acks: []wire.PacketID{5, 7}, RemoteSessionID: sidB, PacketID: 9, Payload: []byte("hello")},
		{Opcode: wire.ControlV1, KeyID: 7, SessionID: sidA, PacketID: 0xfffffffe, Payload: big},
		{Opcode: wire.AckV1, KeyID: 2, SessionID: sidB, Acks: []wire.PacketID{1, 2, 3, 4, 5, 6, 7, 0xffffffff}, RemoteSessionID: sidA},
		{Opcode: wire.ControlSoftResetV1, KeyID: 1, SessionID: sidA, PacketID: 4},
		{Opcode: wire.ControlWKCV1, SessionID: sidA, Acks: []wire.PacketID{0}, RemoteSessionID: sidB, PacketID: 1, Payload: []byte{0x16, 3, 1}},
	}
}

func samePacket(a, b *wire.ControlPacket) bool {
	if a.Opcode != b.Opcode || a.KeyID != b.KeyID || a.SessionID != b.SessionID ||
		a.RemoteSessionID != b.RemoteSessionID || a.PacketID != b.PacketID ||
		len(a.Acks) != len(b.Acks) || !bytes.Equal(a.Payload, b.Payload) {
		return false
	}
	for i := range a.Acks {
		if a.Acks[i] != b.Acks[i] {
			return false
		}
	}
	return true
}

func TestRoundTrip(t *testing.T) {
	withClock(t, time.Unix(1791500000, 0))
	for _, pr := range wrapPairs(t) {
		t.Run(pr.name, func(t *testing.T) {
			for _, dir := range []struct {
				name     string
				from, to Wrapper
			}{{"client->server", pr.client, pr.server}, {"server->client", pr.server, pr.client}} {
				for i, p := range testPackets() {
					b, err := dir.from.Wrap(p)
					if err != nil {
						t.Fatalf("%s packet %d: Wrap: %v", dir.name, i, err)
					}
					extra := len(b) - len(wire.Marshal(p))
					want := pr.overhead
					if v2, ok := dir.from.(*tlsCrypt); ok && v2.wkc != nil && carriesWKc(p.Opcode) {
						want += len(v2.wkc)
					}
					if extra != want || extra > dir.from.Overhead() {
						t.Errorf("%s packet %d: adds %d bytes, want %d (Overhead %d)", dir.name, i, extra, want, dir.from.Overhead())
					}
					got, err := dir.to.Unwrap(b)
					if err != nil {
						t.Fatalf("%s packet %d (%v): Unwrap: %v", dir.name, i, p.Opcode, err)
					}
					if !samePacket(got, p) {
						t.Fatalf("%s packet %d: got %+v, want %+v", dir.name, i, got, p)
					}
				}
			}
		})
	}
}

func TestOverhead(t *testing.T) {
	k := testKey(2)
	tests := []struct {
		w    Wrapper
		want int
	}{
		{NewPlain(), 0},
		{mustTLSAuth(t, k, Normal, ""), 28},
		{mustTLSAuth(t, k, Normal, "md5"), 24},
		{mustTLSAuth(t, k, Normal, "SHA256"), 40},
		{mustTLSAuth(t, k, Normal, "SHA512"), 72},
		{mustTLSCrypt(t, k, true), 40},
		{mustV2(t, k, testWKc(299)), 339},
		{mustV2(t, k, testWKc(1024)), 1064},
	}
	for i, tc := range tests {
		if got := tc.w.Overhead(); got != tc.want {
			t.Errorf("case %d: Overhead = %d, want %d", i, got, tc.want)
		}
	}
}

// TestWireLayout pins the byte layouts against an independent computation
// from the raw key slots.
func TestWireLayout(t *testing.T) {
	withClock(t, time.Unix(0x01020304, 0))
	k := testKey(3)
	p := &wire.ControlPacket{Opcode: wire.ControlV1, KeyID: 2, SessionID: sidA, Acks: []wire.PacketID{3}, RemoteSessionID: sidB, PacketID: 4, Payload: []byte("abc")}
	body := []byte{1, 0, 0, 0, 3}
	body = append(body, sidB[:]...)
	body = append(body, 0, 0, 0, 4, 'a', 'b', 'c')
	pidTime := []byte{0, 0, 0, 1, 1, 2, 3, 4}
	head := append([]byte{4<<3 | 2}, sidA[:]...)

	// tls-auth, direction 1: sends with key[1].hmac (bytes 192..255).
	b, err := mustTLSAuth(t, k, Inverse, "SHA256").Wrap(p)
	if err != nil {
		t.Fatal(err)
	}
	m := hmac.New(sha256.New, k[192:224])
	m.Write(pidTime)
	m.Write(head)
	m.Write(body)
	want := bytes.Join([][]byte{head, m.Sum(nil), pidTime, body}, nil)
	if !bytes.Equal(b, want) {
		t.Errorf("tls-auth layout:\n got %x\nwant %x", b, want)
	}

	// tls-crypt server: sends with key[0]: Ke = bytes 0..31, Ka = 64..95.
	// The client sends with key[1]: Ke = 128..159, Ka = 192..223.
	for _, tc := range []struct {
		client bool
		ke, ka []byte
	}{{false, k[0:32], k[64:96]}, {true, k[128:160], k[192:224]}} {
		b, err = mustTLSCrypt(t, k, tc.client).Wrap(p)
		if err != nil {
			t.Fatal(err)
		}
		m = hmac.New(sha256.New, tc.ka)
		m.Write(head)
		m.Write(pidTime)
		m.Write(body)
		tg := m.Sum(nil)
		block, _ := aes.NewCipher(tc.ke)
		ct := make([]byte, len(body))
		cipher.NewCTR(block, tg[:16]).XORKeyStream(ct, body)
		want = bytes.Join([][]byte{head, pidTime, tg, ct}, nil)
		if !bytes.Equal(b, want) {
			t.Errorf("tls-crypt (client=%v) layout:\n got %x\nwant %x", tc.client, b, want)
		}
	}
}

func TestDirections(t *testing.T) {
	k := testKey(4)
	dirs := []Direction{Normal, Inverse, Bidirectional}
	p := testPackets()[3]
	for _, cd := range dirs {
		for _, sd := range dirs {
			// A packet authenticates when the sender's send slot is the
			// receiver's receive slot: 0/1, 1/0 and bidir/bidir both ways,
			// and also one way between 0 (sends key[0]) and bidirectional
			// (receives key[0]), as with OpenVPN itself.
			sendSlot := map[Direction]int{Normal: 0, Inverse: 1, Bidirectional: 0}[cd]
			recvSlot := map[Direction]int{Normal: 1, Inverse: 0, Bidirectional: 0}[sd]
			ok := sendSlot == recvSlot
			b, err := mustTLSAuth(t, k, cd, "SHA1").Wrap(p)
			if err != nil {
				t.Fatal(err)
			}
			_, err = mustTLSAuth(t, k, sd, "SHA1").Unwrap(b)
			if ok && err != nil {
				t.Errorf("tls-auth client %v, server %v: %v", cd, sd, err)
			}
			if !ok && !errors.Is(err, ErrAuth) {
				t.Errorf("tls-auth client %v, server %v: err = %v, want ErrAuth", cd, sd, err)
			}
		}
	}
	for _, tc := range []struct {
		from, to bool
		ok       bool
	}{{true, false, true}, {false, true, true}, {true, true, false}, {false, false, false}} {
		b, err := mustTLSCrypt(t, k, tc.from).Wrap(p)
		if err != nil {
			t.Fatal(err)
		}
		_, err = mustTLSCrypt(t, k, tc.to).Unwrap(b)
		if tc.ok != (err == nil) || (!tc.ok && !errors.Is(err, ErrAuth)) {
			t.Errorf("tls-crypt client=%v -> client=%v: err = %v", tc.from, tc.to, err)
		}
	}
	// Different digests or keys never authenticate.
	b, _ := mustTLSAuth(t, k, Inverse, "SHA256").Wrap(p)
	if _, err := mustTLSAuth(t, k, Normal, "SHA224").Unwrap(b); !errors.Is(err, ErrAuth) {
		t.Errorf("digest mismatch: err = %v, want ErrAuth", err)
	}
	if _, err := mustTLSAuth(t, testKey(5), Normal, "SHA256").Unwrap(b); !errors.Is(err, ErrAuth) {
		t.Errorf("key mismatch: err = %v, want ErrAuth", err)
	}
	b, _ = mustTLSCrypt(t, k, true).Wrap(p)
	if _, err := mustTLSCrypt(t, testKey(5), false).Unwrap(b); !errors.Is(err, ErrAuth) {
		t.Errorf("tls-crypt key mismatch: err = %v, want ErrAuth", err)
	}
}

func TestTamper(t *testing.T) {
	p := testPackets()[3]
	for _, pr := range wrapPairs(t) {
		if pr.name == "plain" {
			continue
		}
		t.Run(pr.name, func(t *testing.T) {
			// Server to client: what a client actually unwraps.
			b, err := pr.server.Wrap(p)
			if err != nil {
				t.Fatal(err)
			}
			for i := range b {
				for _, flip := range []byte{0x01, 0x80} {
					if i == 0 && flip == 0x80 {
						continue // makes a non-control opcode; checked below
					}
					c := bytes.Clone(b)
					c[i] ^= flip
					if _, err := pr.client.Unwrap(c); !errors.Is(err, ErrAuth) {
						t.Fatalf("byte %d ^ %#x: err = %v, want ErrAuth", i, flip, err)
					}
				}
			}
			c := bytes.Clone(b)
			c[0] ^= 0x80
			if _, err := pr.client.Unwrap(c); !errors.Is(err, wire.ErrBadOpcode) {
				t.Errorf("opcode changed to data: err = %v, want ErrBadOpcode", err)
			}
			if _, err := pr.client.Unwrap(append(bytes.Clone(b), 0)); !errors.Is(err, ErrAuth) {
				t.Errorf("appended byte: err = %v, want ErrAuth", err)
			}
			min := 1 + 8 + pr.overhead
			for n := 0; n < len(b); n++ {
				_, err := pr.client.Unwrap(b[:n])
				want := ErrAuth
				if n < min {
					want = wire.ErrShort
				}
				if !errors.Is(err, want) {
					t.Fatalf("truncated to %d: err = %v, want %v", n, err, want)
				}
			}
			// None of that moved the replay window.
			if _, err := pr.client.Unwrap(b); err != nil {
				t.Fatalf("original after tampering: %v", err)
			}
		})
	}
}

func TestReplay(t *testing.T) {
	k := testKey(6)
	makePair := func(name string) (send, recv func() Wrapper) {
		switch name {
		case "tls-auth":
			return func() Wrapper { return mustTLSAuth(t, k, Normal, "SHA256") }, func() Wrapper { return mustTLSAuth(t, k, Inverse, "SHA256") }
		default:
			return func() Wrapper { return mustTLSCrypt(t, k, false) }, func() Wrapper { return mustTLSCrypt(t, k, true) }
		}
	}
	for _, name := range []string{"tls-auth", "tls-crypt"} {
		t.Run(name, func(t *testing.T) {
			newSend, newRecv := makePair(name)
			withClock(t, time.Unix(1000, 0))
			oldSender := newSend()
			recv := newRecv()
			p := testPackets()[3]
			pkts := make([][]byte, 71) // pkts[i] has pid i
			for i := 1; i < len(pkts); i++ {
				b, err := oldSender.Wrap(p)
				if err != nil {
					t.Fatal(err)
				}
				if tm, pid := rawPID(oldSender, b); tm != 1000 || pid != uint32(i) {
					t.Fatalf("packet %d sent with time %d pid %d", i, tm, pid)
				}
				pkts[i] = b
			}
			steps := []struct {
				pid int
				err error
			}{
				{1, nil},
				{1, ErrReplay},
				{3, nil},
				{2, nil},
				{3, ErrReplay},
				{70, nil},
				{7, nil},        // 63 below the highest: still in the window
				{6, ErrReplay},  // 64 below: too old
				{2, ErrReplay},  // seen, and too old
				{69, nil},       // late but new
				{69, ErrReplay}, // twice
				{70, ErrReplay},
			}
			for i, s := range steps {
				if _, err := recv.Unwrap(pkts[s.pid]); !errors.Is(err, s.err) || (s.err == nil && err != nil) {
					t.Fatalf("step %d (pid %d): err = %v, want %v", i, s.pid, err, s.err)
				}
			}
			// A sender with a newer time starts a new window: its pid 1 is
			// fine, and the old time is now a replay even for unseen ids.
			withClock(t, time.Unix(1005, 0))
			newSender := newSend()
			b, err := newSender.Wrap(p)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := recv.Unwrap(b); err != nil {
				t.Fatalf("newer time, pid 1: %v", err)
			}
			if _, err := recv.Unwrap(b); !errors.Is(err, ErrReplay) {
				t.Fatalf("newer time, pid 1 again: err = %v, want ErrReplay", err)
			}
			if _, err := recv.Unwrap(pkts[68]); !errors.Is(err, ErrReplay) {
				t.Fatalf("older time: err = %v, want ErrReplay", err)
			}
		})
	}
}

func TestReplayWindow(t *testing.T) {
	type step struct {
		time, pid uint32
		ok        bool
	}
	tests := []struct {
		name  string
		steps []step
	}{
		{"first packet any id", []step{{5, 1000, true}, {5, 1000, false}, {5, 999, true}}},
		{"in order", []step{{1, 1, true}, {1, 2, true}, {1, 3, true}, {1, 2, false}}},
		{"jump beyond window clears it", []step{{1, 1, true}, {1, 200, true}, {1, 137, true}, {1, 136, false}, {1, 1, false}, {1, 199, true}}},
		{"exact window edge", []step{{1, 100, true}, {1, 37, true}, {1, 36, false}, {1, 164, true}, {1, 100, false}, {1, 101, true}, {1, 100, false}}},
		{"newer time resets", []step{{1, 50, true}, {2, 1, true}, {2, 1, false}, {1, 51, false}, {2, 2, true}}},
		{"older time rejected", []step{{10, 1, true}, {9, 2, false}, {0, 3, false}}},
		{"max ids", []step{{math.MaxUint32, math.MaxUint32, true}, {math.MaxUint32, math.MaxUint32, false}, {math.MaxUint32, math.MaxUint32 - 63, true}, {math.MaxUint32, 0, false}}},
		{"zero id", []step{{1, 0, true}, {1, 0, false}, {1, 1, true}}},
	}
	for _, tc := range tests {
		var w replayWindow
		for i, s := range tc.steps {
			if got := w.accept(s.time, s.pid); got != s.ok {
				t.Errorf("%s: step %d (%d, %d): accept = %v, want %v", tc.name, i, s.time, s.pid, got, s.ok)
			}
		}
	}
}

func TestSender(t *testing.T) {
	withClock(t, time.Unix(0x7a000000, 0))
	w := mustTLSCrypt(t, testKey(7), true)
	p := testPackets()[0]
	var mu sync.Mutex
	seen := map[uint32]bool{}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				b, err := w.Wrap(p)
				if err != nil {
					t.Error(err)
					return
				}
				tm, pid := rawPID(w, b)
				mu.Lock()
				if tm != 0x7a000000 || seen[pid] {
					t.Errorf("time %#x pid %d (duplicate %v)", tm, pid, seen[pid])
				}
				seen[pid] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	for pid := uint32(1); pid <= 800; pid++ {
		if !seen[pid] {
			t.Fatalf("pid %d never sent", pid)
		}
	}
	// The id space ends at 2^32-1.
	w.(*tlsCrypt).send.last.Store(math.MaxUint32 - 1)
	b, err := w.Wrap(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, pid := rawPID(w, b); pid != math.MaxUint32 {
		t.Fatalf("pid %d, want %d", pid, uint32(math.MaxUint32))
	}
	if _, err := w.Wrap(p); !errors.Is(err, errPIDExhausted) {
		t.Fatalf("after 2^32-1 packets: err = %v", err)
	}
}

func TestWrapRejects(t *testing.T) {
	k := testKey(8)
	ws := []Wrapper{NewPlain(), mustTLSAuth(t, k, Normal, ""), mustTLSCrypt(t, k, true), mustV2(t, k, testWKc(300))}
	bad := []struct {
		p   *wire.ControlPacket
		err error
	}{
		{nil, nil},
		{&wire.ControlPacket{Opcode: wire.DataV2}, wire.ErrBadOpcode},
		{&wire.ControlPacket{Opcode: 0}, wire.ErrBadOpcode},
		{&wire.ControlPacket{Opcode: 31}, wire.ErrBadOpcode},
		{&wire.ControlPacket{Opcode: wire.ControlV1, KeyID: 8}, nil},
		{&wire.ControlPacket{Opcode: wire.AckV1, Acks: make([]wire.PacketID, wire.MaxAcks+1)}, wire.ErrTooMany},
	}
	for _, w := range ws {
		for i, tc := range bad {
			_, err := w.Wrap(tc.p)
			if err == nil || (tc.err != nil && !errors.Is(err, tc.err)) {
				t.Errorf("%T case %d: err = %v, want %v", w, i, err, tc.err)
			}
		}
	}
}

func TestUnwrapRejects(t *testing.T) {
	k := testKey(9)
	data := []byte{wire.Header(wire.DataV2, 0), 0, 0, 1}
	data = append(data, make([]byte, 200)...)
	for _, w := range []Wrapper{NewPlain(), mustTLSAuth(t, k, Normal, ""), mustTLSCrypt(t, k, true)} {
		if _, err := w.Unwrap(data); !errors.Is(err, wire.ErrBadOpcode) {
			t.Errorf("%T data packet: err = %v, want ErrBadOpcode", w, err)
		}
		if _, err := w.Unwrap(nil); !errors.Is(err, wire.ErrShort) {
			t.Errorf("%T empty packet: err = %v, want ErrShort", w, err)
		}
	}
	// Plain: malformed bodies come back as the wire error.
	b := wire.Marshal(&wire.ControlPacket{Opcode: wire.ControlV1, PacketID: 1})
	if _, err := NewPlain().Unwrap(b[:len(b)-1]); !errors.Is(err, wire.ErrShort) {
		t.Errorf("plain truncated: err = %v", err)
	}
	// An authentic packet whose body is malformed is a wire error, not
	// ErrAuth: build one by wrapping a hand-made body.
	srv := mustTLSAuth(t, k, Inverse, "").(*tlsAuth)
	cli := mustTLSAuth(t, k, Normal, "").(*tlsAuth)
	raw := make([]byte, headLen+20, 64)
	raw[0] = wire.Header(wire.ControlV1, 0)
	raw, _ = cli.send.appendPID(raw)
	raw = append(raw, 9) // ack count 9
	copy(raw[headLen:], cli.mac(cli.sendKey, raw[:headLen], raw[headLen+20:]))
	if _, err := srv.Unwrap(raw); !errors.Is(err, wire.ErrTooMany) {
		t.Errorf("authentic packet with 9 acks: err = %v, want ErrTooMany", err)
	}
}

func TestWKcOnlyOnV3(t *testing.T) {
	k := testKey(10)
	wkc := testWKc(321)
	w := mustV2(t, k, wkc)
	for op := wire.Opcode(0); op < 32; op++ {
		if !op.IsControl() {
			continue
		}
		p := &wire.ControlPacket{Opcode: op, SessionID: sidA, PacketID: 0, Payload: []byte("x")}
		for try := 0; try < 2; try++ { // retransmissions carry it too
			b, err := w.Wrap(p)
			if err != nil {
				t.Fatal(err)
			}
			has := len(b) == len(wire.Marshal(p))+40+len(wkc) && bytes.HasSuffix(b, wkc)
			if want := op == wire.ControlHardResetClientV3 || op == wire.ControlWKCV1; has != want {
				t.Errorf("%v: WKc appended = %v, want %v", op, has, want)
			}
		}
	}
	// The server, after cutting the WKc off, sees a valid tls-crypt packet.
	srv := &v2Server{Wrapper: mustTLSCrypt(t, k, false)}
	b, _ := w.Wrap(testPackets()[1])
	if _, err := srv.Unwrap(b); err != nil || !bytes.Equal(srv.lastWKc, wkc) {
		t.Fatalf("server unwrap of V3: %v", err)
	}
	// The client wrapper copied wkc.
	wkc[0] ^= 0xff
	b, _ = w.Wrap(testPackets()[1])
	if bytes.HasSuffix(b, wkc) {
		t.Fatalf("wrapper aliases the caller's wkc")
	}
}

func TestNewErrors(t *testing.T) {
	k := testKey(11)
	if _, err := NewTLSAuth(nil, Normal, ""); !errors.Is(err, ErrKey) {
		t.Errorf("NewTLSAuth(nil): %v", err)
	}
	for _, d := range []Direction{-2, 2, 100} {
		if _, err := NewTLSAuth(k, d, ""); err == nil {
			t.Errorf("NewTLSAuth(direction %d) succeeded", d)
		}
	}
	if _, err := NewTLSCrypt(nil, true); !errors.Is(err, ErrKey) {
		t.Errorf("NewTLSCrypt(nil): %v", err)
	}
	if _, err := NewTLSCryptV2Client(nil, testWKc(300)); !errors.Is(err, ErrKey) {
		t.Errorf("NewTLSCryptV2Client(nil key): %v", err)
	}
	badWKc := [][]byte{nil, testWKc(289), testWKc(1025), append(testWKc(300)[:298], 0x01, 0x2b)}
	for i, wkc := range badWKc {
		if _, err := NewTLSCryptV2Client(k, wkc); !errors.Is(err, ErrKey) {
			t.Errorf("bad wkc %d: err = %v, want ErrKey", i, err)
		}
	}
	for _, n := range []int{290, 299, 1024} {
		if _, err := NewTLSCryptV2Client(k, testWKc(n)); err != nil {
			t.Errorf("wkc of %d bytes: %v", n, err)
		}
	}
}

func TestDigestNames(t *testing.T) {
	good := map[string]int{
		"": 20, "sha1": 20, "SHA1": 20, "SHA-1": 20, "sha_1": 20, " SHA1 ": 20,
		"md5": 16, "MD5": 16,
		"SHA224": 28, "sha-224": 28, "SHA2-224": 28,
		"SHA256": 32, "sha256": 32, "SHA-256": 32, "SHA2-256": 32, "sha2_256": 32,
		"SHA384": 48, "SHA-384": 48, "SHA2-384": 48,
		"SHA512": 64, "sha512": 64, "SHA-512": 64, "SHA2-512": 64,
	}
	k := testKey(12)
	for name, size := range good {
		w, err := NewTLSAuth(k, Normal, name)
		if err != nil {
			t.Errorf("%q: %v", name, err)
			continue
		}
		if got := w.Overhead(); got != size+8 {
			t.Errorf("%q: Overhead = %d, want %d", name, got, size+8)
		}
	}
	for _, name := range []string{"none", "SHA", "SHA2", "SHA3-256", "SHA512-256", "BLAKE2s256", "RIPEMD160", "whirlpool", "SHA2-25", "sha2-2566"} {
		if _, err := NewTLSAuth(k, Normal, name); err == nil {
			t.Errorf("%q accepted", name)
		}
	}
}

func TestParseStaticKey(t *testing.T) {
	k := testKey(13)
	lf := keyText(k, "\n")
	hexLines := func(eol string) string {
		h := hex.EncodeToString(k[:])
		var b strings.Builder
		for i := 0; i < len(h); i += 64 {
			b.WriteString(h[i:i+64] + eol)
		}
		return b.String()
	}
	good := map[string]string{
		"lf":               lf,
		"crlf":             keyText(k, "\r\n"),
		"crlf 64-col":      staticKeyBegin + "\r\n" + hexLines("\r\n") + staticKeyEnd + "\r\n",
		"no final newline": strings.TrimSuffix(lf, "\n"),
		"upper case":       staticKeyBegin + "\n" + strings.ToUpper(hexLines("\n")) + staticKeyEnd + "\n",
		"comments inside": staticKeyBegin + "\n# a comment\n\n" + hexLines("\n")[:130] + "\n; another\n" +
			hexLines("\n")[130:] + "\n" + staticKeyEnd + "\n",
		"indented":         "  \t" + staticKeyBegin + "  \n" + strings.ReplaceAll(hexLines("\n"), "\n", " \n\t") + staticKeyEnd + "\t\n",
		"spaced digits":    staticKeyBegin + "\n" + strings.Join(strings.Split(hex.EncodeToString(k[:]), ""), " ") + "\n" + staticKeyEnd,
		"one line":         staticKeyBegin + "\n" + hex.EncodeToString(k[:]) + "\n" + staticKeyEnd,
		"text around":      "key-direction 1\n<tls-auth>\n" + lf + "</tls-auth>\n" + staticKeyBegin + "\nzz\n",
		"inline with junk": "garbage line\n\x00\xff\n" + lf,
	}
	for name, text := range good {
		got, err := ParseStaticKey([]byte(text))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if *got != *k {
			t.Errorf("%s: wrong key", name)
		}
	}
	h := hex.EncodeToString(k[:])
	bad := map[string]string{
		"empty":          "",
		"garbage":        "this is not a key\n",
		"binary":         "\x00\x01\x02\xff",
		"no begin":       h + "\n" + staticKeyEnd + "\n",
		"no end":         staticKeyBegin + "\n" + h + "\n",
		"short":          staticKeyBegin + "\n" + h[:510] + "\n" + staticKeyEnd,
		"odd digits":     staticKeyBegin + "\n" + h[:511] + "\n" + staticKeyEnd,
		"long":           staticKeyBegin + "\n" + h + "00\n" + staticKeyEnd,
		"non-hex":        staticKeyBegin + "\n" + h[:100] + "g" + h[101:] + "\n" + staticKeyEnd,
		"base64":         staticKeyBegin + "\nAAAA+/==\n" + staticKeyEnd,
		"trailing note":  staticKeyBegin + "\n" + h + " # comment\n" + staticKeyEnd,
		"wrong begin":    strings.Replace(lf, "Static key V1", "Static key V2", 1),
		"tls-crypt-v2":   "-----BEGIN OpenVPN tls-crypt-v2 client key-----\nAAAA\n-----END OpenVPN tls-crypt-v2 client key-----\n",
		"empty block":    staticKeyBegin + "\n" + staticKeyEnd + "\n",
		"end before key": staticKeyEnd + "\n" + staticKeyBegin + "\n",
	}
	for name, text := range bad {
		if _, err := ParseStaticKey([]byte(text)); !errors.Is(err, ErrKey) {
			t.Errorf("%s: err = %v, want ErrKey", name, err)
		} else if strings.Contains(err.Error(), h[:8]) {
			t.Errorf("%s: error quotes key material: %v", name, err)
		}
	}
}

func TestParts(t *testing.T) {
	var k StaticKey
	for i := range k {
		k[i] = byte(i / 64)
	}
	tests := []struct {
		dir  Direction
		want [4]byte
	}{
		{Bidirectional, [4]byte{0, 1, 0, 1}},
		{Normal, [4]byte{0, 1, 2, 3}},
		{Inverse, [4]byte{2, 3, 0, 1}},
	}
	for _, tc := range tests {
		sc, sh, rc, rh := k.Parts(tc.dir)
		for i, part := range [][]byte{sc, sh, rc, rh} {
			if len(part) != 64 || !bytes.Equal(part, bytes.Repeat([]byte{tc.want[i]}, 64)) {
				t.Errorf("%v part %d: %x", tc.dir, i, part)
			}
		}
		sc[0] = 0xee
		if k[0] != 0 {
			t.Fatalf("Parts aliases the key")
		}
	}
	if a, b, c, d := k.Parts(2); a != nil || b != nil || c != nil || d != nil {
		t.Errorf("invalid direction returned parts")
	}
}

func v2KeyText(kc *StaticKey, wkc []byte, eol string) string {
	s := string(pem.EncodeToMemory(&pem.Block{Type: v2ClientKeyType, Bytes: append(bytes.Clone(kc[:]), wkc...)}))
	return strings.ReplaceAll(s, "\n", eol)
}

func TestParseTLSCryptV2ClientKey(t *testing.T) {
	kc := testKey(14)
	wkc := testWKc(299)
	good := map[string]string{
		"lf":            v2KeyText(kc, wkc, "\n"),
		"crlf":          v2KeyText(kc, wkc, "\r\n"),
		"text around":   "<tls-crypt-v2>\n" + v2KeyText(kc, wkc, "\n") + "</tls-crypt-v2>\n",
		"after a block": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}})) + v2KeyText(kc, wkc, "\n"),
	}
	for name, text := range good {
		gk, gw, err := ParseTLSCryptV2ClientKey([]byte(text))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if *gk != *kc || !bytes.Equal(gw, wkc) {
			t.Errorf("%s: wrong key", name)
		}
	}
	bad := map[string]string{
		"empty":          "",
		"garbage":        "nope\n",
		"static key":     keyText(kc, "\n"),
		"server key":     string(pem.EncodeToMemory(&pem.Block{Type: "OpenVPN tls-crypt-v2 server key", Bytes: make([]byte, 128)})),
		"no wkc":         v2KeyText(kc, nil, "\n"),
		"kc too short":   string(pem.EncodeToMemory(&pem.Block{Type: v2ClientKeyType, Bytes: make([]byte, 100)})),
		"wkc too short":  v2KeyText(kc, testWKc(289), "\n"),
		"wkc too long":   v2KeyText(kc, testWKc(1025), "\n"),
		"wrong trailer":  v2KeyText(kc, append(testWKc(300)[:298], 0x01, 0x2b), "\n"),
		"trailing byte":  v2KeyText(kc, append(testWKc(299), 0), "\n"),
		"bad base64":     "-----BEGIN " + v2ClientKeyType + "-----\n!!!!\n-----END " + v2ClientKeyType + "-----\n",
		"truncated text": v2KeyText(kc, wkc, "\n")[:200],
	}
	for name, text := range bad {
		if _, _, err := ParseTLSCryptV2ClientKey([]byte(text)); !errors.Is(err, ErrKey) {
			t.Errorf("%s: err = %v, want ErrKey", name, err)
		}
	}
}
