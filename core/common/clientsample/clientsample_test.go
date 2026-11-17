package clientsample

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"testing"
)

type sample struct {
	V        int      `json:"v"`
	Recorded uint64   `json:"recorded"`
	IPs      []string `json:"ips"`
	Peers    []string `json:"peers"`
}

func reset() {
	mu.Lock()
	count = 0
	ring = [Size]entry{}
	mu.Unlock()
}

func read(t testing.TB) sample {
	t.Helper()
	var s sample
	if err := json.Unmarshal(AppendJSON(nil), &s); err != nil {
		t.Fatal(err)
	}
	if s.V != 1 {
		t.Fatalf("v = %d", s.V)
	}
	if len(s.Peers) != len(s.IPs) {
		t.Fatalf("%d peers for %d ips", len(s.Peers), len(s.IPs))
	}
	return s
}

// ipOf maps n to a distinct IPv4 address in 10.0.0.0/8.
func ipOf(n int) net.IP {
	return net.IP{10, byte(n >> 16), byte(n >> 8), byte(n)}
}

// peerOf maps n to a distinct peer: IPv4 in 172.16.0.0/12 for even n, IPv6
// in 2001:db8::/32 for odd n.
func peerOf(n int) net.IP {
	if n%2 == 0 {
		return net.IP{172, 16 | byte(n>>16)&15, byte(n >> 8), byte(n)}
	}
	ip := net.ParseIP("2001:db8::")
	ip[13], ip[14], ip[15] = byte(n>>16), byte(n>>8), byte(n)
	return ip
}

func TestEmpty(t *testing.T) {
	reset()
	if got := string(AppendJSON(nil)); got != `{"v":1,"recorded":0,"ips":[],"peers":[]}` {
		t.Fatalf("got %s", got)
	}
}

func TestFamilies(t *testing.T) {
	reset()
	fastly, cf := net.IP{151, 101, 2, 3}, net.ParseIP("2a06:98c0:3600::103")
	Record(net.IP{1, 2, 3, 4}, fastly)                        // 4-byte IPv4, 4-byte peer
	Record(net.IPv4(5, 6, 7, 8), net.IPv4(104, 16, 0, 1))     // 16-byte v4-mapped, both
	Record(net.ParseIP("::ffff:9.10.11.12"), cf)              // v4-mapped written as IPv6, IPv6 peer
	Record(net.ParseIP("2001:db8::1"), net.IP{172, 64, 0, 9}) // IPv6 from an IPv4 peer
	Record(net.ParseIP("2a01:5ec0:1000::abcd:1"), nil)        // unknown peer
	Record(net.IP{11, 12, 13, 14}, net.IP{1, 2, 3})           // malformed peer: unknown
	Record(nil, fastly)                                       // ignored
	Record(net.IP{1, 2, 3}, fastly)                           // ignored
	want := `{"v":1,"recorded":6,` +
		`"ips":["1.2.3.4","5.6.7.8","9.10.11.12","2001:db8::1","2a01:5ec0:1000::abcd:1","11.12.13.14"],` +
		`"peers":["151.101.2.3","104.16.0.1","2a06:98c0:3600::103","172.64.0.9","",""]}`
	if got := string(AppendJSON(nil)); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if Recorded() != 6 {
		t.Fatalf("Recorded() = %d", Recorded())
	}
}

func TestWrapKeepsNewestInOrder(t *testing.T) {
	reset()
	const total = 3*Size + 123
	for n := 1; n <= total; n++ {
		Record(ipOf(n), peerOf(n))
	}
	s := read(t)
	if s.Recorded != total {
		t.Fatalf("recorded = %d, want %d", s.Recorded, total)
	}
	if len(s.IPs) != Size {
		t.Fatalf("len(ips) = %d, want %d", len(s.IPs), Size)
	}
	for i, ip := range s.IPs {
		n := total - Size + 1 + i
		if want := ipOf(n).String(); ip != want {
			t.Fatalf("ips[%d] = %s, want %s", i, ip, want)
		}
		if want := peerOf(n).String(); s.Peers[i] != want {
			t.Fatalf("peers[%d] = %s, want %s", i, s.Peers[i], want)
		}
	}
}

// An entry without a peer must not inherit the peer of the entry it
// overwrites.
func TestWrapClearsOldPeer(t *testing.T) {
	reset()
	for n := 1; n <= Size; n++ {
		Record(ipOf(n), peerOf(n))
	}
	for n := Size + 1; n <= 2*Size; n++ {
		Record(ipOf(n), nil)
	}
	for i, p := range read(t).Peers {
		if p != "" {
			t.Fatalf("peers[%d] = %q, want \"\"", i, p)
		}
	}
}

func TestPartialRing(t *testing.T) {
	reset()
	for n := 1; n <= 10; n++ {
		Record(ipOf(n), peerOf(n))
	}
	s := read(t)
	if s.Recorded != 10 || len(s.IPs) != 10 || s.IPs[0] != "10.0.0.1" || s.IPs[9] != "10.0.0.10" ||
		s.Peers[0] != "2001:db8::1" || s.Peers[1] != "172.16.0.2" || s.Peers[9] != "172.16.0.10" {
		t.Fatalf("got %+v", s)
	}
}

func TestPeerIP(t *testing.T) {
	v4, v6 := net.IP{151, 101, 2, 3}, net.ParseIP("2a06:98c0::1")
	for _, c := range []struct {
		addr net.Addr
		want net.IP
	}{
		{&net.TCPAddr{IP: v4, Port: 443}, v4},
		{&net.TCPAddr{IP: v6, Port: 443}, v6},
		{&net.UDPAddr{IP: v4, Port: 443}, v4},
		{&net.UnixAddr{Name: "/run/x.sock", Net: "unix"}, nil},
		{nil, nil},
	} {
		if got := PeerIP(c.addr); !got.Equal(c.want) || (got == nil) != (c.want == nil) {
			t.Errorf("PeerIP(%v) = %v, want %v", c.addr, got, c.want)
		}
	}
	a := net.Addr(&net.TCPAddr{IP: v4, Port: 443})
	if n := testing.AllocsPerRun(1000, func() { _ = PeerIP(a) }); n != 0 {
		t.Fatalf("PeerIP allocates %v times per run", n)
	}
}

// TestConcurrent runs writers and readers together (meant for -race). Each
// writer puts its id in the second octet and a running number in the last
// two, and the same pair in its peer (IPv4 for even writers, IPv6 for odd
// ones), so every reader can check that a writer's entries come out in order
// and that no entry is torn.
func TestConcurrent(t *testing.T) {
	reset()
	const writers, each = 8, 20000
	stop := make(chan struct{})
	var rd sync.WaitGroup
	for r := 0; r < 2; r++ {
		rd.Add(1)
		go func() {
			defer rd.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				s := read(t)
				checkOrder(t, s.IPs, s.Peers)
			}
		}()
	}
	var wr sync.WaitGroup
	for w := 0; w < writers; w++ {
		wr.Add(1)
		go func(w int) {
			defer wr.Done()
			for i := 1; i <= each; i++ {
				Record(net.IP{10, byte(w), byte(i >> 8), byte(i)}, concurrentPeer(w, i))
			}
		}(w)
	}
	wr.Wait()
	close(stop)
	rd.Wait()

	s := read(t)
	if s.Recorded != writers*each {
		t.Fatalf("recorded = %d, want %d", s.Recorded, writers*each)
	}
	if len(s.IPs) != Size {
		t.Fatalf("len(ips) = %d, want %d", len(s.IPs), Size)
	}
	checkOrder(t, s.IPs, s.Peers)
}

func concurrentPeer(w, i int) net.IP {
	if w%2 == 0 {
		return net.IP{172, byte(16 + w), byte(i >> 8), byte(i)}
	}
	ip := net.ParseIP("2001:db8::")
	ip[13], ip[14], ip[15] = byte(w), byte(i>>8), byte(i)
	return ip
}

func checkOrder(t testing.TB, ips, peers []string) {
	last := map[byte]int{}
	for k, s := range ips {
		ip := net.ParseIP(s).To4()
		if ip == nil || ip[0] != 10 || ip[1] >= 8 {
			t.Errorf("bad address %q", s)
			return
		}
		// i wraps at 65536 in the address; with 20000 per writer it never does.
		i := int(ip[2])<<8 | int(ip[3])
		if i <= last[ip[1]] {
			t.Errorf("writer %d: %d after %d", ip[1], i, last[ip[1]])
			return
		}
		last[ip[1]] = i
		if want := concurrentPeer(int(ip[1]), i).String(); peers[k] != want {
			t.Errorf("torn entry: %s from %s, want %s", s, peers[k], want)
			return
		}
	}
}

func TestRecordDoesNotAllocate(t *testing.T) {
	v4, v6 := net.IP{1, 2, 3, 4}, net.ParseIP("2001:db8::1")
	p4, p6 := net.IP{151, 101, 2, 3}, net.ParseIP("2a06:98c0::1")
	if a := testing.AllocsPerRun(1000, func() { Record(v4, p4); Record(v6, p6); Record(v4, nil) }); a != 0 {
		t.Fatalf("Record allocates %v times per run", a)
	}
}

func BenchmarkRecord(b *testing.B) {
	ip, peer := net.IP{5, 160, 1, 2}, net.IP{151, 101, 2, 3}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Record(ip, peer)
	}
}

func BenchmarkRecordIPv6(b *testing.B) {
	ip, peer := net.ParseIP("2a01:5ec0:1000::abcd:1"), net.ParseIP("2a06:98c0:3600::103")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Record(ip, peer)
	}
}

// BenchmarkRecordWithPeerIP is the whole cost at a hook: PeerIP on the
// socket's address, then Record.
func BenchmarkRecordWithPeerIP(b *testing.B) {
	ip := net.IP{5, 160, 1, 2}
	addr := net.Addr(&net.TCPAddr{IP: net.IP{151, 101, 2, 3}, Port: 443})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Record(ip, PeerIP(addr))
	}
}

// Run with -cpu 8 (or more) to measure contention.
func BenchmarkRecordParallel(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		ip, peer := net.IP{5, 160, 1, 2}, net.IP{151, 101, 2, 3}
		for pb.Next() {
			Record(ip, peer)
		}
	})
}

func BenchmarkAppendJSONFullRing(b *testing.B) {
	reset()
	for n := 0; n < Size; n++ {
		Record(net.IP{5, 160, byte(n >> 8), byte(n)}, net.IP{151, 101, byte(n >> 8), byte(n)})
	}
	buf := make([]byte, 0, 40*Size)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf = AppendJSON(buf[:0])
	}
	b.SetBytes(int64(len(buf)))
}

func ExampleAppendJSON() {
	reset()
	Record(net.IP{1, 2, 3, 4}, net.IP{151, 101, 2, 3})
	Record(net.ParseIP("2001:db8::1"), nil)
	fmt.Println(string(AppendJSON(nil)))
	// Output: {"v":1,"recorded":2,"ips":["1.2.3.4","2001:db8::1"],"peers":["151.101.2.3",""]}
}
