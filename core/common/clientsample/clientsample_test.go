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
}

func reset() {
	mu.Lock()
	count = 0
	ring = [Size][2]uint64{}
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
	return s
}

// ipOf maps n to a distinct IPv4 address in 10.0.0.0/8.
func ipOf(n int) net.IP {
	return net.IP{10, byte(n >> 16), byte(n >> 8), byte(n)}
}

func TestEmpty(t *testing.T) {
	reset()
	if got := string(AppendJSON(nil)); got != `{"v":1,"recorded":0,"ips":[]}` {
		t.Fatalf("got %s", got)
	}
}

func TestFamilies(t *testing.T) {
	reset()
	Record(net.IP{1, 2, 3, 4})                    // 4-byte IPv4
	Record(net.IPv4(5, 6, 7, 8))                  // 16-byte v4-mapped
	Record(net.ParseIP("::ffff:9.10.11.12"))      // v4-mapped written as IPv6
	Record(net.ParseIP("2001:db8::1"))            // IPv6
	Record(net.ParseIP("2a01:5ec0:1000::abcd:1")) // IPv6
	Record(nil)                                   // ignored
	Record(net.IP{1, 2, 3})                       // ignored
	want := `{"v":1,"recorded":5,"ips":["1.2.3.4","5.6.7.8","9.10.11.12","2001:db8::1","2a01:5ec0:1000::abcd:1"]}`
	if got := string(AppendJSON(nil)); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if Recorded() != 5 {
		t.Fatalf("Recorded() = %d", Recorded())
	}
}

func TestWrapKeepsNewestInOrder(t *testing.T) {
	reset()
	const total = 3*Size + 123
	for n := 1; n <= total; n++ {
		Record(ipOf(n))
	}
	s := read(t)
	if s.Recorded != total {
		t.Fatalf("recorded = %d, want %d", s.Recorded, total)
	}
	if len(s.IPs) != Size {
		t.Fatalf("len(ips) = %d, want %d", len(s.IPs), Size)
	}
	for i, ip := range s.IPs {
		if want := ipOf(total - Size + 1 + i).String(); ip != want {
			t.Fatalf("ips[%d] = %s, want %s", i, ip, want)
		}
	}
}

func TestPartialRing(t *testing.T) {
	reset()
	for n := 1; n <= 10; n++ {
		Record(ipOf(n))
	}
	s := read(t)
	if s.Recorded != 10 || len(s.IPs) != 10 || s.IPs[0] != "10.0.0.1" || s.IPs[9] != "10.0.0.10" {
		t.Fatalf("got %+v", s)
	}
}

// TestConcurrent runs writers and readers together (meant for -race). Each
// writer puts its id in the second octet and a running number in the last
// two, so every reader can check that a writer's addresses come out in order
// and that no address is torn.
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
				checkOrder(t, read(t).IPs)
			}
		}()
	}
	var wr sync.WaitGroup
	for w := 0; w < writers; w++ {
		wr.Add(1)
		go func(w int) {
			defer wr.Done()
			for i := 1; i <= each; i++ {
				Record(net.IP{10, byte(w), byte(i >> 8), byte(i)})
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
	checkOrder(t, s.IPs)
}

func checkOrder(t testing.TB, ips []string) {
	last := map[byte]int{}
	for _, s := range ips {
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
	}
}

func TestRecordDoesNotAllocate(t *testing.T) {
	v4, v6 := net.IP{1, 2, 3, 4}, net.ParseIP("2001:db8::1")
	if a := testing.AllocsPerRun(1000, func() { Record(v4); Record(v6) }); a != 0 {
		t.Fatalf("Record allocates %v times per run", a)
	}
}

func BenchmarkRecord(b *testing.B) {
	ip := net.IP{5, 160, 1, 2}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Record(ip)
	}
}

func BenchmarkRecordIPv6(b *testing.B) {
	ip := net.ParseIP("2a01:5ec0:1000::abcd:1")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Record(ip)
	}
}

// Run with -cpu 8 (or more) to measure contention.
func BenchmarkRecordParallel(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		ip := net.IP{5, 160, 1, 2}
		for pb.Next() {
			Record(ip)
		}
	})
}

func BenchmarkAppendJSONFullRing(b *testing.B) {
	reset()
	for n := 0; n < Size; n++ {
		Record(net.IP{5, 160, byte(n >> 8), byte(n)})
	}
	buf := make([]byte, 0, 20*Size)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf = AppendJSON(buf[:0])
	}
	b.SetBytes(int64(len(buf)))
}

func ExampleAppendJSON() {
	reset()
	Record(net.IP{1, 2, 3, 4})
	Record(net.ParseIP("2001:db8::1"))
	fmt.Println(string(AppendJSON(nil)))
	// Output: {"v":1,"recorded":2,"ips":["1.2.3.4","2001:db8::1"]}
}
