package protocol

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"sync"
	"testing"
	"time"
)

func TestNativeChannelIDVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/native-channel.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Fields          [5]int32
			Counter         uint32
			RandomWords     [2]uint32
			MonotonicMillis uint64
			Hex, WireHex    string
			CounterAfter    uint32
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, c := range fixture.Cases {
		got := MakeChannelID(ChannelIDInput{Day: c.Fields[0], Hour: c.Fields[1], Minute: c.Fields[2], Second: c.Fields[3], Millisecond: c.Fields[4], Counter: c.Counter, RandomWords: c.RandomWords, MonotonicMillis: c.MonotonicMillis})
		if hex.EncodeToString(got[:]) != c.Hex || c.Hex != c.WireHex || c.CounterAfter != c.Counter+1 {
			t.Fatal("native channel mismatch")
		}
	}
}
func TestChannelGeneratorCounterEntropyAndConcurrency(t *testing.T) {
	seed := bytes.NewReader(append([]byte{255, 255, 255, 255}, make([]byte, 16)...))
	start := time.Date(2026, 10, 7, 18, 33, 45, 678000000, time.UTC)
	g, err := newChannelIDGenerator(seed, start, func() uint64 { return 123456 })
	if err != nil {
		t.Fatal(err)
	}
	for _, counter := range []uint32{0xffffffff, 0} {
		got, err := g.next()
		want := MakeChannelID(ChannelIDInput{Day: 7, Hour: 18, Minute: 33, Second: 45, Millisecond: 678, Counter: counter, MonotonicMillis: 123456})
		if err != nil || got != want {
			t.Fatal("counter or date field differs", err)
		}
	}
	if _, err = g.next(); err != io.EOF {
		t.Fatal("missing entropy not rejected", err)
	}
	if _, err = newChannelIDGenerator(bytes.NewReader(nil), start, func() uint64 { return 0 }); err != io.EOF {
		t.Fatal("missing seed accepted")
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := map[[16]byte]bool{}
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, e := NewChannelID()
			if e != nil {
				t.Error(e)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if seen[id] || id == [16]byte{} {
				t.Error("duplicate/empty ID")
			}
			seen[id] = true
		}()
	}
	wg.Wait()
}
