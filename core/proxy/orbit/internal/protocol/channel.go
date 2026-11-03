package protocol

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"
)

// ChannelIDInput is the exact make_channel_id hash input. Date fields are
// captured at runtime start; the counter increments for each new channel. The
// random words form a uint64 with RandomWords[0] in the high half. A channel ID
// identifies a runtime channel and is neither a credential nor a group ID.
type ChannelIDInput struct {
	Day, Hour, Minute, Second, Millisecond int32
	Counter                                uint32
	RandomWords                            [2]uint32
	MonotonicMillis                        uint64
}

// MakeChannelID reproduces native decimal concatenation and MD5. The native
// implementation stores its hexadecimal string but sends the decoded16 bytes.
func MakeChannelID(in ChannelIDInput) [16]byte {
	raw := fmt.Sprintf("%d%d%d%d%d:%d:%d:%d", in.Day, in.Hour, in.Minute, in.Second, in.Millisecond, in.Counter, uint64(in.RandomWords[0])<<32|uint64(in.RandomWords[1]), in.MonotonicMillis)
	return md5.Sum([]byte(raw))
}

type channelIDGenerator struct {
	mu      sync.Mutex
	started time.Time
	counter uint32
	random  io.Reader
	elapsed func() uint64
}

func newChannelIDGenerator(random io.Reader, started time.Time, elapsed func() uint64) (*channelIDGenerator, error) {
	var seed [4]byte
	if _, err := io.ReadFull(random, seed[:]); err != nil {
		return nil, err
	}
	return &channelIDGenerator{started: started, counter: binary.LittleEndian.Uint32(seed[:]), random: random, elapsed: elapsed}, nil
}
func (g *channelIDGenerator) next() ([16]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	var raw [8]byte
	if _, err := io.ReadFull(g.random, raw[:]); err != nil {
		return [16]byte{}, err
	}
	t := g.started
	in := ChannelIDInput{Day: int32(t.Day()), Hour: int32(t.Hour()), Minute: int32(t.Minute()), Second: int32(t.Second()), Millisecond: int32(t.Nanosecond() / int(time.Millisecond)), Counter: g.counter, RandomWords: [2]uint32{binary.LittleEndian.Uint32(raw[:4]), binary.LittleEndian.Uint32(raw[4:])}, MonotonicMillis: g.elapsed()}
	g.counter++
	return MakeChannelID(in), nil
}

var channelStart = time.Now()
var channelGeneratorOnce sync.Once
var defaultChannelGenerator *channelIDGenerator
var channelGeneratorError error

// NewChannelID creates an ephemeral channel identifier using the recovered
// construction with cryptographic entropy. Portable Go uses monotonic elapsed
// milliseconds since process initialization; the native clock's boot-time epoch
// affects only this opaque digest and is supplied explicitly by MakeChannelID.
func NewChannelID() ([16]byte, error) {
	channelGeneratorOnce.Do(func() {
		defaultChannelGenerator, channelGeneratorError = newChannelIDGenerator(rand.Reader, channelStart, func() uint64 { return uint64(time.Since(channelStart) / time.Millisecond) })
	})
	if channelGeneratorError != nil {
		return [16]byte{}, channelGeneratorError
	}
	return defaultChannelGenerator.next()
}
