package anytls

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math/big"
	"strconv"
	"strings"
)

// These are public wire-protocol default parameters, not implementation code.
const defaultPadding = "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000"

type padRange struct {
	low, high int
	check     bool
}
type padding struct {
	raw   string
	stop  int
	rules map[int][]padRange
}

// Limits that keep a server-sent scheme bounded. Values past them are clamped
// or ignored rather than rejected, like the reference client.
const (
	maxPaddingStop      = 1024
	maxPaddingFragments = 64
	maxPaddingLength    = 65535
)

// parsePadding is as lenient as the reference client: unknown keys and
// unparsable fragments are skipped, reversed ranges are swapped and oversized
// values are clamped. Only an oversized scheme or a missing/invalid "stop"
// make the whole scheme invalid. raw keeps the server's exact bytes so the
// reported padding-md5 matches the server's.
func parsePadding(s string) (*padding, error) {
	if len(s) > 65535 {
		return nil, errors.New("AnyTLS padding scheme too large")
	}
	p := &padding{raw: s, rules: make(map[int][]padRange)}
	stop := false
	for _, line := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if k == "stop" {
			n, e := strconv.Atoi(v)
			if e != nil || n < 0 {
				return nil, errors.New("invalid padding stop")
			}
			p.stop, stop = min(n, maxPaddingStop), true
			continue
		}
		i, e := strconv.Atoi(k)
		if e != nil || i < 0 || i >= maxPaddingStop {
			continue // unknown key, or a packet past any usable stop
		}
		var ranges []padRange
		for _, part := range strings.Split(v, ",") {
			if len(ranges) >= maxPaddingFragments {
				break
			}
			part = strings.TrimSpace(part)
			if part == "c" {
				ranges = append(ranges, padRange{check: true})
				continue
			}
			a, b, ok := strings.Cut(part, "-")
			if !ok {
				continue
			}
			lo, e1 := strconv.Atoi(strings.TrimSpace(a))
			hi, e2 := strconv.Atoi(strings.TrimSpace(b))
			if e1 != nil || e2 != nil || lo < 0 || hi < 0 {
				continue
			}
			if lo > hi {
				lo, hi = hi, lo
			}
			ranges = append(ranges, padRange{low: min(lo, maxPaddingLength), high: min(hi, maxPaddingLength)})
		}
		p.rules[i] = ranges
	}
	if !stop {
		return nil, errors.New("invalid padding stop")
	}
	return p, nil
}
func (p *padding) digest() string { d := md5.Sum([]byte(p.raw)); return hex.EncodeToString(d[:]) }
func (r padRange) size() int {
	if r.high == r.low {
		return r.low
	}
	n, e := rand.Int(rand.Reader, big.NewInt(int64(r.high-r.low+1)))
	if e != nil {
		return r.low
	}
	return r.low + int(n.Int64())
}
