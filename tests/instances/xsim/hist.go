package main

// Latency histogram (from xload): 4 buckets per power of two of microseconds.

import (
	"math"
	"math/bits"
	"sync/atomic"
	"time"
)

const nBuckets = 4 * 30

func bucketOf(us int64) int {
	if us < 4 {
		if us < 0 {
			return 0
		}
		return int(us)
	}
	oct := 63 - bits.LeadingZeros64(uint64(us))
	sub := int((us >> (oct - 2)) & 3)
	b := oct*4 + sub
	if b >= nBuckets {
		b = nBuckets - 1
	}
	return b
}

// bucketUpper is the largest value in bucket b, in microseconds.
func bucketUpper(b int) float64 {
	if b < 4 {
		return float64(b)
	}
	oct, sub := b/4, b%4
	return float64((int64(4+sub+1) << (oct - 2)) - 1)
}

const nShards = 64

type hist struct {
	c [nShards][nBuckets]atomic.Uint64
}

func (h *hist) add(shard int, d time.Duration) {
	h.c[shard%nShards][bucketOf(d.Microseconds())].Add(1)
}

func (h *hist) percentiles(ps ...float64) ([]float64, uint64, float64) {
	var tot [nBuckets]uint64
	var n uint64
	for s := range h.c {
		for b := range h.c[s] {
			v := h.c[s][b].Load()
			tot[b] += v
			n += v
		}
	}
	out := make([]float64, len(ps))
	max := 0.0
	for b := nBuckets - 1; b >= 0; b-- {
		if tot[b] > 0 {
			max = bucketUpper(b) / 1000
			break
		}
	}
	if n == 0 {
		return out, 0, 0
	}
	for i, p := range ps {
		want := uint64(math.Ceil(p * float64(n)))
		var acc uint64
		for b := 0; b < nBuckets; b++ {
			acc += tot[b]
			if acc >= want {
				out[i] = bucketUpper(b) / 1000 // ms
				break
			}
		}
	}
	return out, n, max
}
