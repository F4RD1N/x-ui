package hw

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"slices"
	"sort"
)

// Weight is an RSS queue's weight in a table weighted for an instance
// split: the CPUs of the unit its interrupt is on, over the RSS queues that
// unit holds on all the NICs weighed together.
type Weight struct {
	Unit   string `json:"unit"` // "" the free CPUs, whose queues keep an even share
	CPUs   int    `json:"cpus"`
	Queues int    `json:"queues"`
}

// PerQueue is the weight as CPUs per queue.
func (w Weight) PerQueue() float64 { return float64(w.CPUs) / float64(w.Queues) }

// fixed is the weight in fixed point: equal weights compare equal however
// they are made up (4 CPUs over 2 queues, 2 over 1).
func (w Weight) fixed() int64 { return int64(w.CPUs) << 20 / int64(w.Queues) }

// RSSWeights weighs the RSS queues of the NICs (name -> its RSS queues) by
// the placement's instance split, so that tables weighted by them give every
// instance a share of the hashed packets in proportion to its CPUs, whatever
// number of queues it holds. The free CPUs' queues keep an even share: they
// run no xray, and the placement gives them queues first to spare the
// instances. The NICs are weighed together, as a bond spreads its traffic
// about evenly over its slaves. A queue the placement did not place has no
// weight; nil without a split.
func (pl *Placement) RSSWeights(rss map[string][]int) map[string]map[int]Weight {
	if !pl.Split {
		return nil
	}
	held := map[string]int{}
	for nic, qs := range rss {
		for _, q := range qs {
			if u, ok := pl.Owner[nic][q]; ok {
				held[u]++
			}
		}
	}
	out := map[string]map[int]Weight{}
	for nic, qs := range rss {
		out[nic] = map[int]Weight{}
		for _, q := range qs {
			if u, ok := pl.Owner[nic][q]; ok && pl.CPUs[u] > 0 {
				out[nic][q] = Weight{Unit: u, CPUs: pl.CPUs[u], Queues: held[u]}
			}
		}
	}
	return out
}

// Uneven says whether the instances' weights differ: only then is a
// weighted table called for (the free CPUs' queues keep an even share).
func Uneven(w map[int]Weight) bool {
	first := int64(-1)
	for _, x := range w {
		if x.Unit == "" {
			continue
		}
		switch f := x.fixed(); {
		case first < 0:
			first = f
		case f != first:
			return true
		}
	}
	return false
}

// WeightedTable is base with its entries shared out by weight: the free
// CPUs' queues keep an even share (what base gives them, within the floor
// and the ceiling of size/queues), each instance gets its largest-remainder
// part of the rest by the weights of its queues (one entry a queue at
// least), shared evenly over them, and no queue base does not hash to gets
// any. Parted by instance rather than by queue, every instance is within one
// entry of its exact share, however many queues it holds. nil when a queue
// of base has no weight, or none is an instance's.
//
// The layout is interleaved, not in blocks like ethtool's "weight": it
// keeps as many of base's entries as it can. A queue with more than its part
// gives up some, spread over its entries, and the queues short of theirs
// take those, each spread over them. Writing it then moves only the entries
// that must change queue, so only their flows switch CPU (and may see a
// packet or two out of order); a table in blocks would move almost all of
// them. Built on the kernel's default (entry i to queue i mod k), every
// queue's entries stay spread over the whole table, as before.
func WeightedTable(base []uint32, w map[int]Weight) []uint32 {
	have := map[int]int{}
	for _, q := range base {
		have[int(q)]++
	}
	qs := make([]int, 0, len(have))
	for q := range have {
		qs = append(qs, q)
	}
	sort.Ints(qs)
	if len(qs) == 0 {
		return nil
	}
	lo, hi := len(base)/len(qs), (len(base)+len(qs)-1)/len(qs)
	want := map[int]int{}
	rest := len(base)
	var units []string
	of := map[string][]int{} // instance -> its queues
	for _, q := range qs {
		x, ok := w[q]
		switch {
		case !ok || x.CPUs <= 0 || x.Queues <= 0:
			return nil
		case x.Unit == "":
			want[q] = min(max(have[q], lo), hi)
			rest -= want[q]
		default:
			if of[x.Unit] == nil {
				units = append(units, x.Unit)
			}
			of[x.Unit] = append(of[x.Unit], q)
		}
	}
	ws, least := make([]int64, len(units)), make([]int, len(units))
	for i, u := range units {
		for _, q := range of[u] {
			ws[i] += w[q].fixed()
		}
		least[i] = len(of[u])
	}
	parts := shareOut(rest, ws, least)
	if parts == nil {
		return nil
	}
	// An instance's extra entries go to its queues that have more already.
	for i, u := range units {
		uq := of[u]
		sort.SliceStable(uq, func(a, b int) bool { return have[uq[a]] > have[uq[b]] })
		for j, q := range uq {
			want[q] = parts[i] / len(uq)
			if j < parts[i]%len(uq) {
				want[q]++
			}
		}
	}

	// A queue keeps entry j of its m when (j+1)*keep/m passes a whole
	// number: keep of them, evenly spread.
	out := slices.Clone(base)
	seen := map[int]int{}
	var free []int
	for i, x := range base {
		q := int(x)
		m, keep, j := have[q], min(want[q], have[q]), seen[q]
		seen[q]++
		if (j+1)*keep/m == j*keep/m {
			free = append(free, i)
		}
	}
	// The k-th of the d entries a queue is short of goes (2k+1)/2d of the
	// way through the free ones.
	type gap struct{ q, k, d int }
	var gaps []gap
	for _, q := range qs {
		d := want[q] - have[q]
		for k := 0; k < d; k++ {
			gaps = append(gaps, gap{q, k, d})
		}
	}
	sort.SliceStable(gaps, func(a, b int) bool {
		x, y := gaps[a], gaps[b]
		return (2*x.k+1)*y.d < (2*y.k+1)*x.d
	})
	for i, g := range gaps {
		out[free[i]] = uint32(g.q)
	}
	return out
}

// shareOut shares size entries out by the weights: largest remainder, at
// least least[i] each, ties to the earlier. nil when the leasts do not fit.
func shareOut(size int, ws []int64, least []int) []int {
	var sum int64
	need := 0
	for i, x := range ws {
		sum += x
		need += least[i]
	}
	if len(ws) == 0 || need > size || sum <= 0 {
		return nil
	}
	out := make([]int, len(ws))
	over := make([]int64, len(ws)) // the exact part above out[i], in 1/sum entries
	left := size
	for i, x := range ws {
		out[i] = max(least[i], int(int64(size)*x/sum))
		over[i] = int64(size)*x - int64(out[i])*sum
		left -= out[i]
	}
	// The rest to the largest remainders; when the ones raised to their
	// least took too many, back from the smallest.
	for left != 0 {
		best := -1
		for i := range ws {
			switch {
			case left > 0 && (best < 0 || over[i] > over[best]):
				best = i
			case left < 0 && out[i] > least[i] && (best < 0 || over[i] < over[best]):
				best = i
			}
		}
		if left > 0 {
			out[best]++
			over[best] -= sum
			left--
		} else {
			out[best]--
			over[best] += sum
			left++
		}
	}
	return out
}

// DefaultTable is the kernel's default table of size entries over k queues:
// entry i is i % k.
func DefaultTable(size, k int) []uint32 {
	t := make([]uint32, size)
	for i := range t {
		t[i] = uint32(i % max(k, 1))
	}
	return t
}

// TableSum is a short fingerprint of an RSS table: its size and the start
// of its SHA-256.
func TableSum(t []uint32) string {
	h := sha256.New()
	var b [4]byte
	for _, q := range t {
		binary.LittleEndian.PutUint32(b[:], q)
		h.Write(b[:])
	}
	return fmt.Sprintf("%d:%x", len(t), h.Sum(nil)[:8])
}
