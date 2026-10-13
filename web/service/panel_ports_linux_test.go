//go:build linux

package service

import (
	"testing"

	"github.com/mhsanaei/3x-ui/v2/util/tune"
)

// The GOMEMLIMIT "x-ui tune" writes into the unit is one the panel can split
// among its cores.
func TestTuneGoMemLimitParses(t *testing.T) {
	for _, gib := range []float64{1, 2, 8, 16, 128} {
		f := &tune.Facts{MemBytes: int64(gib * float64(tune.GiB)), PageSize: 4096, G: gib}
		f.MemTotal = f.MemBytes
		f.TCPMemMax = f.MemBytes / 4096 * 3 / 32
		v := tune.ServiceTargets(f).GoMemLimit
		n := parseGoMemLimit(v)
		if n <= 0 || n%(1<<20) != 0 || n < 256<<20 || n > f.MemBytes {
			t.Fatalf("%g GiB: %q parses to %d", gib, v, n)
		}
	}
}
