package conf

import (
	"strings"
	"testing"
	"time"
)

func TestTLSCertificateOCSPIntervalBoundaries(t *testing.T) {
	const maximum = uint64((1<<63 - 1) / time.Second)
	for _, seconds := range []uint64{0, 1, 3600, maximum, maximum + 1, ^uint64(0)} {
		c := &TLSCertConfig{CertStr: []string{"synthetic certificate bytes"}, OcspStapling: seconds}
		got, err := c.Build()
		if seconds > maximum {
			if err == nil || !strings.Contains(err.Error(), "timer range") {
				t.Fatalf("overflow interval %d not rejected: %v", seconds, err)
			}
		} else if err != nil || got.OcspStapling != seconds {
			t.Fatalf("valid interval %d changed: %v", seconds, err)
		}
	}
}
