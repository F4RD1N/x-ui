package dnstt

import (
	"strings"
	"testing"
)

func TestDNSTTMatrixCombinedQNameBudget(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		domain                    string
		qname, labelMin, labelMax uint32
		valid                     bool
	}{
		{"default_domain_capacity", strings.Repeat("a", 63) + "." + strings.Repeat("b", 37), 255, 63, 63, true},
		{"domain_capacity_exceeded", strings.Repeat("a", 63) + "." + strings.Repeat("b", 38), 255, 63, 63, false},
		{"exact_qname_minimum", "tunnel.test", 165, 63, 63, true},
		{"below_qname_minimum", "tunnel.test", 164, 63, 63, false},
		{"randomized_labels", "tunnel.test", 200, 20, 40, true},
		{"label_overhead_exceeds_budget", "tunnel.test", 255, 1, 63, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testConfig(t)
			c.Domain, c.MaxQnameLength, c.LabelMin, c.LabelMax = tc.domain, tc.qname, tc.labelMin, tc.labelMax
			normalized, err := NormalizeConfig(c)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
			if !tc.valid {
				return
			}
			mtu, err := packetMTU(normalized)
			if err != nil || mtu < 80 {
				t.Fatalf("normalized config has insufficient packet capacity: mtu=%d error=%v", mtu, err)
			}
		})
	}
}
