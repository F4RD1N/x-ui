package transport

import (
	"net/http"
	"testing"
)

func TestNativeWebSocketOriginPolicy(t *testing.T) {
	for _, tt := range []struct {
		name   string
		header http.Header
		want   bool
	}{
		{"legacy absent", nil, true},
		{"http", http.Header{"Origin": {"http://vpn.test"}}, true},
		{"https", http.Header{"Origin": {"https://vpn.test"}}, true},
		{"default port", http.Header{"Origin": {"https://vpn.test:443"}}, true},
		{"case", http.Header{"Origin": {"https://VPN.TEST"}}, true},
		{"empty", http.Header{"Origin": {""}}, false},
		{"null", http.Header{"Origin": {"null"}}, false},
		{"foreign", http.Header{"Origin": {"https://other.test"}}, false},
		{"suffix", http.Header{"Origin": {"https://vpn.test.evil.test"}}, false},
		{"scheme", http.Header{"Origin": {"file://vpn.test"}}, false},
		{"userinfo", http.Header{"Origin": {"https://a@vpn.test"}}, false},
		{"path", http.Header{"Origin": {"https://vpn.test/"}}, false},
		{"query", http.Header{"Origin": {"https://vpn.test?"}}, false},
		{"fragment", http.Header{"Origin": {"https://vpn.test#x"}}, false},
		{"other port", http.Header{"Origin": {"https://vpn.test:444"}}, false},
		{"duplicate value", http.Header{"Origin": {"https://vpn.test", "https://vpn.test"}}, false},
		{"duplicate name", http.Header{"Origin": {"https://vpn.test"}, "origin": {"https://vpn.test"}}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := &http.Request{Host: "vpn.test", Header: tt.header}
			_, got := NormalizeWebSocketOrigin(r)
			if got != tt.want {
				t.Fatalf("origin accepted=%v, want %v", got, tt.want)
			}
		})
	}
}
