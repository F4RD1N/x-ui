package options

import (
	"testing"
	"time"
)

// TestPingRestartSet: the client needs to tell a profile without
// ping-restart (OpenVPN's 120 s client default applies) from an explicit
// "ping-restart 0" (no ping-restart at all).
func TestPingRestartSet(t *testing.T) {
	for _, tc := range []struct {
		line string
		set  bool
		want time.Duration
	}{
		{"", false, 0},
		{"ping 10\n", false, 0},
		{"ping-restart 0\n", true, 0},
		{"ping-restart 60\n", true, 60 * time.Second},
		{"ping-exit 30\n", true, 30 * time.Second},
		{"keepalive 10 60\n", true, 60 * time.Second},
		{"keepalive 10 0\n", true, 0},
	} {
		o, err := Parse("client\nremote example.com 1194\n" + tc.line)
		if err != nil {
			t.Fatalf("%q: %v", tc.line, err)
		}
		if o.PingRestartSet != tc.set || o.PingRestart != tc.want {
			t.Errorf("%q: PingRestart %v (set %v), want %v (set %v)", tc.line, o.PingRestart, o.PingRestartSet, tc.want, tc.set)
		}
	}
}
