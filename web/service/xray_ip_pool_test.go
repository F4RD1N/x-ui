package service

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/util/json_util"
)

func fakeHost(t *testing.T, gws []string, addrs ...string) {
	t.Helper()
	oldA, oldG := interfaceAddrs, gatewayAddrs
	t.Cleanup(func() { interfaceAddrs, gatewayAddrs = oldA, oldG })
	interfaceAddrs = func() ([]ifaceAddr, error) {
		var out []ifaceAddr
		for _, s := range addrs {
			p := netip.MustParsePrefix(s)
			out = append(out, ifaceAddr{ip: p.Addr(), net: p.Masked()})
		}
		return out, nil
	}
	gatewayAddrs = func() map[netip.Addr]bool {
		m := map[netip.Addr]bool{}
		for _, g := range gws {
			m[netip.MustParseAddr(g)] = true
		}
		return m
	}
}

func TestLocalIPv4Ranges(t *testing.T) {
	// a /27 with every address configured, including ones a provider never
	// gives out, plus the main /24 with a few of the server's own addresses
	addrs := []string{"103.76.130.12/24", "103.76.130.79/24", "103.76.130.1/24"}
	for i := 96; i <= 127; i++ {
		addrs = append(addrs, "154.193.163."+itoa(i)+"/27")
	}
	fakeHost(t, []string{"103.76.130.1", "154.193.163.97"}, addrs...)
	rs, err := LocalIPv4Ranges()
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 2 || rs[0].CIDR != "103.76.130.0/24" || rs[1].CIDR != "154.193.163.96/27" {
		t.Fatalf("ranges = %+v", rs)
	}
	if got := rs[0].IPs; len(got) != 2 || got[0] != "103.76.130.12" || got[1] != "103.76.130.79" {
		t.Fatalf("/24 ips = %v (the gateway must be left out)", got)
	}
	if rs[0].Label != "103.76.130.12, .79" || rs[1].Label != "154.193.163.98 – .126" {
		t.Fatalf("labels = %q, %q", rs[0].Label, rs[1].Label)
	}
	got := rs[1].IPs
	if len(got) != 29 || got[0] != "154.193.163.98" || got[28] != "154.193.163.126" {
		t.Fatalf("/27 ips = %d %v (network, gateway and broadcast must be left out)", len(got), got)
	}
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }

func TestParseOutboundIPPools(t *testing.T) {
	m, err := ParseOutboundIPPools(`{"direct":"154.193.163.100/27","other":"none","x":""}`)
	if err != nil || len(m) != 1 || m["direct"] != "154.193.163.96/27" {
		t.Fatalf("m=%v err=%v", m, err)
	}
	for _, bad := range []string{`{"d":"1.2.3.4"}`, `{"d":"2001:db8::/64"}`, `[1]`} {
		if _, err := ParseOutboundIPPools(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestWithIPPools(t *testing.T) {
	fakeHost(t, []string{"10.0.0.1"}, "10.0.0.5/29", "10.0.0.6/29")
	raw := json_util.RawMessage(`[{"tag":"direct","protocol":"freedom","sendThrough":"9.9.9.9"},{"tag":"gone","protocol":"freedom","sendThrough":"8.8.8.8"},{"tag":"blocked","protocol":"blackhole"}]`)
	out := withIPPools(raw, map[string]string{"direct": "10.0.0.0/29", "gone": "192.0.2.0/27"})
	var obs []map[string]any
	if err := json.Unmarshal(out, &obs); err != nil {
		t.Fatal(err)
	}
	if obs[0]["sendThrough"] != "10.0.0.5,10.0.0.6" {
		t.Fatalf("direct sendThrough = %v", obs[0]["sendThrough"])
	}
	if obs[1]["sendThrough"] != "8.8.8.8" {
		t.Fatalf("an outbound whose range is not here must keep its sendThrough, got %v", obs[1]["sendThrough"])
	}
	if _, ok := obs[2]["sendThrough"]; ok {
		t.Fatalf("an outbound without a pool must be left alone")
	}
	if string(withIPPools(raw, nil)) != string(raw) {
		t.Fatalf("no pools must change nothing")
	}
}

func TestIPRunsLabel(t *testing.T) {
	addrs := func(ss ...string) (out []netip.Addr) {
		for _, s := range ss {
			out = append(out, netip.MustParseAddr(s))
		}
		return
	}
	for _, tc := range []struct {
		in   []netip.Addr
		want string
	}{
		{addrs("193.16.145.140", "193.16.145.141", "193.16.145.142", "193.16.145.143"), "193.16.145.140 – .143"},
		{addrs("103.76.130.12", "103.76.130.79", "103.76.130.99", "103.76.130.153", "103.76.130.247"), "103.76.130.12, .79, .99, .153, .247"},
		{addrs("193.16.145.59", "193.16.145.132", "193.16.145.133", "193.16.145.134", "193.16.145.135"), "193.16.145.59, .132 – .135"},
		{addrs("10.0.0.255", "10.0.1.0", "10.0.2.7"), "10.0.0.255 – 10.0.1.0, 10.0.2.7"},
		{addrs("10.0.0.5"), "10.0.0.5"},
	} {
		if got := ipRunsLabel(tc.in); got != tc.want {
			t.Errorf("ipRunsLabel = %q, want %q", got, tc.want)
		}
	}
}
