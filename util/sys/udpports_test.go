package sys

import (
	"os"
	"path/filepath"
	"testing"
)

func writeProcSys(t *testing.T, root, name, data string) {
	t.Helper()
	p := filepath.Join(root, "/proc/sys/net/ipv4", name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReadUDPPortUse(t *testing.T) {
	root := t.TempDir()
	writeProcSys(t, root, "ip_local_port_range", "1000\t1009\n")
	writeProcSys(t, root, "ip_local_reserved_ports", "1009\n")

	sockets := []LocalEndpoint{
		{IP: "", Port: 1000}, {IP: "", Port: 1001}, // all addresses
		{IP: "192.0.2.7", Port: 1001}, {IP: "192.0.2.7", Port: 1002}, // its own
		{IP: "192.0.2.8", Port: 1002},
		{IP: "", Port: 53},   // outside the range
		{IP: "", Port: 1009}, // reserved
	}
	u, err := ReadUDPPortUseAt(root, func(fn func(LocalEndpoint)) error {
		for _, s := range sockets {
			fn(s)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if u.Pool != 9 {
		t.Errorf("pool %d, want 9 (10 ports, 1 reserved)", u.Pool)
	}
	for _, c := range []struct {
		from string
		want int
	}{
		{"", 3},          // ports 1000-1002 are taken for a socket on all addresses
		{"192.0.2.7", 3}, // 1000, 1001 (all addresses) and 1002
		{"192.0.2.8", 3}, // 1000, 1001 and 1002
		{"192.0.2.9", 2}, // only the all-address ones
	} {
		if got := u.Used(c.from); got != c.want {
			t.Errorf("Used(%q) = %d, want %d", c.from, got, c.want)
		}
	}

	// No reserved ports file: the whole range is the pool.
	root2 := t.TempDir()
	writeProcSys(t, root2, "ip_local_port_range", "10000 65535\n")
	u, err = ReadUDPPortUseAt(root2, func(func(LocalEndpoint)) error { return nil })
	if err != nil || u.Pool != 55536 || u.Used("") != 0 {
		t.Errorf("no reserved ports: %+v %v", u, err)
	}
	// A bad or missing range is an error, not a guess.
	writeProcSys(t, root2, "ip_local_port_range", "65535 10000\n")
	if _, err := ReadUDPPortUseAt(root2, func(func(LocalEndpoint)) error { return nil }); err == nil {
		t.Error("a reversed range was accepted")
	}
	if _, err := ReadUDPPortUseAt(t.TempDir(), func(func(LocalEndpoint)) error { return nil }); err == nil {
		t.Error("a missing range was accepted")
	}
}

func TestParsePorts(t *testing.T) {
	set := parsePorts(" 80, 443,1000-1003 ,bad,70000,9-7")
	if len(set) != 6 || !set[80] || !set[443] || !set[1000] || !set[1003] {
		t.Errorf("parsePorts: %v", set)
	}
}

func TestAttributeTCP(t *testing.T) {
	eps := map[LocalEndpoint]int{
		{IP: "192.0.2.1", Port: 443}:  5, // xray-2 listens on this address
		{IP: "192.0.2.2", Port: 443}:  7, // the rest on 443: xray-1's
		{IP: "::1", Port: 443}:        1,
		{IP: "192.0.2.1", Port: 8443}: 3, // only a wildcard listener
		{IP: "192.0.2.1", Port: 9000}: 4, // nobody's
		{IP: "192.0.2.9", Port: 2053}: 2, // only a listener on another address
	}
	got := AttributeTCP(eps, []PortOwner{
		{Port: 443, IP: "0.0.0.0", Name: "xray-1"},
		{Port: 443, IP: "192.0.2.1", Name: "xray-2"},
		{Port: 8443, IP: "::", Name: "xray-3"},
		{Port: 2053, IP: "192.0.2.1", Name: "xray-4"},
	})
	want := map[string]int{"xray-1": 8, "xray-2": 5, "xray-3": 3}
	if len(got) != len(want) {
		t.Errorf("AttributeTCP = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("AttributeTCP[%s] = %d, want %d (all: %v)", k, got[k], v, got)
		}
	}
	if got := AttributeTCP(nil, nil); len(got) != 0 {
		t.Errorf("empty: %v", got)
	}
}
