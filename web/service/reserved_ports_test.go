package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPortLists(t *testing.T) {
	set := parsePortList(" 80, 443,1000-1003 ,bad,70000,9-7")
	if got := formatPortList(set); got != "80,443,1000-1003" {
		t.Fatalf("round trip: %s", got)
	}
	if formatPortList(map[int]bool{}) != "" || len(parsePortList("")) != 0 {
		t.Fatal("empty")
	}
}

func TestMergeReserved(t *testing.T) {
	merge := func(current, oldOurs, want string) (string, string) {
		m, o := mergeReserved(parsePortList(current), parsePortList(oldOurs), parsePortList(want))
		return formatPortList(m), formatPortList(o)
	}
	// Someone else reserved 10001-10003; the panel had 443 and 8443 and now
	// has 443 and 31000-31002.
	if m, o := merge("443,8443,10001-10003", "443,8443", "443,31000-31002"); m != "443,10001-10003,31000-31002" || o != "443,31000-31002" {
		t.Fatalf("merge: %s, ours %s", m, o)
	}
	// On the first sync the panel has no record yet: ports already reserved
	// stay, and are not the panel's.
	if m, o := merge("22,443", "", "443"); m != "22,443" || o != "" {
		t.Fatalf("first sync: %s, ours %s", m, o)
	}
	// So when the panel moves to 8443, 443 stays reserved.
	if m, o := merge("22,443", "", "8443"); m != "22,443,8443" || o != "8443" {
		t.Fatalf("moved: %s, ours %s", m, o)
	}
	// One of the panel's that someone else removed comes back.
	if m, o := merge("22", "8443", "8443"); m != "22,8443" || o != "8443" {
		t.Fatalf("restored: %s, ours %s", m, o)
	}
}

func TestSyncReservedPorts(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XUI_DB_FOLDER", dir)
	sysctl := filepath.Join(dir, "ip_local_reserved_ports")
	os.WriteFile(sysctl, []byte("10001-10003\n"), 0o644)
	old := reservedPortsPath
	reservedPortsPath = sysctl
	defer func() { reservedPortsPath = old }()
	read := func(path string) string {
		b, _ := os.ReadFile(path)
		return strings.TrimSpace(string(b))
	}

	syncReservedPorts(parsePortList("443,8443"))
	if got := read(sysctl); got != "443,8443,10001-10003" {
		t.Fatalf("after first sync: %s", got)
	}
	// The inbound on 8443 goes away; someone else adds 22 meanwhile.
	os.WriteFile(sysctl, []byte("22,443,8443,10001-10003\n"), 0o644)
	syncReservedPorts(parsePortList("443"))
	if got := read(sysctl); got != "22,443,10001-10003" {
		t.Fatalf("after removal: %s", got)
	}
	if got := read(filepath.Join(dir, "reserved-ports")); got != "443" {
		t.Fatalf("state file: %s", got)
	}
	// Someone else takes 443 off the list: the same set puts it back.
	os.WriteFile(sysctl, []byte("22,10001-10003\n"), 0o644)
	syncReservedPorts(parsePortList("443"))
	if got := read(sysctl); got != "22,443,10001-10003" {
		t.Fatalf("not restored: %s", got)
	}
	// 10002 was someone else's before the panel wanted it: it stays theirs.
	syncReservedPorts(parsePortList("443,10002"))
	syncReservedPorts(parsePortList("443"))
	if got := read(sysctl); got != "22,443,10001-10003" {
		t.Fatalf("someone else's port removed: %s", got)
	}
}
