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
	// Someone else reserved 10001-10003; the panel had 443 and 8443 and now
	// has 443 and 31000-31002.
	got := mergeReserved("443,8443,10001-10003", "443,8443", parsePortList("443,31000-31002"))
	if got != "443,10001-10003,31000-31002" {
		t.Fatalf("merge: %s", got)
	}
	// On the first sync the panel has no record yet: ports already reserved
	// stay.
	if got := mergeReserved("22,443", "", parsePortList("443")); got != "22,443" {
		t.Fatalf("first sync: %s", got)
	}
}

func TestSyncReservedPorts(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XUI_DB_FOLDER", dir)
	sysctl := filepath.Join(dir, "ip_local_reserved_ports")
	os.WriteFile(sysctl, []byte("10001-10003\n"), 0o644)
	old := reservedPortsPath
	reservedPortsPath = sysctl
	reservedLast = ""
	defer func() { reservedPortsPath = old; reservedLast = "" }()

	syncReservedPorts(parsePortList("443,8443"))
	if b, _ := os.ReadFile(sysctl); strings.TrimSpace(string(b)) != "443,8443,10001-10003" {
		t.Fatalf("after first sync: %s", b)
	}
	// The inbound on 8443 goes away; someone else adds 22 meanwhile.
	os.WriteFile(sysctl, []byte("22,443,8443,10001-10003\n"), 0o644)
	syncReservedPorts(parsePortList("443"))
	if b, _ := os.ReadFile(sysctl); strings.TrimSpace(string(b)) != "22,443,10001-10003" {
		t.Fatalf("after removal: %s", b)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "reserved-ports")); strings.TrimSpace(string(b)) != "443" {
		t.Fatalf("state file: %s", b)
	}
}
