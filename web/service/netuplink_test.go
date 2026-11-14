package service

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/shirou/gopsutil/v4/net"
)

func TestUplinkTraffic(t *testing.T) {
	dir := t.TempDir()
	v4 := filepath.Join(dir, "route")
	v6 := filepath.Join(dir, "ipv6_route")
	os.WriteFile(v4, []byte("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"+
		"bond0\t00000000\t01824C67\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"+
		"bond0\t00824C67\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"+
		"greI3\t08E6000A\t00000000\t0001\t0\t0\t0\tFCFFFFFF\t0\t0\t0\n"), 0o644)
	os.WriteFile(v6, []byte(
		"00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n"+
		"fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001    bond0\n"), 0o644)
	old4, old6 := ipv4RouteFile, ipv6RouteFile
	ipv4RouteFile, ipv6RouteFile = v4, v6
	defer func() { ipv4RouteFile, ipv6RouteFile = old4, old6 }()

	up := defaultRouteInterfaces()
	if len(up) != 1 || !up["bond0"] {
		t.Fatalf("uplinks = %v, want only bond0", up)
	}
	stats := []net.IOCountersStat{
		{Name: "lo", BytesSent: 5, BytesRecv: 5},
		{Name: "eno1", BytesSent: 100, BytesRecv: 110},
		{Name: "eno2", BytesSent: 200, BytesRecv: 190},
		{Name: "bond0", BytesSent: 300, BytesRecv: 300},
		{Name: "greI3", BytesSent: 40, BytesRecv: 60},
	}
	if s, r := uplinkTraffic(stats, up); s != 300 || r != 300 {
		t.Errorf("bonded server: got sent %d recv %d, want 300 300 (bond0 only)", s, r)
	}
	if s, r := uplinkTraffic(stats, map[string]bool{}); s != 640 || r != 660 {
		t.Errorf("no default route: got sent %d recv %d, want every interface but lo", s, r)
	}
	if s, r := uplinkTraffic(stats, map[string]bool{"eno1": true, "eno2": true}); s != 300 || r != 300 {
		t.Errorf("two uplinks: got sent %d recv %d, want their sum", s, r)
	}
}
