package service

import (
	"path/filepath"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/util/tune"
)

// The panel's web port, and the subscription port while that server is on,
// are reserved along with the inbound ports.
func TestAddPanelPorts(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XUI_DB_FOLDER", dir)
	if err := database.InitDB(filepath.Join(dir, "x-ui.db")); err != nil {
		t.Fatal(err)
	}
	defer database.CloseDB()
	s := &XrayService{}
	if err := s.settingService.SetPort(60000); err != nil {
		t.Fatal(err)
	}
	s.settingService.saveSetting("subPort", "2096")
	s.settingService.saveSetting("subEnable", "false")
	got := map[int]bool{443: true}
	s.addPanelPorts(got)
	if !got[443] || !got[60000] || got[2096] {
		t.Fatalf("sub off: %v", got)
	}
	s.settingService.saveSetting("subEnable", "true")
	s.addPanelPorts(got)
	if !got[2096] {
		t.Fatalf("sub on: %v", got)
	}
}

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
