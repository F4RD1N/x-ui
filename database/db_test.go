package database

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database/model"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func testDB(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XUI_DB_FOLDER", dir)
	p := filepath.Join(dir, "x-ui.db")
	if err := InitDB(p); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { CloseDB() })
	return p
}

// An inbound without an instance gets one no sub-inbound uses either.
func TestAssignXrayInstancesSkipsSubInboundInstances(t *testing.T) {
	testDB(t)
	a := &model.Inbound{Port: 443, Tag: "inbound-443", XrayInstance: "xray-1",
		SubInbounds: `[{"port":444,"instance":"xray-2","cores":2,"enable":true}]`}
	b := &model.Inbound{Port: 8443, Tag: "inbound-8443"}
	for _, in := range []*model.Inbound{a, b} {
		if err := db.Create(in).Error; err != nil {
			t.Fatal(err)
		}
	}
	db.Model(&model.Inbound{}).Where("id = ?", b.Id).Update("xray_instance", "")
	if err := assignXrayInstances(); err != nil {
		t.Fatal(err)
	}
	var got model.Inbound
	db.First(&got, b.Id)
	if got.XrayInstance == "xray-1" || got.XrayInstance == "xray-2" || got.XrayInstance == "" {
		t.Errorf("inbound without an instance got %q", got.XrayInstance)
	}
}

// Only a panel database passes: some other program's SQLite file does not.
func TestValidatePanelDB(t *testing.T) {
	panel := testDB(t)
	CloseDB()
	if err := ValidatePanelDB(panel); err != nil {
		t.Errorf("a panel database was refused: %v", err)
	}

	other := filepath.Join(t.TempDir(), "other.db")
	g, err := gorm.Open(sqlite.Open(other), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	g.Exec("create table notes(id integer primary key, body text)")
	sq, _ := g.DB()
	sq.Close()
	if err := ValidatePanelDB(other); err == nil || !strings.Contains(err.Error(), "not an x-ui database") {
		t.Errorf("another program's database: err=%v", err)
	}
}
