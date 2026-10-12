package service

import (
	"path/filepath"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
)

// An upgraded panel's inbounds have no instance yet: each gets its own, in
// creation order, and names already set are kept.
func TestUpgradeAssignsInstances(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x-ui.db")
	if err := database.InitDB(path); err != nil {
		t.Fatal(err)
	}
	db := database.GetDB()
	for i, inst := range []string{"", "xray-1", "", "edge", ""} {
		in := model.Inbound{Port: 20000 + i, Tag: "t" + string(rune('a'+i)), Protocol: model.VLESS}
		if err := db.Create(&in).Error; err != nil {
			t.Fatal(err)
		}
		db.Model(&model.Inbound{}).Where("id = ?", in.Id).Update("xray_instance", inst)
	}
	database.CloseDB()
	if err := database.InitDB(path); err != nil {
		t.Fatal(err)
	}
	defer database.CloseDB()
	var got []string
	database.GetDB().Model(&model.Inbound{}).Order("id").Pluck("xray_instance", &got)
	want := []string{"xray-2", "xray-1", "xray-3", "edge", "xray-4"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("instances: %v, want %v", got, want)
		}
	}
}
