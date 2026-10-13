package service

import (
	"path/filepath"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
)

func TestCheckDialects(t *testing.T) {
	vless := func(extra string) *model.Inbound {
		return &model.Inbound{Protocol: model.VLESS, Settings: `{"clients":[],"decryption":"none"` + extra + `}`}
	}
	for _, extra := range []string{"", `,"dialects":null`, `,"dialects":[]`, `,"dialects":[0]`, `,"dialects":[4,5,255]`} {
		if err := checkDialects(vless(extra)); err != nil {
			t.Errorf("%s: %v", extra, err)
		}
	}
	for _, extra := range []string{`,"dialects":[256]`, `,"dialects":[-1]`, `,"dialects":[4.5]`, `,"dialects":"4"`, `,"dialects":4`, `,"dialects":{"a":1}`} {
		if err := checkDialects(vless(extra)); err == nil {
			t.Errorf("%s accepted", extra)
		}
	}
	if err := checkDialects(&model.Inbound{Protocol: model.VMESS, Settings: `{"dialects":[300]}`}); err != nil {
		t.Errorf("not VLESS: %v", err)
	}
}

// AddInbound refuses dialects the core would refuse, before saving.
func TestAddInboundRefusesBadDialects(t *testing.T) {
	if err := database.InitDB(filepath.Join(t.TempDir(), "x-ui.db")); err != nil {
		t.Fatal(err)
	}
	defer database.CloseDB()
	var is InboundService
	in := vlessInbound(t, "", 0)
	in.Settings = `{"clients":[{"id":"6b0e9c1c-2d6f-4c6e-9b8a-00000000d1a1","email":"dialect@test","enable":true,"flow":""}],"decryption":"none","dialects":[300]}`
	if _, _, err := is.AddInbound(in); err == nil {
		t.Fatal("dialects [300] saved")
	}
	if n, _ := is.GetAllInbounds(); len(n) != 0 {
		t.Fatalf("%d inbounds stored", len(n))
	}
}
