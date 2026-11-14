package job

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/web/service"
	"github.com/mhsanaei/3x-ui/v2/xray"
	"github.com/op/go-logging"
)

// A template fetched from the remote URL with the core's new freedom setting
// "udpRouteEachDestination" is stored byte for byte, and the candidate the job
// hands to "xray -test" still carries it. The core is replaced by a script
// that keeps the candidate and accepts it, so no core binary is needed.
func TestFetchXrayConfigKeepsUDPRouteEachDestination(t *testing.T) {
	const template = `{
  "inbounds": [],
  "outbounds": [
    {"tag": "blocked", "protocol": "blackhole", "settings": {}},
    {"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "AsIs", "udpRouteEachDestination": true}}
  ],
  "routing": {"rules": [{"type": "field", "ip": ["8.8.8.8"], "port": "53", "outboundTag": "direct"}]}
}`
	logger.InitLogger(logging.ERROR)
	dir := t.TempDir()
	if err := database.InitDB(filepath.Join(dir, "x-ui.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.CloseDB() })

	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join(dir, "candidate.json")
	script := "#!/bin/sh\n[ \"$1\" = -test ] && [ \"$2\" = -c ] && cp \"$3\" '" + candidate + "'\n"
	if err := os.WriteFile(filepath.Join(bin, xray.GetBinaryName()), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XUI_BIN_FOLDER", bin)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(template))
	}))
	defer srv.Close()

	settings := service.SettingService{}
	if err := settings.SetXrayConfigUrl(srv.URL); err != nil {
		t.Fatal(err)
	}
	if err := settings.SetXrayConfigInterval(1); err != nil {
		t.Fatal(err)
	}

	NewFetchXrayConfigJob().Run()

	stored, err := (&service.XraySettingService{}).GetXrayConfigTemplate()
	if err != nil || stored != template {
		t.Fatalf("stored template differs (err %v):\n%s", err, stored)
	}
	raw, err := os.ReadFile(candidate)
	if err != nil {
		t.Fatalf("the core was not asked to test the candidate: %v", err)
	}
	var cfg struct {
		Outbounds []struct {
			Tag      string         `json:"tag"`
			Settings map[string]any `json:"settings"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ob := range cfg.Outbounds {
		if ob.Tag == "direct" {
			found = ob.Settings["udpRouteEachDestination"] == true
		}
	}
	if !found {
		t.Fatalf("candidate lost udpRouteEachDestination:\n%s", raw)
	}
}
