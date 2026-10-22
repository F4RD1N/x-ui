package service

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
)

func openTestDB(t *testing.T) {
	t.Helper()
	if err := database.InitDB(filepath.Join(t.TempDir(), "x-ui.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.CloseDB() })
}

// A panel that never saved a template stores the built-in default the first
// time it builds a config, so a later default does not change it.
func TestXrayTemplateStoredOnFirstUse(t *testing.T) {
	openTestDB(t)
	st := &SettingService{}
	got, err := st.GetXrayConfigTemplate()
	if err != nil || got != xrayTemplateConfig {
		t.Fatalf("first use: %v, default returned: %v", err, got == xrayTemplateConfig)
	}
	row, err := st.getSetting("xrayTemplateConfig")
	if err != nil || row.Value != xrayTemplateConfig {
		t.Fatalf("not stored: %v", err)
	}
	// Nothing to keep for an update now: it has one.
	if stored, err := st.KeepPreviousXrayTemplate(); err != nil || stored {
		t.Fatalf("keep after first use: stored=%v err=%v", stored, err)
	}
}

// A database with inbounds but no template comes from a panel that ran on
// the old built-in one (an update, a reinstall over it, "x-ui db="): it keeps
// that one, whichever way it got here.
func TestOldDatabaseKeepsOldTemplate(t *testing.T) {
	openTestDB(t)
	if err := database.GetDB().Create(&model.Inbound{Port: 443, Protocol: "vless", Tag: "inbound-443", Enable: true}).Error; err != nil {
		t.Fatal(err)
	}
	st := &SettingService{}
	got, err := st.GetXrayConfigTemplate()
	if err != nil || got != previousXrayTemplateConfig {
		t.Fatalf("an old database got the new default (err %v)", err)
	}
	if row, err := st.getSetting("xrayTemplateConfig"); err != nil || row.Value != previousXrayTemplateConfig {
		t.Fatalf("not stored: %v", err)
	}
}

// An update keeps the template of the versions before for a panel that
// never saved one, and leaves a saved one alone.
func TestKeepPreviousXrayTemplate(t *testing.T) {
	openTestDB(t)
	st := &SettingService{}
	if stored, err := st.KeepPreviousXrayTemplate(); err != nil || !stored {
		t.Fatalf("stored=%v err=%v", stored, err)
	}
	if got, _ := st.GetXrayConfigTemplate(); got != previousXrayTemplateConfig {
		t.Fatal("the previous default is not what the panel runs")
	}
	if err := st.saveSetting("xrayTemplateConfig", `{"outbounds":[{"protocol":"freedom"}]}`); err != nil {
		t.Fatal(err)
	}
	if stored, _ := st.KeepPreviousXrayTemplate(); stored {
		t.Fatal("a saved template was replaced")
	}
	if got, _ := st.GetXrayConfigTemplate(); got != `{"outbounds":[{"protocol":"freedom"}]}` {
		t.Fatalf("saved template changed: %s", got)
	}
}

// The default is the allow-list: blocked first (what nothing else matches
// goes nowhere), blocks before allows, and the direct outbound without a
// hand-written mark (the panel adds it where marks work).
func TestDefaultXrayTemplate(t *testing.T) {
	var tpl struct {
		Outbounds []struct {
			Tag            string         `json:"tag"`
			Protocol       string         `json:"protocol"`
			StreamSettings map[string]any `json:"streamSettings"`
		} `json:"outbounds"`
		Routing struct {
			Rules []map[string]any `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal([]byte(xrayTemplateConfig), &tpl); err != nil {
		t.Fatal(err)
	}
	if len(tpl.Outbounds) != 2 || tpl.Outbounds[0].Tag != "blocked" || tpl.Outbounds[1].Tag != "direct" {
		t.Fatalf("outbounds: %+v", tpl.Outbounds)
	}
	if tpl.Outbounds[1].StreamSettings != nil {
		t.Fatalf("direct carries stream settings: %v", tpl.Outbounds[1].StreamSettings)
	}
	tags := map[string]int{}
	firstAllow := -1
	for i, r := range tpl.Routing.Rules {
		if tag, _ := r["ruleTag"].(string); tag != "" {
			tags[tag] = i
		}
		if r["outboundTag"] == "direct" && firstAllow < 0 {
			firstAllow = i
		}
	}
	for _, block := range []string{"smtp-block", "guard-block", "speedtest-block", "ip-checkers"} {
		i, ok := tags[block]
		if !ok || i > firstAllow {
			t.Errorf("%s: at %d (first allow at %d, present %v)", block, i, firstAllow, ok)
		}
	}
	for _, allow := range []string{"games-ip", "apps-ip", "apps-ip-apple", "games-domain", "web-domain", "web-domain-medium"} {
		if _, ok := tags[allow]; !ok {
			t.Errorf("%s missing", allow)
		}
	}
	var prev map[string]any
	if err := json.Unmarshal([]byte(previousXrayTemplateConfig), &prev); err != nil {
		t.Fatal(err)
	}
}
