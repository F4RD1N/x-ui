package service

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/util/json_util"
	"gorm.io/gorm"
)

// udpRouteTemplate is an allow-list template in the shape the owner runs:
// "blocked" first, no catch-all, a freedom "direct" that has the core's
// udpRouteEachDestination switched on, and one that has it off.
const udpRouteTemplate = `{
  "log": {"loglevel": "warning"},
  "inbounds": [],
  "outbounds": [
    {"tag": "blocked", "protocol": "blackhole", "settings": {}},
    {"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "AsIs", "redirect": "", "noises": [], "udpRouteEachDestination": true}},
    {"tag": "direct-off", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4", "udpRouteEachDestination": false}},
    {"tag": "plain", "protocol": "freedom", "settings": {}}
  ],
  "routing": {"domainStrategy": "AsIs", "rules": [
    {"type": "field", "ip": ["8.8.8.8"], "port": "53", "outboundTag": "direct"},
    {"type": "field", "port": "3478", "network": "udp", "outboundTag": "direct"}
  ]}
}`

// freedomUDPRoute returns, per freedom outbound tag, what its settings say
// about udpRouteEachDestination: "true", "false", or "" when the key is not
// there at all. It also fails the test if any other freedom setting changed.
func freedomUDPRoute(t *testing.T, raw []byte) map[string]string {
	t.Helper()
	var obs []map[string]any
	if err := json.Unmarshal(raw, &obs); err != nil {
		t.Fatalf("outbounds do not parse: %v\n%s", err, raw)
	}
	got := map[string]string{}
	for _, ob := range obs {
		if ob["protocol"] != "freedom" {
			continue
		}
		tag, _ := ob["tag"].(string)
		st, _ := ob["settings"].(map[string]any)
		switch v, ok := st["udpRouteEachDestination"]; {
		case !ok:
			got[tag] = ""
		case v == true:
			got[tag] = "true"
		case v == false:
			got[tag] = "false"
		default:
			t.Fatalf("%s: udpRouteEachDestination became %#v", tag, v)
		}
		switch tag {
		case "direct":
			if st["domainStrategy"] != "AsIs" || st["redirect"] != "" || st["noises"] == nil {
				t.Errorf("direct: other freedom settings changed: %v", st)
			}
		case "direct-off":
			if st["domainStrategy"] != "UseIPv4" {
				t.Errorf("direct-off: other freedom settings changed: %v", st)
			}
		}
	}
	return got
}

func templateOutbounds(t *testing.T, template string) json_util.RawMessage {
	t.Helper()
	var cfg struct {
		Outbounds json_util.RawMessage `json:"outbounds"`
	}
	if err := json.Unmarshal([]byte(template), &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg.Outbounds
}

func wantUDPRoute(t *testing.T, where string, raw []byte) {
	t.Helper()
	got := freedomUDPRoute(t, raw)
	want := map[string]string{"direct": "true", "direct-off": "false", "plain": ""}
	for tag, w := range want {
		if got[tag] != w {
			t.Errorf("%s: %s udpRouteEachDestination = %q, want %q (all: %v)", where, tag, got[tag], w, got)
		}
	}
}

// The direct mark rewrites every freedom outbound; it must leave the new
// setting as it is, with marks allowed and without.
func TestUDPRouteEachDestinationKeptByDirectMark(t *testing.T) {
	for _, mark := range []bool{true, false} {
		stubMarkProbe(t, mark)
		out := withDirectMark(templateOutbounds(t, udpRouteTemplate))
		wantUDPRoute(t, "withDirectMark", out)
		if mark && !strings.Contains(string(out), `"mark":4242`) {
			t.Errorf("the direct mark was not added: %s", out)
		}
	}
}

// The IP pools rewrite the outbounds that have a pool; the setting stays.
func TestUDPRouteEachDestinationKeptByIPPools(t *testing.T) {
	fakeHost(t, []string{"10.0.0.1"}, "10.0.0.5/29", "10.0.0.6/29")
	out := withIPPools(templateOutbounds(t, udpRouteTemplate), map[string]string{"direct": "10.0.0.0/29", "direct-off": "10.0.0.0/29"})
	wantUDPRoute(t, "withIPPools", out)
	if !strings.Contains(string(out), `"sendThrough":"10.0.0.5,10.0.0.6"`) {
		t.Errorf("the pool was not applied: %s", out)
	}
}

// Saving the template (the xray settings page and the remote-config fetch
// both go through SaveXraySetting) stores it byte for byte, and the checks
// in front of it accept it.
func TestUDPRouteEachDestinationTemplateSavedAsIs(t *testing.T) {
	openTestDB(t)
	s := new(XraySettingService)
	if err := s.CheckXrayTemplateUsable(udpRouteTemplate); err != nil {
		t.Fatalf("CheckXrayTemplateUsable: %v", err)
	}
	if err := s.CheckXrayConfig(udpRouteTemplate); err != nil {
		t.Fatalf("CheckXrayConfig: %v", err)
	}
	if err := s.SaveXraySetting(udpRouteTemplate); err != nil {
		t.Fatal(err)
	}
	stored, err := s.GetXrayConfigTemplate()
	if err != nil || stored != udpRouteTemplate {
		t.Fatalf("stored template differs (err %v):\n%s", err, stored)
	}
}

// The config the core is started with (and that the fetch job hands to
// "xray -test") carries the setting, with the mark and an IP pool applied.
func TestUDPRouteEachDestinationInBuiltConfig(t *testing.T) {
	openTestDB(t)
	stubMarkProbe(t, true)
	fakeHost(t, []string{"10.0.0.1"}, "10.0.0.5/29")
	if err := (&SettingService{}).SetOutboundIPPools(`{"direct":"10.0.0.0/29"}`); err != nil {
		t.Fatal(err)
	}
	cfg, err := (&XrayService{}).GetXrayConfigFor(udpRouteTemplate)
	if err != nil {
		t.Fatal(err)
	}
	wantUDPRoute(t, "GetXrayConfigFor", cfg.OutboundConfigs)
	// Serialised the way the fetch job and the process writer do it.
	full, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	var back struct {
		Outbounds json.RawMessage `json:"outbounds"`
	}
	if err := json.Unmarshal(full, &back); err != nil {
		t.Fatal(err)
	}
	wantUDPRoute(t, "config.json", back.Outbounds)
	var compact bytes.Buffer
	if err := json.Compact(&compact, back.Outbounds); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(compact.String(), `"sendThrough":"10.0.0.5"`) || !strings.Contains(compact.String(), `"mark":4242`) {
		t.Errorf("pool or mark missing: %s", compact.String())
	}
}

// A portable backup's template goes through the same rewrite on restore.
func TestUDPRouteEachDestinationKeptByPortableRestore(t *testing.T) {
	stubMarkProbe(t, true)
	filename := portableFixtureDB(t)
	if err := withBackupDB(filename, false, func(db *gorm.DB) error {
		return db.Model(&model.Setting{}).Where("key = ?", "xrayTemplateConfig").Update("value", udpRouteTemplate).Error
	}); err != nil {
		t.Fatal(err)
	}
	cfg, err := portableCandidateConfig(filename)
	if err != nil {
		t.Fatal(err)
	}
	wantUDPRoute(t, "portableCandidateConfig", cfg.OutboundConfigs)
}

// "Test outbound" copies the outbounds into its own config; the outbound
// under test and the others keep the setting.
func TestUDPRouteEachDestinationKeptByOutboundTest(t *testing.T) {
	var all []any
	if err := json.Unmarshal(templateOutbounds(t, udpRouteTemplate), &all); err != nil {
		t.Fatal(err)
	}
	selected := map[string]any{"tag": "direct", "protocol": "freedom", "settings": map[string]any{"domainStrategy": "AsIs", "redirect": "", "noises": []any{}, "udpRouteEachDestination": true}}
	tag, obs, err := prepareOutboundTest(selected, all)
	if err != nil || tag != "direct" {
		t.Fatalf("tag %q err %v", tag, err)
	}
	cfg := (&OutboundService{}).createTestConfig(tag, obs, 10808)
	wantUDPRoute(t, "createTestConfig", cfg.OutboundConfigs)
}

// A template without the key is not given one anywhere: upstream behaviour
// stays the default and existing templates are not rewritten.
func TestUDPRouteEachDestinationNotAddedWhenAbsent(t *testing.T) {
	stubMarkProbe(t, false)
	raw := json_util.RawMessage(`[{"tag":"direct","protocol":"freedom","settings":{"domainStrategy":"AsIs"}},{"tag":"blocked","protocol":"blackhole"}]`)
	if out := withDirectMark(raw); !bytes.Equal(out, raw) {
		t.Errorf("withDirectMark rewrote a template without the setting: %s", out)
	}
	stubMarkProbe(t, true)
	if out := withDirectMark(raw); strings.Contains(string(out), "udpRouteEachDestination") {
		t.Errorf("withDirectMark added the setting: %s", out)
	}
}
