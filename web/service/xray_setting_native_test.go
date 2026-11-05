package service

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/util/native_client"
)

func TestNativeTemplateInvalidOutboundsDoNotPersist(t *testing.T) {
	openTestDB(t)
	s := new(XraySettingService)
	previous := `{"outbounds":[{"tag":"direct","protocol":"freedom"}]}`
	if err := s.SaveXraySetting(previous); err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []string{"orbit", "dnstt", "openvpn", "ov", "anytls", "shadowtls", "mieru", "dns"} {
		t.Run(protocol, func(t *testing.T) {
			settings := map[string]any{}
			if protocol == "dns" {
				settings["tunnel"] = map[string]any{}
			}
			candidate := nativeCopyJSON(t, map[string]any{"outbounds": []any{
				map[string]any{"protocol": "freedom", "tag": "direct"},
				map[string]any{"protocol": protocol, "tag": "native", "settings": settings},
			}})
			if err := s.SaveXraySetting(candidate); err == nil || !strings.Contains(err.Error(), "index 1") {
				t.Fatalf("invalid native settings accepted or unidentified: %v", err)
			}
			stored, err := s.getSetting("xrayTemplateConfig")
			if err != nil || stored.Value != previous {
				t.Fatal("invalid native outbound replaced working template", err)
			}
		})
	}
}

func TestNativeTemplateExportedOutboundsAndChainsPersistUnchanged(t *testing.T) {
	for _, protocol := range []string{"orbit", "dnstt", "openvpn", "anytls", "shadowtls", "mieru"} {
		t.Run(protocol, func(t *testing.T) {
			fixture := nativeCopySetup(t, protocol)
			var client model.Client
			if err := json.Unmarshal([]byte(nativeCopyJSON(t, fixture.selected)), &client); err != nil {
				t.Fatal(err)
			}
			outbounds, err := native_client.ClientOutbounds(fixture.inbound, client, "unused.example.test")
			if err != nil {
				t.Fatal("cannot export native fixture", err)
			}
			// Legacy handlers and unknown extension metadata stay untouched.
			outbounds = append(outbounds, map[string]any{"tag": "direct", "protocol": "freedom", "settings": map[string]any{"externalOption": true}})
			s := new(XraySettingService)
			variants := []string{"export"}
			if protocol == "openvpn" || protocol == "dnstt" {
				variants = append(variants, "alias")
			}
			for _, variant := range variants {
				if variant == "alias" {
					if protocol == "openvpn" {
						outbounds[0]["protocol"] = "ov"
					} else {
						outbounds[0]["protocol"] = "dnstt"
						outbounds[0]["settings"] = outbounds[0]["settings"].(map[string]any)["tunnel"]
					}
				}
				raw := nativeCopyJSON(t, map[string]any{"outbounds": outbounds, "routing": map[string]any{"domainStrategy": "AsIs", "rules": []any{}}})
				if err := s.SaveXraySetting(raw); err != nil {
					t.Fatalf("valid exported native %s rejected: %v", variant, err)
				}
				stored, err := s.getSetting("xrayTemplateConfig")
				if err != nil || stored.Value != raw {
					t.Fatal("native template or outbound chain rewritten", err)
				}
			}
		})
	}
}

func TestNativeTemplateValidationLeavesStockHandlersAlone(t *testing.T) {
	s := new(XraySettingService)
	for _, raw := range []string{
		xrayTemplateConfig, previousXrayTemplateConfig,
		`{"outbounds":[{"protocol":"dns","settings":{"address":"192.0.2.53","port":53,"network":"tcp"}}]}`,
		`{"outbounds":[{"protocol":"dns","settings":{}}]}`,
		`{"outbounds":[{"protocol":"external-custom","settings":{"opaque":true}}]}`,
		`{"outbounds":[{"protocol":"vless","settings":{}}]}`,
	} {
		if err := s.CheckXrayConfig(raw); err != nil {
			t.Fatalf("native validator changed stock/external handling: %v", err)
		}
	}
	for _, raw := range []string{
		`{"outbounds":[{"protocol":"dns","settings":{"tunnel":null}}]}`,
		`{"outbounds":[{"protocol":"anytls","settings":null}]}`,
		`{"outbounds":[{"protocol":"mieru","settings":{"address":"127.0.0.1","port":1234,"username":"user","password":"secret","transport":"tcp"},"streamSettings":{"network":"ws"}}]}`,
		`{"outbounds":[{"protocol":"mieru","settings":{"address":"127.0.0.1","port":1234,"username":"user","password":"secret","transport":"tcp"},"streamSettings":{"sockopt":{"dialerProxy":"a"}},"proxySettings":{"tag":"b"}}]}`,
	} {
		if err := s.CheckXrayConfig(raw); err == nil {
			t.Fatal("invalid native setting or conflicting chain accepted")
		}
	}
}

func TestNativeTemplateMalformedTransportDoesNotPanicOrPersist(t *testing.T) {
	openTestDB(t)
	s := new(XraySettingService)
	previous := `{"outbounds":[{"tag":"direct","protocol":"freedom"}]}`
	if err := s.SaveXraySetting(previous); err != nil {
		t.Fatal(err)
	}
	candidate := `{"outbounds":[{"protocol":"freedom","tag":"direct"},{"protocol":"mieru","tag":"native","settings":{"address":"127.0.0.1","port":1234,"username":"user","password":"PRIVATE-TRANSPORT-REGRESSION-SECRET","transport":"tcp"},"streamSettings":{"sockopt":{"customSockopt":[null]}}}]}`
	err := s.SaveXraySetting(candidate)
	if err == nil || !strings.Contains(err.Error(), "index 1") {
		t.Fatalf("malformed transport must return an indexed validation error: %v", err)
	}
	for _, sensitive := range []string{"PRIVATE-TRANSPORT-REGRESSION-SECRET", "runtime error", "nil pointer", candidate} {
		if strings.Contains(err.Error(), sensitive) {
			t.Fatal("validation error exposed configuration or panic data")
		}
	}
	stored, err := s.getSetting("xrayTemplateConfig")
	if err != nil || stored.Value != previous {
		t.Fatal("malformed transport replaced working template", err)
	}
	valid := `{"outbounds":[{"protocol":"mieru","tag":"native","settings":{"address":"127.0.0.1","port":1234,"username":"user","password":"synthetic-secret","transport":"tcp"}}]}`
	if err := s.SaveXraySetting(valid); err != nil {
		t.Fatal("recovered validation prevented subsequent valid save", err)
	}
}
