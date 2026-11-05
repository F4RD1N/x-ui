package service

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	panelxray "github.com/mhsanaei/3x-ui/v2/xray"
	coreconf "github.com/xtls/xray-core/infra/conf"
)

func TestAnyTLSStreamDefaultCurvesPreserveExplicitChoices(t *testing.T) {
	for _, mode := range []string{"absent", "null", "empty", "empty-scalar", "classical", "hybrid", "scalar", "invalid-scalar", "invalid-list", "invalid-shape"} {
		t.Run(mode, func(t *testing.T) {
			tls := map[string]any{"minVersion": "1.2", "maxVersion": "1.3", "alpn": []string{"h2"}, "certificates": []any{}, "unknownOption": "preserved"}
			switch mode {
			case "null":
				tls["curvePreferences"] = nil
			case "empty":
				tls["curvePreferences"] = []any{}
			case "empty-scalar":
				tls["curvePreferences"] = ""
			case "classical":
				tls["curvePreferences"] = []string{"CurveP384"}
			case "hybrid":
				tls["curvePreferences"] = []string{"X25519MLKEM768", "X25519"}
			case "scalar":
				tls["curvePreferences"] = "X25519"
			case "invalid-scalar":
				tls["curvePreferences"] = "invalid-curve"
			case "invalid-list":
				tls["curvePreferences"] = []string{""}
			case "invalid-shape":
				tls["curvePreferences"] = map[string]any{"invalid": true}
			}
			input := nativeCopyJSON(t, map[string]any{"network": "tcp", "security": "tls", "tlsSettings": tls, "sockopt": map[string]any{"tcpNoDelay": true}})
			got, err := coreInboundStreamSettings(model.AnyTLS, input)
			if err != nil {
				t.Fatal(err)
			}
			defaulted := mode == "absent" || mode == "null" || mode == "empty" || mode == "empty-scalar"
			if !defaulted {
				if got != input {
					t.Fatal("nonempty explicit TLS preference changed")
				}
				return
			}
			want := profileReviewMap(t, json.RawMessage(input))
			want["tlsSettings"].(map[string]any)["curvePreferences"] = nativeAnyTLSCompatibilityCurves()
			if got != nativeCopyJSON(t, want) {
				t.Fatal("projection changed other TLS or transport settings")
			}
			again, err := coreInboundStreamSettings(model.AnyTLS, got)
			if err != nil || again != got {
				t.Fatal("curve projection is not idempotent")
			}
		})
	}
	for _, protocol := range []model.Protocol{model.VLESS, model.VMESS, model.Trojan, model.Shadowsocks, model.Orbit, model.OpenVPN, model.ShadowTLS, model.Mieru, model.DNSTT} {
		for _, input := range []string{` {"security":"tls","tlsSettings":{"curvePreferences":[]}} `, ` {"security":"tls","tlsSettings":{"curvePreferences":""}} `} {
			if got, err := coreInboundStreamSettings(protocol, input); err != nil || got != input {
				t.Fatalf("changed another protocol's stream: %s", protocol)
			}
		}
	}
}

func TestAnyTLSProfilesGenerateCompatibleDefaultCurves(t *testing.T) {
	for _, name := range []string{"", "profile.example.test"} {
		profile, err := GenerateNativeInboundProfile(NativeCredentialRequest{Protocol: "anytls", ServerName: name})
		if err != nil {
			t.Fatal(err)
		}
		tls := profile.StreamSettings["tlsSettings"].(map[string]any)
		if !reflect.DeepEqual(tls["curvePreferences"], nativeAnyTLSCompatibilityCurves()) {
			t.Fatal("generated AnyTLS profile has incompatible implicit curves")
		}
		if tls["minVersion"] != "1.2" {
			t.Fatal("generated TLS minimum version changed")
		}
	}
}

func TestAnyTLSCurveProjectionCoversRuntimeAndRestoreWithoutDBMutation(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "x-ui.db")
	if err := database.InitDB(filename); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.CloseDB() })
	previous := p
	p = nil
	t.Cleanup(func() { p = previous })
	profile := profileTestGenerate(t, "anytls")
	var rows []model.Inbound
	wanted := make(map[string][]string)
	for index, mode := range []string{"absent", "null", "empty", "empty-scalar", "explicit-hybrid"} {
		stream := profileReviewMap(t, profile.StreamSettings)
		tls := stream["tlsSettings"].(map[string]any)
		curves := nativeAnyTLSCompatibilityCurves()
		switch mode {
		case "absent":
			delete(tls, "curvePreferences")
		case "null":
			tls["curvePreferences"] = nil
		case "empty":
			tls["curvePreferences"] = []any{}
		case "empty-scalar":
			tls["curvePreferences"] = ""
		case "explicit-hybrid":
			curves = []string{"X25519MLKEM768", "X25519"}
			tls["curvePreferences"] = curves
		}
		rows = append(rows, model.Inbound{Protocol: model.AnyTLS, Enable: true, Port: 35000 + index, Tag: mode, Settings: nativeCopyJSON(t, profile.Settings), StreamSettings: nativeCopyJSON(t, stream), Sniffing: `{}`})
		wanted[mode] = curves
	}
	if err := database.GetDB().Create(&rows).Error; err != nil {
		t.Fatal(err)
	}
	assertStream := func(tag, raw string) {
		t.Helper()
		var stream struct {
			TLS struct {
				Curves []string `json:"curvePreferences"`
			} `json:"tlsSettings"`
		}
		if err := json.Unmarshal([]byte(raw), &stream); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(stream.TLS.Curves, wanted[tag]) {
			t.Fatalf("wrong runtime curves for %s: %v", tag, stream.TLS.Curves)
		}
	}
	for _, row := range rows {
		runtime, err := (&InboundService{}).buildRuntimeInboundForAPI(database.GetDB(), &row)
		if err != nil {
			t.Fatal("live API projection failed", err)
		}
		assertStream(row.Tag, runtime.StreamSettings)
		if err := validateNativeInboundSettings(&row); err != nil {
			t.Fatal("projected native inbound validation failed", err)
		}
	}
	running, err := (&XrayService{}).GetXrayConfigFor(`{"outbounds":[{"protocol":"freedom","tag":"direct"}]}`)
	if err != nil {
		t.Fatal("running config projection failed", err)
	}
	restored, err := portableCandidateConfig(filename)
	if err != nil {
		t.Fatal("restore candidate projection failed", err)
	}
	for _, cfg := range []*panelxray.Config{running, restored} {
		matched := 0
		for _, inbound := range cfg.InboundConfigs {
			if _, exists := wanted[inbound.Tag]; !exists {
				continue // The restored template may also contain its panel API inbound.
			}
			matched++
			assertStream(inbound.Tag, string(inbound.StreamSettings))
			var candidate coreconf.InboundDetourConfig
			if err := json.Unmarshal([]byte(nativeCopyJSON(t, inbound)), &candidate); err != nil {
				t.Fatal(err)
			}
			if _, err := candidate.Build(); err != nil {
				t.Fatal("projected inbound does not build", err)
			}
		}
		if matched != len(rows) {
			t.Fatalf("projection lost native inbounds: got %d, want %d", matched, len(rows))
		}
	}
	for _, row := range rows {
		var stored model.Inbound
		if err := database.GetDB().First(&stored, row.Id).Error; err != nil {
			t.Fatal(err)
		}
		if stored.StreamSettings != row.StreamSettings || stored.Settings != row.Settings {
			t.Fatal("runtime projection rewrote stored inbound")
		}
	}
}
