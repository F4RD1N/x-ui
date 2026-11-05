package service

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/xtls/xray-core/app/proxyman/command"
)

func sharedShadowTLSFixture(t *testing.T, method string) map[string]any {
	t.Helper()
	stored, _, _ := profileReviewShadowFixture(t)
	password := "shared-test-secret"
	if method == "2022-blake3-aes-256-gcm" {
		password = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{43}, 32))
	}
	stored["inner"] = map[string]any{"protocol": "shadowsocks", "settings": map[string]any{
		"method": method, "password": password, "network": "tcp",
	}}
	return stored
}

func TestShadowTLSSharedInnerOuterClientLifecycle(t *testing.T) {
	for _, method := range []string{"aes-128-gcm", "chacha20-poly1305", "2022-blake3-aes-256-gcm"} {
		t.Run(method, func(t *testing.T) {
			openTestDB(t)
			previous := p
			p = nil // No runtime core or socket is used by this persistence test.
			t.Cleanup(func() { p = previous })
			stored := sharedShadowTLSFixture(t, method)
			shared := profileReviewJSON(t, stored["inner"])
			in := &model.Inbound{Protocol: model.ShadowTLS, Port: 34483, Tag: "shared-shadowtls", Enable: true, Settings: profileReviewJSON(t, stored), StreamSettings: `{}`, Sniffing: `{}`}
			if err := database.GetDB().Create(in).Error; err != nil {
				t.Fatal(err)
			}
			s := new(InboundService)
			handler := new(nativeServiceHandler)
			var api command.HandlerServiceClient = handler
			s.xrayApi.HandlerServiceClient = &api
			added := map[string]any{"email": "added-shared@example.test", "password": "outer-only-test-password", "enable": true}
			if _, err := s.AddInboundClient(&model.Inbound{Id: in.Id, Settings: profileReviewJSON(t, map[string]any{"clients": []any{added}})}); err != nil {
				t.Fatalf("shared inner outer append rejected: %v", err)
			}
			got, err := s.GetInbound(in.Id)
			if err != nil {
				t.Fatal(err)
			}
			settings := profileReviewMap(t, json.RawMessage(got.Settings))
			if profileReviewJSON(t, settings["inner"]) != shared || len(settings["clients"].([]any)) != 2 {
				t.Fatal("outer append changed shared material or lost accounts")
			}
			clients, err := s.GetClients(got)
			if err != nil || len(clients) != 2 {
				t.Fatal("cannot read appended account", err)
			}
			id := inboundClientID(model.ShadowTLS, clients[1])
			clients[1].Email = "renamed-shared@example.test"
			s.xrayApi.HandlerServiceClient = &api
			if _, err := s.UpdateInboundClient(&model.Inbound{Id: in.Id, Settings: profileReviewJSON(t, map[string]any{"clients": []any{clients[1]}})}, id); err != nil {
				t.Fatalf("shared inner outer rename rejected: %v", err)
			}
			renamed, err := s.GetInbound(in.Id)
			if err != nil {
				t.Fatal(err)
			}
			settings = profileReviewMap(t, json.RawMessage(renamed.Settings))
			if profileReviewJSON(t, settings["inner"]) != shared || settings["clients"].([]any)[1].(map[string]any)["email"] != clients[1].Email {
				t.Fatal("outer rename changed shared material or lost new identity")
			}
			if err := validateNativeInboundSettings(renamed); err != nil {
				t.Fatal("saved shared profile no longer builds", err)
			}
		})
	}
}

func TestShadowTLSSharedInnerCannotReplaceListenerMaterial(t *testing.T) {
	for _, mode := range []string{"omitted", "exact-echo", "changed-key", "changed-network", "null", "managed-append"} {
		t.Run(mode, func(t *testing.T) {
			stored := sharedShadowTLSFixture(t, "2022-blake3-aes-256-gcm")
			before := profileReviewJSON(t, stored)
			added := []any{map[string]any{"email": "new", "password": "new-outer"}}
			request := map[string]any{"clients": added}
			if mode != "omitted" {
				inner := profileReviewMap(t, stored["inner"])
				settings := inner["settings"].(map[string]any)
				request["inner"] = inner
				switch mode {
				case "changed-key":
					settings["password"] = "replacement"
				case "changed-network":
					settings["network"] = "udp"
				case "null":
					request["inner"] = nil
				case "managed-append":
					settings["clients"] = []any{map[string]any{"email": "new", "password": "new-inner"}}
				}
			}
			changed, err := appendNativeInnerClients(model.ShadowTLS, stored, request, added)
			wantError := mode != "omitted" && mode != "exact-echo"
			if (err != nil) != wantError || changed || profileReviewJSON(t, stored) != before {
				t.Fatalf("wrong result or shared mutation: changed=%v err=%v", changed, err)
			}
		})
	}
}

func TestShadowTLSSharedInnerRequiresV3AndUnmanagedList(t *testing.T) {
	for _, mode := range []string{"default", "zero", "v3", "v1", "v2", "v4", "invalid-version", "empty-list", "null-list", "wrong-list-type"} {
		t.Run(mode, func(t *testing.T) {
			stored := sharedShadowTLSFixture(t, "2022-blake3-aes-256-gcm")
			settings := stored["inner"].(map[string]any)["settings"].(map[string]any)
			switch mode {
			case "default":
				delete(stored, "version")
			case "zero":
				stored["version"] = 0
			case "v1":
				stored["version"] = 1
			case "v2":
				stored["version"] = 2
			case "v4":
				stored["version"] = 4
			case "invalid-version":
				stored["version"] = "3"
			case "empty-list":
				settings["clients"] = []any{}
			case "null-list":
				settings["clients"] = nil
			case "wrong-list-type":
				settings["clients"] = map[string]any{}
			}
			before := profileReviewJSON(t, stored)
			wantError := mode != "default" && mode != "zero" && mode != "v3"
			added := []any{map[string]any{"email": "new", "password": "outer-only"}}
			changed, err := appendNativeInnerClients(model.ShadowTLS, stored, map[string]any{"clients": added}, added)
			if (err != nil) != wantError || changed || profileReviewJSON(t, stored) != before {
				t.Fatalf("append confused shared and managed authorization: changed=%v err=%v", changed, err)
			}
			changed, err = renameNativeInnerClient(model.ShadowTLS, stored, "old", "new")
			if (err != nil) != wantError || changed || profileReviewJSON(t, stored) != before {
				t.Fatalf("rename confused shared and managed authorization: changed=%v err=%v", changed, err)
			}
		})
	}
}

func TestShadowTLSLegacySharedInnerEmptyList(t *testing.T) {
	for _, mode := range []string{"absent", "null", "empty", "managed", "invalid"} {
		t.Run(mode, func(t *testing.T) {
			stored := sharedShadowTLSFixture(t, "aes-128-gcm")
			settings := stored["inner"].(map[string]any)["settings"].(map[string]any)
			switch mode {
			case "null":
				settings["clients"] = nil
			case "empty":
				settings["clients"] = []any{}
			case "managed":
				settings["clients"] = []any{map[string]any{"email": "bound", "password": "bound-secret", "method": "aes-128-gcm"}}
			case "invalid":
				settings["clients"] = map[string]any{}
			}
			before := profileReviewJSON(t, stored)
			added := []any{map[string]any{"email": "new", "password": "outer-only"}}
			wantError := mode == "managed" || mode == "invalid"
			changed, err := appendNativeInnerClients(model.ShadowTLS, stored, map[string]any{"clients": added}, added)
			if (err != nil) != wantError || changed || profileReviewJSON(t, stored) != before {
				t.Fatalf("legacy append confused shared and managed auth: changed=%v err=%v", changed, err)
			}
			changed, err = renameNativeInnerClient(model.ShadowTLS, stored, "old", "new")
			if (err != nil) != wantError || changed || profileReviewJSON(t, stored) != before {
				t.Fatalf("legacy rename confused shared and managed auth: changed=%v err=%v", changed, err)
			}
			if !wantError {
				in := &model.Inbound{Protocol: model.ShadowTLS, Port: 34483, Tag: "shared-shadowtls", Enable: true, Settings: profileReviewJSON(t, stored), StreamSettings: `{}`, Sniffing: `{}`}
				if err := validateNativeInboundSettings(in); err != nil {
					t.Fatal("legacy shared config rejected by core builder", err)
				}
			}
		})
	}
}
