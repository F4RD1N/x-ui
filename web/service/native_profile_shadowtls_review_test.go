package service

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/xtls/xray-core/app/proxyman/command"
	coreconf "github.com/xtls/xray-core/infra/conf"
	"gorm.io/gorm"
)

func profileReviewJSON(t *testing.T, value any) string {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func profileReviewMap(t *testing.T, value any) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal([]byte(profileReviewJSON(t, value)), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func profileReviewShadowFixture(t *testing.T) (map[string]any, map[string]any, []any) {
	t.Helper()
	profile, err := GenerateNativeInboundProfile(NativeCredentialRequest{Protocol: "shadowtls", Email: "first@example.test", HandshakeAddress: "cover.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	outer := map[string]any{"email": "second@example.test", "password": "11223344-5566-7788-99aa-bbccddeeff00", "enable": true, "subId": "second-sub"}
	inner := map[string]any{"email": outer["email"], "password": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{71}, 32))}
	added := []any{outer}
	request := map[string]any{"clients": added, "inner": map[string]any{"protocol": "shadowsocks", "settings": map[string]any{"clients": []any{inner}}}}
	return profileReviewMap(t, profile.Settings), request, added
}

func TestNativeProfileReviewShadowTLSAddClientPersistsBoundInner(t *testing.T) {
	openTestDB(t)
	prior := p
	p = nil
	t.Cleanup(func() { p = prior })
	stored, request, _ := profileReviewShadowFixture(t)
	before := profileReviewMap(t, stored)
	in := &model.Inbound{Protocol: model.ShadowTLS, Port: 34481, Tag: "review-shadowtls", Enable: true, Settings: profileReviewJSON(t, stored), StreamSettings: `{}`, Sniffing: `{}`}
	if err := database.GetDB().Create(in).Error; err != nil {
		t.Fatal(err)
	}
	s := new(InboundService)
	handler := new(nativeServiceHandler)
	var api command.HandlerServiceClient = handler
	s.xrayApi.HandlerServiceClient = &api
	restart, err := s.AddInboundClient(&model.Inbound{Id: in.Id, Settings: profileReviewJSON(t, request)})
	if err != nil || !restart || handler.calls != 0 {
		t.Fatalf("add must persist and reload inner without an outer-only API update: restart=%v calls=%d err=%v", restart, handler.calls, err)
	}
	got, err := s.GetInbound(in.Id)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err := json.Unmarshal([]byte(got.Settings), &settings); err != nil {
		t.Fatal(err)
	}
	oldInner := before["inner"].(map[string]any)["settings"].(map[string]any)
	inner := settings["inner"].(map[string]any)["settings"].(map[string]any)
	rows := inner["clients"].([]any)
	if len(rows) != 2 || profileReviewJSON(t, rows[0]) != profileReviewJSON(t, oldInner["clients"].([]any)[0]) || rows[1].(map[string]any)["email"] != "second@example.test" {
		t.Fatal("new client lost mapping or changed existing inner account")
	}
	for _, field := range []string{"method", "password", "network"} {
		if inner[field] != oldInner[field] {
			t.Fatalf("changed shared inner setting %s", field)
		}
	}
	if profileReviewJSON(t, settings["clients"].([]any)[0]) != profileReviewJSON(t, before["clients"].([]any)[0]) {
		t.Fatal("changed existing outer account")
	}
	if err := validateNativeInboundSettings(got); err != nil {
		t.Fatal("merged profile does not build", err)
	}

	// Rejected supplemental material must not partially persist the outer row.
	bad := profileReviewMap(t, request)
	bad["clients"].([]any)[0].(map[string]any)["email"] = "rejected@example.test"
	bad["inner"].(map[string]any)["settings"].(map[string]any)["password"] = "replace-server-key"
	if _, err := s.AddInboundClient(&model.Inbound{Id: in.Id, Settings: profileReviewJSON(t, bad)}); err == nil {
		t.Fatal("server-key overwrite accepted")
	}
	after, err := s.GetInbound(in.Id)
	if err != nil || after.Settings != got.Settings {
		t.Fatal("failed append changed persisted credentials")
	}
	// Rename and disable the new outer client: the paired inner key must stay
	// stored but neither identity may remain in the projected runtime.
	clients, err := s.GetClients(got)
	if err != nil || len(clients) != 2 {
		t.Fatal("cannot read appended clients")
	}
	oldID := inboundClientID(model.ShadowTLS, clients[1])
	clients[1].Email, clients[1].Enable = "renamed-disabled@example.test", false
	if restart, err := s.UpdateInboundClient(&model.Inbound{Id: in.Id, Settings: profileReviewJSON(t, map[string]any{"clients": []any{clients[1]}})}, oldID); err != nil || !restart {
		t.Fatalf("rename/disable did not reload paired identity: %v %v", restart, err)
	}
	renamed, err := s.GetInbound(in.Id)
	if err != nil {
		t.Fatal(err)
	}
	var renamedSettings map[string]any
	if err := json.Unmarshal([]byte(renamed.Settings), &renamedSettings); err != nil {
		t.Fatal(err)
	}
	renamedRows := renamedSettings["inner"].(map[string]any)["settings"].(map[string]any)["clients"].([]any)
	if renamedRows[1].(map[string]any)["email"] != clients[1].Email || renamedRows[1].(map[string]any)["password"] != rows[1].(map[string]any)["password"] || profileReviewJSON(t, renamedRows[0]) != profileReviewJSON(t, rows[0]) {
		t.Fatal("rename changed credential or unrelated inner row")
	}
	// Runtime generation loads traffic/account state alongside inbounds.
	if err := database.GetDB().Preload("ClientStats").First(renamed, in.Id).Error; err != nil {
		t.Fatal(err)
	}
	projected, err := coreInboundSettings(renamed)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains([]byte(projected), []byte(clients[1].Email)) || bytes.Contains([]byte(projected), []byte(rows[1].(map[string]any)["password"].(string))) {
		t.Fatal("inactive renamed account remained in the runtime projection")
	}
	// An orphan target identity can exist in saved advanced settings; it must
	// not be overwritten when another outer account is renamed to that email.
	renamedSettings["inner"].(map[string]any)["settings"].(map[string]any)["clients"] = append(renamedRows, map[string]any{"email": "reserved-inner@example.test", "password": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{93}, 32))})
	renamed.Settings = profileReviewJSON(t, renamedSettings)
	if err := database.GetDB().Save(renamed).Error; err != nil {
		t.Fatal(err)
	}
	firstClients, _ := s.GetClients(renamed)
	firstID := inboundClientID(model.ShadowTLS, firstClients[0])
	firstClients[0].Email = "reserved-inner@example.test"
	if _, err := s.UpdateInboundClient(&model.Inbound{Id: in.Id, Settings: profileReviewJSON(t, map[string]any{"clients": []any{firstClients[0]}})}, firstID); err == nil {
		t.Fatal("rename to existing identity accepted")
	}
	unchanged, _ := s.GetInbound(in.Id)
	if unchanged.Settings != renamed.Settings {
		t.Fatal("rejected rename changed stored identities")
	}
}

func TestNativeProfileReviewShadowTLSRenameBindingValidation(t *testing.T) {
	for _, mode := range []string{"success", "missing-source", "ambiguous-source", "target-collision", "socks", "legacy-inactive", "non-shadowtls"} {
		t.Run(mode, func(t *testing.T) {
			stored, _, _ := profileReviewShadowFixture(t)
			protocol := model.ShadowTLS
			inner := stored["inner"].(map[string]any)
			settings := inner["settings"].(map[string]any)
			rows := settings["clients"].([]any)
			old, next := "first@example.test", "renamed@example.test"
			switch mode {
			case "missing-source":
				old = "missing@example.test"
			case "ambiguous-source":
				settings["clients"] = append(rows, profileReviewMap(t, rows[0]))
			case "target-collision":
				duplicate := profileReviewMap(t, rows[0])
				duplicate["email"] = next
				settings["clients"] = append(rows, duplicate)
			case "socks":
				inner["protocol"] = "socks"
				inner["settings"] = map[string]any{"accounts": []any{map[string]any{"user": "explicit-username", "pass": "unchanged"}}}
			case "legacy-inactive":
				delete(stored, "inner")
			case "non-shadowtls":
				protocol = model.VLESS
			}
			before := profileReviewJSON(t, stored)
			changed, err := renameNativeInnerClient(protocol, stored, old, next)
			if mode == "success" {
				if err != nil || !changed {
					t.Fatalf("rename rejected: %v", err)
				}
				got := settings["clients"].([]any)[0].(map[string]any)
				if got["email"] != next || got["password"] != rows[0].(map[string]any)["password"] {
					t.Fatal("rename changed key or failed email binding")
				}
			} else {
				rejected := mode == "missing-source" || mode == "ambiguous-source" || mode == "target-collision"
				if (err != nil) != rejected || changed || profileReviewJSON(t, stored) != before {
					t.Fatal("rename guard changed unrelated settings or wrong error result")
				}
			}
		})
	}
}

func TestNativeProfileReviewShadowTLSRejectsForgedAppend(t *testing.T) {
	for _, name := range []string{"missing", "unrelated", "duplicate", "existing", "reused-key", "server-password", "network", "protocol", "extra-inner", "relay", "unknown-outer-setting", "null-row", "null-inner", "empty-list"} {
		t.Run(name, func(t *testing.T) {
			stored, request, added := profileReviewShadowFixture(t)
			before := profileReviewJSON(t, stored)
			extra := request["inner"].(map[string]any)
			settings := extra["settings"].(map[string]any)
			rows := settings["clients"].([]any)
			row := rows[0].(map[string]any)
			switch name {
			case "missing":
				delete(request, "inner")
			case "unrelated":
				row["email"] = "unrelated@example.test"
			case "duplicate":
				settings["clients"] = append(rows, row)
			case "existing":
				row["email"] = "first@example.test"
				added[0].(map[string]any)["email"] = "first@example.test"
			case "reused-key":
				row["password"] = stored["inner"].(map[string]any)["settings"].(map[string]any)["clients"].([]any)[0].(map[string]any)["password"]
			case "server-password":
				settings["password"] = "overwrite"
			case "network":
				settings["network"] = "udp"
			case "protocol":
				extra["protocol"] = "vless"
			case "extra-inner":
				extra["server"] = "overwrite"
			case "relay":
				row["address"] = "127.0.0.1"
				row["port"] = 80
			case "unknown-outer-setting":
				request["handshake"] = map[string]any{"address": "overwrite"}
			case "null-row":
				settings["clients"] = []any{nil}
			case "null-inner":
				request["inner"] = nil
			case "empty-list":
				settings["clients"] = []any{}
			}
			if changed, err := appendNativeInnerClients(model.ShadowTLS, stored, request, added); err == nil || changed {
				t.Fatal("forged supplemental request accepted")
			}
			if profileReviewJSON(t, stored) != before {
				t.Fatal("rejection mutated stored material")
			}
		})
	}
}

func TestNativeProfileReviewAppendSupportsManagedInnerProtocols(t *testing.T) {
	for _, protocol := range []string{"socks", "vless", "shadowsocks"} {
		t.Run(protocol, func(t *testing.T) {
			collection, field := "clients", "email"
			outer := map[string]any{"email": "new"}
			oldRow, newRow := map[string]any{"email": "old"}, map[string]any{"email": "new"}
			if protocol == "socks" {
				collection, field = "accounts", "user"
				outer["innerUsername"] = "new"
				oldRow = map[string]any{"user": "old", "pass": "old-secret"}
				newRow = map[string]any{"user": "new", "pass": "new-secret"}
			}
			if protocol == "vless" {
				oldRow["id"] = "old-id"
				newRow["id"] = "new-id"
			}
			if protocol == "shadowsocks" {
				oldRow["password"] = "old-secret"
				newRow["password"] = "new-secret"
			}
			stored := map[string]any{"inner": map[string]any{"protocol": protocol, "settings": map[string]any{collection: []any{oldRow}}}}
			request := map[string]any{"clients": []any{outer}, "inner": map[string]any{"protocol": protocol, "settings": map[string]any{collection: []any{newRow}}}}
			if changed, err := appendNativeInnerClients(model.ShadowTLS, stored, request, []any{outer}); err != nil || !changed {
				t.Fatalf("%s append rejected: %v", protocol, err)
			}
			rows := stored["inner"].(map[string]any)["settings"].(map[string]any)[collection].([]any)
			if len(rows) != 2 || rows[1].(map[string]any)[field] != "new" {
				t.Fatal("wrong binding appended")
			}
		})
	}
	stored, request, added := profileReviewShadowFixture(t)
	before := profileReviewJSON(t, stored)
	if changed, err := appendNativeInnerClients(model.VLESS, stored, request, added); err != nil || changed || before != profileReviewJSON(t, stored) {
		t.Fatal("legacy protocol settings were changed")
	}
}

func TestNativeProfileReviewPortableRestorePreservesTrustAndMappings(t *testing.T) {
	filename := portableFixtureDB(t)
	var originals []model.Inbound
	for index, protocol := range []string{"anytls", "shadowtls"} {
		profile, err := GenerateNativeInboundProfile(NativeCredentialRequest{Protocol: protocol, Email: protocol + "@example.test", ServerName: "vpn.example.test", HandshakeAddress: "cover.example.test"})
		if err != nil {
			t.Fatal(err)
		}
		stream := `{}`
		if profile.StreamSettings != nil {
			stream = profileReviewJSON(t, profile.StreamSettings)
		}
		originals = append(originals, model.Inbound{UserId: 1, Enable: true, Listen: "127.0.0.1", Port: 34571 + index, Protocol: model.Protocol(protocol), Tag: protocol + "-restore-review", Settings: profileReviewJSON(t, profile.Settings), StreamSettings: stream, Sniffing: `{}`})
	}
	if err := withBackupDB(filename, false, func(db *gorm.DB) error { return db.Create(&originals).Error }); err != nil {
		t.Fatal(err)
	}
	archive, err := portableBackupFromSnapshot(filename)
	if err != nil {
		t.Fatal(err)
	}
	checked := false
	candidate, err := preparePanelRestore(bytes.NewReader(archive), t.TempDir(), func(raw string) error {
		checked = true
		var config coreconf.Config
		if err := json.Unmarshal([]byte(raw), &config); err != nil {
			return err
		}
		_, err := config.Build()
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.cleanup(false)
	if !checked {
		t.Fatal("restore did not validate projected core config")
	}
	if err := withBackupDB(candidate.database, true, func(db *gorm.DB) error {
		var restored []model.Inbound
		if err := db.Order("id").Find(&restored).Error; err != nil {
			return err
		}
		if len(restored) != len(originals) {
			return errors.New("restore lost generated profiles")
		}
		for i := range originals {
			if restored[i].Settings != originals[i].Settings || restored[i].StreamSettings != originals[i].StreamSettings {
				return errors.New("restore changed generated trust or credential bindings")
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
