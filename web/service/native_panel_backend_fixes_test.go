package service

import (
	"encoding/json"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	panelxray "github.com/mhsanaei/3x-ui/v2/xray"
)

// A DNSTT inbound whose DNS payload MTU is raised above the 1232 default must
// export clients whose ednsPayloadSize matches that MTU; otherwise the server
// answers FORMERR and the tunnel hangs.
func TestDNSTTExportPropagatesMTUToEdnsPayloadSize(t *testing.T) {
	openTestDB(t)
	profile := profileTestGenerate(t, "dnstt")
	settings := profileTestObject(t, profile.Settings)
	settings["mtu"] = 2000
	client := profileTestClient(t, settings)
	email := client["email"].(string)

	raw, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := json.Marshal(profile.StreamSettings)
	if err != nil {
		t.Fatal(err)
	}
	inbound := &model.Inbound{UserId: 7, Protocol: model.Protocol("dnstt"), Enable: true, Listen: "192.0.2.7", Port: 24443,
		Tag: "native-dnstt-mtu", Settings: string(raw), StreamSettings: string(stream), Sniffing: `{}`,
		ClientStats: []panelxray.ClientTraffic{{Email: email, Enable: true}}}
	if err := database.GetDB().Create(inbound).Error; err != nil {
		t.Fatalf("cannot persist dnstt fixture: %v", err)
	}

	result, err := new(InboundService).GetNativeClientConfig(7, inbound.Id, email, "unused.example.test")
	if err != nil || result == nil {
		t.Fatalf("native dnstt client config failed: %v", err)
	}
	var config map[string]any
	if json.Unmarshal(result.Config, &config) != nil {
		t.Fatal("exported config is not a JSON object")
	}
	outbounds, _ := config["outbounds"].([]any)
	found := false
	for _, item := range outbounds {
		ob, _ := item.(map[string]any)
		if ob["protocol"] != "dns" {
			continue
		}
		tunnel := ob["settings"].(map[string]any)["tunnel"].(map[string]any)
		size, ok := tunnel["ednsPayloadSize"]
		if !ok {
			t.Fatal("exported dnstt client lacks ednsPayloadSize")
		}
		if size.(float64) != 2000 {
			t.Fatalf("ednsPayloadSize %v, want 2000 (the inbound MTU)", size)
		}
		found = true
	}
	if !found {
		t.Fatal("exported config has no dns outbound")
	}
}

// totalGB/expiryTime/limitIp/reset sent as JSON strings (as older panels and
// API scripts do) must parse like a string tgId, not crash with a raw Go
// unmarshal error, and must be stored as numbers so the Telegram bot's numeric
// LIKE lookup matches.
func TestGetClientsCoercesNumericStringFields(t *testing.T) {
	in := &model.Inbound{Protocol: model.VLESS, Settings: `{"clients":[
		{"id":"0b0b7a5e-8c7a-4e0f-9a51-6c0a3f1f7d10","email":"a","tgId":"12345","totalGB":"10","expiryTime":"0","limitIp":"3","reset":"7","enable":true}],"decryption":"none"}`}
	clients, err := (&InboundService{}).GetClients(in)
	if err != nil {
		t.Fatalf("string numeric fields rejected: %v", err)
	}
	if len(clients) != 1 {
		t.Fatalf("%d clients", len(clients))
	}
	c := clients[0]
	if c.TgID != 12345 || c.TotalGB != 10 || c.ExpiryTime != 0 || c.LimitIP != 3 || c.Reset != 7 {
		t.Fatalf("coercion wrong: tgId=%d totalGB=%d expiry=%d limitIp=%d reset=%d", c.TgID, c.TotalGB, c.ExpiryTime, c.LimitIP, c.Reset)
	}

	// The storage normalizer must rewrite the quoted numbers as JSON numbers so
	// the stored settings carry `"tgId": 12345` (what the bot's LIKE expects).
	normalized := clientsWithNumericFields([]byte(in.Settings))
	var parsed struct {
		Clients []map[string]json.RawMessage `json:"clients"`
	}
	if json.Unmarshal(normalized, &parsed) != nil || len(parsed.Clients) != 1 {
		t.Fatal("normalized settings are not valid JSON")
	}
	for _, field := range []string{"tgId", "totalGB", "expiryTime", "limitIp", "reset"} {
		v := string(parsed.Clients[0][field])
		if len(v) == 0 || v[0] == '"' {
			t.Fatalf("field %s not stored as a bare number: %s", field, v)
		}
	}
}

// A v3 ShadowTLS inbound with inner SOCKS must reject a saved client that has
// no innerUsername: export binds the SOCKS account by innerUsername, so without
// it the saved client could never be exported.
func TestValidateShadowTLSV3SocksRequiresInnerUsername(t *testing.T) {
	settings := `{"version":3,"inner":{"protocol":"socks"}}`
	missing := model.Client{Email: "u", Password: "pw"}
	if err := validateInboundClient(model.ShadowTLS, settings, missing); err == nil {
		t.Fatal("v3 ShadowTLS inner SOCKS client without innerUsername was accepted")
	}
	ok := model.Client{Email: "u", Password: "pw", InnerUsername: "u"}
	if err := validateInboundClient(model.ShadowTLS, settings, ok); err != nil {
		t.Fatalf("valid v3 ShadowTLS inner SOCKS client rejected: %v", err)
	}
}
