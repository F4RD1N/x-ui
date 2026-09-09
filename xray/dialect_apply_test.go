package xray

import (
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
	vlessinbound "github.com/xtls/xray-core/proxy/vless/inbound"
)

// Saving an inbound applies it to a running core over the Xray API rather than
// by restarting it: web/service/inbound.go UpdateInbound deletes the inbound by
// tag and re-adds it with XrayAPI.AddInbound, which parses the JSON *in this
// process* with infra/conf and sends the built protobuf.
//
// That makes the panel's own copy of xray-core part of the feature: built
// against upstream, this parse silently drops "dialects" and the live-applied
// inbound would quietly go back to accepting stock VLESS only. This test is
// what keeps the go.mod replace directive honest.
func TestAddInboundCarriesDialects(t *testing.T) {
	raw := []byte(`{
		"tag": "inbound-1111",
		"listen": "0.0.0.0",
		"port": 1111,
		"protocol": "vless",
		"settings": {
			"clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "email": "t@t"}],
			"decryption": "none",
			"dialects": [4, 5]
		},
		"streamSettings": {"network": "tcp"}
	}`)

	detour := new(conf.InboundDetourConfig)
	if err := json.Unmarshal(raw, detour); err != nil {
		t.Fatalf("unmarshal inbound: %v", err)
	}

	built, err := detour.Build()
	if err != nil {
		t.Fatalf("build inbound: %v", err)
	}

	settings, err := built.ProxySettings.GetInstance()
	if err != nil {
		t.Fatalf("get proxy settings: %v", err)
	}

	cfg, ok := settings.(*vlessinbound.Config)
	if !ok {
		t.Fatalf("proxy settings are %T, want *vlessinbound.Config", settings)
	}

	got := cfg.GetDialects()
	if len(got) != 2 || got[0] != 4 || got[1] != 5 {
		t.Errorf("built inbound dialects = %v, want [4 5]; the panel is parsing configs "+
			"with a core that does not know dialects", got)
	}
}

// An inbound that names no dialects must build exactly as it always did, so
// every existing inbound keeps working untouched.
func TestAddInboundWithoutDialectsIsStock(t *testing.T) {
	raw := []byte(`{
		"tag": "inbound-2222",
		"port": 2222,
		"protocol": "vless",
		"settings": {
			"clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "email": "t@t"}],
			"decryption": "none"
		},
		"streamSettings": {"network": "tcp"}
	}`)

	detour := new(conf.InboundDetourConfig)
	if err := json.Unmarshal(raw, detour); err != nil {
		t.Fatalf("unmarshal inbound: %v", err)
	}
	built, err := detour.Build()
	if err != nil {
		t.Fatalf("build inbound: %v", err)
	}
	settings, err := built.ProxySettings.GetInstance()
	if err != nil {
		t.Fatalf("get proxy settings: %v", err)
	}
	if d := settings.(*vlessinbound.Config).GetDialects(); len(d) != 0 {
		t.Errorf("inbound with no dialects built dialects = %v, want empty", d)
	}
}
