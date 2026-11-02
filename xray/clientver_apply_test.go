package xray

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
	vlessinbound "github.com/xtls/xray-core/proxy/vless/inbound"
)

// minClientVer/maxClientVer reach the core on the live-apply path (see
// TestAddInboundCarriesDialects): the panel parses the inbound with its own
// copy of the core's infra/conf.
func TestAddInboundCarriesClientVer(t *testing.T) {
	raw := []byte(`{
		"tag": "inbound-3333",
		"port": 3333,
		"protocol": "vless",
		"settings": {
			"clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "email": "t@t"}],
			"decryption": "none",
			"minClientVer": "25.3.6",
			"maxClientVer": "26.3.27"
		},
		"streamSettings": {"network": "ws", "wsSettings": {"path": "/"}}
	}`)
	detour := new(conf.InboundDetourConfig)
	if err := json.Unmarshal(raw, detour); err != nil {
		t.Fatal(err)
	}
	built, err := detour.Build()
	if err != nil {
		t.Fatal(err)
	}
	settings, err := built.ProxySettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	cfg := settings.(*vlessinbound.Config)
	if !bytes.Equal(cfg.GetMinClientVer(), []byte{25, 3, 6}) || !bytes.Equal(cfg.GetMaxClientVer(), []byte{26, 3, 27}) {
		t.Errorf("built min/max = %v/%v, want [25 3 6]/[26 3 27]", cfg.GetMinClientVer(), cfg.GetMaxClientVer())
	}
}
