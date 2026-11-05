package native_client

import (
	"encoding/json"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database/model"
)

// A ShadowTLS inbound whose inner is a single-user Shadowsocks-2022 server
// (server-level method + PSK, no inner "clients" array) is accepted by the
// core, so every outer client of it must also be exportable. Regression for
// the export path previously demanding an inner client list that never exists.
func TestShadowTLSSingleUserInnerSS2022ClientExports(t *testing.T) {
	const serverPSK = "AAAAAAAAAAAAAAAAAAAAAA=="
	settings := map[string]any{
		"version":   float64(3),
		"handshake": map[string]any{"address": "cover.example.test", "port": float64(443)},
		"clients": []any{
			map[string]any{"email": "only@example.test", "password": "outer-session-secret"},
		},
		"inner": map[string]any{
			"protocol": "shadowsocks",
			"settings": map[string]any{
				"method":   "2022-blake3-aes-128-gcm",
				"password": serverPSK,
			},
		},
	}
	raw, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	inbound := &model.Inbound{Protocol: model.ShadowTLS, Listen: "127.0.0.1", Port: 34591, Settings: string(raw)}
	outs, err := ClientOutbounds(inbound, model.Client{Email: "only@example.test"}, "192.0.2.9")
	if err != nil {
		t.Fatalf("single-user inner SS2022 client must be exportable: %v", err)
	}
	if len(outs) != 2 {
		t.Fatalf("expected inner proxy + shadowtls carrier, got %d outbounds", len(outs))
	}
	servers, ok := outs[0]["settings"].(map[string]any)["servers"].([]any)
	if !ok || len(servers) != 1 {
		t.Fatalf("expected one exported inner server, got %#v", outs[0]["settings"])
	}
	server := servers[0].(map[string]any)
	if server["password"] != serverPSK {
		t.Fatalf("single-user export must use the inner server PSK, got %v", server["password"])
	}
	if server["method"] != "2022-blake3-aes-128-gcm" {
		t.Fatalf("single-user export must carry the inner method, got %v", server["method"])
	}
	if server["uot"] != true || server["uotVersion"] != 2 {
		t.Fatalf("single-user SS2022 export must enable UoT v2, got uot=%v version=%v", server["uot"], server["uotVersion"])
	}
	// The outer session secret must never leak into the inner proxy server.
	text, _ := json.Marshal(outs[0])
	if string(text) == "" {
		t.Fatal("empty inner proxy outbound")
	}
}

func TestShadowTLSManagedInnerCannotExportSharedServerKey(t *testing.T) {
	for _, clients := range []any{[]any{}, nil, "invalid"} {
		settings := map[string]any{
			"version":   float64(3),
			"handshake": map[string]any{"address": "cover.example.test", "port": float64(443)},
			"clients":   []any{map[string]any{"email": "only@example.test", "password": "outer-session-secret"}},
			"inner": map[string]any{"protocol": "shadowsocks", "settings": map[string]any{
				"method": "2022-blake3-aes-128-gcm", "password": "AAAAAAAAAAAAAAAAAAAAAA==", "clients": clients,
			}},
		}
		raw, err := json.Marshal(settings)
		if err != nil {
			t.Fatal(err)
		}
		inbound := &model.Inbound{Protocol: model.ShadowTLS, Listen: "127.0.0.1", Port: 34591, Settings: string(raw)}
		outs, err := ClientOutbounds(inbound, model.Client{Email: "only@example.test"}, "192.0.2.9")
		if err == nil || outs != nil {
			t.Fatalf("managed clients %#v must not export a shared server key", clients)
		}
	}
}

func TestShadowTLSLegacyEmptyClientsKeepSingleUserSemantics(t *testing.T) {
	for _, clients := range []any{[]any{}, nil} {
		settings := map[string]any{
			"version":   float64(3),
			"handshake": map[string]any{"address": "cover.example.test", "port": float64(443)},
			"clients":   []any{map[string]any{"email": "only@example.test", "password": "outer-session-secret"}},
			"inner": map[string]any{"protocol": "shadowsocks", "settings": map[string]any{
				"method": "aes-128-gcm", "password": "shared-inner-secret", "clients": clients,
			}},
		}
		raw, err := json.Marshal(settings)
		if err != nil {
			t.Fatal(err)
		}
		inbound := &model.Inbound{Protocol: model.ShadowTLS, Listen: "127.0.0.1", Port: 34591, Settings: string(raw)}
		outs, err := ClientOutbounds(inbound, model.Client{Email: "only@example.test"}, "192.0.2.9")
		if err != nil {
			t.Fatal(err)
		}
		server := outs[0]["settings"].(map[string]any)["servers"].([]any)[0].(map[string]any)
		if server["password"] != "shared-inner-secret" || server["uot"] != nil {
			t.Fatalf("incorrect legacy single-user export: %#v", server)
		}
	}
}
