package service

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

func coreProjectionObject(t *testing.T, data string) map[string]json.RawMessage {
	t.Helper()
	var out map[string]json.RawMessage
	if err := json.Unmarshal([]byte(data), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func coreProjectionClients(t *testing.T, data string) []map[string]json.RawMessage {
	t.Helper()
	var clients []map[string]json.RawMessage
	if err := json.Unmarshal(coreProjectionObject(t, data)["clients"], &clients); err != nil {
		t.Fatal(err)
	}
	return clients
}

func sameJSON(t *testing.T, got json.RawMessage, want string) {
	t.Helper()
	var a, b any
	if json.Unmarshal(got, &a) != nil || json.Unmarshal([]byte(want), &b) != nil || !reflect.DeepEqual(a, b) {
		t.Fatalf("JSON mismatch: got %s; want %s", got, want)
	}
}

func TestNativeCoreInboundPreservesSupportedSettings(t *testing.T) {
	tests := []struct {
		protocol string
		setting  string
		client   string
	}{
		{"orbit", `"transport":"wss","tls":{"certificate":["server-cert"],"key":["server-key"]},"outerTls":{"certificate":["outer-cert"],"key":["outer-key"]},"host":"front.example","path":"/native","security":"reality","reality":{"privateKey":"private","serverNames":["front.example"],"shortIds":["abcd"],"dest":"front.example:443"},"maxSessions":32,"maxFlows":16,"udpIdleTimeout":30`, `"email":"active","level":2,"key":"vck1_synthetic","expiresAt":9007199254740993`},
		{"dnstt", `"domain":"t.example","privateKey":"private","inner":{"protocol":"socks"},"mtu":1232,"maxSessions":32,"maxStreams":16`, `"email":"active","level":2,"id":"","username":"user","password":"secret"`},
		{"openvpn", `"network":"udp","certificates":{"ca":"ca","cert":"server-cert","key":"server-key","tlsCrypt":"control-key"},"crypto":{"dataCiphers":["AES-256-GCM"],"authHash":"SHA256"},"tunnel":{"ipv4":"10.9.0.0/24","dns":["1.1.1.1"],"mtu":1400},"clientProof":{"required":true},"limits":{"maxSessions":16},"renegotiationSeconds":3600`, `"email":"active","level":2,"commonName":"client-cn","username":"user","password":"secret","clientProof":{"keyId":"proof-id","key":"0123"}`},
		{"anytls", `"maxStreams":32`, `"email":"active","level":2,"password":"uuid","uuidHashMiddle":true`},
		{"shadowtls", `"version":3,"strict":true,"handshake":{"address":"front.example","port":443},"inner":{"protocol":"socks","settings":{"auth":"password","accounts":[{"user":"inner","pass":"secret"}]}}`, `"email":"active","level":2,"password":"uuid","requireUuidSessionId":true`},
		{"mieru", `"transport":"udp"`, `"email":"active","level":2,"username":"uuid","password":"secret","uuidMetadataTrailer":true`},
	}
	for _, tc := range tests {
		t.Run(tc.protocol, func(t *testing.T) {
			input := `{` + tc.setting + `,"handshakeTimeout":15,"clientExport":{"serverName":"export.example","ca":"EXPORT-ONLY-CA"},"clients":[{` + tc.client + `,"enable":true,"expiryTime":0,"totalGB":1024,"limitIp":2,"tgId":123,"subId":"sub","comment":"panel-only","created_at":99,"updated_at":100,"certificate":"EXPORT-ONLY-CERT","privateKey":"EXPORT-ONLY-KEY","tlsCryptV2":"EXPORT-ONLY-CONTROL","innerUsername":"EXPORT-ONLY-INNER"}]}`
			inbound := &model.Inbound{Protocol: model.Protocol(tc.protocol), Settings: input}
			got, err := coreInboundSettings(inbound)
			if err != nil {
				t.Fatal(err)
			}
			if inbound.Settings != input {
				t.Fatal("projection mutated persistent model")
			}
			if strings.Contains(got, "EXPORT-ONLY") || strings.Contains(got, "clientExport") {
				t.Fatal("export-only material leaked into runtime config")
			}
			out := coreProjectionObject(t, got)
			original := coreProjectionObject(t, input)
			for key, value := range original {
				if key == "clients" || key == "clientExport" {
					continue
				}
				sameJSON(t, out[key], string(value))
			}
			clients := coreProjectionClients(t, got)
			if len(clients) != 1 {
				t.Fatalf("got %d clients", len(clients))
			}
			encoded, _ := json.Marshal(clients[0])
			sameJSON(t, encoded, `{`+tc.client+`}`)
			if tc.protocol == "orbit" && string(clients[0]["expiresAt"]) != "9007199254740993" {
				t.Fatal("integer precision lost")
			}
		})
	}
}

func TestNativeCoreInboundCompatibilityFlagsAndOrdinaryDefaults(t *testing.T) {
	for protocol, flag := range map[string]string{"vmess": "rawUuidAuth", "trojan": "uuidHashPrefix", "anytls": "uuidHashMiddle", "shadowtls": "requireUuidSessionId", "mieru": "uuidMetadataTrailer"} {
		for _, value := range []string{"true", "false"} {
			t.Run(protocol+"/"+value, func(t *testing.T) {
				got, err := coreInboundSettingsAt(protocol, `{"clients":[{"email":"a","id":"id","password":"pw","`+flag+`":`+value+`,"enable":true}]}`, nil, 1000)
				if err != nil {
					t.Fatal(err)
				}
				if string(coreProjectionClients(t, got)[0][flag]) != value {
					t.Fatal("explicit compatibility mode lost")
				}
			})
		}
	}
	for _, protocol := range []string{"vmess", "vless", "trojan", "shadowsocks", "hysteria"} {
		t.Run(protocol+"/ordinary", func(t *testing.T) {
			got, err := coreInboundSettingsAt(protocol, `{"decryption":"none","dialects":[0,120],"minClientVer":"25.3.6","clients":[{"id":"id","email":"a","password":"pw","flow":"xtls-rprx-vision-udp443","method":"method","auth":"auth","enable":true,"totalGB":42,"comment":"panel"}]}`, nil, 1000)
			if err != nil {
				t.Fatal(err)
			}
			clients := coreProjectionClients(t, got)
			encoded, _ := json.Marshal(clients[0])
			sameJSON(t, encoded, `{"id":"id","email":"a","password":"pw","flow":"xtls-rprx-vision","method":"method","auth":"auth"}`)
			out := coreProjectionObject(t, got)
			sameJSON(t, out["dialects"], `[0,120]`)
			sameJSON(t, out["minClientVer"], `"25.3.6"`)
		})
	}
	const untouched = ` { "auth": "noauth", "udp": true } `
	if got, err := coreInboundSettingsAt("socks", untouched, nil, 1000); err != nil || got != untouched {
		t.Fatalf("unrelated settings changed: %q, %v", got, err)
	}
}

func TestNativeCoreInboundFiltersDisabledExpiredClients(t *testing.T) {
	const now int64 = 100000
	for _, protocol := range []string{"orbit", "dnstt", "dns", "openvpn", "anytls", "shadowtls", "mieru", "vmess", "trojan"} {
		t.Run(protocol, func(t *testing.T) {
			input := `{"clients":[{"email":"active","enable":true,"expiryTime":100001},{"email":"manual","enable":false},{"email":"stats","enable":true},{"email":"expired","enable":true,"expiryTime":99999},{"email":"stat-expired","enable":true},{"email":"deferred","expiryTime":-86400000},{"email":"unlimited","expiryTime":0}]}`
			stats := []xray.ClientTraffic{{Email: "stats", Enable: false}, {Email: "stat-expired", Enable: true, ExpiryTime: now}, {Email: "active", Enable: true}}
			got, err := coreInboundSettingsAt(protocol, input, stats, now)
			if err != nil {
				t.Fatal(err)
			}
			clients := coreProjectionClients(t, got)
			if len(clients) != 3 {
				t.Fatalf("expected active/deferred/unlimited, got %s", got)
			}
			for i, want := range []string{`"active"`, `"deferred"`, `"unlimited"`} {
				if string(clients[i]["email"]) != want {
					t.Fatal("wrong client survived filtering")
				}
			}
		})
	}
	for _, protocol := range []string{"orbit", "dnstt", "dns", "openvpn", "anytls", "shadowtls", "mieru"} {
		for _, clients := range []string{`[]`, `null`, `[{"email":"disabled","enable":false}]`} {
			if _, err := coreInboundSettingsAt(protocol, `{"clients":`+clients+`}`, nil, now); !errors.Is(err, errNoActiveNativeClients) {
				t.Fatalf("%s empty clients must omit listener: %v", protocol, err)
			}
		}
	}
	if _, err := coreInboundSettingsAt("shadowtls", `{"version":2,"password":"secret","clients":[]}`, nil, now); !errors.Is(err, errNoActiveNativeClients) {
		t.Fatalf("ShadowTLS v2 empty panel account list must omit listener: %v", err)
	}
}

func TestNativeCoreInboundNestedVLESSAndMalformedMetadata(t *testing.T) {
	input := `{"version":3,"clients":[{"email":"outer","password":"outer-password"}],"inner":{"protocol":"vless","settings":{"decryption":"none","clients":[{"id":"id-active","email":"inner-active","level":2,"enable":true},{"id":"id-disabled","email":"inner-disabled","enable":false}]}}}`
	got, err := coreInboundSettingsAt("shadowtls", input, nil, 1000)
	if err != nil {
		t.Fatal(err)
	}
	inner := coreProjectionObject(t, string(coreProjectionObject(t, got)["inner"]))
	clients := coreProjectionClients(t, string(inner["settings"]))
	if len(clients) != 1 || string(clients[0]["email"]) != `"inner-active"` || string(clients[0]["level"]) != "2" {
		t.Fatal("nested VLESS clients not projected correctly")
	}
	if _, exists := clients[0]["enable"]; exists {
		t.Fatal("nested panel fields leaked")
	}
	for _, input := range []string{`null`, `[]`, `{"clients":{}}`, `{"clients":[null]}`, `{"clients":[{"email":"a","enable":"false"}]}`, `{"clients":[{"email":"a","expiryTime":"bad"}]}`} {
		if _, err := coreInboundSettingsAt("anytls", input, nil, 1000); err == nil {
			t.Fatalf("malformed native settings accepted: %s", input)
		}
	}
	if _, err := coreInboundSettings(nil); err == nil {
		t.Fatal("nil inbound accepted")
	}
}

func TestNativeCoreInboundBuildSkipsEmptyWithoutAffectingOthers(t *testing.T) {
	if err := database.InitDB(filepath.Join(t.TempDir(), "x-ui.db")); err != nil {
		t.Fatal(err)
	}
	defer database.CloseDB()
	rows := []*model.Inbound{
		{Enable: true, Protocol: model.Protocol("anytls"), Tag: "expired-native", Port: 1443, Settings: `{"clients":[{"email":"expired","password":"pw","enable":false}]}`, StreamSettings: `{}`, Sniffing: `{}`},
		{Enable: true, Protocol: model.VLESS, Tag: "ordinary", Port: 2443, Settings: `{"decryption":"none","clients":[{"id":"00112233-4455-6677-8899-aabbccddeeff","email":"ordinary","enable":true}]}`, StreamSettings: `{}`, Sniffing: `{}`},
		{Enable: true, Protocol: model.Protocol("mieru"), Tag: "active-native", Port: 3443, Settings: `{"transport":"udp","clientExport":{"serverName":"panel-only"},"clients":[{"email":"native","username":"user","password":"pw","enable":true,"uuidMetadataTrailer":false}]}`, StreamSettings: `{}`, Sniffing: `{}`},
		{Enable: true, Protocol: model.Shadowsocks, Tag: "disabled-ss2022", Port: 4443, Settings: `{"method":"2022-blake3-aes-128-gcm","password":"server-psk","clients":[{"email":"disabled","password":"identity-key","enable":false}]}`, StreamSettings: `{}`, Sniffing: `{}`},
	}
	if err := database.GetDB().Create(&rows).Error; err != nil {
		t.Fatal(err)
	}
	got, err := (&XrayService{}).GetXrayConfigFor(`{"outbounds":[{"protocol":"blackhole","tag":"block"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.InboundConfigs) != 2 || got.InboundConfigs[0].Tag != "ordinary" || got.InboundConfigs[1].Tag != "active-native" {
		t.Fatalf("wrong listeners after projection: %+v", got.InboundConfigs)
	}
	if strings.Contains(string(got.InboundConfigs[1].Settings), "clientExport") {
		t.Fatal("config build bypassed native projection")
	}
	var persisted model.Inbound
	if err := database.GetDB().First(&persisted, rows[2].Id).Error; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(persisted.Settings, "clientExport") {
		t.Fatal("runtime filtering mutated persisted export metadata")
	}
}

func TestNativeCoreInboundShadowTLSLegacyAccountBinding(t *testing.T) {
	for _, version := range []string{"1", "2"} {
		for _, kind := range []string{"vless", "socks", "shadowsocks"} {
			t.Run(version+"/"+kind, func(t *testing.T) {
				innerSettings := `{"decryption":"none","clients":[{"email":"active","id":"active-id"},{"email":"disabled","id":"disabled-id"},{"email":"orphan","id":"orphan-id"}]}`
				collection, identity, want := "clients", "email", `"active"`
				if kind == "socks" {
					innerSettings = `{"auth":"password","accounts":[{"user":"keep","pass":"p1"},{"user":"drop","pass":"p2"},{"user":"orphan","pass":"p3"}]}`
					collection, identity, want = "accounts", "user", `"keep"`
				} else if kind == "shadowsocks" {
					innerSettings = `{"network":"tcp","method":"2022-blake3-aes-128-gcm","password":"server-psk","uuidIdentityKeys":true,"clients":[{"email":"active","password":"uuid","uuidIdentityKeys":false,"level":2},{"email":"disabled","password":"p2"},{"email":"orphan","password":"p3"}]}`
				}
				input := `{"version":` + version + `,"password":"outer","clients":[{"email":"active","enable":true,"innerUsername":"keep"},{"email":"disabled","enable":false,"innerUsername":"drop"}],"inner":{"protocol":"` + kind + `","settings":` + innerSettings + `}}`
				got, err := coreInboundSettingsAt("shadowtls", input, nil, 1000)
				if err != nil {
					t.Fatal(err)
				}
				outer := coreProjectionObject(t, got)
				if _, exists := outer["clients"]; exists {
					t.Fatal("legacy ShadowTLS received panel-only outer clients")
				}
				inner := coreProjectionObject(t, string(outer["inner"]))
				settings := coreProjectionObject(t, string(inner["settings"]))
				var accounts []map[string]json.RawMessage
				_ = json.Unmarshal(settings[collection], &accounts)
				if len(accounts) != 1 || string(accounts[0][identity]) != want {
					t.Fatalf("disabled/orphan inner credential retained: %s", settings[collection])
				}
				if kind == "shadowsocks" && (string(accounts[0]["uuidIdentityKeys"]) != "false" || string(accounts[0]["level"]) != "2" || string(settings["uuidIdentityKeys"]) != "true") {
					t.Fatal("inner SS2022 identity mode or policy level lost")
				}
			})
		}
	}
}

func TestNativeCoreInboundOrbitExpiryAndSS2022Flag(t *testing.T) {
	if _, err := coreInboundSettingsAt("orbit", `{"clients":[{"email":"expired","key":"key","expiresAt":99}]}`, nil, 100000); !errors.Is(err, errNoActiveNativeClients) {
		t.Fatal("expired native Orbit account was retained")
	}
	for _, tc := range []struct{ explicit, want string }{{"", "200"}, {`,"expiresAt":300`, "200"}, {`,"expiresAt":150`, "150"}, {`,"expiresAt":0`, "200"}} {
		got, err := coreInboundSettingsAt("orbit", `{"clients":[{"email":"a","key":"key","expiryTime":200999`+tc.explicit+`}]}`, nil, 100000)
		if err != nil {
			t.Fatal(err)
		}
		if string(coreProjectionClients(t, got)[0]["expiresAt"]) != tc.want {
			t.Fatalf("wrong effective expiry: %s", got)
		}
	}
	got, err := coreInboundSettingsAt("shadowsocks", `{"uuidIdentityKeys":true,"clients":[{"email":"a","password":"key","uuidIdentityKeys":false}]}`, nil, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if string(coreProjectionObject(t, got)["uuidIdentityKeys"]) != "true" || string(coreProjectionClients(t, got)[0]["uuidIdentityKeys"]) != "false" {
		t.Fatal("SS2022 identity mode lost")
	}
}

func TestNativeCoreInboundSS2022ManagedClientsNeverBecomeSingleUser(t *testing.T) {
	for _, clients := range []string{`[]`, `[{"email":"a","enable":false}]`, `[{"email":"a","expiryTime":999}]`} {
		input := `{"method":"2022-blake3-aes-128-gcm","password":"server-psk","clients":` + clients + `}`
		if _, err := coreInboundSettingsAt("shadowsocks", input, nil, 1000); !errors.Is(err, errNoActiveNativeClients) {
			t.Fatalf("managed SS2022 with no active users must omit listener: %v", err)
		}
	}
	for _, input := range []string{
		`{"method":"2022-blake3-aes-128-gcm","password":"server-psk"}`,
		`{"method":"2022-blake3-aes-128-gcm","password":"server-psk","clients":null}`,
		`{"method":"aes-128-gcm","password":"key","clients":[]}`,
	} {
		got, err := coreInboundSettingsAt("shadowsocks", input, nil, 1000)
		if err != nil {
			t.Fatal(err)
		}
		sameJSON(t, json.RawMessage(got), input)
	}
}

func TestNativeCoreInboundShadowTLSMissingBindingIsNotInactive(t *testing.T) {
	for _, kind := range []string{"vless", "shadowsocks", "socks"} {
		t.Run(kind, func(t *testing.T) {
			collection, identity := "clients", "email"
			if kind == "socks" {
				collection, identity = "accounts", "user"
			}
			for _, accounts := range []string{`[]`, `[{"` + identity + `":"other"}]`, `[{"` + identity + `":"a"}]`} {
				input := `{"version":2,"clients":[{"email":"a","innerUsername":"a"},{"email":"b","innerUsername":"b"}],"inner":{"protocol":"` + kind + `","settings":{"` + collection + `":` + accounts + `}}}`
				if _, err := coreInboundSettingsAt("shadowtls", input, nil, 1000); err == nil || errors.Is(err, errNoActiveNativeClients) || !strings.Contains(err.Error(), "matching inner account") {
					t.Fatalf("missing binding must be a validation error: %v", err)
				}
			}
			if kind == "socks" {
				return // SOCKS accounts have no independent enable/expiry metadata.
			}
			for _, state := range []string{`"enable":false`, `"expiryTime":999`} {
				input := `{"version":2,"clients":[{"email":"a"}],"inner":{"protocol":"` + kind + `","settings":{"clients":[{"email":"a",` + state + `}]}}}`
				if _, err := coreInboundSettingsAt("shadowtls", input, nil, 1000); !errors.Is(err, errNoActiveNativeClients) {
					t.Fatalf("present inactive binding must safely omit listener: %v", err)
				}
			}
		})
	}
}
