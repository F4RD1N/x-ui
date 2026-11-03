package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/xtls/xray-core/app/proxyman/command"
	"google.golang.org/grpc"
)

type nativeServiceHandler struct {
	command.HandlerServiceClient
	calls int
}

func (h *nativeServiceHandler) AlterInbound(context.Context, *command.AlterInboundRequest, ...grpc.CallOption) (*command.AlterInboundResponse, error) {
	h.calls++
	return &command.AlterInboundResponse{}, nil
}

func TestNativeClientRevocationRequestsRestartAfterSuccessfulOuterRemoval(t *testing.T) {
	openTestDB(t)
	previousProcess := p
	p = nil
	t.Cleanup(func() { p = previousProcess })
	for index, protocol := range []model.Protocol{model.DNSTT, model.DNS, model.ShadowTLS} {
		first := nativeDisabledClient(protocol, fmt.Sprintf("revoke-%d@example.test", index))
		first["enable"] = true
		second := nativeDisabledClient(protocol, fmt.Sprintf("remain-%d@example.test", index))
		in := &model.Inbound{Protocol: protocol, Port: 34000 + index, Tag: fmt.Sprintf("revoke-%d", index), Settings: nativeTestSettings(t, first, second), StreamSettings: `{}`, Sniffing: `{}`}
		if err := database.GetDB().Create(in).Error; err != nil {
			t.Fatal(err)
		}
		s := new(InboundService)
		clients, err := s.GetClients(in)
		if err != nil {
			t.Fatal(err)
		}
		for i := range clients {
			if err = s.AddClientStat(database.GetDB(), in.Id, &clients[i]); err != nil {
				t.Fatal(err)
			}
		}
		first["enable"] = false
		h := new(nativeServiceHandler)
		var hsi command.HandlerServiceClient = h
		s.xrayApi.HandlerServiceClient = &hsi
		restart, err := s.UpdateInboundClient(&model.Inbound{Id: in.Id, Settings: nativeTestSettings(t, first)}, inboundClientID(protocol, clients[0]))
		if err != nil || !restart || h.calls != 1 {
			t.Fatalf("%s revocation did not force native reload: restart=%v calls=%d err=%v", protocol, restart, h.calls, err)
		}
	}
}

func TestNativeClientIdentityIsPathSafe(t *testing.T) {
	c := model.Client{Email: "user/with%?\u2603@example.test", Password: "sensitive/password", Key: "sensitive-key", ID: "id", Auth: "auth"}
	for _, p := range []model.Protocol{model.Orbit, model.DNSTT, model.DNS, model.OpenVPN, model.AnyTLS, model.ShadowTLS, model.Mieru} {
		id := inboundClientID(p, c)
		if strings.ContainsAny(id, "/%?=+") || !strings.HasPrefix(id, "email:") {
			t.Fatalf("unsafe native identity %q", id)
		}
		decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(id, "email:"))
		if err != nil || string(decoded) != c.Email {
			t.Fatal("identity did not preserve UTF8 email")
		}
		changed := c
		changed.Password = "new"
		changed.Key = "new"
		changed.CommonName = "new"
		if inboundClientID(p, changed) != id {
			t.Fatal("credential rotation changed native identity")
		}
	}
	for p, want := range map[model.Protocol]string{model.VMESS: "id", model.VLESS: "id", model.Trojan: "sensitive/password", model.Shadowsocks: c.Email, model.Hysteria: "auth"} {
		if inboundClientID(p, c) != want {
			t.Fatalf("legacy %s identity changed", p)
		}
	}
}

func TestNativeClientSOCKSAccountingLimits(t *testing.T) {
	for _, tc := range []struct {
		protocol model.Protocol
		settings string
		client   model.Client
	}{
		{model.DNSTT, `{"inner":{"protocol":"socks"}}`, model.Client{Email: "email", Username: "username", Password: "password"}},
		{model.DNS, `{"inner":{"protocol":"socks"}}`, model.Client{Email: "email", Username: "username", Password: "password"}},
		{model.ShadowTLS, `{"version":1,"inner":{"protocol":"socks"}}`, model.Client{Email: "email", InnerUsername: "username"}},
		{model.ShadowTLS, `{"version":2,"inner":{"protocol":"socks"}}`, model.Client{Email: "email", InnerUsername: "username"}},
	} {
		if err := validateInboundClient(tc.protocol, tc.settings, tc.client); err != nil {
			t.Fatal("unlimited separate identity rejected", err)
		}
		limited := tc.client
		limited.TotalGB = 1024
		if err := validateInboundClient(tc.protocol, tc.settings, limited); err == nil {
			t.Fatal("unenforceable traffic quota accepted")
		}
		limited.TotalGB = 0
		limited.LimitIP = 1
		if err := validateInboundClient(tc.protocol, tc.settings, limited); err == nil {
			t.Fatal("unenforceable IP limit accepted")
		}
		limited.Username = limited.Email
		limited.InnerUsername = limited.Email
		limited.TotalGB = 1024
		if err := validateInboundClient(tc.protocol, tc.settings, limited); err != nil {
			t.Fatal("matching SOCKS accounting identity rejected", err)
		}
	}
	if err := validateInboundClient(model.ShadowTLS, `{"version":3,"inner":{"protocol":"socks"}}`, model.Client{Email: "email", Password: "password", InnerUsername: "different", TotalGB: 1024}); err != nil {
		t.Fatal("v3 outer account override rejected", err)
	}
}

func TestNativeClientLiveExpiryAndOrbitSeconds(t *testing.T) {
	c := model.Client{Enable: true, ExpiryTime: time.Now().UnixMilli() - 1000}
	for _, p := range []model.Protocol{model.Orbit, model.DNSTT, model.DNS, model.OpenVPN, model.AnyTLS, model.ShadowTLS, model.Mieru} {
		if clientEnabledForLiveAPI(p, c) {
			t.Fatal("expired native account would be re-added")
		}
	}
	if !clientEnabledForLiveAPI(model.VMESS, c) {
		t.Fatal("legacy live-update semantics changed")
	}
	c.ExpiryTime = -86400000
	if !clientEnabledForLiveAPI(model.DNSTT, c) {
		t.Fatal("deferred expiry treated as expired")
	}
	c.ExpiryTime = 5000999
	c.ExpiresAt = 6000
	got := clientAPIValuesForInbound(c, "", &model.Inbound{Protocol: model.Orbit})
	if got["expiresAt"] != json.Number("5000") {
		t.Fatal("Orbit live API lost earlier panel expiry")
	}
	c.ExpiresAt = 4000
	if got = clientAPIValuesForInbound(c, "", &model.Inbound{Protocol: model.Orbit}); got["expiresAt"] != json.Number("4000") {
		t.Fatal("Orbit native earlier expiry overridden")
	}
}

func TestNativeClientAPIFieldsAndExportSeparation(t *testing.T) {
	c := model.Client{Email: "test@example.test", ID: "id", Password: "pw", Username: "user", Key: "key", CommonName: "cn", Level: 7, ExpiresAt: 9007199254740993, RawUUIDAuth: true, UUIDHashPrefix: true, UUIDHashMiddle: true, RequireUUIDSessionID: true, UUIDMetadataTrailer: true, ClientProof: json.RawMessage(`{"keyId":"synthetic","key":"0000000000000000000000000000000000000000000000000000000000000000"}`), Certificate: "export-cert", PrivateKey: "export-key", TLSCryptV2: "export-tls-crypt-v2", InnerUsername: "export-inner"}
	v := clientAPIValues(c, "aes-128-gcm")
	for _, k := range []string{"rawUuidAuth", "uuidHashPrefix", "uuidHashMiddle", "requireUuidSessionId", "uuidMetadataTrailer"} {
		if v[k] != true {
			t.Fatalf("lost %s", k)
		}
	}
	if v["level"] != json.Number("7") || v["expiresAt"] != json.Number("9007199254740993") {
		t.Fatal("numeric precision lost")
	}
	if _, ok := v["clientProof"].(map[string]any); !ok {
		t.Fatal("nested client proof lost")
	}
	for _, k := range []string{"certificate", "privateKey", "tlsCryptV2", "innerUsername"} {
		if _, ok := v[k]; ok {
			t.Fatalf("export-only %s entered account API", k)
		}
	}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var restored model.Client
	if err = json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.PrivateKey != c.PrivateKey || restored.InnerUsername != c.InnerUsername || restored.ExpiresAt != c.ExpiresAt || !restored.RawUUIDAuth || !restored.UUIDMetadataTrailer {
		t.Fatal("model roundtrip lost protocol/export fields")
	}
}

func TestNativeClientAPIInheritsSS2022IdentityFlag(t *testing.T) {
	c := model.Client{Email: "test@example.test", Password: "00112233-4455-6677-8899-aabbccddeeff"}
	for _, tc := range []struct {
		client string
		want   bool
	}{
		{`{"email":"test@example.test"}`, true},
		{`{"email":"test@example.test","uuidIdentityKeys":false}`, false},
		{`{"email":"test@example.test","uuidIdentityKeys":true}`, true},
	} {
		in := &model.Inbound{Protocol: model.Shadowsocks, Settings: `{"uuidIdentityKeys":true,"clients":[` + tc.client + `]}`}
		got := clientAPIValuesForInbound(c, "2022-blake3-aes-128-gcm", in)
		if got["uuidIdentityKeys"] != tc.want {
			t.Fatal("inbound UUID identity policy ignored per-client override")
		}
		if got["password"] != c.Password {
			t.Fatal("frontend helper mutated password before typed API conversion")
		}
	}
}

func TestNativeClientSS2022FalsePersistence(t *testing.T) {
	openTestDB(t)
	s := new(InboundService)
	client := map[string]any{"email": "ss-first@example.test", "password": "AAAAAAAAAAAAAAAAAAAAAA==", "enable": false, "uuidIdentityKeys": false}
	settings := map[string]any{"method": "2022-blake3-aes-128-gcm", "password": "AAAAAAAAAAAAAAAAAAAAAA==", "uuidIdentityKeys": true, "clients": []any{client}}
	raw, _ := json.Marshal(settings)
	in := &model.Inbound{Protocol: model.Shadowsocks, Port: 33999, Tag: "ss-false-persistence", Settings: string(raw), StreamSettings: `{}`, Sniffing: `{}`}
	if _, _, err := s.AddInbound(in); err != nil {
		t.Fatal(err)
	}
	added := map[string]any{"email": "ss-second@example.test", "password": "AQEBAQEBAQEBAQEBAQEBAQ==", "enable": false, "uuidIdentityKeys": false}
	if _, err := s.AddInboundClient(&model.Inbound{Id: in.Id, Settings: nativeTestSettings(t, added)}); err != nil {
		t.Fatal(err)
	}
	client["comment"] = "edited"
	if _, err := s.UpdateInboundClient(&model.Inbound{Id: in.Id, Settings: nativeTestSettings(t, client)}, "ss-first@example.test"); err != nil {
		t.Fatal(err)
	}
	stored, err := s.GetInbound(in.Id)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err = json.Unmarshal([]byte(stored.Settings), &got); err != nil {
		t.Fatal(err)
	}
	if got["uuidIdentityKeys"] != true {
		t.Fatal("listener UUID flag lost")
	}
	rows, err := settingsClientMaps(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		value, present := row.(map[string]any)["uuidIdentityKeys"]
		if !present || value != false {
			t.Fatal("explicit false disappeared and would inherit true")
		}
	}
}

func TestNativeGetClientsAcceptsProtocolSettingsAndRejectsMalformed(t *testing.T) {
	s := new(InboundService)
	for _, settings := range []string{
		`{"clients":[{"email":"test@example.test","rawUuidAuth":true}],"tlsSettings":{"certificates":[]},"clientExport":{"serverName":"test"},"version":3}`,
		`{"transport":"udp","clients":[{"email":"test@example.test","rawUuidAuth":true}],"inner":{"protocol":"vless"}}`,
	} {
		got, err := s.GetClients(&model.Inbound{Settings: settings})
		if err != nil || len(got) != 1 || !got[0].RawUUIDAuth {
			t.Fatalf("protocol fields broke clients decoding: %v", err)
		}
	}
	for _, settings := range []string{`null`, `[]`, `{"clients":{}}`, `{"clients":[{"rawUuidAuth":"true"}]}`, `{"clients":[1]}`} {
		if _, err := s.GetClients(&model.Inbound{Settings: settings}); err == nil {
			t.Fatalf("malformed clients accepted: %s", settings)
		}
	}
	imported, err := s.GetClients(&model.Inbound{Protocol: model.AnyTLS, Settings: `{"clients":[{"password":"secret","email":"import@example.test"},{"password":"secret2","email":"disabled@example.test","enable":false}]}`})
	if err != nil || len(imported) != 2 || !imported[0].Enable || imported[1].Enable {
		t.Fatal("native import enable default/explicit false changed", err)
	}
	legacy, err := s.GetClients(&model.Inbound{Protocol: model.VMESS, Settings: `{"clients":[{"id":"id","email":"legacy@example.test"}]}`})
	if err != nil || legacy[0].Enable {
		t.Fatal("legacy enable default changed", err)
	}
}

func nativeDisabledClient(p model.Protocol, email string) map[string]any {
	c := map[string]any{"email": email, "enable": false, "level": 7, "unknownPreserved": "keep", "certificate": "client-cert", "privateKey": "client-private", "tlsCryptV2": "client-v2", "innerUsername": "inner-user"}
	switch p {
	case model.Orbit:
		c["key"] = "synthetic-connection-key"
		c["expiresAt"] = int64(1800000000)
	case model.DNSTT, model.DNS:
		c["id"] = "00112233-4455-6677-8899-aabbccddeeff"
	case model.OpenVPN:
		c["commonName"] = "client/special"
		c["clientProof"] = map[string]any{"keyId": "synthetic", "key": strings.Repeat("01", 32)}
	case model.AnyTLS:
		c["password"] = "00112233-4455-6677-8899-aabbccddeeff"
		c["uuidHashMiddle"] = true
	case model.ShadowTLS:
		c["password"] = "00112233-4455-6677-8899-aabbccddeeff"
		c["requireUuidSessionId"] = true
	case model.Mieru:
		c["username"] = "00112233-4455-6677-8899-aabbccddeeff"
		c["password"] = "synthetic-password"
		c["uuidMetadataTrailer"] = true
	}
	return c
}

func nativeTestSettings(t *testing.T, clients ...map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"clients": clients, "clientExport": map[string]any{"serverName": "export.test", "resolver": "127.0.0.1:5353"}})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestNativeClientCRUDPreservesSettings(t *testing.T) {
	openTestDB(t)
	s := new(InboundService)
	for idx, protocol := range []model.Protocol{model.Orbit, model.DNSTT, model.DNS, model.OpenVPN, model.AnyTLS, model.ShadowTLS, model.Mieru} {
		t.Run(string(protocol), func(t *testing.T) {
			email := fmt.Sprintf("first/%s%%?@example.test", protocol)
			first := nativeDisabledClient(protocol, email)
			second := nativeDisabledClient(protocol, "second-"+string(protocol)+"@example.test")
			in := &model.Inbound{Protocol: protocol, Port: 32000 + idx, Tag: "native-test-" + string(protocol), Enable: false, StreamSettings: `{}`, Sniffing: `{}`, Settings: nativeTestSettings(t, first, second)}
			created, restart, err := s.AddInbound(in)
			if err != nil || restart {
				t.Fatalf("create inactive native inbound: %v restart=%v", err, restart)
			}
			stored, err := s.GetInbound(created.Id)
			if err != nil {
				t.Fatal(err)
			}
			var raw map[string]any
			if err = json.Unmarshal([]byte(stored.Settings), &raw); err != nil {
				t.Fatal(err)
			}
			rows, err := settingsClientMaps(raw)
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 2 || rows[0].(map[string]any)["unknownPreserved"] != "keep" || rows[0].(map[string]any)["privateKey"] != "client-private" || raw["clientExport"] == nil {
				t.Fatal("create lost extra/client export fields")
			}
			clients, err := s.GetClients(stored)
			if err != nil {
				t.Fatal(err)
			}
			oldID := inboundClientID(protocol, clients[0])
			first["comment"] = "updated"
			if restart, err = s.UpdateInboundClient(&model.Inbound{Id: created.Id, Settings: nativeTestSettings(t, first)}, oldID); err != nil || restart {
				t.Fatalf("update inactive native client: %v restart=%v", err, restart)
			}
			third := nativeDisabledClient(protocol, "third-"+string(protocol)+"@example.test")
			if restart, err = s.AddInboundClient(&model.Inbound{Id: created.Id, Settings: nativeTestSettings(t, third)}); err != nil || restart {
				t.Fatalf("append inactive native client: %v restart=%v", err, restart)
			}
			if restart, err = s.DelInboundClient(created.Id, oldID); err != nil || restart {
				t.Fatalf("delete native token: %v restart=%v", err, restart)
			}
			stored, err = s.GetInbound(created.Id)
			if err != nil {
				t.Fatal(err)
			}
			remaining, err := s.GetClients(stored)
			if err != nil || len(remaining) != 2 {
				t.Fatalf("remaining clients: %d %v", len(remaining), err)
			}
			for _, c := range remaining {
				if c.Email == email {
					t.Fatal("deleted identity retained")
				}
			}
			before := stored.Settings
			if _, err = s.DelInboundClient(created.Id, "email:not-a-client"); err == nil {
				t.Fatal("unknown delete token accepted")
			}
			stored, _ = s.GetInbound(created.Id)
			if stored.Settings != before {
				t.Fatal("failed delete changed settings")
			}
		})
	}
}

func TestNativeMalformedSettingsRejectedBeforeSave(t *testing.T) {
	openTestDB(t)
	s := new(InboundService)
	in := &model.Inbound{Protocol: model.Mieru, Port: 32999, Tag: "invalid-native", Enable: false, StreamSettings: `{}`, Sniffing: `{}`, Settings: `{"transport":"invalid","clients":[{"username":"user","password":"password","email":"bad@example.test","enable":true}]}`}
	if _, _, err := s.AddInbound(in); err == nil {
		t.Fatal("invalid active native settings saved")
	}
	var count int64
	if err := database.GetDB().Model(&model.Inbound{}).Count(&count).Error; err != nil || count != 0 {
		t.Fatal("failed validation persisted inbound")
	}
	for _, settings := range []string{`{"clients":[]}`, `{"clients":{}}`, `{"clients":[null]}`} {
		if _, err := s.UpdateInboundClient(&model.Inbound{Id: 999, Settings: settings}, "id"); err == nil {
			t.Fatal("malformed update accepted")
		}
	}
}
