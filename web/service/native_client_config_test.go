package service

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	panelxray "github.com/mhsanaei/3x-ui/v2/xray"
	coreconf "github.com/xtls/xray-core/infra/conf"
)

type nativeCopyFixture struct {
	inbound         *model.Inbound
	profile         *NativeInboundProfile
	selected, other map[string]any
}

func nativeCopyJSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal("cannot encode synthetic native copy fixture")
	}
	return string(raw)
}

func nativeCopySetup(t *testing.T, protocol string) nativeCopyFixture {
	t.Helper()
	openTestDB(t)
	kind := protocol
	if kind == "dns" {
		kind = "dnstt"
	}
	request := profileTestRequest(kind)
	request.Email = "selected-" + protocol + "@example.test"
	profile, err := GenerateNativeInboundProfile(request)
	if err != nil {
		t.Fatal("cannot generate copy fixture")
	}
	settings := profileTestObject(t, profile.Settings)
	selected := settings["clients"].([]any)[0].(map[string]any)
	selected["subId"] = "shared-copy-subscription"
	request.Email = "UNSELECTED-" + protocol + "@example.test"
	extra, err := GenerateNativeInboundProfile(request)
	if err != nil {
		t.Fatal("cannot generate second copy fixture account")
	}
	other := profileTestClient(t, extra.Settings)
	other["subId"] = selected["subId"]
	switch kind {
	case "orbit":
		key, err := GenerateNativeCredentials(NativeCredentialRequest{Kind: "orbit", Certificate: profileTestString(t, profileTestObject(t, settings["tls"])["certificate"])})
		if err != nil {
			t.Fatal("cannot bind second Orbit account")
		}
		other["key"] = key["key"]
	case "openvpn":
		certs := profileTestObject(t, settings["certificates"])
		meta := profileTestObject(t, settings["clientExport"])
		issued, err := GenerateNativeOpenVPNClient(NativeCredentialRequest{CACertificate: certs["ca"].(string), IssuerPrivateKey: meta["issuerPrivateKey"].(string), ServerKey: certs["tlsCryptV2"].(string)})
		if err != nil {
			t.Fatal("cannot issue second OpenVPN account")
		}
		for key, value := range issued["client"].(map[string]any) {
			other[key] = value
		}
	case "shadowtls":
		inner := settings["inner"].(map[string]any)["settings"].(map[string]any)
		extraInner := profileTestObject(t, extra.Settings)["inner"].(map[string]any)["settings"].(map[string]any)
		inner["clients"] = append(inner["clients"].([]any), extraInner["clients"].([]any)[0])
	}
	settings["clients"] = append(settings["clients"].([]any), other)
	profile.Settings = settings
	inbound := &model.Inbound{UserId: 7, Protocol: model.Protocol(protocol), Enable: true, Listen: "192.0.2.7", Port: 24443,
		Remark: "../../private\ncopy", Tag: "native-copy-" + protocol, Settings: nativeCopyJSON(t, settings), StreamSettings: nativeCopyJSON(t, profile.StreamSettings), Sniffing: `{}`,
		ClientStats: []panelxray.ClientTraffic{{Email: selected["email"].(string), Enable: true}}}
	if err := database.GetDB().Create(inbound).Error; err != nil {
		t.Fatal("cannot persist native copy fixture")
	}
	return nativeCopyFixture{inbound: inbound, profile: profile, selected: selected, other: other}
}

func nativeCopySnapshot(t *testing.T) []byte {
	t.Helper()
	var inbounds []model.Inbound
	var traffic []panelxray.ClientTraffic
	var settings []model.Setting
	var users []model.User
	for _, query := range []struct{ dest any }{{&inbounds}, {&traffic}, {&settings}, {&users}} {
		if err := database.GetDB().Order("id").Find(query.dest).Error; err != nil {
			t.Fatal("cannot snapshot test database")
		}
	}
	return []byte(nativeCopyJSON(t, []any{inbounds, traffic, settings, users}))
}

func nativeCopyContains(raw []byte, value string) bool {
	encoded, _ := json.Marshal(value)
	return value != "" && (bytes.Contains(raw, encoded) || bytes.Contains(raw, []byte(value)))
}

func nativeCopyAssertPrivateAbsent(t *testing.T, config []byte, value any) {
	t.Helper()
	var text string
	switch v := value.(type) {
	case string:
		text = v
	case []string:
		text = strings.Join(v, "\n")
	case []any:
		var lines []string
		for _, line := range v {
			if s, ok := line.(string); ok {
				lines = append(lines, s)
			}
		}
		text = strings.Join(lines, "\n")
	}
	if text == "" {
		return
	}
	target, rest := pem.Decode([]byte(text))
	if target == nil {
		if nativeCopyContains(config, text) {
			t.Fatal("native client config exposed an unselected credential")
		}
		return
	}
	var document any
	if json.Unmarshal(config, &document) != nil {
		t.Fatal("cannot inspect client config privacy")
	}
	var candidates []*pem.Block
	add := func(text string) {
		for {
			block, rest := pem.Decode([]byte(text))
			if block == nil {
				return
			}
			candidates = append(candidates, block)
			text = string(rest)
		}
	}
	var visit func(any)
	visit = func(value any) {
		switch node := value.(type) {
		case string:
			add(node)
		case []any:
			lines := make([]string, 0, len(node))
			for _, v := range node {
				if s, ok := v.(string); ok {
					lines = append(lines, s)
				}
				visit(v)
			}
			if len(lines) == len(node) {
				add(strings.Join(lines, "\n"))
			}
		case map[string]any:
			for _, v := range node {
				visit(v)
			}
		}
	}
	visit(document)
	for target != nil {
		public := nativeCopyPrivateKeyIdentity(target)
		for _, candidate := range candidates {
			// Public certificates can share issuer/validity/algorithm lines.
			// Compare complete decoded DER, and compare private-key public
			// identities to detect another PEM spelling of the same secret.
			if bytes.Equal(target.Bytes, candidate.Bytes) || (len(public) > 0 && bytes.Equal(public, nativeCopyPrivateKeyIdentity(candidate))) {
				t.Fatal("native client config exposed private server or unselected client material")
			}
		}
		target, rest = pem.Decode(rest)
	}
}

func nativeCopyPrivateKeyIdentity(block *pem.Block) []byte {
	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil
	}
	if err != nil {
		return nil
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil
	}
	public, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil
	}
	return public
}

func TestNativeClientConfigAllProtocolsAreExactPrivateAndReadOnly(t *testing.T) {
	for _, protocol := range []string{"orbit", "dnstt", "dns", "openvpn", "anytls", "shadowtls", "mieru"} {
		t.Run(protocol, func(t *testing.T) {
			fixture := nativeCopySetup(t, protocol)
			// Matching subscription IDs in another row must not turn one-client
			// copy into a subscription-wide aggregation.
			sibling := &model.Inbound{UserId: 8, Protocol: model.Mieru, Enable: true, Listen: "192.0.2.8", Port: 24444, Tag: "unrelated-copy-row", Settings: `{"transport":"tcp","clients":[{"email":"unrelated@example.test","username":"UNRELATED-ROW-USER","password":"UNRELATED-ROW-SECRET","enable":true,"subId":"shared-copy-subscription"}]}`, StreamSettings: `{}`, Sniffing: `{}`}
			if err := database.GetDB().Create(sibling).Error; err != nil {
				t.Fatal("cannot persist unrelated copy fixture")
			}
			before := nativeCopySnapshot(t)
			if err := database.GetDB().Exec("PRAGMA query_only=ON").Error; err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = database.GetDB().Exec("PRAGMA query_only=OFF").Error })
			service := new(InboundService)
			result, err := service.GetNativeClientConfig(7, fixture.inbound.Id, fixture.selected["email"].(string), "unused.example.test")
			if err != nil || result == nil {
				t.Fatalf("native client copy failed: %v", err)
			}
			again, err := service.GetNativeClientConfig(7, fixture.inbound.Id, fixture.selected["email"].(string), "unused.example.test")
			if err != nil || again == nil || !bytes.Equal(result.Config, again.Config) || result.Filename != again.Filename {
				t.Fatal("copy regenerated or changed client material")
			}
			if !bytes.Equal(before, nativeCopySnapshot(t)) {
				t.Fatal("read-only config copy changed database state")
			}
			if !regexp.MustCompile(`^[A-Za-z0-9_-]+\.json$`).MatchString(result.Filename) || filepath.Base(result.Filename) != result.Filename || len(result.Filename) > 160 {
				t.Fatal("unsafe native config filename")
			}
			var config map[string]any
			if json.Unmarshal(result.Config, &config) != nil || config == nil {
				t.Fatal("copied configuration must be one full JSON object")
			}
			for _, field := range []string{"inbounds", "outbounds", "routing"} {
				if config[field] == nil {
					t.Fatalf("copied full config missing %s", field)
				}
			}
			if config["dns"] != nil {
				t.Fatal("copied config invented global DNS settings")
			}
			listeners, ok := config["inbounds"].([]any)
			if !ok || len(listeners) != 1 {
				t.Fatal("copy must expose only its local SOCKS listener")
			}
			listener := listeners[0].(map[string]any)
			if listener["listen"] != "127.0.0.1" || listener["port"] != float64(10808) || listener["protocol"] != "socks" || listener["settings"].(map[string]any)["udp"] != true || listener["sniffing"].(map[string]any)["routeOnly"] != true {
				t.Fatal("copied config lost safe local SOCKS template settings")
			}
			rules := config["routing"].(map[string]any)["rules"].([]any)
			if len(rules) == 0 || rules[len(rules)-1].(map[string]any)["network"] != "tcp,udp" || rules[len(rules)-1].(map[string]any)["outboundTag"] != "proxy" {
				t.Fatal("copied config lacks the final TCP/UDP proxy route")
			}
			var built coreconf.Config
			if json.Unmarshal(result.Config, &built) != nil {
				t.Fatal("copied config cannot decode in bundled core")
			}
			if _, err := built.Build(); err != nil {
				t.Fatalf("copied config cannot build in bundled core: %v", err)
			}
			for _, marker := range []string{fixture.other["email"].(string), "UNRELATED-ROW-SECRET", "UNRELATED-ROW-USER", "clientExport", "issuerPrivateKey"} {
				if nativeCopyContains(result.Config, marker) {
					t.Fatal("copy included an unrelated account or panel-only metadata")
				}
			}
			for _, key := range []string{"password", "username", "id", "key", "privateKey", "certificate", "tlsCryptV2"} {
				nativeCopyAssertPrivateAbsent(t, result.Config, fixture.other[key])
			}
			settings := fixture.profile.Settings
			if tls, ok := settings["tls"].(map[string]any); ok {
				nativeCopyAssertPrivateAbsent(t, result.Config, tls["key"])
			}
			if certs, ok := settings["certificates"].(map[string]any); ok {
				nativeCopyAssertPrivateAbsent(t, result.Config, certs["key"])
				nativeCopyAssertPrivateAbsent(t, result.Config, certs["tlsCryptV2"])
			}
			if meta, ok := settings["clientExport"].(map[string]any); ok {
				nativeCopyAssertPrivateAbsent(t, result.Config, meta["issuerPrivateKey"])
			}
			if protocol == "dnstt" || protocol == "dns" {
				nativeCopyAssertPrivateAbsent(t, result.Config, settings["privateKey"])
			}
			if protocol == "shadowtls" {
				inner := settings["inner"].(map[string]any)["settings"].(map[string]any)
				for _, raw := range inner["clients"].([]any) {
					account := raw.(map[string]any)
					if account["email"] == fixture.other["email"] {
						nativeCopyAssertPrivateAbsent(t, result.Config, account["password"])
					}
				}
			}
			if protocol == "anytls" {
				tls := profileTestObject(t, fixture.profile.StreamSettings["tlsSettings"])
				for _, cert := range tls["certificates"].([]any) {
					nativeCopyAssertPrivateAbsent(t, result.Config, cert.(map[string]any)["key"])
				}
			}
			credential := "password"
			switch protocol {
			case "orbit":
				credential = "key"
			case "dnstt", "dns":
				credential = "id"
			case "openvpn":
				credential = "privateKey"
			}
			if !nativeCopyContains(result.Config, fixture.selected[credential].(string)) {
				t.Fatal("copied config does not use the exact stored selected credential")
			}
			if protocol == "mieru" && !nativeCopyContains(result.Config, fixture.selected["username"].(string)) {
				t.Fatal("copied Mieru account has the wrong username")
			}
			if protocol == "openvpn" && !nativeCopyContains(result.Config, fixture.selected["certificate"].(string)) {
				t.Fatal("copied OpenVPN account has the wrong certificate")
			}
		})
	}
}

func TestNativeClientConfigRejectsInactiveAmbiguousAndUnauthorized(t *testing.T) {
	cases := []string{"other-owner", "no-owner", "missing-inbound", "missing-email", "email-whitespace", "email-case", "unsupported", "disabled-inbound", "expired-inbound", "inbound-quota", "inbound-quota-overflow", "disabled-client", "expired-client", "disabled-stats", "expired-stats", "stats-quota", "stats-quota-overflow", "client-quota", "client-quota-overflow", "duplicate-client", "malformed-settings", "null-settings", "missing-credential", "duplicate-stats"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			fixture := nativeCopySetup(t, "anytls")
			user, id, email := 7, fixture.inbound.Id, fixture.selected["email"].(string)
			settings := fixture.profile.Settings
			stats := fixture.inbound.ClientStats[0]
			past := time.Now().Add(-time.Minute).UnixMilli()
			switch name {
			case "other-owner":
				user = 8
			case "no-owner":
				user = 0
			case "missing-inbound":
				id += 1000
			case "missing-email":
				email = "missing@example.test"
			case "email-whitespace":
				email = " " + email + " "
			case "email-case":
				email = strings.ToUpper(email)
			case "unsupported":
				fixture.inbound.Protocol = model.VMESS
			case "disabled-inbound":
				fixture.inbound.Enable = false
			case "expired-inbound":
				fixture.inbound.ExpiryTime = past
			case "inbound-quota":
				fixture.inbound.Total = 100
				fixture.inbound.Up = 60
				fixture.inbound.Down = 40
			case "inbound-quota-overflow":
				fixture.inbound.Total = 100
				fixture.inbound.Up = math.MaxInt64
				fixture.inbound.Down = 1
			case "disabled-client":
				fixture.selected["enable"] = false
			case "expired-client":
				fixture.selected["expiryTime"] = past
			case "disabled-stats":
				stats.Enable = false
			case "expired-stats":
				stats.ExpiryTime = past
			case "stats-quota":
				stats.Total = 100
				stats.Up = 60
				stats.Down = 40
			case "stats-quota-overflow":
				stats.Total = 100
				stats.Up = math.MaxInt64
				stats.Down = 1
			case "client-quota":
				fixture.selected["totalGB"] = 100
				stats.Up = 60
				stats.Down = 40
			case "client-quota-overflow":
				fixture.selected["totalGB"] = 100
				stats.Up = math.MaxInt64
				stats.Down = 1
			case "duplicate-client":
				settings["clients"] = append(settings["clients"].([]any), profileTestObject(t, fixture.selected))
			case "missing-credential":
				delete(fixture.selected, "password")
			case "duplicate-stats":
				// Model uniqueness normally prevents this state. Reproduce an
				// old/corrupt schema only inside this test's temporary database.
				for _, statement := range []string{"CREATE TABLE client_traffics_corrupt AS SELECT * FROM client_traffics", "DROP TABLE client_traffics", "ALTER TABLE client_traffics_corrupt RENAME TO client_traffics"} {
					if err := database.GetDB().Exec(statement).Error; err != nil {
						t.Fatal("cannot construct corrupt temporary traffic schema")
					}
				}
				duplicate := stats
				duplicate.Id = stats.Id + 100
				if err := database.GetDB().Create(&duplicate).Error; err != nil {
					t.Fatal("cannot persist intentionally corrupted duplicate stats")
				}
			}
			fixture.inbound.Settings = nativeCopyJSON(t, settings)
			if name == "malformed-settings" {
				fixture.inbound.Settings = `{"clients":[PRIVATE-MARKER`
			}
			if name == "null-settings" {
				fixture.inbound.Settings = `null`
			}
			fixture.inbound.ClientStats = nil
			if err := database.GetDB().Save(fixture.inbound).Error; err != nil {
				t.Fatal(err)
			}
			if err := database.GetDB().Save(&stats).Error; err != nil {
				t.Fatal(err)
			}
			before := nativeCopySnapshot(t)
			result, err := new(InboundService).GetNativeClientConfig(user, id, email, "vpn.example.test")
			if err == nil || result != nil {
				t.Fatal("unauthorized, inactive, corrupt or ambiguous copy returned credentials")
			}
			selectedPassword, _ := fixture.selected["password"].(string)
			for _, marker := range []string{"PRIVATE-MARKER", selectedPassword, fixture.other["email"].(string), "SELECT ", "UNIQUE constraint"} {
				if marker != "" && strings.Contains(err.Error(), marker) {
					t.Fatal("copy error exposed credential or database diagnostics")
				}
			}
			if !bytes.Equal(before, nativeCopySnapshot(t)) {
				t.Fatal("rejected copy changed database state")
			}
		})
	}
}

func TestNativeClientConfigAllowsMissingStatsAndExactSharedSubscription(t *testing.T) {
	fixture := nativeCopySetup(t, "mieru")
	if err := database.GetDB().Where("inbound_id = ?", fixture.inbound.Id).Delete(&panelxray.ClientTraffic{}).Error; err != nil {
		t.Fatal(err)
	}
	service := new(InboundService)
	first, err := service.GetNativeClientConfig(7, fixture.inbound.Id, fixture.selected["email"].(string), "vpn.example.test")
	if err != nil || first == nil {
		t.Fatal("active configured account without traffic stats should be exportable")
	}
	second, err := service.GetNativeClientConfig(7, fixture.inbound.Id, fixture.other["email"].(string), "vpn.example.test")
	if err != nil || second == nil {
		t.Fatal("exact second account sharing subscription ID should be exportable")
	}
	if bytes.Equal(first.Config, second.Config) || !nativeCopyContains(first.Config, fixture.selected["password"].(string)) || nativeCopyContains(first.Config, fixture.other["password"].(string)) || !nativeCopyContains(second.Config, fixture.other["password"].(string)) {
		t.Fatal("shared subscription IDs confused exact client selection")
	}
}

func TestNativeClientConfigOrbitAccountExpiryIsEnforced(t *testing.T) {
	fixture := nativeCopySetup(t, "orbit")
	fixture.selected["expiresAt"] = time.Now().Add(-time.Minute).Unix()
	fixture.inbound.Settings = nativeCopyJSON(t, fixture.profile.Settings)
	if err := database.GetDB().Save(fixture.inbound).Error; err != nil {
		t.Fatal(err)
	}
	before := nativeCopySnapshot(t)
	if result, err := new(InboundService).GetNativeClientConfig(7, fixture.inbound.Id, fixture.selected["email"].(string), "vpn.example.test"); err == nil || result != nil {
		t.Fatal("expired Orbit protocol account returned client credentials")
	}
	if !bytes.Equal(before, nativeCopySnapshot(t)) {
		t.Fatal("expired Orbit account export mutated saved data")
	}
}
