package sub

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/web/service"
	"github.com/op/go-logging"
)

func TestNativeProfileReviewAddedShadowTLSClientExportsOnlyMatchedSecrets(t *testing.T) {
	t.Setenv("XUI_LOG_FOLDER", t.TempDir())
	logger.InitLogger(logging.ERROR)
	t.Cleanup(logger.CloseLogger)
	if err := database.InitDB(filepath.Join(t.TempDir(), "panel.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.CloseDB() })
	makeProfile := func(email string) *service.NativeInboundProfile {
		profile, err := service.GenerateNativeInboundProfile(service.NativeCredentialRequest{Protocol: "shadowtls", Email: email, HandshakeAddress: "cover.example.test"})
		if err != nil {
			t.Fatal(err)
		}
		return profile
	}
	first, second := makeProfile("first@example.test"), makeProfile("second@example.test")
	firstSettings, secondSettings := nativeTestMap(t, first.Settings), nativeTestMap(t, second.Settings)
	firstInner := firstSettings["inner"].(map[string]any)["settings"].(map[string]any)
	secondInner := secondSettings["inner"].(map[string]any)["settings"].(map[string]any)
	newOuter := secondSettings["clients"].([]any)[0].(map[string]any)
	newInner := secondInner["clients"].([]any)[0].(map[string]any)
	inbound := &model.Inbound{Protocol: model.ShadowTLS, Listen: "127.0.0.1", Port: 34493, Tag: "profile-review-append-export", Enable: true, Settings: nativeTestJSONString(t, firstSettings), StreamSettings: `{}`, Sniffing: `{}`}
	if err := database.GetDB().Create(inbound).Error; err != nil {
		t.Fatal(err)
	}
	request := map[string]any{"clients": []any{newOuter}, "inner": map[string]any{"protocol": "shadowsocks", "settings": map[string]any{"clients": []any{newInner}}}}
	s := new(service.InboundService)
	if restart, err := s.AddInboundClient(&model.Inbound{Id: inbound.Id, Settings: nativeTestJSONString(t, request)}); err != nil || !restart {
		t.Fatalf("new native client: restart=%v err=%v", restart, err)
	}
	stored, err := s.GetInbound(inbound.Id)
	if err != nil {
		t.Fatal(err)
	}
	clients, err := s.GetClients(stored)
	if err != nil || len(clients) != 2 {
		t.Fatalf("stored clients: %d %v", len(clients), err)
	}
	// Exercise the same standalone client edit route after adding an account.
	oldEmail := clients[1].Email
	clients[1].Email = "renamed@example.test"
	rename := map[string]any{"clients": []any{clients[1]}}
	clientID := "email:" + base64.RawURLEncoding.EncodeToString([]byte(oldEmail))
	if restart, err := s.UpdateInboundClient(&model.Inbound{Id: inbound.Id, Settings: nativeTestJSONString(t, rename)}, clientID); err != nil || !restart {
		t.Fatalf("rename bound subscriber: restart=%v err=%v", restart, err)
	}
	stored, err = s.GetInbound(inbound.Id)
	if err != nil {
		t.Fatal(err)
	}
	clients, err = s.GetClients(stored)
	if err != nil || len(clients) != 2 || clients[1].Email != "renamed@example.test" {
		t.Fatal("renamed outer identity was not persisted")
	}
	for i, client := range clients {
		outs, err := nativeClientOutbounds(stored, client, "192.0.2.7")
		if err != nil {
			t.Fatal("appended account is not exportable", err)
		}
		nativeTestOutboundsBuild(t, outs)
		server := nativeTestMap(t, nativeTestSettings(t, outs[0])["servers"].([]any)[0])
		selected, other := firstInner["clients"].([]any)[0].(map[string]any), newInner
		outerOther := newOuter
		if i == 1 {
			selected, other = newInner, selected
			outerOther = firstSettings["clients"].([]any)[0].(map[string]any)
		}
		if server["password"] != firstInner["password"].(string)+":"+selected["password"].(string) || server["uot"] != true || server["uotVersion"] != float64(2) {
			t.Fatal("subscriber got wrong inner identity, shared key or UDP carrier settings")
		}
		text := nativeTestJSONString(t, outs)
		for _, secret := range []string{other["password"].(string), outerOther["password"].(string)} {
			if strings.Contains(text, secret) {
				t.Fatal("subscription contains unrelated subscriber secret")
			}
		}
	}
}

func TestNativeProfileReviewAnyTLSExplicitTrustFiltersPrivatePEM(t *testing.T) {
	profile, inbound, client := nativeProfileExportFixture(t, "anytls")
	settings := nativeTestMap(t, profile.Settings)
	meta := settings["clientExport"].(map[string]any)
	ca := meta["ca"].(string)
	serverTLS := nativeTestMap(t, profile.StreamSettings)["tlsSettings"].(map[string]any)
	material := serverTLS["certificates"].([]any)[0].(map[string]any)
	keyLines := material["key"].([]any)
	var keyText []string
	for _, line := range keyLines {
		keyText = append(keyText, line.(string))
	}
	bundle := ca + "\n" + strings.Join(keyText, "\n")
	for _, format := range []string{"string", "lines"} {
		t.Run(format, func(t *testing.T) {
			meta["ca"] = bundle
			if format == "lines" {
				meta["ca"] = strings.Split(bundle, "\n")
			}
			inbound.Settings = nativeTestJSONString(t, settings)
			outs, err := nativeClientOutbounds(inbound, client, "192.0.2.7")
			if err != nil {
				t.Fatal(err)
			}
			nativeTestOutboundsBuild(t, outs)
			nativeProfileAssertNoServerSecrets(t, profile, outs)
			trust := nativeTestSettings(t, outs[0])["tlsSettings"].(map[string]any)
			if trust["serverName"] != "vpn.example.test" || trust["allowInsecure"] == true {
				t.Fatal("explicit trust weakened hostname/certificate verification")
			}
			roots := x509.NewCertPool()
			for _, block := range nativeProfilePEMBlocks(trust["certificates"]) {
				if block.Type != "CERTIFICATE" {
					t.Fatal("private or unknown PEM exported as trust")
				}
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					t.Fatal(err)
				}
				roots.AddCert(cert)
			}
			blocks := nativeProfilePEMBlocks(material["certificate"])
			leaf, err := x509.ParseCertificate(blocks[0].Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "vpn.example.test"}); err != nil {
				t.Fatal("filtered public trust cannot verify generated server", err)
			}
		})
	}
	for _, invalid := range []any{strings.Join(keyText, "\n"), []any{ca, 4}, map[string]any{"certificateFile": "/etc/shadow"}, 4, []any{}, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid DER")}))} {
		meta["ca"] = invalid
		inbound.Settings = nativeTestJSONString(t, settings)
		if outs, err := nativeClientOutbounds(inbound, client, "192.0.2.7"); err == nil || len(outs) != 0 {
			t.Fatal("malformed or noncertificate explicit trust produced subscription")
		}
	}
	// The PEM parser also accepts native Go []string input before JSON storage.
	trust, err := exportPublicCertificateTrust(map[string]any{"certificates": []any{map[string]any{"certificate": strings.Split(bundle, "\n")}}})
	if err != nil || len(trust) != 1 {
		t.Fatal("native string-array trust rejected")
	}
	encoded, _ := json.Marshal(trust)
	if bytes.Contains(encoded, []byte("PRIVATE KEY")) {
		t.Fatal("private PEM retained")
	}
}
