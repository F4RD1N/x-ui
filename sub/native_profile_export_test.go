package sub

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/web/service"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/ctlwrap"
)

// These tests exercise generated, ephemeral material through the real JSON
// subscription exporter. No listener, external resolver, or cover server runs.
func nativeProfileExportFixture(t *testing.T, protocol string) (*service.NativeInboundProfile, *model.Inbound, model.Client) {
	t.Helper()
	request := service.NativeCredentialRequest{
		Kind: "inbound-profile", Protocol: protocol, ServerName: "vpn.example.test",
		Email: exportEmail, Domain: "t.example.test", HandshakeAddress: "cover.example.test", Port: 1443,
	}
	if protocol == "orbit" {
		request.ServerAddress = "192.0.2.7"
	}
	return nativeProfileExportRequest(t, request)
}

func nativeProfileExportRequest(t *testing.T, request service.NativeCredentialRequest) (*service.NativeInboundProfile, *model.Inbound, model.Client) {
	t.Helper()
	protocol := request.Protocol
	profile, err := service.GenerateNativeInboundProfile(request)
	if err != nil {
		t.Fatalf("generate %s profile: %v", protocol, err)
	}
	if profile == nil || profile.Protocol != protocol {
		t.Fatal("profile protocol differs from request")
	}
	settings := nativeTestMap(t, profile.Settings)
	rows, ok := settings["clients"].([]any)
	if !ok || len(rows) != 1 {
		t.Fatal("profile must contain one initial managed client")
	}
	var client model.Client
	if err := json.Unmarshal([]byte(nativeTestJSONString(t, rows[0])), &client); err != nil {
		t.Fatal(err)
	}
	if client.Email == "" || (request.Email != "" && client.Email != request.Email) || !client.Enable || client.SubID == "" {
		t.Fatal("generated client is not enabled and exportable by its exact identity")
	}
	// An unrelated first row detects accidental first-account selection. Stored
	// account records are preserved verbatim, including future export metadata.
	settings["clients"] = append([]any{map[string]any{
		"email": "other@example.test", "enable": true, "id": exportOtherUUID,
		"password": "OTHER-PROFILE-PASSWORD", "key": "OTHER-PROFILE-CONNECTION-KEY",
		"privateKey": "OTHER-PROFILE-PRIVATE-KEY", "certificate": "OTHER-PROFILE-CERTIFICATE",
	}}, rows...)
	if protocol == "shadowtls" {
		inner := settings["inner"].(map[string]any)["settings"].(map[string]any)
		inner["clients"] = append([]any{map[string]any{"email": "other@example.test", "password": "OTHER-INNER-PROFILE-PASSWORD"}}, inner["clients"].([]any)...)
	}
	stream := "{}"
	if profile.StreamSettings != nil {
		stream = nativeTestJSONString(t, profile.StreamSettings)
	}
	inbound := &model.Inbound{Protocol: model.Protocol(protocol), Listen: "0.0.0.0", Port: 1443, Tag: "profile-" + protocol,
		Remark: "Generated profile", Settings: nativeTestJSONString(t, settings), StreamSettings: stream, Sniffing: "{}", Enable: true}
	return profile, inbound, client
}

func nativeProfilePEMBlocks(value any) []*pem.Block {
	var blocks []*pem.Block
	var visit func(any)
	parse := func(text string) {
		data := []byte(text)
		for len(data) > 0 {
			block, rest := pem.Decode(data)
			if block == nil {
				break
			}
			blocks = append(blocks, block)
			data = rest
		}
	}
	visit = func(v any) {
		switch v := v.(type) {
		case string:
			parse(v)
		case map[string]any:
			for _, field := range v {
				visit(field)
			}
		case []string:
			parse(strings.Join(v, "\n"))
		case []any:
			lines := make([]string, 0, len(v))
			for _, item := range v {
				if line, ok := item.(string); ok {
					lines = append(lines, line)
				}
				visit(item)
			}
			if len(lines) == len(v) {
				parse(strings.Join(lines, "\n"))
			}
		}
	}
	visit(value)
	return blocks
}

func nativeProfileAssertNoServerSecrets(t *testing.T, profile *service.NativeInboundProfile, output any) {
	t.Helper()
	serverMaterial := nativeTestMap(t, profile.Settings)
	delete(serverMaterial, "clients")
	// Include all metadata so retained private CA issuer material, if present,
	// is also checked. Only selected client PEM belongs in a subscription.
	serverMaterial["streamSettings"] = profile.StreamSettings
	forbidden := nativeProfilePEMBlocks(serverMaterial)
	outputMap := nativeTestMap(t, map[string]any{"output": output})
	for _, exported := range nativeProfilePEMBlocks(outputMap) {
		for _, server := range forbidden {
			if (strings.Contains(server.Type, "PRIVATE KEY") || server.Type == "OpenVPN tls-crypt-v2 server key") && bytes.Equal(exported.Bytes, server.Bytes) {
				t.Fatal("subscription exported a server or private CA issuer key")
			}
		}
		if exported.Type == "OpenVPN tls-crypt-v2 server key" {
			t.Fatal("subscription contains a server wrapping key")
		}
	}
	text := nativeTestJSONString(t, output)
	for _, marker := range []string{"OTHER-PROFILE-", "OTHER-INNER-PROFILE-", "other@example.test", "clientExport"} {
		if strings.Contains(text, marker) {
			t.Fatalf("unrelated identity or panel metadata exported: %s", marker)
		}
	}
}

func TestNativeProfileExportAllGeneratedProtocols(t *testing.T) {
	for _, protocol := range []string{"orbit", "dnstt", "openvpn", "anytls", "shadowtls", "mieru"} {
		t.Run(protocol, func(t *testing.T) {
			profile, inbound, client := nativeProfileExportFixture(t, protocol)
			storedSettings, storedStream := inbound.Settings, inbound.StreamSettings
			outs, err := nativeClientOutbounds(inbound, client, "192.0.2.7")
			if err != nil {
				t.Fatal(err)
			}
			nativeTestOutboundsBuild(t, outs)
			nativeProfileAssertNoServerSecrets(t, profile, outs)
			s := NewSubJsonService("", "", "", "", NewSubService(false, "-ieo"))
			configs, err := s.getNativeConfig(inbound, client, "192.0.2.7")
			if err != nil || len(configs) != 1 {
				t.Fatalf("generated profile complete JSON: count=%d error=%v", len(configs), err)
			}
			var config conf.Config
			if err := json.Unmarshal(configs[0], &config); err != nil {
				t.Fatal(err)
			}
			if _, err := config.Build(); err != nil {
				t.Fatalf("generated complete JSON does not load: %v", err)
			}
			var document map[string]any
			if err := json.Unmarshal(configs[0], &document); err != nil {
				t.Fatal(err)
			}
			nativeProfileAssertNoServerSecrets(t, profile, document)
			if inbound.Settings != storedSettings || inbound.StreamSettings != storedStream {
				t.Fatal("export changed the generated stored profile")
			}
			client.Email = "missing@example.test"
			if got, err := s.getNativeConfig(inbound, client, "192.0.2.7"); err == nil || len(got) != 0 {
				t.Fatal("absent subscriber produced a fallback configuration")
			}
		})
	}
}

func TestNativeProfileExportGeneratedProtocolMaterial(t *testing.T) {
	for _, protocol := range []string{"orbit", "dnstt", "openvpn", "anytls", "shadowtls", "mieru"} {
		t.Run(protocol, func(t *testing.T) {
			profile, inbound, client := nativeProfileExportFixture(t, protocol)
			exportHost := "192.0.2.7"
			if protocol == "orbit" {
				exportHost = "subscription.example.test"
			}
			outs, err := nativeClientOutbounds(inbound, client, exportHost)
			if err != nil {
				t.Fatal(err)
			}
			settings := nativeTestSettings(t, outs[0])
			switch protocol {
			case "orbit":
				if settings["key"] != client.Key || settings["transport"] != "tcp" || settings["address"] != "192.0.2.7" {
					t.Fatal("Orbit export lost its selected account or transport")
				}
				if _, exists := settings["peer"]; exists {
					t.Fatal("Orbit TCP export contains a WebSocket-only peer field")
				}
				tlsMaterial := nativeTestMap(t, profile.Settings["tls"])
				var leaf *x509.Certificate
				for _, block := range nativeProfilePEMBlocks(tlsMaterial["certificate"]) {
					leaf, err = x509.ParseCertificate(block.Bytes)
					if err != nil {
						t.Fatal(err)
					}
					break
				}
				if leaf == nil {
					t.Fatal("Orbit leaf is missing")
				}
				for _, name := range []string{"192.0.2.7", "vpn.example.test"} {
					if err := leaf.VerifyHostname(name); err != nil {
						t.Fatalf("Orbit leaf does not authenticate the selected endpoint or supplied name: %v", err)
					}
				}
				if err := leaf.VerifyHostname("192.0.2.8"); err == nil {
					t.Fatal("Orbit leaf accepts an unrelated endpoint")
				}
				key, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(client.Key, "vck1_"))
				pin := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
				if err != nil || len(key) != 64 || !bytes.Equal(key[32:], pin[:]) {
					t.Fatal("Orbit client key is not bound to the generated leaf")
				}
			case "dnstt":
				private, err := hex.DecodeString(profile.Settings["privateKey"].(string))
				if err != nil {
					t.Fatal(err)
				}
				key, err := ecdh.X25519().NewPrivateKey(private)
				if err != nil {
					t.Fatal(err)
				}
				public := hex.EncodeToString(key.PublicKey().Bytes())
				if outs[0]["protocol"] != "dns" || settings["publicKey"] != public || profile.PublicKey != public || settings["domain"] != "t.example.test" {
					t.Fatal("DNS tunnel public identity differs from generated server")
				}
				resolvers := settings["resolvers"].([]any)
				if len(resolvers) != 1 || nativeTestMap(t, resolvers[0])["address"] != "192.0.2.7:1443" || nativeTestMap(t, resolvers[0])["transport"] != "udp" {
					t.Fatal("DNS resolver did not follow the deployed endpoint")
				}
				if nativeTestMap(t, settings["inner"])["uuid"] != client.ID {
					t.Fatal("DNS tunnel selected UUID lost")
				}
			case "openvpn":
				certs := nativeTestMap(t, settings["certificates"])
				if certs["cert"] != client.Certificate || certs["key"] != client.PrivateKey || certs["tlsCryptV2"] != client.TLSCryptV2 {
					t.Fatal("OpenVPN client material lost during export")
				}
				server := nativeTestMap(t, profile.Settings["certificates"])
				wrapping, err := ctlwrap.ParseTLSCryptV2ServerKey([]byte(server["tlsCryptV2"].(string)))
				if err != nil {
					t.Fatal(err)
				}
				clientKey, wrapped, err := ctlwrap.ParseTLSCryptV2ClientKey([]byte(client.TLSCryptV2))
				if err != nil {
					t.Fatal(err)
				}
				unwrapped, _, err := ctlwrap.UnwrapTLSCryptV2ClientKey(wrapping, wrapped)
				if err != nil || !bytes.Equal(clientKey[:], unwrapped[:]) {
					t.Fatal("exported client control key is not issued by generated server")
				}
			case "anytls":
				tlsSettings := nativeTestMap(t, settings["tlsSettings"])
				if settings["password"] != client.Password || tlsSettings["serverName"] != "vpn.example.test" || tlsSettings["allowInsecure"] == true {
					t.Fatal("AnyTLS export lost credential or secure hostname verification")
				}
				pool := x509.NewCertPool()
				for _, block := range nativeProfilePEMBlocks(tlsSettings["certificates"]) {
					if block.Type != "CERTIFICATE" {
						t.Fatal("AnyTLS trust contains private material")
					}
					cert, err := x509.ParseCertificate(block.Bytes)
					if err != nil {
						t.Fatal(err)
					}
					pool.AddCert(cert)
				}
				stream := nativeTestMap(t, profile.StreamSettings)
				serverTLS := nativeTestMap(t, stream["tlsSettings"])
				blocks := nativeProfilePEMBlocks(serverTLS["certificates"])
				var leaf *x509.Certificate
				for _, block := range blocks {
					if block.Type == "CERTIFICATE" {
						leaf, err = x509.ParseCertificate(block.Bytes)
						if err != nil {
							t.Fatal(err)
						}
						break
					}
				}
				if leaf == nil {
					t.Fatal("AnyTLS generated leaf missing")
				}
				if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "vpn.example.test"}); err != nil {
					t.Fatalf("exported trust does not authenticate generated TLS server: %v", err)
				}
				if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "wrong.example.test"}); err == nil {
					t.Fatal("exported trust accepts wrong hostname")
				}
			case "shadowtls":
				if len(outs) != 2 || outs[0]["protocol"] != "shadowsocks" || outs[1]["protocol"] != "shadowtls" {
					t.Fatal("ShadowTLS encrypted inner graph lost")
				}
				inner := nativeTestMap(t, nativeTestMap(t, profile.Settings["inner"])["settings"])
				innerClients := inner["clients"].([]any)
				selected := nativeTestMap(t, innerClients[0])
				server := nativeTestMap(t, settings["servers"].([]any)[0])
				if selected["email"] != client.Email || server["password"] != inner["password"].(string)+":"+selected["password"].(string) || server["method"] != "2022-blake3-aes-256-gcm" || server["uot"] != true || server["uotVersion"] != float64(2) {
					t.Fatal("ShadowTLS selected encrypted identity or UoT metadata lost")
				}
				carrier := nativeTestSettings(t, outs[1])
				if carrier["password"] != client.Password || carrier["serverName"] != "cover.example.test" || carrier["strict"] != true || carrier["allowInsecure"] == true {
					t.Fatal("ShadowTLS cover verification or outer identity lost")
				}
			case "mieru":
				if settings["username"] != client.Username || settings["password"] != client.Password || settings["transport"] != "tcp" {
					t.Fatal("Mieru secure transport default or account lost")
				}
			}
		})
	}
}

func TestNativeProfileExportGeneratedUsableDefaults(t *testing.T) {
	for _, protocol := range []string{"orbit", "openvpn", "mieru"} {
		t.Run(protocol, func(t *testing.T) {
			request := service.NativeCredentialRequest{Kind: "inbound-profile", Protocol: protocol}
			if protocol == "orbit" {
				request.ServerAddress = "192.0.2.7"
			}
			profile, inbound, client := nativeProfileExportRequest(t, request)
			if len(profile.Requirements) != 0 {
				t.Fatal("usable generated profile still has missing deployment requirements")
			}
			if protocol == "openvpn" {
				tunnel := nativeTestMap(t, profile.Settings["tunnel"])
				if dns, present := tunnel["dns"]; present && dns != nil {
					servers, ok := dns.([]any)
					if !ok || len(servers) != 0 {
						t.Fatal("OpenVPN generation invented a DNS resolver")
					}
				}
				certificates := nativeTestMap(t, profile.Settings["certificates"])
				blocks := nativeProfilePEMBlocks(certificates["cert"])
				if len(blocks) != 1 {
					t.Fatal("OpenVPN generated server leaf is missing")
				}
				leaf, err := x509.ParseCertificate(blocks[0].Bytes)
				if err != nil {
					t.Fatal(err)
				}
				if len(leaf.DNSNames) != 0 || len(leaf.IPAddresses) != 0 {
					t.Fatal("OpenVPN generation invented a certificate deployment identity")
				}
			} else if protocol == "orbit" {
				material := nativeTestMap(t, profile.Settings["tls"])
				blocks := nativeProfilePEMBlocks(material["certificate"])
				if len(blocks) != 1 {
					t.Fatal("Orbit generated server leaf is missing")
				}
				leaf, err := x509.ParseCertificate(blocks[0].Bytes)
				if err != nil {
					t.Fatal(err)
				}
				if len(leaf.DNSNames) != 0 || len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != "192.0.2.7" {
					t.Fatal("IP-only Orbit request invented a DNS identity or lost its selected IP")
				}
			}
			outs, err := nativeClientOutbounds(inbound, client, "192.0.2.7")
			if err != nil {
				t.Fatal(err)
			}
			nativeTestOutboundsBuild(t, outs)
			nativeProfileAssertNoServerSecrets(t, profile, outs)
			jsonService := NewSubJsonService("", "", "", "", NewSubService(false, "-ieo"))
			configs, err := jsonService.getNativeConfig(inbound, client, "192.0.2.7")
			if err != nil || len(configs) != 1 {
				t.Fatalf("default profile subscription failed: count=%d error=%v", len(configs), err)
			}
			var config conf.Config
			if err := json.Unmarshal(configs[0], &config); err != nil {
				t.Fatal(err)
			}
			if _, err := config.Build(); err != nil {
				t.Fatalf("default generated subscriber configuration does not load: %v", err)
			}
		})
	}
}

func TestNativeProfileExportIncompleteDeploymentRequirements(t *testing.T) {
	for _, tc := range []struct {
		protocol, field string
	}{
		{"anytls", "serverName"},
		{"orbit", "serverAddress"},
		{"dnstt", "domain"},
		{"shadowtls", "handshake.address"},
	} {
		t.Run(tc.protocol, func(t *testing.T) {
			profile, inbound, client := nativeProfileExportRequest(t, service.NativeCredentialRequest{Kind: "inbound-profile", Protocol: tc.protocol})
			found := false
			for _, requirement := range profile.Requirements {
				if requirement.Field == tc.field && requirement.Message != "" {
					found = true
				}
			}
			if !found {
				t.Fatal("missing deployment identity was not reported as a requirement")
			}
			text := nativeTestJSONString(t, profile)
			for _, invented := range []string{"vpn.internal", "tunnel.invalid", "www.microsoft.com", "1.1.1.1", "8.8.8.8"} {
				if strings.Contains(text, invented) {
					t.Fatalf("incomplete profile contains invented deployment value %s", invented)
				}
			}
			switch tc.protocol {
			case "anytls":
				if client.Password == "" || len(nativeProfilePEMBlocks(profile.Settings)) != 0 || len(nativeProfilePEMBlocks(profile.StreamSettings)) != 0 {
					t.Fatal("AnyTLS must retain authentication without inventing a server certificate")
				}
				stream := nativeTestMap(t, profile.StreamSettings)
				if stream["network"] != "tcp" || stream["security"] != "tls" {
					t.Fatal("incomplete AnyTLS profile lost its secure transport skeleton")
				}
			case "orbit":
				if client.Key != "" || profile.Settings["transport"] != "tcp" || len(nativeProfilePEMBlocks(profile.Settings)) != 0 {
					t.Fatal("Orbit generated an endpoint-bound key before its endpoint was supplied")
				}
			case "dnstt":
				if profile.Settings["domain"] != "" || client.ID == "" {
					t.Fatal("DNS tunnel must leave its domain blank and retain client authentication")
				}
				private, err := hex.DecodeString(profile.Settings["privateKey"].(string))
				if err != nil {
					t.Fatal(err)
				}
				key, err := ecdh.X25519().NewPrivateKey(private)
				if err != nil || profile.PublicKey != hex.EncodeToString(key.PublicKey().Bytes()) {
					t.Fatal("missing deployment domain discarded or corrupted generated DNS tunnel keys")
				}
			case "shadowtls":
				if nativeTestMap(t, profile.Settings["handshake"])["address"] != "" || client.Password == "" {
					t.Fatal("ShadowTLS must leave its cover blank and retain outer authentication")
				}
				inner := nativeTestMap(t, nativeTestMap(t, profile.Settings["inner"])["settings"])
				selected := nativeTestMap(t, inner["clients"].([]any)[0])
				serverKey, err := base64.StdEncoding.DecodeString(inner["password"].(string))
				if err != nil || len(serverKey) != 32 {
					t.Fatal("incomplete ShadowTLS profile lost its encrypted-inner server key")
				}
				userKey, err := base64.StdEncoding.DecodeString(selected["password"].(string))
				if err != nil || len(userKey) != 32 || bytes.Equal(serverKey, userKey) || selected["email"] != client.Email {
					t.Fatal("incomplete ShadowTLS profile lost its independent selected user key")
				}
			}
			// Requirements stop incomplete profiles at the form/save boundary.
			// An exporter may return an incomplete graph, but a missing domain,
			// cover or Orbit account cannot build into a usable outbound.
			// AnyTLS outbound syntax alone cannot prove server certificate setup.
			if tc.protocol != "anytls" {
				if outs, err := nativeClientOutbounds(inbound, client, "192.0.2.7"); err == nil {
					var config conf.Config
					if err := json.Unmarshal([]byte(nativeTestJSONString(t, map[string]any{"outbounds": outs})), &config); err != nil {
						t.Fatal(err)
					}
					if _, err := config.Build(); err == nil {
						t.Fatal("incomplete deployment unexpectedly built a usable outbound")
					}
				}
			}
		})
	}
}
