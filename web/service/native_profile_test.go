package service

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	coreconf "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/openvpn"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/ctlwrap"
	"github.com/xtls/xray-core/proxy/orbit"
)

func profileTestRequest(protocol string) NativeCredentialRequest {
	request := NativeCredentialRequest{Kind: "inbound-profile", Protocol: protocol, ServerName: "vpn.example.test", Email: "profile@example.test", Domain: "tunnel.example.test", HandshakeAddress: "cover.example.test"}
	if protocol == "orbit" {
		request.ServerAddress = "192.0.2.7"
	}
	return request
}

func profileTestGenerate(t *testing.T, protocol string) *NativeInboundProfile {
	t.Helper()
	profile, err := GenerateNativeInboundProfile(profileTestRequest(protocol))
	if err != nil || profile == nil {
		t.Fatalf("%s generation failed: %v", protocol, err)
	}
	return profile
}

func profileTestObject(t *testing.T, value any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal("cannot encode generated profile object")
	}
	var result map[string]any
	if json.Unmarshal(raw, &result) != nil || result == nil {
		t.Fatal("expected generated profile object")
	}
	return result
}

func profileTestClient(t *testing.T, settings map[string]any) map[string]any {
	t.Helper()
	rows, ok := profileTestObject(t, settings)["clients"].([]any)
	if !ok || len(rows) != 1 {
		t.Fatal("generated profile must contain exactly one selected client")
	}
	return profileTestObject(t, rows[0])
}

func profileTestString(t *testing.T, value any) string {
	t.Helper()
	if result, ok := value.(string); ok && result != "" {
		return result
	}
	// The protocol TLS schema stores PEM as lines; OpenVPN uses a string.
	raw, _ := json.Marshal(value)
	var lines []string
	if json.Unmarshal(raw, &lines) == nil && len(lines) > 0 {
		return strings.Join(lines, "\n")
	}
	t.Fatal("required generated string or PEM lines missing")
	return ""
}

func profileTestCertificate(t *testing.T, value any) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(profileTestString(t, value)))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("generated public certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal("generated public certificate is not X509")
	}
	if time.Now().Before(cert.NotBefore) || !time.Now().Add(24*time.Hour).Before(cert.NotAfter) {
		t.Fatal("generated certificate is not currently valid for at least one day")
	}
	return cert
}

func profileTestKeyPair(t *testing.T, certificate, key any) *x509.Certificate {
	t.Helper()
	if _, err := tls.X509KeyPair([]byte(profileTestString(t, certificate)), []byte(profileTestString(t, key))); err != nil {
		t.Fatal("generated leaf certificate and private key do not match")
	}
	return profileTestCertificate(t, certificate)
}

func profileTestVerify(t *testing.T, leaf, root *x509.Certificate, name string, usage x509.ExtKeyUsage) {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: name, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
		t.Fatalf("generated certificate chain, hostname or EKU is invalid: %v", err)
	}
}

func TestNativeProfilesBuildThroughPanelProjection(t *testing.T) {
	for _, protocol := range []string{"orbit", "dnstt", "openvpn", "anytls", "shadowtls", "mieru"} {
		t.Run(protocol, func(t *testing.T) {
			profile := profileTestGenerate(t, protocol)
			if profile.Protocol != protocol {
				t.Fatal("generated protocol differs from request")
			}
			client := profileTestClient(t, profile.Settings)
			if client["email"] != "profile@example.test" || client["enable"] != true || profileTestString(t, client["subId"]) == "" {
				t.Fatal("generated account lacks usable panel subscription metadata")
			}
			for _, field := range []string{"uuidHashMiddle", "requireUuidSessionId", "uuidMetadataTrailer", "uuidIdentityKeys", "rawUuidAuth", "uuidHashPrefix", "clientProof"} {
				if value, exists := client[field]; exists && value != false {
					t.Fatalf("custom authentication %s was unexpectedly enabled by default", field)
				}
			}
			before, _ := json.Marshal(profile)
			settings, _ := json.Marshal(profile.Settings)
			projected, err := coreInboundSettingsAt(protocol, string(settings), nil, time.Now().UnixMilli())
			if err != nil {
				t.Fatalf("generated profile cannot be projected: %v", err)
			}
			inbound := map[string]any{"tag": "profile-test", "protocol": protocol, "listen": "127.0.0.1", "port": 31415, "settings": json.RawMessage(projected)}
			if len(profile.StreamSettings) > 0 {
				inbound["streamSettings"] = profile.StreamSettings
			}
			raw, _ := json.Marshal(map[string]any{"inbounds": []any{inbound}, "outbounds": []any{map[string]any{"protocol": "blackhole", "tag": "blocked"}}})
			var config coreconf.Config
			if err := json.Unmarshal(raw, &config); err != nil {
				t.Fatal("generated full configuration cannot be decoded")
			}
			if _, err := config.Build(); err != nil {
				t.Fatalf("generated full configuration cannot be built: %v", err)
			}
			after, _ := json.Marshal(profile)
			if !bytes.Equal(before, after) {
				t.Fatal("runtime projection changed the stored profile")
			}
		})
	}
}

func TestNativeProfileOrbitLeafPin(t *testing.T) {
	profile := profileTestGenerate(t, "orbit")
	if profile.Settings["transport"] != "tcp" {
		t.Fatal("Orbit profile must use the protected TCP carrier by default")
	}
	for _, field := range []string{"host", "path", "outerTls"} {
		if value, exists := profile.Settings[field]; exists && value != "" && value != nil {
			t.Fatalf("TCP profile unexpectedly contains incompatible %s", field)
		}
	}
	material := profileTestObject(t, profile.Settings["tls"])
	leaf := profileTestKeyPair(t, material["certificate"], material["key"])
	if leaf.IsCA {
		t.Fatal("Orbit identity must pin a non-CA leaf")
	}
	if err := leaf.VerifyHostname("vpn.example.test"); err != nil {
		t.Fatal("Orbit leaf SAN differs from requested server name")
	}
	if err := leaf.VerifyHostname("192.0.2.7"); err != nil {
		t.Fatal("Orbit leaf must also verify the actual selected numeric endpoint")
	}
	if profileTestObject(t, profile.Settings["clientExport"])["address"] != "192.0.2.7" {
		t.Fatal("Orbit export metadata lost the selected numeric endpoint")
	}
	key := profileTestString(t, profileTestClient(t, profile.Settings)["key"])
	if _, err := (&orbit.Account{Key: key}).AsAccount(); err != nil {
		t.Fatal("generated Orbit connection key cannot be decoded")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(key, "vck1_"))
	pin := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	if err != nil || len(decoded) != 64 || !bytes.Equal(decoded[32:], pin[:]) {
		t.Fatal("Orbit client connection key is not bound to its server leaf SPKI")
	}
}

func TestNativeProfileDNSTTKeyPairAndInnerIdentity(t *testing.T) {
	profile := profileTestGenerate(t, "dnstt")
	private, err := hex.DecodeString(profileTestString(t, profile.Settings["privateKey"]))
	if err != nil || len(private) != 32 {
		t.Fatal("DNSTT private key must be canonical X25519 hex")
	}
	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil || profile.PublicKey != hex.EncodeToString(key.PublicKey().Bytes()) {
		t.Fatal("DNSTT public key does not match generated private key")
	}
	if profile.Settings["domain"] != "tunnel.example.test" || profileTestObject(t, profile.Settings["inner"])["protocol"] != "vless" {
		t.Fatal("DNSTT profile changed the requested domain or inner protocol")
	}
	client := profileTestClient(t, profile.Settings)
	id, err := uuid.Parse(profileTestString(t, client["id"]))
	if err != nil || id == uuid.Nil || client["username"] != nil || client["password"] != nil {
		t.Fatal("DNSTT VLESS credential is missing or mixed with SOCKS credentials")
	}
}

func TestNativeProfileAnyTLSTrustedServerIdentity(t *testing.T) {
	profile := profileTestGenerate(t, "anytls")
	if profile.StreamSettings["network"] != "tcp" || profile.StreamSettings["security"] != "tls" {
		t.Fatal("AnyTLS profile must use native TCP with outer server TLS")
	}
	settings := profileTestObject(t, profile.StreamSettings["tlsSettings"])
	certificates, ok := settings["certificates"].([]any)
	if !ok || len(certificates) != 1 {
		t.Fatal("AnyTLS profile lacks exactly one server TLS keypair")
	}
	material := profileTestObject(t, certificates[0])
	leaf := profileTestKeyPair(t, material["certificate"], material["key"])
	meta := profileTestObject(t, profile.Settings["clientExport"])
	if meta["serverName"] != "vpn.example.test" {
		t.Fatal("AnyTLS export server name differs from certificate SAN input")
	}
	root := leaf
	if ca, exists := meta["ca"]; exists {
		root = profileTestCertificate(t, ca)
	}
	profileTestVerify(t, leaf, root, "vpn.example.test", x509.ExtKeyUsageServerAuth)
	if settings["allowInsecure"] == true || meta["allowInsecure"] == true {
		t.Fatal("generated TLS profile must retain certificate verification")
	}
}

func TestNativeProfileCertificateIPNames(t *testing.T) {
	for _, protocol := range []string{"orbit", "anytls", "openvpn"} {
		for _, name := range []string{"192.0.2.10", "2001:db8::10"} {
			t.Run(protocol+"/"+name, func(t *testing.T) {
				request := profileTestRequest(protocol)
				request.ServerName = name
				request.ServerAddress = "" // Literal server names are their own endpoints.
				profile, err := GenerateNativeInboundProfile(request)
				if err != nil {
					t.Fatalf("IP certificate generation failed: %v", err)
				}
				var cert any
				switch protocol {
				case "orbit":
					cert = profileTestObject(t, profile.Settings["tls"])["certificate"]
				case "openvpn":
					cert = profileTestObject(t, profile.Settings["certificates"])["cert"]
				case "anytls":
					settings := profileTestObject(t, profile.StreamSettings["tlsSettings"])
					cert = profileTestObject(t, settings["certificates"].([]any)[0])["certificate"]
				}
				leaf := profileTestCertificate(t, cert)
				if len(leaf.IPAddresses) != 1 || len(leaf.DNSNames) != 0 || leaf.VerifyHostname(name) != nil {
					t.Fatal("IP server identity must use an IP SAN instead of a DNS SAN")
				}
			})
		}
	}
}

func TestNativeProfileOrbitRequiresUsableNumericEndpoint(t *testing.T) {
	for _, address := range []string{"vpn.example.test", "https://192.0.2.7", "192.0.2.7:443", "192.0.2.7/32", "0.0.0.0", "::", "224.0.0.1", "ff02::1", "169.254.1.2", "fe80::1"} {
		request := profileTestRequest("orbit")
		request.ServerAddress = address
		if profile, err := GenerateNativeInboundProfile(request); err == nil || profile != nil {
			t.Fatalf("unusable Orbit endpoint accepted: %q", address)
		}
	}
	for _, address := range []string{"127.0.0.1", "10.0.0.7", "192.0.2.7", "2001:db8::7", "::1"} {
		request := profileTestRequest("orbit")
		request.ServerAddress = address
		profile, err := GenerateNativeInboundProfile(request)
		if err != nil {
			t.Fatalf("valid numeric Orbit endpoint rejected: %v", err)
		}
		leaf := profileTestCertificate(t, profileTestObject(t, profile.Settings["tls"])["certificate"])
		if leaf.VerifyHostname(address) != nil || leaf.VerifyHostname(request.ServerName) != nil {
			t.Fatal("Orbit endpoint selection lost endpoint IP or supplied DNS SAN")
		}
	}
}

func TestNativeProfileMissingDeploymentInputsRemainExplicit(t *testing.T) {
	for protocol, required := range map[string]string{"anytls": "serverName", "orbit": "serverAddress", "dnstt": "domain", "shadowtls": "handshake.address"} {
		t.Run(protocol, func(t *testing.T) {
			profile, err := GenerateNativeInboundProfile(NativeCredentialRequest{Kind: "inbound-profile", Protocol: protocol})
			if err != nil || profile == nil {
				t.Fatalf("partial cryptographic profile generation failed: %v", err)
			}
			found := false
			for _, requirement := range profile.Requirements {
				if requirement.Field == required && requirement.Message != "" {
					found = true
				}
			}
			if !found {
				t.Fatalf("partial profile did not identify missing %s", required)
			}
			client := profileTestClient(t, profile.Settings)
			if client["enable"] != true || profileTestString(t, client["email"]) == "" || profileTestString(t, client["subId"]) == "" {
				t.Fatal("partial profile lost its generated panel account")
			}
			encoded, _ := json.Marshal(profile)
			for _, fabricated := range []string{"vpn.internal", "www.microsoft.com", ".tunnel.invalid", "1.1.1.1"} {
				if strings.Contains(string(encoded), fabricated) {
					t.Fatal("partial profile invented external deployment information")
				}
			}
			switch protocol {
			case "anytls":
				profileTestString(t, client["password"])
				tlsSettings := profileTestObject(t, profile.StreamSettings["tlsSettings"])
				if profile.StreamSettings["network"] != "tcp" || profile.StreamSettings["security"] != "tls" || tlsSettings["certificates"] != nil || profile.Settings["clientExport"] != nil {
					t.Fatal("AnyTLS without identity must preserve its TLS skeleton without inventing a certificate")
				}
			case "orbit":
				if profile.Settings["transport"] != "tcp" || profile.Settings["tls"] != nil || profile.Settings["clientExport"] != nil || client["key"] != nil {
					t.Fatal("Orbit without endpoint must defer its certificate and bound client key")
				}
			case "dnstt":
				if profile.Settings["domain"] != "" || profile.Settings["clientExport"] != nil {
					t.Fatal("DNSTT without a deployment domain invented a domain or resolver")
				}
				private, err := hex.DecodeString(profileTestString(t, profile.Settings["privateKey"]))
				if err != nil || len(private) != 32 {
					t.Fatal("partial DNSTT profile lost private key")
				}
				key, err := ecdh.X25519().NewPrivateKey(private)
				if err != nil || profile.PublicKey != hex.EncodeToString(key.PublicKey().Bytes()) {
					t.Fatal("partial DNSTT key pair is inconsistent")
				}
				if id, err := uuid.Parse(profileTestString(t, client["id"])); err != nil || id == uuid.Nil {
					t.Fatal("partial DNSTT profile lost authenticated inner UUID")
				}
			case "shadowtls":
				if profileTestObject(t, profile.Settings["handshake"])["address"] != "" || profile.Settings["clientExport"] != nil {
					t.Fatal("ShadowTLS without a cover endpoint invented a target or SNI")
				}
				outerSecret := profileTestString(t, client["password"])
				inner := profileTestObject(t, profile.Settings["inner"])
				settings := profileTestObject(t, inner["settings"])
				innerClient := profileTestClient(t, settings)
				serverKey, err := base64.StdEncoding.Strict().DecodeString(profileTestString(t, settings["password"]))
				if err != nil || len(serverKey) != 32 {
					t.Fatal("partial ShadowTLS profile lost inner server key")
				}
				userKey, err := base64.StdEncoding.Strict().DecodeString(profileTestString(t, innerClient["password"]))
				if err != nil || len(userKey) != 32 || bytes.Equal(serverKey, userKey) || outerSecret == settings["password"] || outerSecret == innerClient["password"] || innerClient["email"] != client["email"] {
					t.Fatal("partial ShadowTLS encrypted account binding or independent secrets lost")
				}
			}
		})
	}
}

func TestNativeProfileOpenVPNWithoutIdentityDoesNotInventExternalValues(t *testing.T) {
	profile, err := GenerateNativeInboundProfile(NativeCredentialRequest{Protocol: "openvpn"})
	if err != nil {
		t.Fatal(err)
	}
	tunnel := profileTestObject(t, profile.Settings["tunnel"])
	rawDNS, _ := json.Marshal(tunnel["dns"])
	if string(rawDNS) != "[]" {
		t.Fatal("OpenVPN must explicitly disable generated external DNS without user input")
	}
	stored, _ := json.Marshal(profile.Settings)
	projected, err := coreInboundSettingsAt("openvpn", string(stored), nil, time.Now().UnixMilli())
	if err != nil {
		t.Fatalf("generated OpenVPN profile cannot be projected: %v", err)
	}
	var native coreconf.OpenVPNInboundConfig
	if err := json.Unmarshal([]byte(projected), &native); err != nil {
		t.Fatalf("generated OpenVPN profile cannot be decoded by the core: %v", err)
	}
	if native.Settings.Tunnel.DNS == nil || len(native.Settings.Tunnel.DNS) != 0 {
		t.Fatal("OpenVPN core validation reintroduced an external DNS server")
	}
	built, err := native.Build()
	if err != nil {
		t.Fatalf("generated OpenVPN profile cannot be built: %v", err)
	}
	runtime, err := openvpn.ParseServerSettings(built.(*openvpn.ServerConfig).Settings)
	if err != nil {
		t.Fatalf("generated OpenVPN profile cannot be decoded at runtime: %v", err)
	}
	if runtime.Tunnel.DNS == nil || len(runtime.Tunnel.DNS) != 0 {
		t.Fatal("OpenVPN core serialization reintroduced an external DNS server at runtime")
	}
	certificates := profileTestObject(t, profile.Settings["certificates"])
	server := profileTestKeyPair(t, certificates["cert"], certificates["key"])
	if len(server.DNSNames) != 0 || len(server.IPAddresses) != 0 {
		t.Fatal("OpenVPN generated an external server identity without user input")
	}
	ca := profileTestCertificate(t, certificates["ca"])
	profileTestVerify(t, server, ca, "", x509.ExtKeyUsageServerAuth)
	client := profileTestClient(t, profile.Settings)
	leaf := profileTestKeyPair(t, client["certificate"], client["privateKey"])
	profileTestVerify(t, leaf, ca, "", x509.ExtKeyUsageClientAuth)
}

func TestNativeProfileOrbitAddressOnlyDoesNotInventDNSName(t *testing.T) {
	profile, err := GenerateNativeInboundProfile(NativeCredentialRequest{Protocol: "orbit", ServerAddress: "192.0.2.7"})
	if err != nil {
		t.Fatal(err)
	}
	material := profileTestObject(t, profile.Settings["tls"])
	leaf := profileTestKeyPair(t, material["certificate"], material["key"])
	if len(leaf.DNSNames) != 0 || len(leaf.IPAddresses) != 1 || leaf.VerifyHostname("192.0.2.7") != nil {
		t.Fatal("address-only Orbit profile invented DNS identity or lost its IP identity")
	}
	key := profileTestString(t, profileTestClient(t, profile.Settings)["key"])
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(key, "vck1_"))
	pin := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	if err != nil || len(decoded) != 64 || !bytes.Equal(decoded[32:], pin[:]) {
		t.Fatal("address-only Orbit client key lost its certificate pin")
	}
}

func TestNativeProfileOpenVPNPKIAndWrappedClientKey(t *testing.T) {
	profile := profileTestGenerate(t, "openvpn")
	certificates := profileTestObject(t, profile.Settings["certificates"])
	client := profileTestClient(t, profile.Settings)
	ca := profileTestCertificate(t, certificates["ca"])
	server := profileTestKeyPair(t, certificates["cert"], certificates["key"])
	leaf := profileTestKeyPair(t, client["certificate"], client["privateKey"])
	if !ca.IsCA || !ca.BasicConstraintsValid || ca.KeyUsage&x509.KeyUsageCertSign == 0 || server.IsCA || leaf.IsCA {
		t.Fatal("OpenVPN CA/server/client role separation is invalid")
	}
	if bytes.Equal(ca.RawSubjectPublicKeyInfo, server.RawSubjectPublicKeyInfo) || bytes.Equal(ca.RawSubjectPublicKeyInfo, leaf.RawSubjectPublicKeyInfo) || bytes.Equal(server.RawSubjectPublicKeyInfo, leaf.RawSubjectPublicKeyInfo) {
		t.Fatal("OpenVPN CA, server and client must have independent keys")
	}
	if server.SerialNumber.Cmp(leaf.SerialNumber) == 0 || leaf.Subject.CommonName != client["commonName"] {
		t.Fatal("OpenVPN leaf identities or serial numbers are not distinct and bound")
	}
	profileTestVerify(t, server, ca, "vpn.example.test", x509.ExtKeyUsageServerAuth)
	profileTestVerify(t, leaf, ca, "", x509.ExtKeyUsageClientAuth)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
		t.Fatal("client certificate must not also authorize server authentication")
	}
	if _, err := server.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Fatal("server certificate must not also authorize client authentication")
	}
	wrapping, err := ctlwrap.ParseTLSCryptV2ServerKey([]byte(profileTestString(t, certificates["tlsCryptV2"])))
	if err != nil {
		t.Fatal("generated server control wrapping key is invalid")
	}
	issued, wrapped, err := ctlwrap.ParseTLSCryptV2ClientKey([]byte(profileTestString(t, client["tlsCryptV2"])))
	if err != nil {
		t.Fatal("generated per-client wrapped key is invalid")
	}
	unwrapped, _, err := ctlwrap.UnwrapTLSCryptV2ClientKey(wrapping, wrapped)
	if err != nil || issued == nil || unwrapped == nil || !bytes.Equal(issued[:], unwrapped[:]) {
		t.Fatal("client control key does not unwrap under its server key")
	}
}

func TestNativeProfileOpenVPNIssuerRemainsPanelOnly(t *testing.T) {
	profile := profileTestGenerate(t, "openvpn")
	certificates := profileTestObject(t, profile.Settings["certificates"])
	ca := profileTestCertificate(t, certificates["ca"])
	meta := profileTestObject(t, profile.Settings["clientExport"])
	issuer := profileTestString(t, meta["issuerPrivateKey"])
	block, _ := pem.Decode([]byte(issuer))
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatal("retained issuer key is not PKCS8 PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal("retained issuer key cannot be decoded")
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		t.Fatal("retained issuer key cannot sign future client certificates")
	}
	public, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !bytes.Equal(public, ca.RawSubjectPublicKeyInfo) {
		t.Fatal("retained issuer private key does not match the CA certificate")
	}
	raw, err := json.Marshal(profile.Settings)
	if err != nil {
		t.Fatal("profile settings cannot be serialized for backup")
	}
	var restored map[string]any
	if json.Unmarshal(raw, &restored) != nil || profileTestObject(t, restored["clientExport"])["issuerPrivateKey"] != issuer {
		t.Fatal("settings serialization did not preserve future-issuance material")
	}
	projected, err := coreInboundSettingsAt("openvpn", string(raw), nil, time.Now().UnixMilli())
	encodedIssuer, _ := json.Marshal(issuer)
	if err != nil || strings.Contains(projected, "issuerPrivateKey") || strings.Contains(projected, "clientExport") || bytes.Contains([]byte(projected), encodedIssuer) {
		t.Fatal("panel-only CA issuer key leaked into core runtime configuration")
	}
}

func TestNativeProfileShadowTLSEncryptedInnerAndMieruDefault(t *testing.T) {
	profile := profileTestGenerate(t, "shadowtls")
	settings := profileTestObject(t, profile.Settings)
	if settings["version"] != float64(3) || settings["strict"] != true {
		t.Fatal("ShadowTLS profile must use strict v3")
	}
	if profileTestObject(t, settings["handshake"])["address"] != "cover.example.test" {
		t.Fatal("ShadowTLS did not retain the supplied handshake address")
	}
	outer := profileTestClient(t, settings)
	inner := profileTestObject(t, settings["inner"])
	innerSettings := profileTestObject(t, inner["settings"])
	selected := profileTestClient(t, innerSettings)
	if inner["protocol"] != "shadowsocks" || innerSettings["method"] != "2022-blake3-aes-256-gcm" || innerSettings["network"] != "tcp" || selected["email"] != outer["email"] {
		t.Fatal("ShadowTLS encrypted inner account does not match exported outer account")
	}
	serverKey, err := base64.StdEncoding.Strict().DecodeString(profileTestString(t, innerSettings["password"]))
	if err != nil || len(serverKey) != 32 {
		t.Fatal("inner SS2022 server key is invalid")
	}
	userKey, err := base64.StdEncoding.Strict().DecodeString(profileTestString(t, selected["password"]))
	if err != nil || len(userKey) != 32 || bytes.Equal(serverKey, userKey) || outer["password"] == selected["password"] || outer["password"] == innerSettings["password"] {
		t.Fatal("ShadowTLS outer, server and selected identity secrets must be independent")
	}
	mieru := profileTestGenerate(t, "mieru")
	if mieru.Settings["transport"] != "tcp" {
		t.Fatal("Mieru profile should default to its TCP underlay")
	}
	credentials := profileTestClient(t, mieru.Settings)
	if profileTestString(t, credentials["username"]) == profileTestString(t, credentials["password"]) {
		t.Fatal("Mieru password must be independently generated")
	}
}

func TestNativeProfileGenerationsDoNotReuseCredentials(t *testing.T) {
	for _, protocol := range []string{"orbit", "dnstt", "openvpn", "anytls", "shadowtls", "mieru"} {
		t.Run(protocol, func(t *testing.T) {
			a, b := profileTestGenerate(t, protocol), profileTestGenerate(t, protocol)
			first, second := profileTestClient(t, a.Settings), profileTestClient(t, b.Settings)
			if first["subId"] == second["subId"] {
				t.Fatal("independent profile generations reused subscription identity")
			}
			field := "password"
			switch protocol {
			case "orbit":
				field = "key"
			case "dnstt":
				field = "id"
				if a.Settings["privateKey"] == b.Settings["privateKey"] {
					t.Fatal("independent profiles reused DNS private key")
				}
			case "openvpn":
				field = "privateKey"
			}
			if profileTestString(t, first[field]) == profileTestString(t, second[field]) {
				t.Fatal("independent profile generations reused client secret")
			}
		})
	}
}

func TestNativeProfileOpenVPNAdditionalClientUsesOriginalIssuer(t *testing.T) {
	profile := profileTestGenerate(t, "openvpn")
	certificates := profileTestObject(t, profile.Settings["certificates"])
	issuer := profileTestObject(t, profile.Settings["clientExport"])
	ca := profileTestCertificate(t, certificates["ca"])
	original := profileTestClient(t, profile.Settings)
	before, _ := json.Marshal(profile)
	for _, wrappedAndProof := range []bool{false, true} {
		request := NativeCredentialRequest{Kind: "openvpn-client", CACertificate: profileTestString(t, certificates["ca"]), IssuerPrivateKey: profileTestString(t, issuer["issuerPrivateKey"]), ClientProofRequired: wrappedAndProof}
		if wrappedAndProof {
			request.ServerKey = profileTestString(t, certificates["tlsCryptV2"])
		}
		response, err := GenerateNativeOpenVPNClient(request)
		if err != nil {
			t.Fatalf("additional client generation failed: %v", err)
		}
		if len(response) != 1 {
			t.Fatal("issuance response must contain client material only")
		}
		client := profileTestObject(t, response["client"])
		leaf := profileTestKeyPair(t, client["certificate"], client["privateKey"])
		profileTestVerify(t, leaf, ca, "", x509.ExtKeyUsageClientAuth)
		if leaf.Subject.CommonName != client["commonName"] || client["commonName"] == original["commonName"] || client["privateKey"] == original["privateKey"] {
			t.Fatal("new client identity must be fresh and bound to its certificate")
		}
		encoded, _ := json.Marshal(response)
		for _, secret := range []string{request.IssuerPrivateKey, profileTestString(t, certificates["key"]), profileTestString(t, certificates["tlsCryptV2"])} {
			needle, _ := json.Marshal(secret)
			if bytes.Contains(encoded, needle) {
				t.Fatal("client issuance echoed issuer or server secrets")
			}
		}
		if wrappedAndProof {
			wrap, err := ctlwrap.ParseTLSCryptV2ServerKey([]byte(request.ServerKey))
			if err != nil {
				t.Fatal(err)
			}
			issued, wrapped, err := ctlwrap.ParseTLSCryptV2ClientKey([]byte(profileTestString(t, client["tlsCryptV2"])))
			if err != nil {
				t.Fatal("additional client wrapping key cannot be parsed")
			}
			unwrapped, _, err := ctlwrap.UnwrapTLSCryptV2ClientKey(wrap, wrapped)
			if err != nil || issued == nil || unwrapped == nil || !bytes.Equal(issued[:], unwrapped[:]) {
				t.Fatal("additional client key does not unwrap under the original server")
			}
			proof := profileTestObject(t, client["clientProof"])
			secret, err := hex.DecodeString(profileTestString(t, proof["key"]))
			if err != nil || len(secret) != 32 || profileTestString(t, proof["keyId"]) == "" {
				t.Fatal("requested additional-client proof is invalid")
			}
		} else if client["tlsCryptV2"] != nil || client["clientProof"] != nil {
			t.Fatal("unrequested wrapping/proof changed ordinary client authentication")
		}
	}
	after, _ := json.Marshal(profile)
	if !bytes.Equal(before, after) {
		t.Fatal("issuing another client changed the original profile or credentials")
	}
}

func profileTestIssuer(t *testing.T, change func(*x509.Certificate)) (string, string, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	certificate := &x509.Certificate{SerialNumber: big.NewInt(100), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	if change != nil {
		change(certificate)
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})), key
}

func TestNativeProfileOpenVPNAdditionalClientBoundsIssuerValidity(t *testing.T) {
	ca, private, key := profileTestIssuer(t, func(c *x509.Certificate) {
		c.NotBefore = time.Now().Add(-time.Minute)
		c.NotAfter = time.Now().Add(45 * time.Minute)
	})
	sec1, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, encoding := range []string{private, string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}))} {
		response, err := GenerateNativeOpenVPNClient(NativeCredentialRequest{CACertificate: ca, IssuerPrivateKey: encoding})
		if err != nil {
			t.Fatalf("valid short-lived issuer rejected: %v", err)
		}
		client := profileTestObject(t, response["client"])
		leafBlock, _ := pem.Decode([]byte(profileTestString(t, client["certificate"])))
		rootBlock, _ := pem.Decode([]byte(ca))
		leaf, leafErr := x509.ParseCertificate(leafBlock.Bytes)
		root, rootErr := x509.ParseCertificate(rootBlock.Bytes)
		if leafErr != nil || rootErr != nil || leaf.NotAfter.After(root.NotAfter) || leaf.NotBefore.Before(root.NotBefore) {
			t.Fatal("new client validity extends beyond issuer validity")
		}
		profileTestVerify(t, leaf, root, "", x509.ExtKeyUsageClientAuth)
	}
}

func TestNativeProfileOpenVPNAdditionalClientRejectsInvalidIssuers(t *testing.T) {
	ca, private, _ := profileTestIssuer(t, nil)
	_, wrongKey, _ := profileTestIssuer(t, nil)
	for _, mutation := range []struct {
		name   string
		change func(*x509.Certificate)
	}{
		{"not-ca", func(c *x509.Certificate) { c.IsCA = false }},
		{"cannot-sign", func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDigitalSignature }},
		{"expired", func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) }},
		{"not-yet-valid", func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Hour) }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			invalidCA, matchingKey, _ := profileTestIssuer(t, mutation.change)
			if response, err := GenerateNativeOpenVPNClient(NativeCredentialRequest{CACertificate: invalidCA, IssuerPrivateKey: matchingKey}); err == nil || response != nil {
				t.Fatal("invalid issuer produced a client credential")
			}
		})
	}
	for _, request := range []NativeCredentialRequest{
		{CACertificate: ca, IssuerPrivateKey: wrongKey},
		{CACertificate: "SENSITIVE-invalid-ca", IssuerPrivateKey: private},
		{CACertificate: ca, IssuerPrivateKey: "SENSITIVE-invalid-key"},
		{CACertificate: ca + ca, IssuerPrivateKey: private},
		{CACertificate: ca, IssuerPrivateKey: private + private},
		{CACertificate: ca, IssuerPrivateKey: private, ServerKey: "SENSITIVE-invalid-wrapping-key"},
	} {
		response, err := GenerateNativeOpenVPNClient(request)
		if err == nil || response != nil || strings.Contains(err.Error(), "SENSITIVE") || strings.Contains(err.Error(), "PRIVATE KEY") {
			t.Fatal("invalid issuer material was accepted or echoed in an error")
		}
	}
}

func TestNativeProfileOpenVPNIssuerKeyStrengthAndEncodings(t *testing.T) {
	for _, name := range []string{"rsa-1024", "ecdsa-224", "rsa-2048-pkcs1", "ed25519-pkcs8"} {
		t.Run(name, func(t *testing.T) {
			var signer crypto.Signer
			var err error
			switch name {
			case "rsa-1024":
				signer, err = rsa.GenerateKey(rand.Reader, 1024)
			case "ecdsa-224":
				signer, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
			case "rsa-2048-pkcs1":
				signer, err = rsa.GenerateKey(rand.Reader, 2048)
			case "ed25519-pkcs8":
				_, signer, err = ed25519.GenerateKey(rand.Reader)
			}
			if err != nil {
				t.Fatal(err)
			}
			ca := &x509.Certificate{SerialNumber: big.NewInt(200), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
			der, err := x509.CreateCertificate(rand.Reader, ca, ca, signer.Public(), signer)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := x509.MarshalPKCS8PrivateKey(signer)
			if err != nil {
				t.Fatal(err)
			}
			kind := "PRIVATE KEY"
			if name == "rsa-2048-pkcs1" {
				kind, encoded = "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(signer.(*rsa.PrivateKey))
			}
			request := NativeCredentialRequest{CACertificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), IssuerPrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: encoded}))}
			response, err := GenerateNativeOpenVPNClient(request)
			if name == "rsa-1024" || name == "ecdsa-224" {
				if err == nil || response != nil {
					t.Fatal("weak certificate issuer was accepted")
				}
				return
			}
			if err != nil {
				t.Fatalf("supported strong issuer rejected: %v", err)
			}
			client := profileTestObject(t, response["client"])
			leaf := profileTestKeyPair(t, client["certificate"], client["privateKey"])
			profileTestVerify(t, leaf, profileTestCertificate(t, request.CACertificate), "", x509.ExtKeyUsageClientAuth)
		})
	}
}
