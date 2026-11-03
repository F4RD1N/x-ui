package sub

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/util/json_util"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"
	coretls "github.com/xtls/xray-core/transport/internet/tls"
)

const (
	exportFixtureUUID = "00112233-4455-0677-8899-aabbccddeeff"
	exportOtherUUID   = "ffeeddcc-bbaa-0988-7766-554433221100"
	exportEmail       = "selected@example.test"
)

type nativeExportPKI struct {
	ca, serverCert, serverKey, clientCert, clientKey string
	pin                                              [32]byte
}

// These keys are generated only for local config parsing. None is a deployed
// credential or a copied production key.
func makeNativeExportPKI(t *testing.T) nativeExportPKI {
	t.Helper()
	newKey := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	encodeKey := func(k *ecdsa.PrivateKey) string {
		b, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}))
	}
	caKey := newKey()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "export-test-ca"},
		NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	result := nativeExportPKI{ca: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))}
	for _, client := range []bool{false, true} {
		key := newKey()
		leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "vpn.example.test"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"vpn.example.test"}}
		if client {
			leaf.SerialNumber = big.NewInt(3)
			leaf.Subject.CommonName = "selected-client"
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		if client {
			result.clientCert, result.clientKey = certPEM, encodeKey(key)
		} else {
			result.serverCert, result.serverKey = certPEM, encodeKey(key)
			parsed, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			result.pin = sha256.Sum256(parsed.RawSubjectPublicKeyInfo)
		}
	}
	return result
}

func nativeTestJSONString(t *testing.T, value any) string {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func nativeTestMap(t *testing.T, value any) map[string]any {
	t.Helper()
	b := nativeTestJSONString(t, value)
	var out map[string]any
	if err := json.Unmarshal([]byte(b), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func nativeTestClient(t *testing.T, key string, pki nativeExportPKI) model.Client {
	t.Helper()
	return model.Client{ID: exportFixtureUUID, Email: exportEmail, Password: exportFixtureUUID, Username: exportFixtureUUID, Key: key, CommonName: "selected-client", Enable: true, SubID: "native-export", Certificate: pki.clientCert, PrivateKey: pki.clientKey, InnerUsername: "selected-inner", ClientProof: json.RawMessage(`{"keyId":"selected-proof","key":"` + strings.Repeat("01", 32) + `"}`)}
}

func nativeTestInbound(t *testing.T, protocol string, settings map[string]any, client model.Client) *model.Inbound {
	t.Helper()
	selected := nativeTestMap(t, client)
	settings["clients"] = []any{
		map[string]any{"email": "other@example.test", "password": exportOtherUUID, "id": exportOtherUUID, "username": "OTHER-USERNAME", "key": "OTHER-CONNECTION-KEY", "privateKey": "OTHER-PRIVATE-KEY", "certificate": "OTHER-CERTIFICATE"},
		selected,
	}
	return &model.Inbound{Protocol: model.Protocol(protocol), Listen: "0.0.0.0", Port: 1443, Tag: "export-" + protocol, Remark: "test " + protocol, Settings: nativeTestJSONString(t, settings), StreamSettings: `{}`, Sniffing: `{}`, Enable: true}
}

func nativeTestOutboundsBuild(t *testing.T, outbounds []map[string]any) {
	t.Helper()
	if len(outbounds) == 0 {
		t.Fatal("no native outbounds produced")
	}
	for _, raw := range outbounds {
		var c conf.OutboundDetourConfig
		if err := json.Unmarshal([]byte(nativeTestJSONString(t, raw)), &c); err != nil {
			t.Fatalf("outbound JSON does not load: %v", err)
		}
		if _, err := c.Build(); err != nil {
			t.Fatalf("%s outbound does not build: %v", c.Protocol, err)
		}
	}
	// Also exercise the complete generated graph, including proxySettings tags.
	var config conf.Config
	if err := json.Unmarshal([]byte(nativeTestJSONString(t, map[string]any{"outbounds": outbounds})), &config); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Build(); err != nil {
		t.Fatalf("complete native outbound graph does not build: %v", err)
	}
}

func nativeTestSettings(t *testing.T, out map[string]any) map[string]any {
	t.Helper()
	settings := nativeTestMap(t, out["settings"])
	if out["protocol"] == "dns" {
		return nativeTestMap(t, settings["tunnel"])
	}
	return settings
}

func TestNativeExportAllProtocolsLoadAndKeepSelectedAccount(t *testing.T) {
	pki := makeNativeExportPKI(t)
	seed := bytes.Repeat([]byte{7}, 32)
	key := "vck1_" + base64.RawURLEncoding.EncodeToString(append(append([]byte{}, seed...), pki.pin[:]...))
	private, err := ecdh.X25519().NewPrivateKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	publicHex := hex.EncodeToString(private.PublicKey().Bytes())
	client := nativeTestClient(t, key, pki)
	client.UUIDHashMiddle, client.RequireUUIDSessionID, client.UUIDMetadataTrailer = true, true, true
	cases := []struct {
		protocol string
		settings map[string]any
	}{
		{"orbit", map[string]any{"transport": "tcp", "tls": map[string]any{"certificate": strings.Split(pki.serverCert, "\n"), "key": strings.Split(pki.serverKey, "\n")}, "maxSessions": 64}},
		{"dnstt", map[string]any{"domain": "tunnel.example.test", "privateKey": hex.EncodeToString(seed), "inner": map[string]any{"protocol": "vless"}, "clientExport": map[string]any{"resolvers": []any{map[string]any{"transport": "udp", "address": "127.0.0.1:5353"}}}}},
		{"openvpn", map[string]any{"network": "udp", "certificates": map[string]any{"ca": pki.ca, "cert": pki.serverCert, "key": pki.serverKey}, "crypto": map[string]any{"dataCiphers": []string{"AES-256-GCM", "AES-128-GCM"}, "authHash": "SHA256"}, "tunnel": map[string]any{"mtu": 1400}, "clientProof": map[string]any{"required": true}}},
		{"anytls", map[string]any{"maxStreams": 64, "clientExport": map[string]any{"serverName": "vpn.example.test", "ca": pki.ca}}},
		{"shadowtls", map[string]any{"version": 3, "strict": true, "handshake": map[string]any{"address": "vpn.example.test", "port": 443}, "inner": map[string]any{"protocol": "vless", "settings": map[string]any{"decryption": "none", "clients": []any{map[string]any{"email": "other@example.test", "id": exportOtherUUID}, map[string]any{"email": exportEmail, "id": exportFixtureUUID}}}}}},
		{"mieru", map[string]any{"transport": "udp"}},
	}
	for _, tc := range cases {
		t.Run(tc.protocol, func(t *testing.T) {
			inbound := nativeTestInbound(t, tc.protocol, tc.settings, client)
			if tc.protocol == "anytls" {
				inbound.StreamSettings = nativeTestJSONString(t, map[string]any{"network": "tcp", "security": "tls", "tlsSettings": map[string]any{"serverName": "vpn.example.test", "certificates": []any{map[string]any{"certificate": strings.Split(pki.serverCert, "\n"), "key": strings.Split(pki.serverKey, "\n")}}}})
			}
			original := *inbound
			outs, err := nativeClientOutbounds(inbound, client, "192.0.2.7")
			if err != nil {
				t.Fatal(err)
			}
			nativeTestOutboundsBuild(t, outs)
			if inbound.Settings != original.Settings || inbound.StreamSettings != original.StreamSettings || inbound.Listen != original.Listen || inbound.Port != original.Port {
				t.Fatal("export mutated stored inbound")
			}
			all := nativeTestJSONString(t, outs)
			for _, forbidden := range []string{"OTHER-USERNAME", "OTHER-CONNECTION-KEY", "OTHER-PRIVATE-KEY", "OTHER-CERTIFICATE", "maxSessions", "clientExport"} {
				if strings.Contains(all, forbidden) {
					t.Fatalf("inbound-only or unrelated-account value exported: %s", forbidden)
				}
			}
			encodedServerKey := strings.Trim(nativeTestJSONString(t, pki.serverKey), `"`)
			serverKeyLine := strings.Split(pki.serverKey, "\n")[1]
			if strings.Contains(all, encodedServerKey) || strings.Contains(all, serverKeyLine) {
				t.Fatal("server private key leaked into client export")
			}
			settings := nativeTestSettings(t, outs[0])
			switch tc.protocol {
			case "orbit":
				if settings["key"] != key || settings["address"] != "192.0.2.7" {
					t.Fatal("Orbit selected credential or endpoint lost")
				}
			case "dnstt":
				if outs[0]["protocol"] != "dns" || settings["publicKey"] != publicHex || strings.Contains(all, hex.EncodeToString(seed)) {
					t.Fatal("DNSTT public/private key projection is wrong")
				}
				if nativeTestMap(t, settings["inner"])["uuid"] != exportFixtureUUID {
					t.Fatal("wrong DNSTT inner UUID")
				}
			case "openvpn":
				certs := nativeTestMap(t, settings["certificates"])
				if certs["cert"] != pki.clientCert || certs["key"] != pki.clientKey || certs["ca"] != pki.ca {
					t.Fatal("OpenVPN did not use per-client certificate/key")
				}
				if nativeTestMap(t, settings["clientProof"])["keyId"] != "selected-proof" {
					t.Fatal("OpenVPN selected proof missing")
				}
			case "anytls":
				if settings["uuidHashMiddle"] != true || nativeTestMap(t, settings["tlsSettings"])["serverName"] != "vpn.example.test" {
					t.Fatal("AnyTLS native TLS/auth settings lost")
				}
				if stream, ok := outs[0]["streamSettings"]; ok && nativeTestMap(t, stream)["security"] == "tls" {
					t.Fatal("AnyTLS TLS was wrapped twice")
				}
			case "shadowtls":
				if len(outs) != 2 || outs[0]["protocol"] != "vless" || outs[0]["tag"] != "proxy" || outs[1]["protocol"] != "shadowtls" || outs[1]["tag"] != "native-shadowtls" {
					t.Fatal("ShadowTLS inner/carrier graph is wrong")
				}
				chain := nativeTestMap(t, outs[0]["proxySettings"])
				if chain["tag"] != "native-shadowtls" || chain["transportLayer"] != true || nativeTestSettings(t, outs[1])["uuidSessionId"] != true {
					t.Fatal("ShadowTLS authenticated chaining fields lost")
				}
				if strings.Contains(all, exportOtherUUID) {
					t.Fatal("ShadowTLS selected the first inner user instead of matching email")
				}
			case "mieru":
				if settings["username"] != exportFixtureUUID || settings["uuidMetadataTrailer"] != true || settings["transport"] != "udp" {
					t.Fatal("Mieru selected account or UDP transport lost")
				}
			}
		})
	}
}

func TestNativeExportOrbitRealityPublicKeyOnly(t *testing.T) {
	pki := makeNativeExportPKI(t)
	seed := bytes.Repeat([]byte{9}, 32)
	private, err := ecdh.X25519().NewPrivateKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	privateText := base64.RawURLEncoding.EncodeToString(seed)
	publicText := base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())
	key := "vck1_" + base64.RawURLEncoding.EncodeToString(append(bytes.Repeat([]byte{3}, 32), pki.pin[:]...))
	client := nativeTestClient(t, key, pki)
	inbound := nativeTestInbound(t, "orbit", map[string]any{"transport": "tcp", "security": "reality", "reality": map[string]any{"privateKey": privateText, "serverNames": []string{"vpn.example.test"}, "shortIds": []string{"a1b2"}, "dest": "vpn.example.test:443"}}, client)
	outs, err := nativeClientOutbounds(inbound, client, "192.0.2.7")
	if err != nil {
		t.Fatal(err)
	}
	nativeTestOutboundsBuild(t, outs)
	settings := nativeTestSettings(t, outs[0])
	reality := nativeTestMap(t, settings["reality"])
	if settings["security"] != "reality" || reality["publicKey"] != publicText || reality["shortId"] != "a1b2" || reality["serverName"] != "vpn.example.test" {
		t.Fatal("Reality public settings do not match server")
	}
	if strings.Contains(nativeTestJSONString(t, outs), privateText) {
		t.Fatal("Reality private key leaked")
	}
}

func TestNativeExportOrbitProtocolExpiry(t *testing.T) {
	pki := makeNativeExportPKI(t)
	key := "vck1_" + base64.RawURLEncoding.EncodeToString(append(bytes.Repeat([]byte{3}, 32), pki.pin[:]...))
	for _, tc := range []struct {
		name       string
		expires    int64
		wantActive bool
	}{
		{"unlimited", 0, true},
		{"future", time.Now().Add(time.Hour).Unix(), true},
		{"expired", time.Now().Add(-time.Hour).Unix(), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := nativeTestClient(t, key, pki)
			client.ExpiresAt = tc.expires
			inbound := nativeTestInbound(t, "orbit", map[string]any{"transport": "tcp"}, client)
			if got := nativeClientExportActive(inbound, client); got != tc.wantActive {
				t.Fatalf("protocol expiry activity = %v, want %v", got, tc.wantActive)
			}
			outs, err := nativeClientOutbounds(inbound, client, "192.0.2.7")
			if !tc.wantActive {
				if err == nil || len(outs) != 0 {
					t.Fatal("expired Orbit account exported a client configuration")
				}
				return
			}
			if err != nil {
				t.Fatalf("active Orbit account not exported: %v", err)
			}
			nativeTestOutboundsBuild(t, outs)
		})
	}
}

func TestNativeExportOpenVPNWrapperDirectionAndClientV2(t *testing.T) {
	pki := makeNativeExportPKI(t)
	client := nativeTestClient(t, "", pki)
	static := "-----BEGIN OpenVPN Static key V1-----\n" + strings.Repeat("12", 256) + "\n-----END OpenVPN Static key V1-----\n"
	for _, direction := range []int{0, 1} {
		t.Run(string(rune('0'+direction)), func(t *testing.T) {
			inbound := nativeTestInbound(t, "openvpn", map[string]any{"network": "tcp", "certificates": map[string]any{"ca": pki.ca, "cert": pki.serverCert, "key": pki.serverKey, "tlsAuth": static, "keyDirection": direction}}, client)
			outs, err := nativeClientOutbounds(inbound, client, "192.0.2.7")
			if err != nil {
				t.Fatal(err)
			}
			nativeTestOutboundsBuild(t, outs)
			certs := nativeTestMap(t, nativeTestSettings(t, outs[0])["certificates"])
			if certs["tlsAuth"] != static || certs["keyDirection"] != float64(1-direction) {
				t.Fatal("client tls-auth direction is not opposite to server")
			}
		})
	}
	// A syntactically valid client v2 wrapper proves export selects that block;
	// cryptographic server wrapping is tested in the OpenVPN protocol suite.
	wkc := bytes.Repeat([]byte{5}, 290)
	binary.BigEndian.PutUint16(wkc[len(wkc)-2:], uint16(len(wkc)))
	client.TLSCryptV2 = string(pem.EncodeToMemory(&pem.Block{Type: "OpenVPN tls-crypt-v2 client key", Bytes: append(bytes.Repeat([]byte{4}, 256), wkc...)}))
	serverV2 := string(pem.EncodeToMemory(&pem.Block{Type: "OpenVPN tls-crypt-v2 server key", Bytes: bytes.Repeat([]byte{8}, 128)}))
	inbound := nativeTestInbound(t, "openvpn", map[string]any{"certificates": map[string]any{"ca": pki.ca, "cert": pki.serverCert, "key": pki.serverKey, "tlsCryptV2": serverV2}}, client)
	outs, err := nativeClientOutbounds(inbound, client, "192.0.2.7")
	if err != nil {
		t.Fatal(err)
	}
	nativeTestOutboundsBuild(t, outs)
	if nativeTestMap(t, nativeTestSettings(t, outs[0])["certificates"])["tlsCryptV2"] != client.TLSCryptV2 || strings.Contains(nativeTestJSONString(t, outs), "OpenVPN tls-crypt-v2 server key") {
		t.Fatal("server v2 wrapping key exported instead of client key")
	}
}

func TestNativeExportOpenVPNRejectsReencodedServerPrivateKey(t *testing.T) {
	pki := makeNativeExportPKI(t)
	block, _ := pem.Decode([]byte(pki.serverKey))
	if block == nil {
		t.Fatal("missing generated server key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("unexpected generated key type")
	}
	sec1, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for name, encoded := range map[string]string{
		"extra-whitespace":   "\n\n" + strings.ReplaceAll(pki.serverKey, "\n", "\r\n") + "\n",
		"different-encoding": string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1})),
	} {
		t.Run(name, func(t *testing.T) {
			client := nativeTestClient(t, "", pki)
			client.Certificate, client.PrivateKey, client.CommonName = pki.serverCert, encoded, "vpn.example.test"
			if client.PrivateKey == pki.serverKey {
				t.Fatal("fixture must bypass exact PEM string comparison")
			}
			if _, err := tls.X509KeyPair([]byte(client.Certificate), []byte(client.PrivateKey)); err != nil {
				t.Fatalf("fixture is not a usable equivalent key pair: %v", err)
			}
			inbound := nativeTestInbound(t, "openvpn", map[string]any{"certificates": map[string]any{"ca": pki.ca, "cert": pki.serverCert, "key": pki.serverKey}}, client)
			outs, err := nativeClientOutbounds(inbound, client, "192.0.2.7")
			if err == nil || len(outs) != 0 || !strings.Contains(err.Error(), "server private key") {
				t.Fatalf("equivalent server private key was not explicitly rejected: %v", err)
			}
		})
	}
}

func TestNativeExportShadowTLSSOCKSUsesExactInnerUsername(t *testing.T) {
	client := model.Client{Email: exportEmail, Password: exportFixtureUUID, InnerUsername: "selected-inner", Enable: true}
	settings := map[string]any{"version": 3, "handshake": map[string]any{"address": "vpn.example.test"}, "inner": map[string]any{"protocol": "socks", "settings": map[string]any{"auth": "password", "accounts": []any{map[string]any{"user": "other-inner", "pass": "OTHER-INNER-PASSWORD"}, map[string]any{"user": "selected-inner", "pass": "selected-inner-password"}}}}}
	inbound := nativeTestInbound(t, "shadowtls", settings, client)
	outs, err := nativeClientOutbounds(inbound, client, "192.0.2.7")
	if err != nil {
		t.Fatal(err)
	}
	nativeTestOutboundsBuild(t, outs)
	all := nativeTestJSONString(t, outs)
	if outs[0]["protocol"] != "socks" || !strings.Contains(all, "selected-inner-password") || strings.Contains(all, "OTHER-INNER-PASSWORD") {
		t.Fatal("SOCKS inner credential does not match selected innerUsername")
	}
}

func TestNativeExportShadowTLSV1V2UseSharedCarrierAndSelectedInner(t *testing.T) {
	for _, version := range []int{1, 2} {
		for _, innerProtocol := range []string{"vless", "socks"} {
			t.Run(string(rune('0'+version))+"/"+innerProtocol, func(t *testing.T) {
				client := model.Client{Email: exportEmail, Password: "PANEL-OUTER-PASSWORD", InnerUsername: "selected-inner", Enable: true, RequireUUIDSessionID: true}
				innerSettings := map[string]any{"decryption": "none", "clients": []any{map[string]any{"email": "other@example.test", "id": exportOtherUUID}, map[string]any{"email": exportEmail, "id": exportFixtureUUID}}}
				if innerProtocol == "socks" {
					innerSettings = map[string]any{"auth": "password", "accounts": []any{map[string]any{"user": "other-inner", "pass": "OTHER-INNER-PASSWORD"}, map[string]any{"user": "selected-inner", "pass": "selected-inner-password"}}}
				}
				settings := map[string]any{"version": version, "password": "shared-carrier-password", "handshake": map[string]any{"address": "vpn.example.test"}, "inner": map[string]any{"protocol": innerProtocol, "settings": innerSettings}}
				inbound := nativeTestInbound(t, "shadowtls", settings, client)
				outs, err := nativeClientOutbounds(inbound, client, "192.0.2.7")
				if err != nil {
					t.Fatal(err)
				}
				nativeTestOutboundsBuild(t, outs)
				carrier := nativeTestSettings(t, outs[1])
				if carrier["password"] != "shared-carrier-password" || carrier["version"] != float64(version) {
					t.Fatal("v1/v2 export did not use server carrier settings")
				}
				if _, exists := carrier["uuidSessionId"]; exists {
					t.Fatal("v3 UUID marker leaked into older carrier version")
				}
				all := nativeTestJSONString(t, outs)
				if strings.Contains(all, "OTHER-INNER-PASSWORD") || strings.Contains(all, exportOtherUUID) || strings.Contains(all, "PANEL-OUTER-PASSWORD") {
					t.Fatal("wrong inner or outer panel credential exported")
				}
			})
		}
	}
}

func TestNativeExportShadowTLSShadowsocksInner(t *testing.T) {
	for _, method := range []string{"aes-128-gcm", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"} {
		t.Run(method, func(t *testing.T) {
			client := model.Client{Email: exportEmail, Password: exportFixtureUUID, Enable: true}
			innerUser := map[string]any{"email": exportEmail, "method": method, "password": "selected-inner-password"}
			innerSettings := map[string]any{"method": method, "clients": []any{map[string]any{"email": "other@example.test", "method": method, "password": "OTHER-INNER-PASSWORD"}, innerUser}}
			wantPassword := "selected-inner-password"
			if strings.HasPrefix(method, "2022-") {
				keyBytes := 16
				if strings.Contains(method, "256") {
					keyBytes = 32
				}
				psk := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{42}, keyBytes))
				identity, err := hex.DecodeString(strings.ReplaceAll(exportFixtureUUID, "-", ""))
				if err != nil {
					t.Fatal(err)
				}
				if keyBytes == 32 {
					identity = append(identity, identity...)
				}
				innerUser["password"] = exportFixtureUUID
				innerUser["uuidIdentityKeys"] = true
				innerSettings["password"] = psk
				wantPassword = psk + ":" + base64.StdEncoding.EncodeToString(identity)
			}
			settings := map[string]any{"version": 3, "handshake": map[string]any{"address": "vpn.example.test"}, "inner": map[string]any{"protocol": "shadowsocks", "settings": innerSettings}}
			inbound := nativeTestInbound(t, "shadowtls", settings, client)
			outs, err := nativeClientOutbounds(inbound, client, "192.0.2.7")
			if err != nil {
				t.Fatal(err)
			}
			nativeTestOutboundsBuild(t, outs)
			if len(outs) != 2 || outs[0]["protocol"] != "shadowsocks" || outs[1]["protocol"] != "shadowtls" {
				t.Fatal("inner Shadowsocks carrier graph is wrong")
			}
			servers := nativeTestSettings(t, outs[0])["servers"].([]any)
			if len(servers) != 1 {
				t.Fatal("export included unrelated inner accounts")
			}
			account := nativeTestMap(t, servers[0])
			if account["method"] != method || account["password"] != wantPassword {
				t.Fatal("wrong inner method, PSK or selected identity")
			}
			if strings.HasPrefix(method, "2022-") {
				if account["uot"] != true || account["uotVersion"] != float64(2) {
					t.Fatal("SS2022 carrier export must enable UoT v2 inside servers[0]")
				}
				var parsed conf.ShadowsocksClientConfig
				if err := json.Unmarshal([]byte(nativeTestJSONString(t, nativeTestSettings(t, outs[0]))), &parsed); err != nil {
					t.Fatal(err)
				}
				built, err := parsed.Build()
				if err != nil {
					t.Fatal(err)
				}
				config, ok := built.(*shadowsocks_2022.ClientConfig)
				if !ok || !config.UdpOverTcp || config.UdpOverTcpVersion != 2 {
					t.Fatalf("SS2022 parser did not activate UoT v2: %#v", built)
				}
			} else {
				for _, field := range []string{"uot", "uotVersion"} {
					if _, exists := account[field]; exists {
						t.Fatalf("ordinary AEAD export incorrectly added unsupported %s", field)
					}
				}
			}
			if strings.Contains(nativeTestJSONString(t, outs), "OTHER-INNER-PASSWORD") {
				t.Fatal("first inner account exported instead of matching email")
			}
			innerUser["email"] = "no-match@example.test"
			inbound.Settings = nativeTestJSONString(t, settings)
			if outputs, err := nativeClientOutbounds(inbound, client, "192.0.2.7"); err == nil || len(outputs) != 0 {
				t.Fatal("missing inner Shadowsocks identity produced fallback")
			}
		})
	}
}

func TestNativeExportMissingOrAmbiguousCredentialsFailClosed(t *testing.T) {
	pki := makeNativeExportPKI(t)
	client := nativeTestClient(t, "", pki)
	for _, missing := range []string{"certificate", "privateKey"} {
		t.Run("openvpn/"+missing, func(t *testing.T) {
			c := client
			if missing == "certificate" {
				c.Certificate = ""
			} else {
				c.PrivateKey = ""
			}
			inbound := nativeTestInbound(t, "openvpn", map[string]any{"certificates": map[string]any{"ca": pki.ca, "cert": pki.serverCert, "key": pki.serverKey}}, c)
			if outs, err := nativeClientOutbounds(inbound, c, "192.0.2.7"); err == nil || len(outs) != 0 {
				t.Fatal("missing client material produced usable fallback")
			}
		})
	}
	t.Run("openvpn/required-proof", func(t *testing.T) {
		c := client
		c.ClientProof = nil
		inbound := nativeTestInbound(t, "openvpn", map[string]any{"certificates": map[string]any{"ca": pki.ca, "cert": pki.serverCert, "key": pki.serverKey}, "clientProof": map[string]any{"required": true}}, c)
		if outs, err := nativeClientOutbounds(inbound, c, "192.0.2.7"); err == nil || len(outs) != 0 {
			t.Fatal("required client proof was silently omitted")
		}
	})
	for _, mode := range []string{"missing-outer", "duplicate-outer", "missing-inner", "duplicate-inner", "disabled-inner", "missing-socks-username"} {
		t.Run(mode, func(t *testing.T) {
			innerClients := []any{map[string]any{"email": exportEmail, "id": exportFixtureUUID}}
			if mode == "missing-inner" {
				innerClients[0] = map[string]any{"email": "other@example.test", "id": exportOtherUUID}
			}
			if mode == "duplicate-inner" {
				innerClients = append(innerClients, map[string]any{"email": exportEmail, "id": exportOtherUUID})
			}
			if mode == "disabled-inner" {
				innerClients[0] = map[string]any{"email": exportEmail, "id": exportFixtureUUID, "enable": false}
			}
			settings := map[string]any{"version": 3, "handshake": map[string]any{"address": "vpn.example.test"}, "inner": map[string]any{"protocol": "vless", "settings": map[string]any{"decryption": "none", "clients": innerClients}}}
			c := client
			if mode == "missing-socks-username" {
				c.InnerUsername = ""
				settings["inner"] = map[string]any{"protocol": "socks", "settings": map[string]any{"auth": "password", "accounts": []any{map[string]any{"user": "first", "pass": "first-password"}}}}
			}
			inbound := nativeTestInbound(t, "shadowtls", settings, c)
			if mode == "missing-outer" {
				c.Email = "absent@example.test"
			}
			if mode == "duplicate-outer" {
				settings["clients"] = []any{nativeTestMap(t, c), nativeTestMap(t, c)}
				inbound.Settings = nativeTestJSONString(t, settings)
			}
			outs, err := nativeClientOutbounds(inbound, c, "192.0.2.7")
			if err == nil || len(outs) != 0 {
				t.Fatal("ambiguous or absent account produced fallback config")
			}
			if strings.Contains(err.Error(), pki.serverKey) || strings.Contains(err.Error(), pki.clientKey) {
				t.Fatal("error exposed private material")
			}
		})
	}
}

func TestNativeExportVMessTrojanCompatibilityAndDefaults(t *testing.T) {
	s := &SubJsonService{}
	for _, enabled := range []bool{false, true} {
		client := model.Client{ID: exportFixtureUUID, Email: exportEmail, Security: "auto", Password: exportFixtureUUID, RawUUIDAuth: enabled, UUIDHashPrefix: enabled}
		for _, protocol := range []model.Protocol{model.VMESS, model.Trojan} {
			t.Run(string(protocol)+"/"+map[bool]string{false: "standard", true: "custom"}[enabled], func(t *testing.T) {
				inbound := &model.Inbound{Protocol: protocol, Listen: "192.0.2.7", Port: 1443, Settings: `{}`, StreamSettings: `{}`}
				var raw json_util.RawMessage
				if protocol == model.VMESS {
					raw = s.genVnext(inbound, json_util.RawMessage(`{}`), client)
				} else {
					raw = s.genServer(inbound, json_util.RawMessage(`{}`), client)
				}
				var out map[string]any
				if err := json.Unmarshal(raw, &out); err != nil {
					t.Fatal(err)
				}
				nativeTestOutboundsBuild(t, []map[string]any{out})
				field := "rawUuidAuth"
				if protocol == model.Trojan {
					field = "uuidHashPrefix"
				}
				if enabled && !strings.Contains(string(raw), `"`+field+`": true`) {
					t.Fatal("compatibility flag missing from client export")
				}
				if !enabled && strings.Contains(string(raw), `"`+field+`"`) {
					t.Fatal("ordinary config acquired a new compatibility field")
				}
			})
		}
	}
}

func TestNativeExportVLESSOrdinaryEncryptionFallback(t *testing.T) {
	client := model.Client{ID: exportFixtureUUID, Email: exportEmail, Enable: true}
	for _, tc := range []struct {
		name           string
		settings       map[string]any
		wantEncryption string
		wantBuild      bool
	}{
		{"ordinary-missing", map[string]any{"decryption": "none"}, "none", true},
		{"ordinary-empty", map[string]any{"decryption": "none", "encryption": ""}, "none", true},
		{"explicit-none", map[string]any{"decryption": "none", "encryption": "none"}, "none", true},
		{"explicit-custom-preserved", map[string]any{"decryption": "none", "encryption": "explicit-client-public-material"}, "explicit-client-public-material", false},
		{"encrypted-server-no-guess", map[string]any{"decryption": "mlkem768x25519plus.native.600s.server-private-material"}, "", false},
		{"unknown-server-no-guess", map[string]any{"decryption": "unknown"}, "", false},
		{"missing-server-no-guess", map[string]any{}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inbound := &model.Inbound{Protocol: model.VLESS, Listen: "192.0.2.7", Port: 1443, Settings: nativeTestJSONString(t, tc.settings), StreamSettings: `{}`}
			raw := (&SubJsonService{}).genVless(inbound, json_util.RawMessage(`{}`), client)
			var out map[string]any
			if err := json.Unmarshal(raw, &out); err != nil {
				t.Fatal(err)
			}
			vnext := nativeTestSettings(t, out)["vnext"].([]any)
			users := nativeTestMap(t, vnext[0])["users"].([]any)
			if encryption := nativeTestMap(t, users[0])["encryption"]; encryption != tc.wantEncryption {
				t.Fatalf("encryption = %v, want %q", encryption, tc.wantEncryption)
			}
			if tc.wantBuild {
				nativeTestOutboundsBuild(t, []map[string]any{out})
			} else {
				var config conf.OutboundDetourConfig
				if err := json.Unmarshal(raw, &config); err != nil {
					t.Fatal(err)
				}
				if _, err := config.Build(); err == nil {
					t.Fatal("incomplete or invalid public encryption material silently became usable plaintext")
				}
			}
		})
	}
}

func TestNativeExportCompleteJSONHasProxyRoutingAndNoFallbackOnError(t *testing.T) {
	s := NewSubJsonService("", "", "", "", NewSubService(false, "-ieo"))
	client := model.Client{Email: exportEmail, Username: "selected-user", Password: "selected-password", Enable: true}
	inbound := nativeTestInbound(t, "mieru", map[string]any{"transport": "tcp"}, client)
	configs, err := s.getNativeConfig(inbound, client, "192.0.2.7")
	if err != nil || len(configs) != 1 {
		t.Fatalf("native complete JSON: configs=%d error=%v", len(configs), err)
	}
	var parsed conf.Config
	if err := json.Unmarshal(configs[0], &parsed); err != nil {
		t.Fatal(err)
	}
	if _, err := parsed.Build(); err != nil {
		t.Fatalf("complete subscription config rejected: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(configs[0], &document); err != nil {
		t.Fatal(err)
	}
	outs, ok := document["outbounds"].([]any)
	if !ok || len(outs) != 3 || nativeTestMap(t, outs[0])["protocol"] != "mieru" || nativeTestMap(t, outs[0])["tag"] != "proxy" {
		t.Fatal("complete native JSON does not start with the authenticated proxy")
	}
	routing := nativeTestMap(t, document["routing"])
	rules, ok := routing["rules"].([]any)
	if !ok || len(rules) == 0 || nativeTestMap(t, rules[0])["outboundTag"] != "proxy" {
		t.Fatal("native subscription lost proxy routing")
	}
	bad := nativeTestInbound(t, "openvpn", map[string]any{"certificates": map[string]any{"ca": "unused"}}, client)
	if configs, err := s.getNativeConfig(bad, client, "192.0.2.7"); err == nil || len(configs) != 0 {
		t.Fatal("failed native export produced direct/block-only fallback config")
	}
}

func TestNativeExportAnyTLSSelfSignedTrustAndHostnameVerification(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(8), Subject: pkix.Name{CommonName: "vpn.example.test"}, DNSNames: []string{"vpn.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(t.TempDir(), "combined.pem")
	if err := os.WriteFile(certPath, []byte(certPEM+keyPEM), 0600); err != nil {
		t.Fatal(err)
	}
	for _, fileBacked := range []bool{false, true} {
		for _, goodName := range []bool{false, true} {
			name := "vpn.example.test"
			if !goodName {
				name = "wrong.example.test"
			}
			label := map[bool]string{false: "inline", true: "file"}[fileBacked] + "/" + name
			t.Run(label, func(t *testing.T) {
				client := model.Client{Email: exportEmail, Password: "synthetic-password", Enable: true}
				inbound := nativeTestInbound(t, "anytls", map[string]any{"clientExport": map[string]any{"serverName": name}}, client)
				serverCert := map[string]any{"certificate": strings.Split(certPEM+keyPEM, "\n"), "key": strings.Split(keyPEM, "\n")}
				if fileBacked {
					serverCert = map[string]any{"certificateFile": certPath, "keyFile": certPath}
				}
				inbound.StreamSettings = nativeTestJSONString(t, map[string]any{"security": "tls", "tlsSettings": map[string]any{"certificates": []any{serverCert}}})
				outs, err := nativeClientOutbounds(inbound, client, "192.0.2.7")
				if err != nil {
					t.Fatal(err)
				}
				nativeTestOutboundsBuild(t, outs)
				all := nativeTestJSONString(t, outs)
				if strings.Contains(all, "PRIVATE KEY") || strings.Contains(all, strings.Split(keyPEM, "\n")[1]) || strings.Contains(all, certPath) {
					t.Fatal("private block or local path leaked into public TLS trust")
				}
				tlsSettings := nativeTestMap(t, nativeTestSettings(t, outs[0])["tlsSettings"])
				var parsed conf.TLSConfig
				if err := json.Unmarshal([]byte(nativeTestJSONString(t, tlsSettings)), &parsed); err != nil {
					t.Fatal(err)
				}
				built, err := parsed.Build()
				if err != nil {
					t.Fatal(err)
				}
				clientTLS := built.(*coretls.Config).GetTLSConfig()
				if clientTLS.InsecureSkipVerify || clientTLS.ServerName != name {
					t.Fatal("export disabled or altered hostname verification")
				}
				serverSide, clientSide := net.Pipe()
				_ = serverSide.SetDeadline(time.Now().Add(2 * time.Second))
				_ = clientSide.SetDeadline(time.Now().Add(2 * time.Second))
				server := tls.Server(serverSide, &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})
				remote := tls.Client(clientSide, clientTLS)
				done := make(chan error, 1)
				go func() { done <- server.Handshake() }()
				err = remote.Handshake()
				_ = clientSide.Close()
				_ = serverSide.Close()
				<-done
				if goodName && err != nil {
					t.Fatalf("self-signed SAN-matching certificate rejected: %v", err)
				}
				if !goodName {
					var hostname x509.HostnameError
					if !errors.As(err, &hostname) {
						t.Fatalf("wrong name was not rejected by hostname verification: %v", err)
					}
				}
			})
		}
	}
}

func TestNativeExportSS2022CanonicalURIClashAndJSON(t *testing.T) {
	uuidBytes, err := hex.DecodeString(strings.ReplaceAll(exportFixtureUUID, "-", ""))
	if err != nil {
		t.Fatal(err)
	}
	for _, keyBytes := range []int{16, 32} {
		method := "2022-blake3-aes-128-gcm"
		identityBytes := append([]byte{}, uuidBytes...)
		if keyBytes == 32 {
			method = "2022-blake3-aes-256-gcm"
			identityBytes = append(identityBytes, uuidBytes...)
		}
		canonical := base64.StdEncoding.EncodeToString(identityBytes)
		psk := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{42}, keyBytes))
		for _, mode := range []string{"inherit", "client-enable", "client-disable", "ordinary"} {
			t.Run(method+"/"+mode, func(t *testing.T) {
				enabled := mode == "inherit" || mode == "client-enable"
				password := canonical
				if enabled {
					password = exportFixtureUUID
				}
				client := model.Client{Email: exportEmail, Password: password, Enable: true, UUIDIdentityKeys: mode == "client-enable"}
				row := nativeTestMap(t, client)
				settings := map[string]any{"method": method, "password": psk, "clients": []any{row}}
				switch mode {
				case "inherit":
					settings["uuidIdentityKeys"] = true
				case "client-enable":
					settings["uuidIdentityKeys"] = false
					row["uuidIdentityKeys"] = true
				case "client-disable":
					settings["uuidIdentityKeys"] = true
					row["uuidIdentityKeys"] = false
				}
				inbound := &model.Inbound{Protocol: model.Shadowsocks, Listen: "192.0.2.7", Port: 1443, Settings: nativeTestJSONString(t, settings), StreamSettings: `{"network":"tcp","security":"none"}`, Remark: "SS export"}
				identity, err := ss2022ExportIdentity(inbound, client)
				if err != nil || identity != canonical {
					t.Fatalf("canonical identity differs: %q, %v", identity, err)
				}
				service := NewSubService(false, "-ieo")
				link := service.genShadowsocksLink(inbound, exportEmail)
				uri, err := url.Parse(link)
				if err != nil || uri.User == nil {
					t.Fatalf("bad Shadowsocks URI: %v", err)
				}
				userinfo, err := base64.StdEncoding.DecodeString(uri.User.Username())
				if err != nil || string(userinfo) != method+":"+psk+":"+canonical {
					t.Fatalf("URI credential did not preserve PSK and canonical identity: %v", err)
				}
				clash := NewSubClashService(service).buildProxy(inbound, client, map[string]any{"network": "tcp", "security": "none"}, "")
				if clash["password"] != psk+":"+canonical || clash["cipher"] != method {
					t.Fatal("Clash password differs from canonical URI identity")
				}
				raw := (&SubJsonService{}).genServer(inbound, json_util.RawMessage(`{}`), client)
				var outbound map[string]any
				if err := json.Unmarshal(raw, &outbound); err != nil {
					t.Fatal(err)
				}
				nativeTestOutboundsBuild(t, []map[string]any{outbound})
				servers := nativeTestSettings(t, outbound)["servers"].([]any)
				account := nativeTestMap(t, servers[0])
				flag, _ := account["uuidIdentityKeys"].(bool)
				if flag != enabled || account["password"] != psk+":"+password {
					t.Fatal("JSON did not preserve effective import mode and password")
				}
			})
		}
	}
	// Ordinary Shadowsocks remains a single password without an SS2022 PSK.
	client := model.Client{Email: exportEmail, Password: "standard-password", Enable: true}
	inbound := &model.Inbound{Protocol: model.Shadowsocks, Listen: "192.0.2.7", Port: 1443, Settings: nativeTestJSONString(t, map[string]any{"method": "aes-128-gcm", "password": "unused-server-password", "clients": []any{nativeTestMap(t, client)}}), StreamSettings: `{"network":"tcp","security":"none"}`}
	identity, err := ss2022ExportIdentity(inbound, client)
	if err != nil || identity != client.Password {
		t.Fatal("ordinary Shadowsocks password changed")
	}
	service := NewSubService(false, "-ieo")
	uri, err := url.Parse(service.genShadowsocksLink(inbound, exportEmail))
	if err != nil {
		t.Fatal(err)
	}
	userinfo, err := base64.StdEncoding.DecodeString(uri.User.Username())
	if err != nil || string(userinfo) != "aes-128-gcm:standard-password" {
		t.Fatal("ordinary Shadowsocks URI changed")
	}
	clash := NewSubClashService(service).buildProxy(inbound, client, map[string]any{"network": "tcp", "security": "none"}, "")
	if clash["password"] != client.Password {
		t.Fatal("ordinary Shadowsocks Clash password changed")
	}
}
