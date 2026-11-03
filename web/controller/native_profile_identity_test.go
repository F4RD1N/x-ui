package controller

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/web/service"
	"github.com/op/go-logging"
)

type nativeIdentityHTTPResult struct {
	Success bool                          `json:"success"`
	Msg     string                        `json:"msg"`
	Obj     *service.NativeInboundProfile `json:"obj"`
}

func nativeIdentityHTTPRequest(t *testing.T, input map[string]string) (*httptest.ResponseRecorder, nativeIdentityHTTPResult) {
	t.Helper()
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "http://request-host.example.invalid:2053/panel/api/server/native/credentials", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Forwarded-Host", "198.51.100.99")
	request.Header.Set("X-Real-IP", "198.51.100.98")
	request.Header.Set("Forwarded", "for=198.51.100.97;host=forwarded.example.invalid;proto=https")
	response := httptest.NewRecorder()
	credentialRouter(true).ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("credential response status or cache control is incorrect")
	}
	var decoded nativeIdentityHTTPResult
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatal("credential response is not valid JSON")
	}
	return response, decoded
}

func nativeIdentityObject(t *testing.T, value any) map[string]any {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatal("expected credential object is absent")
	}
	return object
}

func nativeIdentityLeaf(t *testing.T, profile *service.NativeInboundProfile) *x509.Certificate {
	t.Helper()
	var material any
	switch profile.Protocol {
	case "anytls":
		tls := nativeIdentityObject(t, profile.StreamSettings["tlsSettings"])
		certificates, ok := tls["certificates"].([]any)
		if !ok || len(certificates) != 1 {
			t.Fatal("AnyTLS generated certificate is absent")
		}
		material = nativeIdentityObject(t, certificates[0])["certificate"]
	case "orbit":
		material = nativeIdentityObject(t, profile.Settings["tls"])["certificate"]
	case "openvpn":
		material = nativeIdentityObject(t, profile.Settings["certificates"])["cert"]
	default:
		t.Fatal("unexpected profile protocol")
	}
	var text string
	switch value := material.(type) {
	case string:
		text = value
	case []any:
		lines := make([]string, len(value))
		for i, line := range value {
			var ok bool
			lines[i], ok = line.(string)
			if !ok {
				t.Fatal("certificate lines must be strings")
			}
		}
		text = strings.Join(lines, "\n")
	default:
		t.Fatal("certificate PEM is absent")
	}
	block, _ := pem.Decode([]byte(text))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("certificate PEM is invalid")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal("generated certificate is invalid")
	}
	return certificate
}

func TestNativeProfileHTTPIdentityNormalization(t *testing.T) {
	t.Setenv("XUI_LOG_FOLDER", t.TempDir())
	logger.InitLogger(logging.ERROR)
	t.Cleanup(logger.CloseLogger)
	for _, tc := range []struct {
		name, protocol, serverName, serverAddress, wantName, wantAddress string
		wantDNS, wantIP                                                  string
	}{
		{"anytls-dns", "anytls", " \tVPN.Example.TEST.\r\n", "", "vpn.example.test", "", "vpn.example.test", ""},
		{"anytls-ipv4", "anytls", " 192.0.2.23 ", "", "192.0.2.23", "", "", "192.0.2.23"},
		{"anytls-ipv6", "anytls", " \t[2001:0DB8:0:0::23]\n", "", "2001:db8::23", "", "", "2001:db8::23"},
		{"openvpn-dns", "openvpn", " \tVPN.Example.TEST.\n", "", "vpn.example.test", "", "vpn.example.test", ""},
		{"openvpn-ipv4", "openvpn", " 192.0.2.23 ", "", "192.0.2.23", "", "", "192.0.2.23"},
		{"openvpn-ipv6", "openvpn", " [2001:0DB8:0:0::23] ", "", "2001:db8::23", "", "", "2001:db8::23"},
		{"orbit-address-ipv4", "orbit", " \tVPN.Example.TEST.\n", " 192.0.2.44 ", "vpn.example.test", "192.0.2.44", "vpn.example.test", "192.0.2.44"},
		{"orbit-address-ipv6", "orbit", " VPN.Example.TEST. ", " \t[2001:0DB8:0:0::44]\n", "vpn.example.test", "2001:db8::44", "vpn.example.test", "2001:db8::44"},
		{"orbit-name-ipv6", "orbit", " [2001:0DB8:0:0::44] ", "", "2001:db8::44", "2001:db8::44", "", "2001:db8::44"},
		{"orbit-both-ipv6", "orbit", " [2001:0DB8:0:0::44] ", " [2001:db8::44] ", "2001:db8::44", "2001:db8::44", "", "2001:db8::44"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := map[string]string{"kind": "inbound-profile", "protocol": tc.protocol, "serverName": tc.serverName}
			if tc.serverAddress != "" {
				input["serverAddress"] = tc.serverAddress
			}
			_, response := nativeIdentityHTTPRequest(t, input)
			if !response.Success || response.Obj == nil || response.Obj.Protocol != tc.protocol || len(response.Obj.Requirements) != 0 {
				t.Fatal("valid explicit identity did not produce a complete profile")
			}
			certificate := nativeIdentityLeaf(t, response.Obj)
			if err := certificate.VerifyHostname(tc.wantName); err != nil {
				t.Fatal("certificate does not authenticate the normalized supplied identity")
			}
			wantDNSCount, wantIPCount := 0, 0
			if tc.wantDNS != "" {
				wantDNSCount = 1
			}
			if tc.wantIP != "" {
				wantIPCount = 1
			}
			if len(certificate.DNSNames) != wantDNSCount || len(certificate.IPAddresses) != wantIPCount {
				t.Fatal("certificate contains missing, duplicate or inferred identities")
			}
			if wantDNSCount != 0 && certificate.DNSNames[0] != tc.wantDNS {
				t.Fatal("DNS SAN is not canonical")
			}
			if wantIPCount != 0 && certificate.IPAddresses[0].String() != tc.wantIP {
				t.Fatal("IP SAN is not canonical")
			}
			for _, inferred := range []string{"request-host.example.invalid", "forwarded.example.invalid", "198.51.100.99", "198.51.100.98", "198.51.100.97"} {
				if certificate.VerifyHostname(inferred) == nil {
					t.Fatal("request or forwarding headers overrode the explicit certificate identity")
				}
			}
			metadata := nativeIdentityObject(t, response.Obj.Settings["clientExport"])
			switch tc.protocol {
			case "anytls":
				if metadata["serverName"] != tc.wantName {
					t.Fatal("AnyTLS export metadata did not retain the canonical explicit name")
				}
			case "orbit":
				if metadata["address"] != tc.wantAddress || metadata["serverName"] != nil {
					t.Fatal("Orbit export metadata did not retain only its canonical explicit endpoint")
				}
			}
		})
	}
}

func TestNativeProfileHTTPRejectsMalformedIdentity(t *testing.T) {
	t.Setenv("XUI_LOG_FOLDER", t.TempDir())
	logger.InitLogger(logging.ERROR)
	t.Cleanup(logger.CloseLogger)
	check := func(t *testing.T, input map[string]string, invalid string) {
		t.Helper()
		response, decoded := nativeIdentityHTTPRequest(t, input)
		if decoded.Success || decoded.Obj != nil {
			t.Fatal("invalid identity returned generated credentials")
		}
		if strings.Contains(decoded.Msg, strings.TrimSpace(invalid)) {
			t.Fatal("identity error echoed rejected input")
		}
		for _, marker := range []string{"PRIVATE KEY", "BEGIN CERTIFICATE", "issuerPrivateKey", "tlsCryptV2", "vck1_", "private-marker"} {
			if bytes.Contains(response.Body.Bytes(), []byte(marker)) {
				t.Fatal("identity error exposed credential material or rejected input")
			}
		}
	}
	invalidNames := []string{
		"private-marker.example:443", "[2001:db8::23]:443", "[2001:db8::23", "2001:db8::23]",
		"[[2001:db8::23]]", "[]", "[192.0.2.23]", "[private-marker.example]", "bad name.example",
	}
	for _, protocol := range []string{"anytls", "openvpn", "orbit"} {
		for _, invalid := range invalidNames {
			t.Run(protocol+"/"+invalid, func(t *testing.T) {
				input := map[string]string{"kind": "inbound-profile", "protocol": protocol, "serverName": invalid}
				if protocol == "orbit" {
					input["serverAddress"] = "192.0.2.44"
				}
				check(t, input, invalid)
			})
		}
	}
	for _, invalid := range []string{"192.0.2.44:443", "[2001:db8::44]:443", "[2001:db8::44", "2001:db8::44]", "[[2001:db8::44]]", "[192.0.2.44]", "private-marker.example", "ff02::1", " [ff02::1] ", "239.1.2.3"} {
		t.Run("orbit-address/"+invalid, func(t *testing.T) {
			check(t, map[string]string{"kind": "inbound-profile", "protocol": "orbit", "serverName": "vpn.example.test", "serverAddress": invalid}, invalid)
		})
	}
}
