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
	"github.com/op/go-logging"
)

func TestNativeProfileHTTPNeverInventsDeploymentIdentity(t *testing.T) {
	t.Setenv("XUI_LOG_FOLDER", t.TempDir())
	logger.InitLogger(logging.ERROR)
	t.Cleanup(logger.CloseLogger)
	for _, tc := range []struct {
		protocol, field string
	}{
		{"orbit", "serverAddress"}, {"anytls", "serverName"},
		{"dnstt", "domain"}, {"shadowtls", "handshake.address"},
	} {
		t.Run(tc.protocol, func(t *testing.T) {
			body, _ := json.Marshal(map[string]string{"kind": "inbound-profile", "protocol": tc.protocol})
			request := httptest.NewRequest(http.MethodPost, "http://panel.example.invalid:2053/panel/api/server/native/credentials", bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-Forwarded-Host", "198.51.100.99")
			response := httptest.NewRecorder()
			credentialRouter(true).ServeHTTP(response, request)
			var decoded struct {
				Success bool `json:"success"`
				Obj     struct {
					Settings     map[string]any `json:"settings"`
					Requirements []struct {
						Field string `json:"field"`
					} `json:"requirements"`
				} `json:"obj"`
			}
			if json.Unmarshal(response.Body.Bytes(), &decoded) != nil || !decoded.Success || len(decoded.Obj.Requirements) != 1 || decoded.Obj.Requirements[0].Field != tc.field {
				t.Fatal("missing deployment input must produce a partial profile with its requirement")
			}
			for _, invented := range []string{"panel.example.invalid", "198.51.100.99", "vpn.internal", "tunnel.invalid", "www.microsoft.com", "1.1.1.1"} {
				if bytes.Contains(response.Body.Bytes(), []byte(invented)) {
					t.Fatal("profile invented a deployment-specific identity or endpoint")
				}
			}
			clients, ok := decoded.Obj.Settings["clients"].([]any)
			if !ok || len(clients) != 1 {
				t.Fatal("partial profile lost its generated panel account")
			}
			if (tc.protocol == "orbit" || tc.protocol == "anytls") && bytes.Contains(response.Body.Bytes(), []byte("BEGIN CERTIFICATE")) {
				t.Fatal("missing explicit TLS identity unexpectedly generated a certificate")
			}
		})
	}
}

func TestNativeProfileHTTPUsesOnlyExplicitOrbitEndpoint(t *testing.T) {
	t.Setenv("XUI_LOG_FOLDER", t.TempDir())
	logger.InitLogger(logging.ERROR)
	t.Cleanup(logger.CloseLogger)
	requestProfile := func(body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "http://198.51.100.99:2053/panel/api/server/native/credentials", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		credentialRouter(true).ServeHTTP(response, request)
		return response
	}
	response := requestProfile(`{"kind":"inbound-profile","protocol":"orbit","serverName":"vpn.example.test","serverAddress":"192.0.2.44"}`)
	var decoded struct {
		Success bool `json:"success"`
		Obj     struct {
			Settings map[string]any `json:"settings"`
		} `json:"obj"`
	}
	if json.Unmarshal(response.Body.Bytes(), &decoded) != nil || !decoded.Success {
		t.Fatal("explicit Orbit endpoint generation failed")
	}
	metadata, ok := decoded.Obj.Settings["clientExport"].(map[string]any)
	if !ok || metadata["address"] != "192.0.2.44" || metadata["serverName"] != nil {
		t.Fatal("explicit endpoint must be preserved without unsupported peer metadata")
	}
	material := decoded.Obj.Settings["tls"].(map[string]any)
	var lines []string
	for _, line := range material["certificate"].([]any) {
		lines = append(lines, line.(string))
	}
	block, _ := pem.Decode([]byte(strings.Join(lines, "\n")))
	if block == nil {
		t.Fatal("generated Orbit certificate is missing")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || certificate.VerifyHostname("192.0.2.44") != nil || certificate.VerifyHostname("vpn.example.test") != nil || certificate.VerifyHostname("198.51.100.99") == nil {
		t.Fatal("certificate SANs must contain only explicitly supplied deployment identities")
	}
	// A DNS name without an explicit IP must remain incomplete; even localhost
	// must not be resolved automatically into an invented deployment endpoint.
	response = requestProfile(`{"kind":"inbound-profile","protocol":"orbit","serverName":"localhost"}`)
	if !bytes.Contains(response.Body.Bytes(), []byte(`"field":"serverAddress"`)) || bytes.Contains(response.Body.Bytes(), []byte("127.0.0.1")) || bytes.Contains(response.Body.Bytes(), []byte("BEGIN CERTIFICATE")) {
		t.Fatal("DNS-only identity must not trigger automatic endpoint resolution")
	}
	for _, address := range []string{"0.0.0.0", "::", "255.255.255.255", "224.0.0.1", "ff02::1", "fe80::1", "private-marker.invalid", "127.0.0.1:443"} {
		body, _ := json.Marshal(map[string]string{"kind": "inbound-profile", "protocol": "orbit", "serverAddress": address})
		response = requestProfile(string(body))
		var failed map[string]any
		if json.Unmarshal(response.Body.Bytes(), &failed) != nil || failed["success"] == true || bytes.Contains(response.Body.Bytes(), []byte("PRIVATE KEY")) || bytes.Contains(response.Body.Bytes(), []byte("private-marker")) {
			t.Fatal("invalid explicit endpoint accepted or sensitive input echoed")
		}
	}
}
