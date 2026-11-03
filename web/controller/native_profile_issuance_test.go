package controller

import (
	"bytes"
	"crypto/tls"
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

func TestNativeProfileOpenVPNClientHTTP(t *testing.T) {
	t.Setenv("XUI_LOG_FOLDER", t.TempDir())
	logger.InitLogger(logging.ERROR)
	t.Cleanup(logger.CloseLogger)
	profile, err := service.GenerateNativeInboundProfile(service.NativeCredentialRequest{Protocol: "openvpn", ServerName: "vpn.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	certificates := profile.Settings["certificates"].(map[string]any)
	issuer := profile.Settings["clientExport"].(map[string]any)["issuerPrivateKey"].(string)
	input := service.NativeCredentialRequest{Kind: "openvpn-client", CACertificate: certificates["ca"].(string), IssuerPrivateKey: issuer, ServerKey: certificates["tlsCryptV2"].(string), ClientProofRequired: true}
	request := func(loggedIn bool, body string) *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/panel/api/server/native/credentials", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		credentialRouter(loggedIn).ServeHTTP(response, req)
		return response
	}
	body, _ := json.Marshal(input)
	if response := request(false, string(body)); response.Code != http.StatusNotFound || bytes.Contains(response.Body.Bytes(), []byte("PRIVATE KEY")) {
		t.Fatal("unauthenticated client issuance exposed credentials")
	}
	response := request(true, string(body))
	var result struct {
		Success bool `json:"success"`
		Obj     struct {
			Client struct {
				CommonName  string            `json:"commonName"`
				Certificate string            `json:"certificate"`
				PrivateKey  string            `json:"privateKey"`
				TLSCryptV2  string            `json:"tlsCryptV2"`
				ClientProof map[string]string `json:"clientProof"`
			} `json:"client"`
		} `json:"obj"`
	}
	if json.Unmarshal(response.Body.Bytes(), &result) != nil || !result.Success || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("authenticated issuance failed or returned cacheable credentials")
	}
	client := result.Obj.Client
	pair, err := tls.X509KeyPair([]byte(client.Certificate), []byte(client.PrivateKey))
	if err != nil || len(pair.Certificate) == 0 || client.TLSCryptV2 == "" || client.ClientProof["key"] == "" {
		t.Fatal("HTTP response omitted requested usable client credentials")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.Subject.CommonName != client.CommonName {
		t.Fatal("HTTP client certificate identity mismatch")
	}
	caBlock, _ := pem.Decode([]byte(input.CACertificate))
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatal("HTTP client certificate cannot authenticate under the original CA")
	}
	for _, secret := range []string{issuer, certificates["key"].(string), input.ServerKey} {
		encoded, _ := json.Marshal(secret)
		if bytes.Contains(response.Body.Bytes(), encoded) {
			t.Fatal("client issuance HTTP response leaked issuer/server credentials")
		}
	}
	for _, invalid := range []string{`{"kind":"openvpn-client"}`, `{"kind":"openvpn-client","caCertificate":"SENSITIVE-invalid-ca","issuerPrivateKey":"SENSITIVE-invalid-key"}`, `{"kind":"openvpn-client","clientProofRequired":"true"}`} {
		response := request(true, invalid)
		var failure struct {
			Success bool `json:"success"`
		}
		if json.Unmarshal(response.Body.Bytes(), &failure) != nil || failure.Success || response.Header().Get("Cache-Control") != "no-store" || bytes.Contains(response.Body.Bytes(), []byte("SENSITIVE")) || bytes.Contains(response.Body.Bytes(), []byte("PRIVATE KEY")) {
			t.Fatal("invalid client issuance request accepted, cacheable, or echoed secret input")
		}
	}
}

func TestNativeProfileOrbitRealityHTTP(t *testing.T) {
	t.Setenv("XUI_LOG_FOLDER", t.TempDir())
	logger.InitLogger(logging.ERROR)
	t.Cleanup(logger.CloseLogger)
	for _, loggedIn := range []bool{false, true} {
		response := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/panel/api/server/native/credentials", strings.NewReader(`{"kind":"orbit-reality"}`))
		req.Header.Set("Content-Type", "application/json")
		credentialRouter(loggedIn).ServeHTTP(response, req)
		if !loggedIn {
			if response.Code != http.StatusNotFound || bytes.Contains(response.Body.Bytes(), []byte("privateKey")) {
				t.Fatal("unauthenticated Reality generation exposed credentials")
			}
			continue
		}
		var result struct {
			Success bool              `json:"success"`
			Obj     map[string]string `json:"obj"`
		}
		if json.Unmarshal(response.Body.Bytes(), &result) != nil || !result.Success || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("authenticated Reality generation failed or allowed caching")
		}
		if result.Obj["privateKey"] == "" || result.Obj["publicKey"] == "" || len(result.Obj["shortId"]) != 16 || !strings.HasPrefix(result.Obj["key"], "vck1_") {
			t.Fatal("Reality HTTP generation omitted its key material")
		}
	}
}
