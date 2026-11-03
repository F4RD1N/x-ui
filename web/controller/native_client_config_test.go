package controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/web/service"
	panelsession "github.com/mhsanaei/3x-ui/v2/web/session"
	"github.com/op/go-logging"
)

type nativeClientConfigHTTPResult struct {
	Success bool   `json:"success"`
	Msg     string `json:"msg"`
	Obj     *struct {
		Config   json.RawMessage `json:"config"`
		Filename string          `json:"filename"`
	} `json:"obj"`
}

func nativeClientConfigRouter(userID int) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(sessions.Sessions("test-session", cookie.NewStore([]byte("synthetic-test-signing-key-32byte!"))))
	if userID > 0 {
		router.Use(func(c *gin.Context) {
			panelsession.SetLoginUser(c, &model.User{Id: userID, Username: "synthetic-owner"})
			c.Next()
		})
	}
	group := router.Group("/panel/api/inbounds")
	group.Use(new(APIController).checkAPIAuth)
	NewInboundController(group)
	return router
}

func nativeClientConfigFixture(t *testing.T, userID int, email string) (*model.Inbound, string) {
	t.Helper()
	profile, err := service.GenerateNativeInboundProfile(service.NativeCredentialRequest{Protocol: "anytls", ServerName: "vpn.example.test", Email: email})
	if err != nil {
		t.Fatal("cannot generate synthetic profile")
	}
	clients := profile.Settings["clients"].([]any)
	selected := clients[0].(map[string]any)
	password := selected["password"].(string)
	profile.Settings["clients"] = append([]any{map[string]any{"email": "other@example.test", "password": "UNSELECTED-SYNTHETIC-PASSWORD", "enable": true, "subId": "other-subscription"}}, clients...)
	settings, err := json.Marshal(profile.Settings)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := json.Marshal(profile.StreamSettings)
	if err != nil {
		t.Fatal(err)
	}
	inbound := &model.Inbound{UserId: userID, Protocol: model.AnyTLS, Enable: true, Listen: "192.0.2.7", Port: 1443,
		Tag: fmt.Sprintf("native-client-config-%d", userID), Remark: "../../unsafe\\remark\r\nHeader: value", Settings: string(settings), StreamSettings: string(stream), Sniffing: "{}"}
	if err := database.GetDB().Create(inbound).Error; err != nil {
		t.Fatal("cannot persist synthetic inbound")
	}
	return inbound, password
}

func nativeClientConfigRequest(t *testing.T, router *gin.Engine, id, body, host string, headers map[string]string) (*httptest.ResponseRecorder, nativeClientConfigHTTPResult) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/panel/api/inbounds/"+id+"/clientConfig", strings.NewReader(body))
	req.Host = host
	req.Header.Set("Content-Type", "application/json")
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	var decoded nativeClientConfigHTTPResult
	if response.Code == http.StatusOK {
		if json.Unmarshal(response.Body.Bytes(), &decoded) != nil {
			t.Fatal("client config endpoint returned malformed JSON")
		}
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("client config endpoint allowed credential caching")
		}
	}
	return response, decoded
}

func nativeClientConfigAssertFailure(t *testing.T, response *httptest.ResponseRecorder, result nativeClientConfigHTTPResult, selectedSecret string) {
	t.Helper()
	if response.Code != http.StatusOK || result.Success || result.Obj != nil {
		t.Fatal("invalid export request was not rejected safely")
	}
	for _, forbidden := range []string{selectedSecret, "UNSELECTED-SYNTHETIC-PASSWORD", "PRIVATE KEY", "BEGIN CERTIFICATE"} {
		if forbidden != "" && bytes.Contains(response.Body.Bytes(), []byte(forbidden)) {
			t.Fatal("export failure disclosed private profile material")
		}
	}
}

func TestNativeClientConfigHTTPAuthenticationOwnershipAndExactSelection(t *testing.T) {
	t.Setenv("XUI_LOG_FOLDER", t.TempDir())
	logger.InitLogger(logging.ERROR)
	t.Cleanup(logger.CloseLogger)
	portableControllerDB(t)
	const owner = 41
	const email = "Selected@example.test"
	inbound, selectedSecret := nativeClientConfigFixture(t, owner, email)
	id := strconv.Itoa(inbound.Id)
	body, _ := json.Marshal(map[string]string{"email": email})
	unauthenticated, _ := nativeClientConfigRequest(t, nativeClientConfigRouter(0), id, string(body), "panel.example.test:2053", nil)
	if unauthenticated.Code != http.StatusNotFound || unauthenticated.Body.Len() != 0 {
		t.Fatal("unauthenticated client config route was exposed")
	}
	router := nativeClientConfigRouter(owner)
	response, result := nativeClientConfigRequest(t, router, id, string(body), "panel.example.test:2053", nil)
	if response.Code != http.StatusOK || !result.Success || result.Obj == nil {
		t.Fatal("authenticated native client config export failed")
	}
	var document map[string]any
	if json.Unmarshal(result.Obj.Config, &document) != nil || document == nil {
		t.Fatal("client config must be a JSON object rather than an escaped JSON string")
	}
	for _, field := range []string{"inbounds", "outbounds", "routing"} {
		if document[field] == nil {
			t.Fatal("export did not produce a complete runnable client document")
		}
	}
	if !bytes.Contains(result.Obj.Config, []byte(selectedSecret)) || bytes.Contains(result.Obj.Config, []byte("UNSELECTED-SYNTHETIC-PASSWORD")) {
		t.Fatal("HTTP export did not select only the exact requested account")
	}
	filename := result.Obj.Filename
	if filename == "" || filepath.Base(filename) != filename || !strings.HasSuffix(filename, ".json") || strings.ContainsAny(filename, "\\/:\"<>") || strings.IndexFunc(filename, unicode.IsControl) >= 0 {
		t.Fatal("suggested download filename contains unsafe path or header characters")
	}
	response, result = nativeClientConfigRequest(t, nativeClientConfigRouter(owner+1), id, string(body), "panel.example.test", nil)
	nativeClientConfigAssertFailure(t, response, result, selectedSecret)
	for _, invalidID := range []string{"0", "-1", "not-an-id", "214748364899999999999999", "999999"} {
		t.Run("id/"+invalidID, func(t *testing.T) {
			response, result := nativeClientConfigRequest(t, router, invalidID, string(body), "panel.example.test", nil)
			nativeClientConfigAssertFailure(t, response, result, selectedSecret)
		})
	}
	for _, invalidEmail := range []string{"selected@example.test", "Selected", " Selected@example.test", "Selected@example.test ", "missing@example.test", ""} {
		t.Run("email/"+invalidEmail, func(t *testing.T) {
			body, _ := json.Marshal(map[string]string{"email": invalidEmail})
			response, result := nativeClientConfigRequest(t, router, id, string(body), "panel.example.test", nil)
			nativeClientConfigAssertFailure(t, response, result, selectedSecret)
		})
	}
}

func TestNativeClientConfigHTTPRejectsMalformedBodies(t *testing.T) {
	t.Setenv("XUI_LOG_FOLDER", t.TempDir())
	logger.InitLogger(logging.ERROR)
	t.Cleanup(logger.CloseLogger)
	portableControllerDB(t)
	inbound, selectedSecret := nativeClientConfigFixture(t, 51, "selected@example.test")
	router := nativeClientConfigRouter(51)
	for _, tc := range []struct{ name, body string }{
		{"empty", ""}, {"null", "null"}, {"array", "[]"}, {"missing email", "{}"},
		{"null email", `{"email":null}`}, {"number email", `{"email":7}`},
		{"unknown field", `{"email":"selected@example.test","serverAddress":"192.0.2.8"}`},
		{"duplicate email", `{"email":"other@example.test","email":"selected@example.test"}`},
		{"duplicate identical email", `{"email":"selected@example.test","email":"selected@example.test"}`},
		{"escaped duplicate email", `{"email":"other@example.test","\u0065mail":"selected@example.test"}`},
		{"trailing object", `{"email":"selected@example.test"}{}`},
		{"trailing scalar", `{"email":"selected@example.test"} true`},
		{"oversized", `{"email":"` + strings.Repeat("x", (1<<20)+1) + `"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response, result := nativeClientConfigRequest(t, router, strconv.Itoa(inbound.Id), tc.body, "panel.example.test", nil)
			nativeClientConfigAssertFailure(t, response, result, selectedSecret)
		})
	}
}

func TestNativeClientConfigHTTPBodyBoundaryAndContentType(t *testing.T) {
	t.Setenv("XUI_LOG_FOLDER", t.TempDir())
	logger.InitLogger(logging.ERROR)
	t.Cleanup(logger.CloseLogger)
	portableControllerDB(t)
	inbound, selectedSecret := nativeClientConfigFixture(t, 61, "selected@example.test")
	router := nativeClientConfigRouter(61)
	id := strconv.Itoa(inbound.Id)
	const body = `{"email":"selected@example.test"}`
	for _, size := range []int{4096, 4097} {
		t.Run(fmt.Sprintf("bytes-%d", size), func(t *testing.T) {
			padded := body + strings.Repeat(" ", size-len(body))
			response, result := nativeClientConfigRequest(t, router, id, padded, "panel.example.test", nil)
			if size == 4096 {
				if response.Code != http.StatusOK || !result.Success || result.Obj == nil {
					t.Fatal("valid JSON at the request size limit was rejected")
				}
			} else {
				nativeClientConfigAssertFailure(t, response, result, selectedSecret)
			}
		})
	}
	for _, contentType := range []string{"", "text/plain", "application/x-www-form-urlencoded", "application/json; broken"} {
		t.Run("content-type/"+contentType, func(t *testing.T) {
			response, result := nativeClientConfigRequest(t, router, id, body, "panel.example.test", map[string]string{"Content-Type": contentType})
			nativeClientConfigAssertFailure(t, response, result, selectedSecret)
		})
	}
	response, result := nativeClientConfigRequest(t, router, id, " \n"+body+"\t", "panel.example.test", map[string]string{"Content-Type": "application/json; charset=utf-8"})
	if response.Code != http.StatusOK || !result.Success || result.Obj == nil {
		t.Fatal("ordinary JSON whitespace or charset was rejected")
	}
}

func TestNativeClientConfigHTTPHostValidationAndForwardingIsolation(t *testing.T) {
	t.Setenv("XUI_LOG_FOLDER", t.TempDir())
	logger.InitLogger(logging.ERROR)
	t.Cleanup(logger.CloseLogger)
	portableControllerDB(t)
	inbound, selectedSecret := nativeClientConfigFixture(t, 71, "selected@example.test")
	router := nativeClientConfigRouter(71)
	id := strconv.Itoa(inbound.Id)
	const body = `{"email":"selected@example.test"}`
	for _, host := range []string{"panel.example.test", "panel.example.test:2053", "192.0.2.77:2053", "[2001:db8::77]", "[2001:db8::77]:2053"} {
		t.Run("valid/"+host, func(t *testing.T) {
			response, result := nativeClientConfigRequest(t, router, id, body, host, map[string]string{
				"X-Forwarded-Host": "attacker.example.invalid:443", "X-Real-IP": "198.51.100.99",
				"X-Forwarded-For": "198.51.100.98", "Forwarded": "for=198.51.100.97;host=attacker.example.invalid;proto=https",
			})
			if response.Code != http.StatusOK || !result.Success || result.Obj == nil {
				t.Fatal("valid request host failed native client export")
			}
			for _, injected := range []string{"attacker.example.invalid", "198.51.100.99", "198.51.100.98", "198.51.100.97"} {
				if bytes.Contains(result.Obj.Config, []byte(injected)) {
					t.Fatal("untrusted forwarding headers changed the client configuration")
				}
			}
		})
	}
	for _, host := range []string{"", "https://panel.example.test", "user@panel.example.test", "panel.example.test/path", "panel example.test",
		"panel.example.test:0", "panel.example.test:65536", "panel.example.test:abc", "[2001:db8::77", "2001:db8::77]", "[192.0.2.77]",
		"0.0.0.0", "239.1.2.3", "[::]", "[ff02::1]"} {
		t.Run("invalid/"+host, func(t *testing.T) {
			response, result := nativeClientConfigRequest(t, router, id, body, host, map[string]string{"X-Forwarded-Host": "valid.example.test"})
			nativeClientConfigAssertFailure(t, response, result, selectedSecret)
		})
	}
	if err := database.GetDB().Model(inbound).Update("listen", "").Error; err != nil {
		t.Fatal("cannot prepare wildcard listener fixture")
	}
	response, result := nativeClientConfigRequest(t, router, id, body, "endpoint.example.test:2053", map[string]string{"X-Forwarded-Host": "attacker.example.invalid:443"})
	if response.Code != http.StatusOK || !result.Success || result.Obj == nil {
		t.Fatal("wildcard listener did not use the validated request Host")
	}
	var exported struct {
		Outbounds []struct {
			Protocol string `json:"protocol"`
			Settings struct {
				Address string `json:"address"`
				Port    int    `json:"port"`
			} `json:"settings"`
		} `json:"outbounds"`
	}
	if json.Unmarshal(result.Obj.Config, &exported) != nil || len(exported.Outbounds) == 0 || exported.Outbounds[0].Protocol != "anytls" || exported.Outbounds[0].Settings.Address != "endpoint.example.test" || exported.Outbounds[0].Settings.Port != inbound.Port {
		t.Fatal("wildcard listener export selected the wrong request endpoint or used the panel port")
	}
	if bytes.Contains(result.Obj.Config, []byte("attacker.example.invalid")) {
		t.Fatal("forwarded Host overrode the validated request Host fallback")
	}
}
