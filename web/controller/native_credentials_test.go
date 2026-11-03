package controller

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	panelsession "github.com/mhsanaei/3x-ui/v2/web/session"
	"github.com/op/go-logging"
)

func credentialRouter(loggedIn bool) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(sessions.Sessions("test-session", cookie.NewStore([]byte("synthetic-test-signing-key-32byte!"))))
	if loggedIn {
		r.Use(func(c *gin.Context) {
			panelsession.SetLoginUser(c, &model.User{Id: 1, Username: "test-admin"})
			c.Next()
		})
	}
	api := new(APIController)
	group := r.Group("/panel/api/server")
	group.Use(api.checkAPIAuth)
	group.POST("/native/credentials", new(ServerController).nativeCredentials)
	return r
}

func TestNativeCredentialsHTTPAuthenticationAndValidation(t *testing.T) {
	t.Setenv("XUI_LOG_FOLDER", t.TempDir())
	logger.InitLogger(logging.ERROR)
	t.Cleanup(logger.CloseLogger)
	request := func(loggedIn bool, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/panel/api/server/native/credentials", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		credentialRouter(loggedIn).ServeHTTP(w, req)
		return w
	}
	if w := request(false, `{"kind":"dnstt"}`); w.Code != http.StatusNotFound || bytes.Contains(w.Body.Bytes(), []byte("privateKey")) {
		t.Fatal("unauthenticated key generation exposed")
	}
	w := request(true, `{"kind":"dnstt"}`)
	var result struct {
		Success bool              `json:"success"`
		Obj     map[string]string `json:"obj"`
	}
	if json.Unmarshal(w.Body.Bytes(), &result) != nil || !result.Success || len(result.Obj["privateKey"]) != 64 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("authenticated generation failed")
	}
	for _, body := range []string{`{}`, `null`, `{"kind":"dnstt","unknown":true}`, `{"kind":"dnstt"}{}`, `{"kind":123}`, `{"kind":"` + strings.Repeat("x", (1<<20)+1) + `"}`} {
		w := request(true, body)
		var response map[string]any
		if json.Unmarshal(w.Body.Bytes(), &response) != nil {
			t.Fatal("invalid JSON error response")
		}
		if response["success"] == true {
			t.Fatal("malformed request accepted")
		}
		if bytes.Contains(w.Body.Bytes(), []byte("privateKey")) {
			t.Fatal("failure generated key")
		}
	}
}
