package controller

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/util/backup"
	"github.com/mhsanaei/3x-ui/v2/web/service"
)

func portableControllerDB(t *testing.T) {
	t.Helper()
	t.Setenv("XUI_DB_FOLDER", t.TempDir())
	if err := database.InitDB(config.GetDBPath()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.CloseDB() })
}

func TestPortableHTTPDownloadUsesArchiveAndNoStore(t *testing.T) {
	portableControllerDB(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	controller := &ServerController{}
	router.GET("/backup", controller.getDb)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/backup", nil))
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/zip" || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected backup response headers: %v", response.Header())
	}
	if response.Header().Get("Content-Disposition") != "attachment; filename=x-ui-backup.zip" {
		t.Fatal("archive download name changed")
	}
	if _, err := backup.Decode(bytes.NewReader(response.Body.Bytes()), int64(response.Body.Len())); err != nil {
		t.Fatal("HTTP backup is not a valid portable archive:", err)
	}
}

func TestPortableRestoredURLKeepsProxyAndUpdatesDirectListener(t *testing.T) {
	portableControllerDB(t)
	for _, row := range []model.Setting{{Key: "webPort", Value: "2443"}, {Key: "webBasePath", Value: "/restored/"}, {Key: "webCertFile", Value: "managed-certificate.pem"}} {
		if err := database.GetDB().Create(&row).Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct{ host, want string }{{"127.0.0.1:2053", "https://127.0.0.1:2443/restored/"}, {"[::1]:2053", "https://[::1]:2443/restored/"}, {"panel.example.test", "/restored/"}, {"panel.example.test:443", "/restored/"}} {
		ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
		ctx.Request = httptest.NewRequest(http.MethodPost, "http://"+tc.host+"/restore", nil)
		if got := restoredPanelURL(ctx, &service.SettingService{}, 2053); got != tc.want {
			t.Fatalf("host %s: got %s", tc.host, got)
		}
	}
}
