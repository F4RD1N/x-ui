package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/web/service"
	panelsession "github.com/mhsanaei/3x-ui/v2/web/session"
	"github.com/op/go-logging"
)

type inertPanelUpdater struct {
	state                   *service.PanelUpdateState
	startError, statusError error
	starts, reads           int
}

func (f *inertPanelUpdater) StartPanelUpdate() (*service.PanelUpdateState, error) {
	f.starts++
	return f.state, f.startError
}

func (f *inertPanelUpdater) PanelUpdateStatus() (*service.PanelUpdateState, error) {
	f.reads++
	return f.state, f.statusError
}

func updaterHTTPFixture(t *testing.T, backend *inertPanelUpdater) (*gin.Engine, *http.Cookie) {
	t.Helper()
	t.Setenv("XUI_LOG_FOLDER", t.TempDir())
	logger.InitLogger(logging.ERROR)
	t.Cleanup(logger.CloseLogger)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(sessions.Sessions("update-test-session", cookie.NewStore([]byte("synthetic-update-cookie-key-32byte!"))))
	router.POST("/fixture/login", func(c *gin.Context) {
		panelsession.SetLoginUser(c, &model.User{Id: 1, Username: "synthetic-admin"})
		if err := sessions.Default(c).Save(); err != nil {
			t.Fatal(err)
		}
		c.Status(http.StatusNoContent)
	})
	api := new(APIController)
	group := router.Group("/panel/api/server")
	group.Use(api.checkAPIAuth)
	controller := &ServerController{panelUpdates: backend}
	// Use production route registration without starting background service tasks.
	controller.initRouter(group)
	login := httptest.NewRecorder()
	router.ServeHTTP(login, httptest.NewRequest(http.MethodPost, "/fixture/login", nil))
	cookies := login.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one signed login cookie, got %d", len(cookies))
	}
	return router, cookies[0]
}

func updaterRequest(router *gin.Engine, method, path string, auth *http.Cookie) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, nil)
	if auth != nil {
		request.AddCookie(auth)
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func TestPanelUpdateHTTPRoutesRequireValidSession(t *testing.T) {
	backend := &inertPanelUpdater{state: &service.PanelUpdateState{ID: "secret-job", State: "running"}}
	router, auth := updaterHTTPFixture(t, backend)
	invalid := *auth
	invalid.Value = "tampered-session"
	for _, session := range []*http.Cookie{nil, &invalid} {
		for method, endpoint := range map[string]string{http.MethodPost: "/updatePanel", http.MethodGet: "/updatePanelStatus"} {
			response := updaterRequest(router, method, "/panel/api/server"+endpoint, session)
			if response.Code != http.StatusNotFound || response.Body.Len() != 0 {
				t.Fatalf("unauthenticated %s exposed updater state: %d", endpoint, response.Code)
			}
		}
	}
	if backend.starts != 0 || backend.reads != 0 {
		t.Fatal("unauthenticated requests reached the updater backend")
	}
}

func TestPanelUpdateHTTPAcceptanceAndPersistentStatusContract(t *testing.T) {
	backend := &inertPanelUpdater{state: &service.PanelUpdateState{
		ID: "job-123", Unit: "x-ui-update-job-123", State: "running", Phase: "preparing",
		StartedAt: 1700000000000, CurrentVersion: "2.9.0-dialect.11.5",
	}}
	router, auth := updaterHTTPFixture(t, backend)
	for index, state := range []string{"running", "running", "failed", "succeeded", "idle"} {
		backend.state.State = state
		if state == "failed" || state == "succeeded" {
			backend.state.Phase = "finished"
			backend.state.FinishedAt = 1700000001000
		}
		method, endpoint := http.MethodGet, "/updatePanelStatus"
		if index == 0 {
			method, endpoint = http.MethodPost, "/updatePanel"
		}
		response := updaterRequest(router, method, "/panel/api/server"+endpoint, auth)
		var value struct {
			Success bool                     `json:"success"`
			Message string                   `json:"msg"`
			State   service.PanelUpdateState `json:"obj"`
		}
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &value) != nil || !value.Success {
			t.Fatalf("authenticated %s failed: %s", endpoint, response.Body.String())
		}
		if value.State != *backend.state || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("state or no-store contract changed")
		}
		if value.Message != "" {
			t.Fatal("accepted POST/status response must not announce completion through a generic success toast")
		}
	}
	if backend.starts != 1 || backend.reads != 4 {
		t.Fatalf("unexpected backend calls: start=%d read=%d", backend.starts, backend.reads)
	}
}

func TestPanelUpdateHTTPSafeKnownErrorsAndNoRawCommandOutput(t *testing.T) {
	backend := &inertPanelUpdater{}
	router, auth := updaterHTTPFixture(t, backend)
	const private = "DO-NOT-RETURN-command-token-or-private-path"
	for _, tc := range []struct {
		name, method, endpoint, message string
		err                             error
	}{
		{"busy", http.MethodPost, "/updatePanel", "already running", fmt.Errorf("%s: %w", private, service.ErrPanelUpdateBusy)},
		{"startup timeout", http.MethodPost, "/updatePanel", "startup could not be confirmed", fmt.Errorf("%s: %w", private, service.ErrPanelUpdateStartupTimeout)},
		{"unexpected start", http.MethodPost, "/updatePanel", "unable to start", errors.New(private)},
		{"status read", http.MethodGet, "/updatePanelStatus", "temporarily unavailable", errors.New(private)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend.startError, backend.statusError = tc.err, tc.err
			response := updaterRequest(router, tc.method, "/panel/api/server"+tc.endpoint, auth)
			var value struct {
				Success bool            `json:"success"`
				Message string          `json:"msg"`
				Object  json.RawMessage `json:"obj"`
			}
			if json.Unmarshal(response.Body.Bytes(), &value) != nil || value.Success || !strings.Contains(value.Message, tc.message) {
				t.Fatalf("wrong safe error: %s", response.Body.String())
			}
			if strings.Contains(response.Body.String(), private) || string(value.Object) != "null" || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("error response exposed backend detail/state or allowed caching")
			}
		})
	}
}
