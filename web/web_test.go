package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/op/go-logging"
	"github.com/robfig/cron/v3"
	"github.com/xlzd/gotp"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/netnstest"
	"github.com/mhsanaei/3x-ui/v2/web/global"
	"github.com/mhsanaei/3x-ui/v2/web/service"
)

// The logger is a nil pointer until initialised. Its file goes to a
// temporary folder, and nothing below CRITICAL reaches syslog. A server
// started here starts the cores, which reserve their ports in
// ip_local_reserved_ports: as root the tests run in a network namespace of
// their own, and the panel's files go to that folder too.
func TestMain(m *testing.M) {
	if code, done := netnstest.Reexec(ownNetnsEnv); done {
		os.Exit(code)
	}
	dir, err := os.MkdirTemp("", "web-test-log")
	if err != nil {
		panic(err)
	}
	os.Setenv("XUI_LOG_FOLDER", dir)
	os.Setenv("XUI_DB_FOLDER", dir)
	os.Setenv("XUI_BIN_FOLDER", dir)
	logger.InitLogger(logging.CRITICAL)
	code := m.Run()
	logger.CloseLogger()
	os.RemoveAll(dir)
	os.Exit(code)
}

// testEngine builds the panel's router on a fresh database whose admin is
// admin/admin, under /hetzner/.
func testEngine(t *testing.T) *gin.Engine {
	t.Helper()
	if err := database.InitDB(filepath.Join(t.TempDir(), "x-ui.db")); err != nil {
		t.Fatal(err)
	}
	var ss service.SettingService
	if err := ss.SetBasePath("/hetzner/"); err != nil {
		t.Fatal(err)
	}
	// Controllers schedule their jobs on the server's cron, which is never
	// started here.
	s := NewServer()
	s.cron = cron.New(cron.WithSeconds())
	global.SetWebServer(s)
	engine, err := s.initRouter()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.wsHub.Stop()
		database.CloseDB()
	})
	return engine
}

func login(engine *gin.Engine, body string, contentType string) (*httptest.ResponseRecorder, string) {
	r := httptest.NewRequest("POST", "/hetzner/login", strings.NewReader(body))
	r.Header.Set("Content-Type", contentType)
	r.RemoteAddr = "192.0.2.1:40000"
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, r)
	var msg struct {
		Success bool   `json:"success"`
		Msg     string `json:"msg"`
	}
	json.Unmarshal(w.Body.Bytes(), &msg)
	if !msg.Success {
		return w, "failed: " + msg.Msg
	}
	return w, "ok"
}

// The session lasts as long as the panel says, also for a cookie kept past
// its Max-Age (a captured one), not the 30 days the cookie codec defaults to.
func TestSessionEndsAtMaxAge(t *testing.T) {
	engine := testEngine(t)
	var ss service.SettingService
	// sessionMaxAge is read when the router is built; 360 minutes is the
	// default.
	if n, _ := ss.GetSessionMaxAge(); n != 360 {
		t.Fatalf("sessionMaxAge %d", n)
	}
	synctest.Test(t, func(t *testing.T) {
		w, res := login(engine, "username=admin&password=admin", "application/x-www-form-urlencoded")
		if res != "ok" {
			t.Fatal(res)
		}
		cookie := w.Header().Get("Set-Cookie")
		cookie = cookie[:strings.Index(cookie, ";")]
		loggedIn := func() bool {
			r := httptest.NewRequest("GET", "/hetzner/", nil)
			r.Header.Set("Cookie", cookie)
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, r)
			return w.Code == http.StatusTemporaryRedirect
		}
		if !loggedIn() {
			t.Fatal("not logged in after login")
		}
		time.Sleep(5 * time.Hour)
		if !loggedIn() {
			t.Fatal("logged out after 5 hours of 6")
		}
		time.Sleep(2 * time.Hour)
		if loggedIn() {
			t.Fatal("still logged in after 7 hours of 6")
		}
	})
}

// A large body sent before login is not read whole.
func TestLoginBodyIsCapped(t *testing.T) {
	engine := testEngine(t)
	big := `{"username":"` + strings.Repeat("a", 2<<20) + `"}`
	_, res := login(engine, big, "application/json")
	if res != "failed: The Input data format is invalid." {
		t.Fatalf("2 MiB login body: %s", res)
	}
	if _, res := login(engine, `{"username":"admin","password":"admin"}`, "application/json"); res != "ok" {
		t.Fatalf("normal login: %s", res)
	}
}

// After a wrong 2FA code the typed password is the right one; no failed
// login logs the password, and a header that is not an IP is not logged.
func TestFailedLoginLogsNoPassword(t *testing.T) {
	engine := testEngine(t)
	var us service.UserService
	if err := us.UpdateFirstUser("fardin", "right-pass-1"); err != nil {
		t.Fatal(err)
	}
	var ss service.SettingService
	if err := ss.SetTwoFactorToken(gotp.RandomSecret(16)); err != nil {
		t.Fatal(err)
	}
	if err := ss.SetTwoFactorEnable(true); err != nil {
		t.Fatal(err)
	}
	for _, form := range []url.Values{
		{"username": {"fardin"}, "password": {"right-pass-1"}, "twoFactorCode": {"000000"}},
		{"username": {"fardin"}, "password": {"right-pass-2"}},
	} {
		r := httptest.NewRequest("POST", "/hetzner/login", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("X-Real-IP", "<img src=x onerror=alert(1)>")
		r.RemoteAddr = "192.0.2.1:40000"
		engine.ServeHTTP(httptest.NewRecorder(), r)
	}
	logs := strings.Join(logger.GetLogs(100, "DEBUG"), "\n")
	if strings.Count(logs, "failed login") != 2 {
		t.Fatalf("failed logins not logged:\n%s", logs)
	}
	for _, bad := range []string{"right-pass", "<img"} {
		if strings.Contains(logs, bad) {
			t.Errorf("log carries %q:\n%s", bad, logs)
		}
	}
	if !strings.Contains(logs, `IP "192.0.2.1"`) {
		t.Errorf("the address is not the connection's:\n%s", logs)
	}
}

// Real pages come in each request's language.
func TestPagesInRequestLanguage(t *testing.T) {
	engine := testEngine(t)
	for lang, want := range map[string]string{"fa-IR": "خوش\u200cآمدید", "en-US": "Welcome", "ru-RU": "Добро пожаловать!"} {
		for i := 0; i < 2; i++ {
			r := httptest.NewRequest("GET", "/hetzner/", nil)
			r.AddCookie(&http.Cookie{Name: "lang", Value: lang})
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, r)
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "– "+want+"</title>") {
				t.Fatalf("%s: %d, no %q title", lang, w.Code, want)
			}
		}
	}
}

// loginCookie logs admin in and returns the session cookie.
func loginCookie(t *testing.T, engine *gin.Engine) string {
	t.Helper()
	w, res := login(engine, "username=admin&password=admin", "application/x-www-form-urlencoded")
	if res != "ok" {
		t.Fatal(res)
	}
	cookie := w.Header().Get("Set-Cookie")
	return cookie[:strings.Index(cookie, ";")]
}

// Saving the xray template alone keeps the remote config; an interval that
// is not a whole number of minutes is refused, not stored as 0.
func TestXraySettingKeepsRemoteConfig(t *testing.T) {
	engine := testEngine(t)
	cookie := loginCookie(t, engine)
	var ss service.SettingService
	ss.SetXrayConfigUrl("https://example.com/x.json")
	ss.SetXrayConfigInterval(5)
	template, err := ss.GetXrayConfigTemplate()
	if err != nil {
		t.Fatal(err)
	}
	post := func(form url.Values) bool {
		r := httptest.NewRequest("POST", "/hetzner/panel/xray/update", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Cookie", cookie)
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, r)
		var msg struct {
			Success bool `json:"success"`
		}
		json.Unmarshal(w.Body.Bytes(), &msg)
		return msg.Success
	}
	check := func(when, wantURL string, wantInterval int) {
		t.Helper()
		u, _ := ss.GetXrayConfigUrl()
		n, _ := ss.GetXrayConfigInterval()
		if u != wantURL || n != wantInterval {
			t.Errorf("%s: url %q interval %d, want %q %d", when, u, n, wantURL, wantInterval)
		}
	}
	if !post(url.Values{"xraySetting": {template}}) {
		t.Fatal("template alone refused")
	}
	check("template alone", "https://example.com/x.json", 5)
	if post(url.Values{"xraySetting": {template}, "xrayConfigUrl": {"https://example.com/y.json"}, "xrayConfigInterval": {"1.5"}}) {
		t.Error("interval 1.5 accepted")
	}
	check("interval 1.5", "https://example.com/x.json", 5)
	if !post(url.Values{"xraySetting": {template}, "xrayConfigUrl": {""}, "xrayConfigInterval": {"7"}}) {
		t.Fatal("full form refused")
	}
	check("full form", "", 7)
}

// The Multi Instance plan's messages come in the viewer's language.
func TestMultiInstancePlanTranslated(t *testing.T) {
	engine := testEngine(t)
	cookie := loginCookie(t, engine)
	db := database.GetDB()
	settings := `{"clients":[{"id":"6b0e9c1c-2d6f-4c6e-9b8a-00000000aa01","email":"plan@test","enable":true}],"decryption":"none"}`
	// The only port after the inbound's own is another inbound's, so no
	// free port is left for a sub-inbound.
	src := &model.Inbound{UserId: 1, Enable: true, Remark: "src", Port: 65534, Protocol: model.VLESS, Tag: "inbound-65534",
		Settings: settings, StreamSettings: `{"network":"tcp","security":"none"}`, Sniffing: `{"enabled":false}`}
	other := &model.Inbound{UserId: 1, Enable: true, Remark: "other", Port: 65535, Protocol: model.VLESS, Tag: "inbound-65535",
		Settings: strings.Replace(settings, "plan@test", "plan2@test", 1), StreamSettings: src.StreamSettings, Sniffing: src.Sniffing}
	for _, in := range []*model.Inbound{src, other} {
		if err := db.Create(in).Error; err != nil {
			t.Fatal(err)
		}
	}
	for lang, want := range map[string]string{
		"fa-IR": "فقط 0 پورت آزاد بعد از 65534 باقی مانده است",
		"en-US": "Only 0 free ports are left after 65534",
	} {
		form := url.Values{"count": {"1"}, "cores": {"0"}, "max": {"false"}, "subs": {"[]"}}
		r := httptest.NewRequest("POST", "/hetzner/panel/api/inbounds/"+strconv.Itoa(src.Id)+"/multiInstance", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Cookie", cookie+"; lang="+lang)
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, r)
		var msg struct {
			Obj struct {
				Error string            `json:"error"`
				Items []json.RawMessage `json:"items"`
			} `json:"obj"`
		}
		json.Unmarshal(w.Body.Bytes(), &msg)
		if msg.Obj.Error != want || len(msg.Obj.Items) != 0 {
			t.Errorf("%s: %s", lang, w.Body.String())
		}
	}
}
