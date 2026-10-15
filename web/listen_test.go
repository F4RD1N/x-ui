package web

import (
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/util/netnstest"
	"github.com/mhsanaei/3x-ui/v2/web/global"
	"github.com/mhsanaei/3x-ui/v2/web/service"
)

const ownNetnsEnv = "XUI_WEB_TEST_NETNS"

// startable sets up a server to Start, on a database of its own whose web
// port is port, retrying its listener quickly. Start starts the cores,
// which reserve ports in the kernel: only in the tests' own namespace.
func startable(t *testing.T, port int) *Server {
	t.Helper()
	if !netnstest.Own(ownNetnsEnv) {
		t.Skip("starts the cores: runs only as root, in a network namespace of its own")
	}
	if err := database.InitDB(filepath.Join(t.TempDir(), "x-ui.db")); err != nil {
		t.Fatal(err)
	}
	var ss service.SettingService
	if err := ss.SetPort(port); err != nil {
		t.Fatal(err)
	}
	old := listenRetry
	listenRetry = 50 * time.Millisecond
	s := NewServer()
	global.SetWebServer(s)
	t.Cleanup(func() {
		s.Stop()
		listenRetry = old
		database.CloseDB()
	})
	return s
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// answers says whether the panel answers HTTP on port.
func answers(port int) bool {
	c := http.Client{Timeout: time.Second}
	resp, err := c.Get("http://127.0.0.1:" + strconv.Itoa(port) + "/")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatal(what)
}

// A panel whose port another program listens on still starts, jobs and
// cores and all, without its web server; the web server listens once the
// port is free.
func TestStartWithoutItsPort(t *testing.T) {
	port := freePort(t)
	s := startable(t, port)
	other, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if s.Address() != "" {
		t.Fatalf("listening on %q next to another program", s.Address())
	}
	if len(s.cron.Entries()) == 0 {
		t.Fatal("the jobs were not started")
	}
	time.Sleep(150 * time.Millisecond) // a few retries
	other.Close()
	eventually(t, "the web server never listened once the port was free", func() bool { return s.Address() != "" && answers(port) })
	if want := net.JoinHostPort("", strconv.Itoa(port)); s.Address() != want {
		t.Errorf("listening on %q, want %q", s.Address(), want)
	}
	s.Stop()
	if s.Address() != "" || answers(port) {
		t.Error("still listening after Stop")
	}
}

// A server replacing one that listened on fallback comes back there when
// its new address cannot be listened on.
func TestStartFallsBackToTheOldAddress(t *testing.T) {
	port := freePort(t)
	s := startable(t, port)
	other, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	oldPort := freePort(t)
	fallback := net.JoinHostPort("127.0.0.1", strconv.Itoa(oldPort))
	if err := s.StartWithFallback(fallback); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if s.Address() != fallback || !answers(oldPort) {
		t.Fatalf("listening on %q, want %q", s.Address(), fallback)
	}
}

// A Start that fails stops what it started, and not the cores: it never
// got to them, and the running ones belong to the server it replaces.
func TestFailedStartLeavesTheCores(t *testing.T) {
	s := startable(t, freePort(t))
	if err := database.GetDB().Where("key = ?", "webPort").Delete(&model.Setting{}).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.GetDB().Create(&model.Setting{Key: "webPort", Value: "not a port"}).Error; err != nil {
		t.Fatal(err)
	}
	// Cores started (here none can: there is no xray) are not stopped by
	// hand, whatever an earlier test's Stop did.
	var xs service.XrayService
	xs.RestartXray(false)
	xs.SetToNeedRestart()
	if err := s.Start(); err == nil {
		t.Fatal("started without a port")
	}
	if s.ctx.Err() == nil {
		t.Error("the failed server's jobs and hub are still running")
	}
	// A stop of the cores would mark them stopped by hand, and a pending
	// restart would no longer be done.
	if !xs.IsNeedRestartAndSetFalse() {
		t.Error("the failed Start stopped the cores")
	}
}
