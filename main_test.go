package main

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/util/netnstest"
	"github.com/mhsanaei/3x-ui/v2/web/service"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const ownNetnsEnv = "XUI_MAIN_TEST_NETNS"

// Moving the panel's port reserves it in ip_local_reserved_ports and closes
// the connections holding it: as root the tests run in a network namespace
// of their own.
func TestMain(m *testing.M) {
	if code, done := netnstest.Reexec(ownNetnsEnv); done {
		os.Exit(code)
	}
	os.Exit(m.Run())
}

// portMoves skips a test that moves the panel's port where that would
// reach the host's reservations and connections.
func portMoves(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 && !netnstest.Own(ownNetnsEnv) {
		t.Skip("moves the panel's port: as root, only in a network namespace of its own")
	}
}

// panelDB writes a panel database with one inbound named remark to path.
func panelDB(t *testing.T, path, remark string) []byte {
	t.Helper()
	if err := database.InitDB(path); err != nil {
		t.Fatal(err)
	}
	if err := database.GetDB().Create(&model.Inbound{Remark: remark, Port: 443, Tag: "inbound-443", XrayInstance: "xray-1"}).Error; err != nil {
		t.Fatal(err)
	}
	database.CloseDB()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// importSetup gives the test a live panel database and serves file.
func importSetup(t *testing.T, file []byte) (live string, url string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XUI_DB_FOLDER", dir)
	live = config.GetDBPath()
	panelDB(t, live, "live")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(file) }))
	t.Cleanup(srv.Close)
	return live, srv.URL + "/x-ui.db"
}

func remarks(t *testing.T, path string) string {
	t.Helper()
	g, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s, _ := g.DB(); s.Close() }()
	var r []string
	g.Model(&model.Inbound{}).Pluck("remark", &r)
	return strings.Join(r, ",")
}

func TestImportDB(t *testing.T) {
	src := panelDB(t, filepath.Join(t.TempDir(), "src.db"), "imported")
	live, url := importSetup(t, src)
	if err := importDbFromURL(url); err != nil {
		t.Fatal(err)
	}
	if got := remarks(t, live); got != "imported" {
		t.Errorf("live database has %q", got)
	}
	backups, _ := filepath.Glob(live + ".backup-*")
	if len(backups) != 1 || remarks(t, backups[0]) != "live" {
		t.Errorf("backups %v", backups)
	}
	if _, err := os.Stat(live + ".temp"); err == nil {
		t.Error("the temporary file was left behind")
	}
}

// Another program's SQLite file is refused before the live database is
// touched.
func TestImportRejectsForeignSQLite(t *testing.T) {
	other := filepath.Join(t.TempDir(), "other.db")
	g, err := gorm.Open(sqlite.Open(other), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	g.Exec("create table notes(id integer primary key, body text)")
	s, _ := g.DB()
	s.Close()
	b, _ := os.ReadFile(other)
	live, url := importSetup(t, b)
	before, _ := os.ReadFile(live)
	if err := importDbFromURL(url); err == nil {
		t.Fatal("another program's database was imported")
	}
	after, _ := os.ReadFile(live)
	if !bytes.Equal(before, after) {
		t.Error("the live database changed")
	}
	if backups, _ := filepath.Glob(live + ".backup-*"); len(backups) != 0 {
		t.Errorf("backups %v", backups)
	}
}

// While a process -- the panel -- has the database open, or a journal lies
// next to it, the import refuses.
func TestImportRefusesDatabaseInUse(t *testing.T) {
	src := panelDB(t, filepath.Join(t.TempDir(), "src.db"), "imported")
	live, url := importSetup(t, src)

	f, err := os.Open(live)
	if err != nil {
		t.Fatal(err)
	}
	holder := exec.Command("sleep", "30")
	holder.ExtraFiles = []*os.File{f}
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	f.Close()
	err = importDbFromURL(url)
	holder.Process.Kill()
	holder.Wait()
	if err == nil || !strings.Contains(err.Error(), "open") {
		t.Errorf("imported under a process holding the database: err=%v", err)
	}

	os.WriteFile(live+"-journal", []byte("x"), 0o644)
	if err := importDbFromURL(url); err == nil || !strings.Contains(err.Error(), "-journal") {
		t.Errorf("imported next to a journal: err=%v", err)
	}
	if got := remarks(t, live); got != "live" {
		t.Errorf("live database has %q", got)
	}
}

// A setting the CLI fails to apply makes it fail, so a script can tell.
func TestSettingFailuresAreReported(t *testing.T) {
	portMoves(t)
	t.Setenv("XUI_DB_FOLDER", t.TempDir())
	t.Cleanup(func() { database.CloseDB() })
	if err := updateSetting(60000, "fardin", strings.Repeat("p", 80), "hetzner", "", false); err == nil {
		t.Error("a password bcrypt refuses was reported as applied")
	}
	if err := updateSetting(60000, "fardin", "fardin", "hetzner", "", false); err != nil {
		t.Errorf("good settings: %v", err)
	}
	if err := updateXrayEgress("garbage"); err == nil {
		t.Error("a malformed outgoing IP list was accepted")
	}
	if err := updateXrayEgress("xray-1=999.1.1.1"); err == nil {
		t.Error("a bad outgoing IP was accepted")
	}
	if err := updateCert("/etc/cert.pem", ""); err == nil {
		t.Error("a certificate without its key was accepted")
	}
}

// "x-ui setting -port" reserves the new port and closes the outgoing
// connections that hold it, so the restart that applies it can listen; a
// port another program listens on is refused and the old one kept.
func TestSettingPortFreesThePort(t *testing.T) {
	portMoves(t)
	if !netnstest.Own(ownNetnsEnv) {
		t.Skip("closes connections: runs only as root, in a network namespace of its own")
	}
	dir := t.TempDir()
	t.Setenv("XUI_DB_FOLDER", dir)
	t.Cleanup(func() { database.CloseDB() })
	free := func() int {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}

	srv, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go func() {
		for {
			c, err := srv.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	port := free()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}}
	c, err := d.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	read := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 1))
		c.Close()
		read <- err
	}()

	if err := updateSetting(port, "", "", "", "", false); err != nil {
		t.Fatalf("port held by an outgoing connection: %v", err)
	}
	select {
	case err := <-read:
		if err == nil || !strings.Contains(err.Error(), "abort") {
			t.Errorf("the connection saw %v, want it aborted", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("the connection on the port is still open")
	}
	reserved, _ := os.ReadFile("/proc/sys/net/ipv4/ip_local_reserved_ports")
	if !strings.Contains(","+strings.TrimSpace(string(reserved))+",", ","+strconv.Itoa(port)+",") {
		t.Errorf("reserved %q, want %d among them", reserved, port)
	}
	if ours, _ := os.ReadFile(filepath.Join(dir, "reserved-ports")); strings.TrimSpace(string(ours)) != strconv.Itoa(port) {
		t.Errorf("state file %q, want %d", ours, port)
	}

	taken := free()
	other, err := net.Listen("tcp", ":"+strconv.Itoa(taken))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := updateSetting(taken, "", "", "", "", false); err == nil {
		t.Error("a port another program listens on was set")
	}
	var ss service.SettingService
	if got, _ := ss.GetPort(); got != port {
		t.Errorf("port %d after the refused move, want %d", got, port)
	}
}
