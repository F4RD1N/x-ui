package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

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
