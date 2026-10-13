package job

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/web/service"
	"github.com/mhsanaei/3x-ui/v2/xray"

	"github.com/xtls/xray-core/app/proxyman/command"
	"google.golang.org/grpc"
)

// jobDB gives the test a panel database and bin folder of its own.
func jobDB(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XUI_BIN_FOLDER", dir)
	t.Setenv("XUI_LOG_FOLDER", dir)
	t.Setenv("XUI_DB_FOLDER", dir)
	if err := database.InitDB(filepath.Join(dir, "x-ui.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.CloseDB() })
	return dir
}

// fakeCore stands in for a core's handler API. failAdd makes AddUser fail.
type fakeCore struct {
	command.UnimplementedHandlerServiceServer
	mu      sync.Mutex
	calls   []string
	failAdd bool
}

func (f *fakeCore) AlterInbound(ctx context.Context, r *command.AlterInboundRequest) (*command.AlterInboundResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	op := r.Operation.Type[strings.LastIndex(r.Operation.Type, ".")+1:]
	f.calls = append(f.calls, op)
	if f.failAdd && op == "AddUserOperation" {
		return nil, errors.New("no")
	}
	return &command.AlterInboundResponse{}, nil
}

// limitedClient sets up an inbound whose client, limited to one IP, shows
// up from a second IP, against a fake core; it returns the job and core.
func limitedClient(t *testing.T, protocol model.Protocol, settings string) (*CheckClientIpJob, *fakeCore) {
	t.Helper()
	dir := jobDB(t)
	fb := filepath.Join(dir, "fb")
	os.MkdirAll(fb, 0o755)
	os.WriteFile(filepath.Join(fb, "fail2ban-client"), []byte("#!/bin/sh\nexit 0\n"), 0o755)
	t.Setenv("PATH", fb+":"+os.Getenv("PATH"))

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	core := &fakeCore{}
	command.RegisterHandlerServiceServer(gs, core)
	go gs.Serve(l)
	t.Cleanup(gs.Stop)

	accessLog := filepath.Join(dir, "access.log")
	os.WriteFile(filepath.Join(dir, "config.json"), []byte(fmt.Sprintf(`{"log":{"access":%q},"inbounds":[{"tag":"api","port":%d,"listen":"127.0.0.1","protocol":"tunnel","settings":{"address":"127.0.0.1"}}]}`, accessLog, l.Addr().(*net.TCPAddr).Port)), 0o644)
	in := &model.Inbound{UserId: 1, Enable: true, Port: 23456, Protocol: protocol, Tag: "inbound-23456", Settings: settings, StreamSettings: `{"network":"ws"}`}
	if err := database.GetDB().Create(in).Error; err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	line := func(ip string, d time.Duration) string {
		return fmt.Sprintf("%s from %s:5555 accepted tcp:example.com:443 [inbound-23456 >> direct] email: lim@test\n", now.Add(d).Format("2006/01/02 15:04:05"), ip)
	}
	os.WriteFile(accessLog, []byte(line("1.1.1.1", -time.Minute)), 0o644)
	j := NewCheckClientIpJob()
	j.Run()
	f, _ := os.OpenFile(accessLog, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(line("2.2.2.2", 0))
	f.Close()
	return j, core
}

// Disconnecting a client over its IP limit re-adds it with every field the
// core API needs, even when the stored client lacks "flow" or "cipher".
func TestIPLimitDisconnectReAddsClient(t *testing.T) {
	for _, c := range []struct {
		protocol model.Protocol
		settings string
	}{
		{model.VLESS, `{"clients":[{"id":"6b0e9c1c-2d6f-4c6e-9b8a-000000000099","email":"lim@test","enable":true,"limitIp":1}],"decryption":"none"}`},
		{model.Shadowsocks, `{"method":"aes-256-gcm","clients":[{"password":"pw","email":"lim@test","enable":true,"limitIp":1}]}`},
	} {
		t.Run(string(c.protocol), func(t *testing.T) {
			j, core := limitedClient(t, c.protocol, c.settings)
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("the job panicked: %v", r)
					}
				}()
				j.Run()
			}()
			if got := strings.Join(core.calls, ","); got != "RemoveUserOperation,AddUserOperation" {
				t.Errorf("core calls %s", got)
			}
		})
	}
}

// A client the core lost because the re-add failed is brought back by a
// restart.
func TestIPLimitFailedReAddAsksForRestart(t *testing.T) {
	var xs service.XrayService
	xs.IsNeedRestartAndSetFalse()
	j, core := limitedClient(t, model.VLESS, `{"clients":[{"id":"6b0e9c1c-2d6f-4c6e-9b8a-000000000099","email":"lim@test","enable":true,"flow":"","limitIp":1}],"decryption":"none"}`)
	core.failAdd = true
	j.Run()
	if got := strings.Join(core.calls, ","); got != "RemoveUserOperation,AddUserOperation,AddUserOperation" {
		t.Errorf("core calls %s, want one retry", got)
	}
	if !xs.IsNeedRestartAndSetFalse() {
		t.Error("no restart was asked for")
	}
}

// fetchSetup serves body as the remote template and points the panel at it,
// with a fake core that logs each run.
func fetchSetup(t *testing.T, body func() string) (j *FetchXrayConfigJob, hits *atomic.Int32, coreRuns func() int) {
	t.Helper()
	dir := jobDB(t)
	runs := filepath.Join(dir, "runs")
	os.WriteFile(filepath.Join(dir, xray.GetBinaryName()), []byte("#!/bin/sh\necho \"$@\" >> "+runs+"\n"), 0o755)
	hits = &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte(body()))
	}))
	t.Cleanup(srv.Close)
	var ss service.SettingService
	ss.SetXrayConfigUrl(srv.URL)
	ss.SetXrayConfigInterval(1)
	coreRuns = func() int {
		b, _ := os.ReadFile(runs)
		return bytes.Count(b, []byte("-test"))
	}
	return NewFetchXrayConfigJob(), hits, coreRuns
}

// A fetched template that is the stored one, apart from layout, is neither
// tested, stored nor applied.
func TestFetchUnchangedTemplateDoesNothing(t *testing.T) {
	var stored string
	j, hits, coreRuns := fetchSetup(t, func() string {
		var v any
		json.Unmarshal([]byte(stored), &v)
		b, _ := json.Marshal(v) // same config, other layout and key order
		return string(b)
	})
	var ss service.SettingService
	stored, _ = ss.GetXrayConfigTemplate()
	var xs service.XrayService
	xs.IsNeedRestartAndSetFalse()
	j.Run()
	if hits.Load() != 1 {
		t.Fatalf("fetched %d times", hits.Load())
	}
	if n := coreRuns(); n != 0 {
		t.Errorf("the core tested an unchanged template %d times", n)
	}
	if apply, _ := ss.GetXrayConfigLastApply(); apply != 0 {
		t.Error("an unchanged template was applied")
	}
	if xs.IsNeedRestartAndSetFalse() {
		t.Error("an unchanged template restarts the cores")
	}
}

// The tick that is due runs even when it finds a hair less than the
// interval gone; an earlier one does not, nor does one while a run is under
// way.
func TestFetchIntervalAndOverlap(t *testing.T) {
	j, hits, _ := fetchSetup(t, func() string { return "{}" })
	j.lastFetch = time.Now().Add(-time.Minute + 50*time.Millisecond)
	j.Run()
	if hits.Load() != 1 {
		t.Fatalf("a due tick was skipped (%d fetches)", hits.Load())
	}
	j.lastFetch = time.Now().Add(-20 * time.Second)
	j.Run()
	if hits.Load() != 1 {
		t.Fatal("fetched before the interval")
	}
	j.lastFetch = time.Time{}
	j.running.Store(true)
	j.Run()
	if hits.Load() != 1 {
		t.Fatal("a run overlapped one under way")
	}
}
