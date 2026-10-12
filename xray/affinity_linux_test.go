//go:build linux

package xray

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/json_util"
	"github.com/op/go-logging"
)

// threadCPUs reads Cpus_allowed_list of every thread of pid.
func threadCPUs(t *testing.T, pid int) map[string]string {
	t.Helper()
	tasks, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, task := range tasks {
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/status", pid, task.Name()))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(line, "Cpus_allowed_list:"); ok {
				out[task.Name()] = strings.TrimSpace(v)
			}
		}
	}
	return out
}

func allOn(m map[string]string, want string) bool {
	if len(m) == 0 {
		return false
	}
	for _, v := range m {
		if v != want {
			return false
		}
	}
	return true
}

func needCPUs(t *testing.T, n int) []int {
	cpus := AvailableCPUs()
	if len(cpus) < n {
		t.Skipf("needs %d CPUs", n)
	}
	return cpus
}

// TestMain lets the test binary serve as a many-threaded child process.
func TestMain(m *testing.M) {
	if os.Getenv("AFFINITY_TEST_CHILD") == "1" {
		for i := 0; i < 6; i++ {
			go func() {
				runtime.LockOSThread()
				time.Sleep(time.Minute)
			}()
		}
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	t, _ := os.MkdirTemp("", "xray-log-")
	os.Setenv("XUI_LOG_FOLDER", t)
	logger.InitLogger(logging.ERROR)
	code := m.Run()
	os.RemoveAll(t)
	os.Exit(code)
}

func TestStartPinnedAndRepin(t *testing.T) {
	cpus := needCPUs(t, 2)
	first, second := cpus[0], cpus[1]

	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "AFFINITY_TEST_CHILD=1")
	setSysProcAttr(cmd)
	started := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		if err := pinCurrentThread([]int{first}); err != nil {
			started <- err
			return
		}
		started <- cmd.Start()
		cmd.Wait()
		close(done)
	}()
	if err := <-started; err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); <-done }()
	time.Sleep(300 * time.Millisecond) // let the child start its threads

	got := threadCPUs(t, cmd.Process.Pid)
	if len(got) < 4 || !allOn(got, fmt.Sprint(first)) {
		t.Fatalf("child not pinned from the start: %v", got)
	}
	// The panel itself keeps every CPU.
	if len(AvailableCPUs()) != len(cpus) {
		t.Fatal("pinning a child narrowed the panel")
	}

	if err := pinProcess(cmd.Process.Pid, []int{second}); err != nil {
		t.Fatal(err)
	}
	if got := threadCPUs(t, cmd.Process.Pid); !allOn(got, fmt.Sprint(second)) {
		t.Fatalf("not re-pinned: %v", got)
	}
	if got := ProcessCPUs(cmd.Process.Pid); len(got) != 1 || got[0] != second {
		t.Fatalf("ProcessCPUs: %v", got)
	}
}

// xrayBinary finds a core to run: XRAY_TEST_BINARY, or the installed one.
func xrayBinary(t *testing.T) string {
	for _, p := range []string{os.Getenv("XRAY_TEST_BINARY"), "/usr/local/x-ui/bin/" + GetBinaryName()} {
		if p != "" {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	t.Skip("no xray binary")
	return ""
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// TestInstanceProcessPinned runs a real core through NewInstanceProcess:
// it must start on its CPUs, stay alive (the thread that forked it is the
// one its Pdeathsig watches), move when SetCPUs is called and answer its
// API throughout.
func TestInstanceProcessPinned(t *testing.T) {
	cpus := needCPUs(t, 2)
	bin := xrayBinary(t)
	dir := t.TempDir()
	if err := os.Symlink(bin, filepath.Join(dir, GetBinaryName())); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XUI_BIN_FOLDER", dir)
	t.Setenv("XUI_LOG_FOLDER", dir)

	apiPort := freePort(t)
	cfg := &Config{
		LogConfig:       json_util.RawMessage(`{"loglevel":"warning"}`),
		API:             json_util.RawMessage(`{"tag":"api","services":["HandlerService","StatsService"]}`),
		Stats:           json_util.RawMessage(`{}`),
		OutboundConfigs: json_util.RawMessage(`[{"protocol":"freedom","tag":"direct"}]`),
		RouterConfig:    json_util.RawMessage(`{"rules":[{"inboundTag":["api"],"outboundTag":"api"}]}`),
		InboundConfigs: []InboundConfig{{
			Listen: json_util.RawMessage(`"127.0.0.1"`), Port: apiPort, Protocol: "tunnel",
			Settings: json_util.RawMessage(`{"address":"127.0.0.1"}`), Tag: "api",
		}},
	}
	p := NewInstanceProcess("xray-test", cfg, filepath.Join(dir, "config-xray-test.json"), []int{cpus[0]})
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()

	// The core is up when its API answers.
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", apiPort), 200*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) || !p.IsRunning() {
			t.Fatalf("core did not come up: %v (%s)", err, p.GetResult())
		}
		time.Sleep(100 * time.Millisecond)
	}
	if got := threadCPUs(t, p.Pid()); !allOn(got, fmt.Sprint(cpus[0])) {
		t.Fatalf("core not pinned: %v", got)
	}
	if p.GetAPIPort() != apiPort || p.Name() != "xray-test" {
		t.Fatalf("api port %d, name %q", p.GetAPIPort(), p.Name())
	}
	var written Config
	b, _ := os.ReadFile(filepath.Join(dir, "config-xray-test.json"))
	if json.Unmarshal(b, &written) != nil || written.InboundConfigs[0].Port != apiPort {
		t.Fatal("instance config not written")
	}

	// Moving it keeps it running.
	want := fmt.Sprintf("%d-%d", cpus[0], cpus[1])
	if cpus[1] != cpus[0]+1 {
		want = fmt.Sprintf("%d,%d", cpus[0], cpus[1])
	}
	if err := p.SetCPUs(cpus[:2]); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if got := threadCPUs(t, p.Pid()); !allOn(got, want) {
		t.Fatalf("core not moved: %v", got)
	}
	if !p.IsRunning() {
		t.Fatal("core died when moved")
	}
	// Still alive a while later: nothing tied to the forking thread fired.
	time.Sleep(time.Second)
	if !p.IsRunning() {
		t.Fatalf("core exited: %s", p.GetResult())
	}
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	// Stopping an instance keeps its config file; only test runs remove theirs.
	if _, err := os.Stat(filepath.Join(dir, "config-xray-test.json")); err != nil {
		t.Fatal("instance config removed on stop")
	}
}
