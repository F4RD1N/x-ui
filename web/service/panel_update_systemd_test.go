package service

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Explicit opt-in: only random test units and temporary paths are touched.
// The production worker is exercised, but curl and installer are local fakes.
func TestPanelUpdateIsolatedRealSystemdLifecycle(t *testing.T) {
	if os.Getenv("XUI_TEST_ISOLATED_SYSTEMD_UPDATE") != "1" {
		t.Skip("requires explicit isolated systemd smoke opt-in")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		t.Skip("systemd manager unavailable")
	}
	systemdRun, err := exec.LookPath("systemd-run")
	if err != nil {
		t.Fatal(err)
	}
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		t.Fatal(err)
	}
	control := t.TempDir()
	gate, running, codeFile := filepath.Join(control, "release"), filepath.Join(control, "running"), filepath.Join(control, "code")
	os.WriteFile(codeFile, []byte("0"), 0600)
	opts := updateTestOptions(t, `[[ -e "/proc/$$/fd/9" && "${XUI_UPDATE_LOCK_FD:-}" == 9 ]] || exit 92
flock -n 9 || exit 93
touch `+updateTestQuote(running)+`
for ((i=0; i<1000; i++)); do [[ -e `+updateTestQuote(gate)+` ]] && break; sleep 0.02; done
[[ -e `+updateTestQuote(gate)+` ]] || exit 94
exit "$(cat `+updateTestQuote(codeFile)+`)"`)
	opts.systemdRun, opts.systemctl = systemdRun, systemctl
	id := fmt.Sprintf("test-parent-%d", time.Now().UnixNano())
	unit, stale := "x-ui-update-"+id+".service", "x-ui-update-test-stale-"+id+".service"
	units := []string{unit, stale}
	t.Cleanup(func() {
		os.WriteFile(gate, nil, 0600)
		for _, name := range units {
			_, _ = panelUpdateCommand(3*time.Second, systemctl, "stop", name)
			_, _ = panelUpdateCommand(3*time.Second, systemctl, "reset-failed", name)
		}
	})
	os.MkdirAll(opts.logFolder, 0700)
	os.MkdirAll(opts.runtimeFolder, 0700)
	jobDir, err := os.MkdirTemp(opts.runtimeFolder, "parent-")
	if err != nil {
		t.Fatal(err)
	}
	startup := filepath.Join(jobDir, "startup")
	launchArgs := []string{systemdRun, "--unit=" + unit, "--collect", "--property=Type=exec", "--description=isolated x-ui worker smoke", opts.bash}
	workerArgs, err := panelUpdateWorkerArgs(opts, startup, id, unit)
	if err != nil {
		t.Fatal(err)
	}
	launchArgs = append(launchArgs, panelUpdateSystemdLiteralArgs(workerArgs)...)
	// Keep the actual launching parent alive, then kill it while its separate
	// transient worker is running. This never starts the real installer.
	parent := exec.Command(opts.bash, append([]string{"-c", `"$@" || exit $?; exec sleep 60`, "test-parent"}, launchArgs...)...)
	if err := parent.Start(); err != nil {
		t.Fatal(err)
	}
	parentDone := make(chan error, 1)
	go func() { parentDone <- parent.Wait() }()
	t.Cleanup(func() { _ = parent.Process.Kill() })
	awaitUpdateFile(t, startup)
	os.WriteFile(startup+".ack", []byte("start\n"), 0600)
	awaitUpdateFile(t, running)
	if err := parent.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-parentDone:
	case <-time.After(time.Second):
		t.Fatal("synthetic launcher did not terminate")
	}
	state := awaitUpdateState(t, opts, id, "running")
	if state.Phase != "installing" {
		t.Fatal("worker did not survive parent to reach synthetic installer")
	}
	out, err := panelUpdateCommand(3*time.Second, systemctl, "show", unit, "--property=ActiveState", "--value")
	if err != nil || strings.TrimSpace(string(out)) != "active" {
		t.Fatal("separate worker service died with parent")
	}
	if _, err := startPanelUpdate(opts); !errors.Is(err, ErrPanelUpdateBusy) {
		t.Fatalf("second real transient worker was not blocked: %v", err)
	}
	os.WriteFile(gate, nil, 0600)
	awaitUpdateState(t, opts, id, "succeeded")
	// Retain a deliberately failed unrelated test unit, just like a stale
	// transient fragment. New update units must not reuse or clear it.
	// A deliberately immediate failure may make systemd-run itself return
	// nonzero before its start job completes. The retained failed state below
	// is the fixture's intended outcome, not a successful launcher exit code.
	_, _ = panelUpdateCommand(3*time.Second, systemdRun, "--unit="+stale, "--property=Type=exec", "/bin/bash", "-c", "exit 17")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		out, _ = panelUpdateCommand(time.Second, systemctl, "show", stale, "--property=ActiveState", "--value")
		if strings.TrimSpace(string(out)) == "failed" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if strings.TrimSpace(string(out)) != "failed" {
		t.Fatal("synthetic stale unit not retained")
	}
	opts.legacyUnit = stale
	for _, result := range []int{9, 0} {
		os.WriteFile(codeFile, []byte(fmt.Sprint(result)), 0600)
		accepted, err := startPanelUpdate(opts)
		if err != nil {
			t.Fatal(err)
		}
		units = append(units, accepted.Unit)
		want := "failed"
		if result == 0 {
			want = "succeeded"
		}
		terminal := awaitUpdateState(t, opts, accepted.ID, want)
		if terminal.ExitCode != result {
			t.Fatal("wrong terminal installer result")
		}
	}
	out, err = panelUpdateCommand(3*time.Second, systemctl, "show", stale, "--property=ActiveState", "--value")
	if err != nil || strings.TrimSpace(string(out)) != "failed" {
		t.Fatal("new updater modified stale unit")
	}
}
