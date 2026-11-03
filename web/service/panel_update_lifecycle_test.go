package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func updateTestQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func updateTestScript(t *testing.T, path, script string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/bash\nset -u\n"+script+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}
func updateTestOptions(t *testing.T, installer string) panelUpdateOptions {
	t.Helper()
	root := t.TempDir()
	opts := defaultPanelUpdateOptions()
	opts.logFolder = filepath.Join(root, "logs ' ; literal $(uname) ${XUI_UNSET_TEST_VARIABLE} %n")
	opts.runtimeFolder, opts.workFolder, opts.lockFile = filepath.Join(root, "requests"), root, filepath.Join(root, "update.lock")
	opts.systemdRun, opts.systemctl, opts.legacyUnit = "", "", ""
	opts.startupTimeout, opts.commandTimeout = 2*time.Second, 2*time.Second
	opts.downloadURL = "https://invalid.test/no-network-is-used"
	if opts.bash == "" || opts.setsid == "" || opts.flock == "" {
		t.Skip("bash, setsid and flock are required")
	}
	installPath := updateTestScript(t, filepath.Join(root, "synthetic-installer.sh"), installer)
	opts.curl = updateTestScript(t, filepath.Join(root, "fake-curl"), `dest=
while (( $# )); do
  if [[ "$1" == -o ]]; then dest=$2; shift 2; else shift; fi
done
[[ -n "$dest" ]] || exit 91
cp -- `+updateTestQuote(installPath)+` "$dest"`)
	return opts
}
func awaitUpdateState(t *testing.T, opts panelUpdateOptions, id, expected string) *PanelUpdateState {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		state, err := panelUpdateStatus(opts)
		if err == nil && state.ID == id && state.State == expected {
			return state
		}
		time.Sleep(10 * time.Millisecond)
	}
	state, err := panelUpdateStatus(opts)
	t.Fatalf("wanted %s for %s; got %+v %v", expected, id, state, err)
	return nil
}
func awaitUpdateFile(t *testing.T, name string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(name); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("missing fixture signal %s", name)
}

func TestPanelUpdateSuccessFailureRetryAndCleanup(t *testing.T) {
	control := filepath.Join(t.TempDir(), "result")
	if err := os.WriteFile(control, []byte("0"), 0600); err != nil {
		t.Fatal(err)
	}
	opts := updateTestOptions(t, `echo 'synthetic installer output, not status metadata'; exit "$(cat `+updateTestQuote(control)+`)"`)
	seen := map[string]bool{}
	for _, code := range []int{0, 7, 0} {
		os.WriteFile(control, []byte(fmt.Sprint(code)), 0600)
		accepted, err := startPanelUpdate(opts)
		if err != nil {
			t.Fatal(err)
		}
		if seen[accepted.ID] || accepted.ID == "" || accepted.Unit != "x-ui-update-"+accepted.ID+".service" {
			t.Fatal("reused/fixed updater identity")
		}
		seen[accepted.ID] = true
		want := "succeeded"
		if code != 0 {
			want = "failed"
		}
		state := awaitUpdateState(t, opts, accepted.ID, want)
		if state.ExitCode != code || state.StartedAt == 0 || state.FinishedAt < state.StartedAt || state.Phase != "finished" {
			t.Fatalf("invalid terminal state: %+v", state)
		}
		encoded, _ := json.Marshal(state)
		if strings.Contains(string(encoded), "synthetic installer output") {
			t.Fatal("raw log leaked into status")
		}
	}
	left, _ := filepath.Glob(filepath.Join(opts.workFolder, "x-ui-update.*"))
	requests, _ := os.ReadDir(opts.runtimeFolder)
	if len(left) != 0 || len(requests) != 0 {
		t.Fatal("updater left temporary scripts or startup requests")
	}
	log, err := os.ReadFile(filepath.Join(opts.logFolder, "update.log"))
	if err != nil || !strings.Contains(string(log), "failed (exit 7)") || !strings.Contains(string(log), "succeeded (exit 0)") {
		t.Fatal("terminal failures or successful retry were not logged")
	}
}

func TestPanelUpdateConcurrentRequestsPreserveOwnerStatus(t *testing.T) {
	control := t.TempDir()
	gate, running := filepath.Join(control, "release"), filepath.Join(control, "running")
	opts := updateTestOptions(t, `[[ -e "/proc/$$/fd/9" && "${XUI_UPDATE_LOCK_FD:-}" == 9 ]] || exit 92
flock -n 9 || exit 93
touch `+updateTestQuote(running)+`
for ((i=0; i<500; i++)); do [[ -e `+updateTestQuote(gate)+` ]] && break; sleep 0.02; done
[[ -e `+updateTestQuote(gate)+` ]] || exit 94`)
	owner, err := startPanelUpdate(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer os.WriteFile(gate, nil, 0600)
	awaitUpdateFile(t, running)
	var group sync.WaitGroup
	errorsCh := make(chan error, 8)
	for i := 0; i < cap(errorsCh); i++ {
		group.Add(1)
		go func() { defer group.Done(); _, err := startPanelUpdate(opts); errorsCh <- err }()
	}
	group.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if !errors.Is(err, errPanelUpdateBusy) {
			t.Fatalf("concurrent attempt was not deterministically rejected: %v", err)
		}
	}
	state, err := panelUpdateStatus(opts)
	if err != nil || state.ID != owner.ID || state.State != "running" {
		t.Fatal("losing request overwrote active updater status")
	}
	os.WriteFile(gate, nil, 0600)
	awaitUpdateState(t, opts, owner.ID, "succeeded")
}

func TestPanelUpdateFastCompletionConcurrentNextRequest(t *testing.T) {
	opts := updateTestOptions(t, "exit 0")
	var group sync.WaitGroup
	errorsCh := make(chan error, 12)
	for i := 0; i < cap(errorsCh); i++ {
		group.Add(1)
		go func() { defer group.Done(); _, err := startPanelUpdate(opts); errorsCh <- err }()
	}
	group.Wait()
	close(errorsCh)
	accepted := 0
	for err := range errorsCh {
		if err == nil {
			accepted++
			continue
		}
		if !errors.Is(err, ErrPanelUpdateBusy) {
			t.Fatalf("fast completion produced ambiguous startup failure: %v", err)
		}
	}
	if accepted == 0 {
		t.Fatal("no concurrent update was accepted")
	}
	state, err := panelUpdateStatus(opts)
	if err != nil {
		t.Fatal(err)
	}
	awaitUpdateState(t, opts, state.ID, "succeeded")
}

func TestPanelUpdateUniqueUnitsLegacyBusyAndLauncherErrors(t *testing.T) {
	opts := updateTestOptions(t, "exit 0")
	units := filepath.Join(opts.workFolder, "units")
	opts.systemctl = updateTestScript(t, filepath.Join(opts.workFolder, "fake-systemctl"), "echo inactive")
	opts.legacyUnit = "x-ui-update.service"
	opts.systemdRun = updateTestScript(t, filepath.Join(opts.workFolder, "fake-systemd-run"), `printf '%s\n' "$1" >> `+updateTestQuote(units)+`
while [[ "$1" == --* ]]; do shift; done
args=(); for arg in "$@"; do args+=("${arg//\$\$/\$}"); done; set -- "${args[@]}"
"$@" </dev/null >/dev/null 2>&1 &`)
	for i := 0; i < 2; i++ {
		state, err := startPanelUpdate(opts)
		if err != nil {
			t.Fatal(err)
		}
		awaitUpdateState(t, opts, state.ID, "succeeded")
	}
	data, _ := os.ReadFile(units)
	lines := strings.Fields(string(data))
	if len(lines) != 2 || lines[0] == lines[1] || lines[0] == "--unit=x-ui-update.service" {
		t.Fatal("transient units are not unique")
	}
	opts.systemctl = updateTestScript(t, opts.systemctl, "echo active")
	if _, err := startPanelUpdate(opts); !errors.Is(err, errPanelUpdateBusy) {
		t.Fatal("active legacy updater was not preserved")
	}
	after, _ := os.ReadFile(units)
	if string(after) != string(data) {
		t.Fatal("attempted another launch while legacy updater active")
	}
	opts.systemctl = updateTestScript(t, opts.systemctl, "echo failed")
	opts.systemdRun = updateTestScript(t, opts.systemdRun, "echo synthetic-launch-failure >&2; exit 17")
	if _, err := startPanelUpdate(opts); err == nil || !strings.Contains(err.Error(), "synthetic-launch-failure") {
		t.Fatal("launcher failure hidden")
	}
}

func TestPanelUpdateStartupTimeoutNeverRunsUnacknowledgedInstaller(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "must-not-run")
	opts := updateTestOptions(t, "touch "+updateTestQuote(marker))
	// A delayed launcher starts the real worker after the API has timed out.
	opts.systemdRun = updateTestScript(t, filepath.Join(opts.workFolder, "delayed-launcher"), `while [[ "$1" == --* ]]; do shift; done
args=(); for arg in "$@"; do args+=("${arg//\$\$/\$}"); done; set -- "${args[@]}"
(sleep 0.15; "$@") </dev/null >/dev/null 2>&1 &`)
	opts.startupTimeout = 30 * time.Millisecond
	if _, err := startPanelUpdate(opts); err == nil || !strings.Contains(err.Error(), "confirmation timed out") {
		t.Fatal("delayed startup was accepted")
	}
	newer := PanelUpdateState{ID: "newer-completed-job", Unit: "synthetic-newer.service", State: "succeeded", Phase: "finished", StartedAt: 1, FinishedAt: 2}
	newerJSON, _ := json.Marshal(newer)
	statusPath := filepath.Join(opts.logFolder, "update-status.json")
	os.WriteFile(statusPath, newerJSON, 0600)
	time.Sleep(300 * time.Millisecond)
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unacknowledged installer ran after timeout")
	}
	state, err := panelUpdateStatus(opts)
	if err != nil || state.State != "succeeded" || state.ID != newer.ID {
		t.Fatalf("cancelled late worker overwrote shared status: %+v %v", state, err)
	}
}

func TestPanelUpdateReadyWorkerRequiresAcknowledgementBeforeDownload(t *testing.T) {
	opts := updateTestOptions(t, "exit 0")
	marker := filepath.Join(opts.workFolder, "curl-must-not-run")
	opts.curl = updateTestScript(t, opts.curl, "touch "+updateTestQuote(marker)+"; exit 99")
	os.MkdirAll(opts.logFolder, 0700)
	jobDir := filepath.Join(opts.workFolder, "unacknowledged")
	os.MkdirAll(jobDir, 0700)
	startup := filepath.Join(jobDir, "startup")
	args, err := panelUpdateWorkerArgs(opts, startup, "unacknowledged", "unacknowledged-test.service")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(opts.bash, args...)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	awaitUpdateFile(t, startup)
	time.Sleep(40 * time.Millisecond)
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("worker downloaded before API acknowledged startup")
	}
	os.RemoveAll(jobDir)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled worker succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled ready worker did not exit")
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("worker downloaded after startup cancellation")
	}
}

func TestPanelUpdateStatusReconcilesInterruptedWorkerWithoutMutatingDisk(t *testing.T) {
	opts := updateTestOptions(t, "exit 0")
	os.MkdirAll(opts.logFolder, 0700)
	file := filepath.Join(opts.logFolder, "update-status.json")
	state := PanelUpdateState{ID: "fixture", Unit: "fixture.service", State: "running", Phase: "installing", StartedAt: 1}
	raw, _ := json.Marshal(state)
	os.WriteFile(file, raw, 0600)
	lock, err := os.OpenFile(opts.lockFile, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	got, err := panelUpdateStatus(opts)
	if err != nil || got.State != "running" {
		t.Fatal("active lock owner was marked failed")
	}
	syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	got, err = panelUpdateStatus(opts)
	if err != nil || got.State != "failed" || got.Phase != "interrupted" || got.ExitCode != -1 {
		t.Fatal("interrupted worker remained running forever")
	}
	after, _ := os.ReadFile(file)
	if string(after) != string(raw) {
		t.Fatal("status reader overwrote worker-owned state")
	}
	os.WriteFile(file, []byte("bad-json"), 0600)
	if _, err := panelUpdateStatus(opts); err == nil {
		t.Fatal("corrupt status silently accepted")
	}
	os.Remove(file)
	got, err = panelUpdateStatus(opts)
	if err != nil || got.State != "idle" {
		t.Fatal("missing status did not report idle")
	}
}

func TestPanelInstallerSharedLockBeforeMutation(t *testing.T) {
	raw, err := os.ReadFile("../../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	start, end := strings.Index(text, "# Serialize panel, CLI"), strings.Index(text, "# A run that was killed")
	if start < 0 || end <= start {
		t.Fatal("installer lock must precede recovery and stage cleanup")
	}
	root := t.TempDir()
	lockPath := filepath.Join(root, "shared.lock")
	fragment := strings.ReplaceAll(text[start:end], `"/run/lock/x-ui-update.lock"`, updateTestQuote(lockPath))
	fragment = strings.ReplaceAll(fragment, "mkdir -p /run/lock", "mkdir -p "+updateTestQuote(root))
	probe := updateTestScript(t, filepath.Join(root, "probe.sh"), "die(){ echo \"$*\" >&2; exit 1; }\n"+fragment+"\nprintf locked")
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	cmd := exec.Command("bash", probe)
	cmd.Env = append(os.Environ(), "XUI_UPDATE_LOCK_FD=9")
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "already running") {
		t.Fatal("forged marker bypassed real shared lock")
	}
	wrongFD := filepath.Join(root, "wrong.lock")
	cmd = exec.Command("bash", "-c", `exec 9>"$1"; flock -n 9 || exit 90; XUI_UPDATE_LOCK_FD=9 bash "$2"`, "test", wrongFD, probe)
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "already running") {
		t.Fatal("unrelated inherited descriptor bypassed dev/inode verification")
	}
	syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	// Reuse the exact open-file description inherited through FD 9.
	cmd = exec.Command("bash", "-c", `exec 9>"$1"; flock -n 9 || exit 90; XUI_UPDATE_LOCK_FD=9 bash "$2"`, "test", lockPath, probe)
	if out, err := cmd.CombinedOutput(); err != nil || string(out) != "locked" {
		t.Fatalf("inherited owned lock rejected: %s %v", out, err)
	}
	downloadStart, downloadEnd := strings.Index(text, "download_tarball() {"), strings.Index(text, "fetch_tarball() {")
	if downloadStart < 0 || downloadEnd <= downloadStart {
		t.Fatal("artifact download helper is missing")
	}
	download := text[downloadStart:downloadEnd]
	if strings.Contains(download, "--max-time") || !strings.Contains(download, "--connect-timeout 20") ||
		!strings.Contains(download, "--speed-limit 1024 --speed-time 120") || !strings.Contains(download, "attempt <= 5") {
		t.Fatal("artifact download must bound connection stalls and retries without cutting off productive slow transfers")
	}
}
