package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/logger"
)

// The panel can update itself to the latest release of its own repository. It
// cannot update the Xray core separately -- a release carries the panel and the
// core it was built against together, which is what keeps dialects working.

const panelRepo = "F4RD1N/x-ui"

const panelUpdateLockFile = "/run/lock/x-ui-update.lock"

var (
	ErrPanelUpdateBusy           = errors.New("an x-ui update is already running; wait for it to finish")
	ErrPanelUpdateStartupTimeout = errors.New("updater startup confirmation timed out")
	errPanelUpdateBusy           = ErrPanelUpdateBusy
)

// PanelUpdateState intentionally contains no installer output or credentials.
type PanelUpdateState struct {
	ID             string `json:"id"`
	Unit           string `json:"unit"`
	State          string `json:"state"`
	Phase          string `json:"phase"`
	StartedAt      int64  `json:"startedAt"`
	FinishedAt     int64  `json:"finishedAt"`
	ExitCode       int    `json:"exitCode"`
	CurrentVersion string `json:"currentVersion"`
}

type panelUpdateOptions struct {
	logFolder, runtimeFolder, workFolder, lockFile   string
	systemdRun, systemctl, setsid, bash, curl, flock string
	downloadURL, legacyUnit                          string
	startupTimeout, commandTimeout                   time.Duration
}

func defaultPanelUpdateOptions() panelUpdateOptions {
	find := func(name string) string { path, _ := exec.LookPath(name); return path }
	return panelUpdateOptions{
		logFolder: config.GetLogFolder(), runtimeFolder: "/run/x-ui-update", workFolder: os.TempDir(), lockFile: panelUpdateLockFile,
		systemdRun: find("systemd-run"), systemctl: find("systemctl"), setsid: find("setsid"), bash: find("bash"), curl: find("curl"), flock: find("flock"),
		downloadURL: "https://raw.githubusercontent.com/" + panelRepo + "/main/install.sh", legacyUnit: "x-ui-update.service",
		startupTimeout: 5 * time.Second, commandTimeout: 10 * time.Second,
	}
}

// Each attempt gets a unique transient unit. A persistent flock, not the unit
// name, serializes mutation and survives the panel process being stopped.
func (s *ServerService) StartPanelUpdate() (*PanelUpdateState, error) {
	opts := defaultPanelUpdateOptions()
	state, err := startPanelUpdate(opts)
	if err == nil {
		logger.Info("Panel update accepted: ", state.ID, "; log: ", filepath.Join(opts.logFolder, "update.log"))
	}
	return state, err
}

func (s *ServerService) UpdatePanel() error { _, err := s.StartPanelUpdate(); return err }

func (s *ServerService) PanelUpdateStatus() (*PanelUpdateState, error) {
	return panelUpdateStatus(defaultPanelUpdateOptions())
}

func readPanelUpdateState(path string) (*PanelUpdateState, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return &PanelUpdateState{State: "idle", CurrentVersion: config.GetVersion()}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading update status: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 16<<10))
	if err != nil {
		return nil, fmt.Errorf("reading update status: %w", err)
	}
	var state PanelUpdateState
	if json.Unmarshal(data, &state) != nil || (state.State != "running" && state.State != "succeeded" && state.State != "failed") {
		return nil, errors.New("invalid update status; inspect update.log")
	}
	state.CurrentVersion = config.GetVersion()
	return &state, nil
}

func panelUpdateStatus(opts panelUpdateOptions) (*PanelUpdateState, error) {
	path := filepath.Join(opts.logFolder, "update-status.json")
	state, err := readPanelUpdateState(path)
	if err != nil || state.State != "running" {
		return state, err
	}
	f, err := os.OpenFile(opts.lockFile, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("checking update lock: %w", err)
	}
	defer f.Close()
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
		return state, nil
	}
	if err != nil {
		return nil, fmt.Errorf("checking update lock: %w", err)
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	// Completion writes its terminal state before releasing the same lock.
	latest, err := readPanelUpdateState(path)
	if err != nil {
		return nil, err
	}
	if latest.State == "running" {
		latest.State, latest.Phase, latest.ExitCode = "failed", "interrupted", -1
		latest.FinishedAt = time.Now().UnixMilli()
	}
	return latest, nil
}

func panelUpdateCommand(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = time.Second
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	return out, err
}

func startPanelUpdate(opts panelUpdateOptions) (*PanelUpdateState, error) {
	if opts.bash == "" || opts.curl == "" || opts.flock == "" {
		return nil, errors.New("bash, curl and flock are required to update the panel")
	}
	if opts.systemdRun == "" && opts.setsid == "" {
		return nil, errors.New("systemd-run or setsid is required to launch the updater")
	}
	if opts.systemdRun != "" && opts.systemctl != "" && opts.legacyUnit != "" {
		out, err := panelUpdateCommand(opts.commandTimeout, opts.systemctl, "show", opts.legacyUnit, "--property=ActiveState", "--value")
		if err != nil {
			return nil, fmt.Errorf("checking legacy updater state: %w", err)
		}
		switch strings.TrimSpace(string(out)) {
		case "active", "activating", "deactivating", "reloading":
			return nil, errPanelUpdateBusy
		}
	}
	for _, dir := range []string{opts.logFolder, opts.runtimeFolder, filepath.Dir(opts.lockFile)} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("preparing updater directory: %w", err)
		}
	}
	logPath := filepath.Join(opts.logFolder, "update.log")
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("opening update log: %w", err)
	}
	log.Close()
	jobDir, err := os.MkdirTemp(opts.runtimeFolder, "request-")
	if err != nil {
		return nil, fmt.Errorf("preparing update request: %w", err)
	}
	accepted := false
	defer func() {
		if !accepted {
			_ = os.RemoveAll(jobDir)
		}
	}()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, errors.New("generating update request ID failed")
	}
	id := hex.EncodeToString(nonce[:])
	unit := "x-ui-update-" + id + ".service"
	startup := filepath.Join(jobDir, "startup")
	args, err := panelUpdateWorkerArgs(opts, startup, id, unit)
	if err != nil {
		return nil, fmt.Errorf("writing private updater worker: %w", err)
	}
	if opts.systemdRun != "" {
		commandArgs := append([]string{"--unit=" + unit, "--collect", "--property=Type=exec", "--description=x-ui panel update " + id, opts.bash}, panelUpdateSystemdLiteralArgs(args)...)
		out, err := panelUpdateCommand(opts.commandTimeout, opts.systemdRun, commandArgs...)
		if err != nil {
			return nil, fmt.Errorf("starting updater %s: %w: %s", unit, err, strings.TrimSpace(string(out)))
		}
	} else {
		cmd := exec.Command(opts.setsid, append([]string{opts.bash}, args...)...)
		if err := cmd.Start(); err != nil {
			return nil, fmt.Errorf("starting updater: %w", err)
		}
		go func() { _ = cmd.Wait() }()
	}
	deadline := time.NewTimer(opts.startupTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if data, err := os.ReadFile(startup); err == nil {
			switch strings.TrimSpace(string(data)) {
			case "ready":
				state, err := readPanelUpdateState(filepath.Join(opts.logFolder, "update-status.json"))
				if err != nil {
					return nil, err
				}
				if state.ID != id {
					return nil, errors.New("updater status changed before startup confirmation; inspect update.log")
				}
				if err := os.WriteFile(startup+".ack", []byte("start\n"), 0600); err != nil {
					return nil, fmt.Errorf("acknowledging updater startup: %w", err)
				}
				accepted = true // The worker now owns request-directory cleanup.
				return state, nil
			case "busy":
				return nil, errPanelUpdateBusy
			case "":
			default:
				return nil, errors.New("updater failed during startup; inspect update.log")
			}
		}
		select {
		case <-deadline.C:
			return nil, fmt.Errorf("%w for %s; inspect update.log before retrying", ErrPanelUpdateStartupTimeout, unit)
		case <-ticker.C:
		}
	}
}

func panelUpdateWorkerArgs(opts panelUpdateOptions, startup, id, unit string) ([]string, error) {
	worker := filepath.Join(filepath.Dir(startup), "worker.sh")
	if err := os.WriteFile(worker, []byte(panelUpdateWorkerScript), 0600); err != nil {
		return nil, err
	}
	return []string{worker, filepath.Join(opts.logFolder, "update.log"), opts.lockFile, startup, filepath.Join(opts.logFolder, "update-status.json"), id, unit, opts.workFolder, opts.curl, opts.flock, opts.bash, opts.downloadURL}, nil
}

// systemd expands $VARIABLE and ${VARIABLE} in ExecStart arguments. Doubling
// dollars is its documented literal form, including on older systemd versions
// without systemd-run --expand-environment=no. The shell script itself stays in
// a private file, so the manager never interprets shell source.
func panelUpdateSystemdLiteralArgs(args []string) []string {
	result := make([]string, len(args))
	for index, arg := range args {
		result[index] = strings.ReplaceAll(arg, "$", "$$")
	}
	return result
}

// All paths and URLs are positional arguments, never interpolated into shell
// source. The installer inherits FD 9 and verifies it against the stable lock.
const panelUpdateWorkerScript = `set -u
umask 077
log_file=$1; lock_file=$2; startup=$3; status_file=$4; job_id=$5; unit=$6
request_dir=${startup%/*}
work_root=$7; curl_cmd=$8; flock_cmd=$9; bash_cmd=${10}; download_url=${11}
work_dir=; owns_lock=0; phase=preparing; started_at=0
write_status() {
    local state=$1 code=$2 finished=$3
    local temp="${status_file}.tmp.$$"
    printf '{"id":"%s","unit":"%s","state":"%s","phase":"%s","startedAt":%s,"finishedAt":%s,"exitCode":%s}\n' "$job_id" "$unit" "$state" "$phase" "$started_at" "$finished" "$code" > "$temp" && mv -f -- "$temp" "$status_file"
}
finish() {
    local code=$?
    trap - EXIT
    if [[ -n "$work_dir" ]]; then rm -rf -- "$work_dir"; fi
    if [[ "$owns_lock" == 1 ]]; then
        local state=failed
        [[ "$code" == 0 ]] && state=succeeded
        phase=finished
        write_status "$state" "$code" "$(( $(date +%s) * 1000 ))" || true
        printf 'Updater %s finished: %s (exit %s)\n' "$job_id" "$state" "$code"
    fi
    if [[ ! -s "$startup" && -d "$request_dir" ]]; then printf 'failed:%s\n' "$code" > "$startup"; fi
    exit "$code"
}
trap finish EXIT
trap 'exit 143' TERM HUP
trap 'exit 130' INT
exec >> "$log_file" 2>&1 || exit 1
exec 9> "$lock_file" || exit 1
if ! "$flock_cmd" -n 9; then printf 'busy\n' > "$startup"; exit 75; fi
[[ -d "$request_dir" ]] || exit 124
owns_lock=1
started_at=$(( $(date +%s) * 1000 ))
phase=preparing
write_status running 0 0 || exit 1
printf 'ready\n' > "$startup" || exit 1
printf 'Updater %s started in %s\n' "$job_id" "$unit"
acknowledged=0
for ((attempt=0; attempt<1500; attempt++)); do
    if [[ -f "$startup.ack" ]]; then acknowledged=1; break; fi
    [[ -d "$request_dir" ]] || exit 124
    sleep 0.02
done
if [[ "$acknowledged" != 1 ]]; then rm -rf -- "$request_dir"; exit 124; fi
rm -rf -- "$request_dir"
phase=downloading
write_status running 0 0 || exit 1
work_dir=$(mktemp -d -- "$work_root/x-ui-update.XXXXXXXX") || exit 1
"$curl_cmd" -4fsSL --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 120 --retry 2 --retry-delay 2 --retry-max-time 180 "$download_url" -o "$work_dir/install.sh" 9>&- || exit $?
"$bash_cmd" -n "$work_dir/install.sh" 9>&- || exit $?
phase=installing
write_status running 0 0 || exit 1
XUI_MODE=update XUI_UPDATE_LOCK_FD=9 "$bash_cmd" "$work_dir/install.sh"
exit $?
`

// PanelUpdateInfo describes what an update would move between.
type PanelUpdateInfo struct {
	Current   string `json:"current"`
	Latest    string `json:"latest"`
	Available bool   `json:"available"`
}

// CheckPanelUpdate asks the repository for its latest release.
func (s *ServerService) CheckPanelUpdate() (*PanelUpdateInfo, error) {
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Get(fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", panelRepo))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("checking for updates: server answered %s", resp.Status)
	}

	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, err
	}

	current := strings.TrimPrefix(config.GetVersion(), "v")
	latest := strings.TrimPrefix(release.TagName, "v")
	return &PanelUpdateInfo{
		Current:   current,
		Latest:    latest,
		Available: latest != "" && latest != current,
	}, nil
}
