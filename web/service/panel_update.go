package service

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/logger"
)

// The panel can update itself to the latest release of its own repository. It
// cannot update the Xray core separately -- a release carries the panel and the
// core it was built against together, which is what keeps dialects working.

const panelRepo = "F4RD1N/x-ui"

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

// UpdatePanel starts an update in the background and returns immediately.
//
// The updater has to outlive this process, because updating means stopping the
// panel, replacing its files and starting it again. A child spawned from here
// would sit in the panel's own systemd cgroup and be killed the moment the
// panel stops -- halfway through replacing itself. systemd-run puts it in a
// transient unit of its own instead, which survives.
func (s *ServerService) UpdatePanel() error {
	script := fmt.Sprintf(
		"set -e; curl -4fsSL https://raw.githubusercontent.com/%s/main/install.sh -o /tmp/x-ui-update.sh; "+
			"XUI_MODE=update bash /tmp/x-ui-update.sh", panelRepo)

	logFile := config.GetLogFolder() + "/update.log"
	shell := fmt.Sprintf("{ date; %s; } >> %s 2>&1", script, logFile)

	if _, err := exec.LookPath("systemd-run"); err == nil {
		cmd := exec.Command("systemd-run",
			"--unit=x-ui-update",
			"--collect",
			"--description=x-ui panel update",
			"/bin/bash", "-c", shell)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("starting the updater: %v: %s", err, strings.TrimSpace(string(out)))
		}
		logger.Info("Panel update started; following it in ", logFile)
		return nil
	}

	// No systemd: detach as far as we can and hope the panel is not in a
	// cgroup that takes the child with it.
	cmd := exec.Command("setsid", "/bin/bash", "-c", shell)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting the updater: %w", err)
	}
	go func() { _ = cmd.Wait() }()
	logger.Info("Panel update started; following it in ", logFile)
	return nil
}
