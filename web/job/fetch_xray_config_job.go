package job

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/web/service"
)

// FetchXrayConfigJob pulls the Xray config template from a remote URL on a
// timer, so a fleet of panels can be pointed at one published config.
//
// It is registered on a fixed one-minute tick and decides for itself whether
// enough time has passed, rather than being scheduled at the configured
// interval. Cron entries are only built when the panel starts, so scheduling by
// interval would mean the setting did nothing until the panel was restarted.
type FetchXrayConfigJob struct {
	settingService     service.SettingService
	xraySettingService service.XraySettingService
	xrayService        service.XrayService

	lastFetch time.Time
}

// NewFetchXrayConfigJob creates a new remote Xray config fetch job.
func NewFetchXrayConfigJob() *FetchXrayConfigJob {
	return new(FetchXrayConfigJob)
}

// Run fetches the template if the configured interval has elapsed. It is a
// no-op when no URL is set or the interval is zero, which is the default.
func (j *FetchXrayConfigJob) Run() {
	url, err := j.settingService.GetXrayConfigUrl()
	if err != nil || url == "" {
		return
	}
	minutes, err := j.settingService.GetXrayConfigInterval()
	if err != nil || minutes <= 0 {
		return
	}
	if time.Since(j.lastFetch) < time.Duration(minutes)*time.Minute {
		return
	}
	j.lastFetch = time.Now()

	body, err := fetchConfig(url)
	if err != nil {
		logger.Warning("Fetching Xray config from ", url, " failed: ", err)
		return
	}

	// Reject anything that is not a usable Xray config before it is stored: a
	// captive portal or an error page would otherwise replace the template and
	// take the core down at the next restart.
	if err := j.xraySettingService.CheckXrayConfig(body); err != nil {
		logger.Warning("Xray config fetched from ", url, " is not valid, keeping the current one: ", err)
		return
	}

	current, err := j.xraySettingService.GetXrayConfigTemplate()
	if err == nil && current == body {
		// Nothing changed, so nothing is restarted. Without this the core would
		// be bounced on every interval and drop every connection with it.
		return
	}

	if err := j.xraySettingService.SaveXraySetting(body); err != nil {
		logger.Warning("Saving the fetched Xray config failed: ", err)
		return
	}

	logger.Info("Xray config template updated from ", url)
	j.xrayService.SetToNeedRestart()
}

// fetchConfig downloads the config template, refusing a response too large to
// be one.
func fetchConfig(url string) (string, error) {
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("server answered %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", err
	}
	return string(body), nil
}
