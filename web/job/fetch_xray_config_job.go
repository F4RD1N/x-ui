package job

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/web/service"
	"github.com/mhsanaei/3x-ui/v2/xray"
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
	// Recorded before the outcome is known, so a check that fails still shows
	// as a check: a check time well ahead of an apply time is how a URL that
	// has stopped working looks from the panel.
	if err := j.settingService.SetXrayConfigLastCheck(j.lastFetch.Unix()); err != nil {
		logger.Warning("Could not record the Xray config check time: ", err)
	}

	body, err := fetchConfig(url)
	if err != nil {
		logger.Warning("Fetching Xray config from ", url, " failed: ", err)
		return
	}

	// Reject anything that is not a usable Xray config before it is stored.
	//
	// Two checks, because the cheap one is not enough on its own: unmarshalling
	// into the config struct ignores unknown fields, so an error page rendered
	// as JSON, or a config naming a protocol that does not exist, would sail
	// through it and stop the core at the next restart.
	if err := j.xraySettingService.CheckXrayTemplateUsable(body); err != nil {
		logger.Warning("Xray config fetched from ", url, " is not usable, keeping the current one: ", err)
		return
	}

	// The real check: build the config the core would actually run -- this
	// template plus the enabled inbounds -- and ask the core itself whether it
	// would accept it. Nothing is stored unless it says yes, so a bad config at
	// the far end of the URL cannot take a running core down.
	candidate, err := j.xrayService.GetXrayConfigFor(body)
	if err != nil {
		logger.Warning("Xray config fetched from ", url, " could not be assembled, keeping the current one: ", err)
		return
	}
	candidateJSON, err := json.MarshalIndent(candidate, "", "  ")
	if err != nil {
		logger.Warning("Xray config fetched from ", url, " could not be serialised, keeping the current one: ", err)
		return
	}
	if err := xray.TestConfig(string(candidateJSON)); err != nil {
		logger.Warning("Xray config fetched from ", url, " was refused by the core, keeping the current one: ", err)
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

	if err := j.settingService.SetXrayConfigLastApply(time.Now().Unix()); err != nil {
		logger.Warning("Could not record the Xray config apply time: ", err)
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
