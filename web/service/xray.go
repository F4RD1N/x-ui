package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/xray"

	"go.uber.org/atomic"
)

var (
	lock              sync.Mutex  // serialises starting and stopping the cores
	isNeedXrayRestart atomic.Bool // Indicates that restart was requested for Xray
	isManuallyStopped atomic.Bool // Indicates that Xray was stopped manually from the panel
)

// XrayService provides business logic for Xray process management.
// It handles starting, stopping, restarting Xray, and managing its configuration.
type XrayService struct {
	inboundService InboundService
	settingService SettingService
}

// IsXrayRunning reports whether at least one core is running.
func (s *XrayService) IsXrayRunning() bool {
	for _, p := range snapshotProcs() {
		if p.IsRunning() {
			return true
		}
	}
	return false
}

// failedProc returns the first core that stopped with an error.
func failedProc() *xray.Process {
	for _, p := range snapshotProcs() {
		if p.IsRunning() {
			continue
		}
		err := p.GetErr()
		if err == nil {
			continue
		}
		if runtime.GOOS == "windows" && err.Error() == "exit status 1" {
			// exit status 1 on Windows means that Xray process was killed
			// as we kill process to stop in on Windows, this is not an error
			continue
		}
		return p
	}
	return nil
}

// GetXrayErr returns the error of the first core that failed, if any.
func (s *XrayService) GetXrayErr() error {
	if p := failedProc(); p != nil {
		return fmt.Errorf("%s: %w", p.Name(), p.GetErr())
	}
	return nil
}

// GetXrayResult returns what the first failed core last said.
func (s *XrayService) GetXrayResult() string {
	p := failedProc()
	if p == nil {
		return ""
	}
	result := p.GetResult()
	if runtime.GOOS == "windows" && result == "exit status 1" {
		return ""
	}
	if result == "" {
		return ""
	}
	return p.Name() + ": " + result
}

// GetXrayVersion returns the version of the cores.
func (s *XrayService) GetXrayVersion() string {
	for _, p := range snapshotProcs() {
		if v := p.GetVersion(); v != "" && v != "Unknown" {
			return v
		}
	}
	return "Unknown"
}

// RemoveIndex removes an element at the specified index from a slice.
// Returns a new slice with the element removed.
func RemoveIndex(s []any, index int) []any {
	return append(s[:index], s[index+1:]...)
}

// GetXrayConfig retrieves and builds the Xray configuration from settings and inbounds.
func (s *XrayService) GetXrayConfig() (*xray.Config, error) {
	templateConfig, err := s.settingService.GetXrayConfigTemplate()
	if err != nil {
		return nil, err
	}
	return s.buildXrayConfig(templateConfig)
}

// GetXrayConfigFor builds the config the core would run if the given template
// were the stored one, without storing it. It is how a candidate template can
// be tested against the real core before it is allowed anywhere near the
// running one.
func (s *XrayService) GetXrayConfigFor(templateConfig string) (*xray.Config, error) {
	return s.buildXrayConfig(templateConfig)
}

func (s *XrayService) buildXrayConfig(templateConfig string) (*xray.Config, error) {
	c, _, err := s.buildXrayConfigAndInbounds(templateConfig)
	return c, err
}

// buildXrayConfigAndInbounds builds the whole config and also returns the
// inbounds it was built from.
func (s *XrayService) buildXrayConfigAndInbounds(templateConfig string) (*xray.Config, []*model.Inbound, error) {
	xrayConfig := &xray.Config{}
	err := json.Unmarshal([]byte(templateConfig), xrayConfig)
	if err != nil {
		return nil, nil, err
	}

	s.inboundService.AddTraffic(nil, nil)

	inbounds, err := s.inboundService.GetAllInbounds()
	if err != nil {
		return nil, nil, err
	}
	for _, inbound := range inbounds {
		if !inbound.Enable {
			continue
		}
		// get settings clients
		settings := map[string]any{}
		json.Unmarshal([]byte(inbound.Settings), &settings)
		clients, ok := settings["clients"].([]any)
		if ok {
			// Fast O(N) lookup map for client traffic enablement
			clientStats := inbound.ClientStats
			enableMap := make(map[string]bool, len(clientStats))
			for _, clientTraffic := range clientStats {
				enableMap[clientTraffic.Email] = clientTraffic.Enable
			}

			// filter and clean clients
			var final_clients []any
			for _, client := range clients {
				c, ok := client.(map[string]any)
				if !ok {
					continue
				}

				email, _ := c["email"].(string)

				// check users active or not via stats
				if enable, exists := enableMap[email]; exists && !enable {
					logger.Infof("Remove Inbound User %s due to expiration or traffic limit", email)
					continue
				}

				// check manual disabled flag
				if manualEnable, ok := c["enable"].(bool); ok && !manualEnable {
					continue
				}

				// clear client config for additional parameters
				for key := range c {
					if key != "email" && key != "id" && key != "password" && key != "flow" && key != "method" && key != "auth" {
						delete(c, key)
					}
					if flow, ok := c["flow"].(string); ok && flow == "xtls-rprx-vision-udp443" {
						c["flow"] = "xtls-rprx-vision"
					}
				}
				fillShadowsocksClientMethod(inbound.Protocol, settings, c)
				final_clients = append(final_clients, any(c))
			}

			settings["clients"] = final_clients
			modifiedSettings, err := json.MarshalIndent(settings, "", "  ")
			if err != nil {
				return nil, nil, err
			}

			inbound.Settings = string(modifiedSettings)
		}

		if len(inbound.StreamSettings) > 0 {
			// Unmarshal stream JSON
			var stream map[string]any
			json.Unmarshal([]byte(inbound.StreamSettings), &stream)

			// Remove the "settings" field under "tlsSettings" and "realitySettings"
			tlsSettings, ok1 := stream["tlsSettings"].(map[string]any)
			realitySettings, ok2 := stream["realitySettings"].(map[string]any)
			if ok1 || ok2 {
				if ok1 {
					delete(tlsSettings, "settings")
				} else if ok2 {
					delete(realitySettings, "settings")
				}
			}

			delete(stream, "externalProxy")

			newStream, err := json.MarshalIndent(stream, "", "  ")
			if err != nil {
				return nil, nil, err
			}
			inbound.StreamSettings = string(newStream)
		}

		inboundConfig := inbound.GenXrayInboundConfig()
		xrayConfig.InboundConfigs = append(xrayConfig.InboundConfigs, *inboundConfig)
		// Sub-inbounds: the same inbound on their own ports.
		for _, sub := range inbound.Subs() {
			if !sub.Enable {
				continue
			}
			c := *inboundConfig
			c.Port = sub.Port
			c.Tag = model.SubTag(inbound.Tag, sub.Port)
			xrayConfig.InboundConfigs = append(xrayConfig.InboundConfigs, c)
		}
	}
	// The cores are planned per inbound and sub-inbound alike.
	return xrayConfig, model.ExpandSubInbounds(inbounds), nil
}

// GetXrayTraffic collects, and resets, the traffic counters of every running
// core, summed per inbound, outbound and client.
func (s *XrayService) GetXrayTraffic() ([]*xray.Traffic, []*xray.ClientTraffic, error) {
	var traffics []*xray.Traffic
	var clientTraffics []*xray.ClientTraffic
	ran := false
	var lastErr error
	for _, p := range snapshotProcs() {
		if !p.IsRunning() {
			continue
		}
		var api xray.XrayAPI
		if err := api.Init(p.GetAPIPort()); err != nil {
			lastErr = err
			continue
		}
		t, c, err := api.GetTraffic(true)
		api.Close()
		if err != nil {
			logger.Debug("Failed to fetch Xray traffic of", p.Name(), ":", err)
			lastErr = err
			continue
		}
		ran = true
		traffics = append(traffics, t...)
		clientTraffics = append(clientTraffics, c...)
	}
	if !ran {
		if lastErr == nil {
			lastErr = errors.New("xray is not running")
		}
		return nil, nil, lastErr
	}
	return mergeTraffic(traffics), mergeClientTraffic(clientTraffics), nil
}

// fillShadowsocksClientMethod gives a shadowsocks client with no cipher the
// inbound's. With a classic (non-2022) cipher every client must name one,
// and a client saved without it made the core refuse the whole config --
// "unsupported cipher method:" -- taking down every inbound in it.
func fillShadowsocksClientMethod(protocol model.Protocol, settings map[string]any, client map[string]any) {
	if protocol != model.Shadowsocks {
		return
	}
	method, _ := settings["method"].(string)
	if method == "" || strings.HasPrefix(method, "2022-") {
		return
	}
	if m, _ := client["method"].(string); m == "" {
		client["method"] = method
	}
}

// mergeTraffic sums entries for the same inbound or outbound reported by
// several cores (every core has the template's outbounds), counting a
// sub-inbound's traffic on its inbound.
func mergeTraffic(in []*xray.Traffic) []*xray.Traffic {
	type key struct {
		inbound, outbound bool
		tag               string
	}
	idx := map[key]*xray.Traffic{}
	out := make([]*xray.Traffic, 0, len(in))
	for _, t := range in {
		tag := t.Tag
		if t.IsInbound {
			tag = model.ParentTag(tag) // a sub-inbound's traffic is its inbound's
		}
		k := key{t.IsInbound, t.IsOutbound, tag}
		if m, ok := idx[k]; ok {
			m.Up += t.Up
			m.Down += t.Down
			continue
		}
		c := *t
		c.Tag = tag
		idx[k] = &c
		out = append(out, &c)
	}
	return out
}

// mergeClientTraffic sums entries of the same client, which two cores can
// both report while an inbound moves between them.
func mergeClientTraffic(in []*xray.ClientTraffic) []*xray.ClientTraffic {
	idx := map[string]*xray.ClientTraffic{}
	out := make([]*xray.ClientTraffic, 0, len(in))
	for _, t := range in {
		if m, ok := idx[t.Email]; ok {
			m.Up += t.Up
			m.Down += t.Down
			continue
		}
		c := *t
		idx[t.Email] = &c
		out = append(out, &c)
	}
	return out
}

// RestartXray brings the cores in line with the stored config. With isForce
// every core restarts; otherwise only the cores whose config changed in a
// way their API could not apply restart, and the rest keep their
// connections.
func (s *XrayService) RestartXray(isForce bool) error {
	lock.Lock()
	defer lock.Unlock()
	logger.Debug("restart Xray, force:", isForce)
	isManuallyStopped.Store(false)
	if isForce {
		// A full restart brings back the instances stopped one by one.
		instMu.Lock()
		stoppedInst = map[string]bool{}
		instMu.Unlock()
	}
	return s.applyInstances(isForce)
}

// StopXray stops every core.
func (s *XrayService) StopXray() error {
	lock.Lock()
	defer lock.Unlock()
	isManuallyStopped.Store(true)
	logger.Debug("Attempting to stop Xray...")
	if !s.IsXrayRunning() {
		return errors.New("xray is not running")
	}
	return stopAllInstances()
}

// SetToNeedRestart marks that Xray needs to be restarted.
func (s *XrayService) SetToNeedRestart() {
	isNeedXrayRestart.Store(true)
}

// IsNeedRestartAndSetFalse checks if restart is needed and resets the flag to false.
// While the cores are stopped by hand it says no and keeps the flag: the
// periodic restart would start them all again, and the change is applied
// when they are started anyway.
func (s *XrayService) IsNeedRestartAndSetFalse() bool {
	if isManuallyStopped.Load() {
		return false
	}
	return isNeedXrayRestart.CompareAndSwap(true, false)
}

// DidXrayCrash reports whether a core that should run is not running, and
// the cores were not stopped by hand.
func (s *XrayService) DidXrayCrash() bool {
	if isManuallyStopped.Load() {
		return false
	}
	list := snapshotProcs()
	if len(list) == 0 {
		// Nothing runs: a crash, unless every instance was stopped by hand.
		instMu.RLock()
		defer instMu.RUnlock()
		return len(stoppedInst) == 0
	}
	for _, p := range list {
		if !p.IsRunning() {
			instMu.RLock()
			due := restartDueLocked(p.Name(), p)
			instMu.RUnlock()
			if due {
				return true
			}
		}
	}
	return false
}
