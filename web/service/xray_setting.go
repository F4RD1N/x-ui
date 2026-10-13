package service

import (
	_ "embed"
	"encoding/json"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/util/common"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

// XraySettingService provides business logic for Xray configuration management.
// It handles validation and storage of Xray template configurations.
type XraySettingService struct {
	SettingService
}

func (s *XraySettingService) SaveXraySetting(newXraySettings string) error {
	if err := s.CheckXrayConfig(newXraySettings); err != nil {
		return err
	}
	return s.SettingService.saveSetting("xrayTemplateConfig", newXraySettings)
}

func (s *XraySettingService) CheckXrayConfig(XrayTemplateConfig string) error {
	xrayConfig := &xray.Config{}
	err := json.Unmarshal([]byte(XrayTemplateConfig), xrayConfig)
	if err != nil {
		return common.NewError("xray template config invalid:", err)
	}
	return nil
}

// CheckXrayTemplateUsable rejects a template that would leave the core running
// but useless.
//
// Unmarshalling alone proves almost nothing, because encoding/json ignores
// fields it does not know: an error page that happens to be JSON parses into an
// empty config, and the core will happily start on it -- with no outbound, so
// nothing it accepts can go anywhere. A template with no outbounds is never
// what anyone meant, so it is refused here rather than silently swallowing
// every connection. So is one without the API and stats the panel runs every
// core through.
func (s *XraySettingService) CheckXrayTemplateUsable(XrayTemplateConfig string) error {
	xrayConfig := &xray.Config{}
	if err := json.Unmarshal([]byte(XrayTemplateConfig), xrayConfig); err != nil {
		return common.NewError("xray template config invalid:", err)
	}

	var outbounds []any
	if len(xrayConfig.OutboundConfigs) > 0 {
		_ = json.Unmarshal(xrayConfig.OutboundConfigs, &outbounds)
	}
	if len(outbounds) == 0 {
		return common.NewError("xray template config has no outbounds; the core would start but route nothing")
	}
	return checkPanelAPI(xrayConfig)
}

// checkPanelAPI refuses a template without what the panel needs from every
// core: the API, on the inbound tagged "api" that each core gets its own
// port of (an "api" listen would put every core on one port), routed to it,
// and the per-user stats that traffic counting and quotas rest on.
func checkPanelAPI(c *xray.Config) error {
	var api struct {
		Tag      string   `json:"tag"`
		Listen   string   `json:"listen"`
		Services []string `json:"services"`
	}
	if len(c.API) == 0 || json.Unmarshal(c.API, &api) != nil || api.Tag != "api" {
		return common.NewError(`xray template config has no "api" section tagged "api"`)
	}
	if api.Listen != "" {
		return common.NewError(`xray template config sets "api.listen"; the panel needs the API on the inbound tagged "api"`)
	}
	services := map[string]bool{}
	for _, name := range api.Services {
		services[name] = true
	}
	if !services["HandlerService"] || !services["StatsService"] {
		return common.NewError(`xray template config's API lacks HandlerService or StatsService`)
	}
	apiInbound := false
	for _, ic := range c.InboundConfigs {
		if ic.Tag == "api" && ic.Port > 0 {
			apiInbound = true
		}
	}
	if !apiInbound {
		return common.NewError(`xray template config has no inbound tagged "api" with a port`)
	}
	var routing struct {
		Rules []struct {
			InboundTag  json.RawMessage `json:"inboundTag"`
			OutboundTag string          `json:"outboundTag"`
		} `json:"rules"`
	}
	_ = json.Unmarshal(c.RouterConfig, &routing)
	routed := false
	for _, r := range routing.Rules {
		var tags []string
		if json.Unmarshal(r.InboundTag, &tags) != nil {
			var one string
			if json.Unmarshal(r.InboundTag, &one) == nil {
				tags = []string{one}
			}
		}
		for _, t := range tags {
			if t == "api" && r.OutboundTag == "api" {
				routed = true
			}
		}
	}
	if !routed {
		return common.NewError(`xray template config does not route the "api" inbound to the API`)
	}
	if s := strings.TrimSpace(string(c.Stats)); s == "" || s == "null" {
		return common.NewError(`xray template config has no "stats" section`)
	}
	var policy struct {
		Levels map[string]struct {
			Up   bool `json:"statsUserUplink"`
			Down bool `json:"statsUserDownlink"`
		} `json:"levels"`
	}
	_ = json.Unmarshal(c.Policy, &policy)
	if l, ok := policy.Levels["0"]; !ok || !l.Up || !l.Down {
		return common.NewError(`xray template config does not count user traffic (policy.levels."0" statsUserUplink and statsUserDownlink)`)
	}
	return nil
}
