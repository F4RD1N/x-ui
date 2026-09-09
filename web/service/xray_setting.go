package service

import (
	_ "embed"
	"encoding/json"

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
// every connection.
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
	return nil
}
