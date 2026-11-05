package service

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/util/common"
	"github.com/mhsanaei/3x-ui/v2/xray"
	coreconf "github.com/xtls/xray-core/infra/conf"
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
	return checkNativeTemplateOutbounds(xrayConfig.OutboundConfigs)
}

// Validate native handlers before storing a template that could prevent the
// next core start. Build only the native outbounds: ordinary protocol settings,
// routing/geodata and external-core extensions keep their existing handling.
// No handlers are started and no network requests are made here.
func checkNativeTemplateOutbounds(raw []byte) error {
	var outbounds []json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &outbounds) != nil {
		return nil
	}
	for index, outbound := range outbounds {
		var header struct {
			Protocol string          `json:"protocol"`
			Settings json.RawMessage `json:"settings"`
		}
		if json.Unmarshal(outbound, &header) != nil {
			continue
		}
		switch strings.ToLower(header.Protocol) {
		case "orbit", "dnstt", "openvpn", "ov", "anytls", "shadowtls", "mieru":
		case "dns":
			// The native wrapper is opt-in. A stock DNS outbound without a
			// tunnel must not be reinterpreted as a DNSTT configuration.
			var fields map[string]json.RawMessage
			if json.Unmarshal(header.Settings, &fields) != nil {
				continue
			}
			if _, requested := fields["tunnel"]; !requested {
				continue
			}
		default:
			continue
		}
		var candidate coreconf.OutboundDetourConfig
		if err := json.Unmarshal(outbound, &candidate); err != nil {
			return fmt.Errorf("invalid native outbound at index %d: %w", index, err)
		}
		if err := buildNativeTemplateOutbound(&candidate); err != nil {
			return fmt.Errorf("invalid native outbound at index %d: %w", index, err)
		}
	}
	return nil
}

func buildNativeTemplateOutbound(candidate *coreconf.OutboundDetourConfig) (err error) {
	// Shared transport parsers are also reached by native outbounds. Keep a
	// malformed optional transport field from escaping the validation path;
	// never include panic data, which could contain configuration secrets.
	defer func() {
		if recover() != nil {
			err = errors.New("invalid native outbound options")
		}
	}()
	_, err = candidate.Build()
	return err
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
