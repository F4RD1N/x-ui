package sub

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/util/json_util"
	"github.com/mhsanaei/3x-ui/v2/util/native_client"
	"github.com/xtls/xray-core/infra/conf"
)

var errNativeJSONSubscriptionRequired = errors.New("native protocols and custom authentication require the JSON subscription endpoint")
var errNativeExportUnavailable = errors.New("native JSON export unavailable")

// SS2022's UUID notation is an import convention. URI/Clash clients receive
// its canonical base64 identity key, while the separate server PSK is retained.
func ss2022ExportIdentity(inbound *model.Inbound, client model.Client) (string, error) {
	var settings map[string]any
	if json.Unmarshal([]byte(inbound.Settings), &settings) != nil {
		return "", errors.New("invalid Shadowsocks export settings")
	}
	enabled, _ := settings["uuidIdentityKeys"].(bool)
	if rows, ok := settings["clients"].([]any); ok {
		for _, item := range rows {
			row := exportObject(item)
			if exportString(row["email"]) == client.Email {
				if flag, present := row["uuidIdentityKeys"]; present {
					var ok bool
					enabled, ok = flag.(bool)
					if !ok {
						return "", errors.New("uuidIdentityKeys export flag must be boolean")
					}
				} else if client.UUIDIdentityKeys {
					enabled = true
				}
				break
			}
		}
	}
	if !enabled {
		return client.Password, nil
	}
	return conf.NormalizeSS2022IdentityKey(exportString(settings["method"]), client.Password)
}

func nativeSubscriptionProtocol(protocol model.Protocol) bool {
	return native_client.Supports(protocol)
}

func nativeClientExportActive(inbound *model.Inbound, client model.Client) bool {
	if !client.Enable || (client.ExpiryTime > 0 && client.ExpiryTime <= time.Now().UnixMilli()) {
		return false
	}
	if inbound.Protocol == "orbit" && client.ExpiresAt > 0 && client.ExpiresAt <= time.Now().Unix() {
		return false
	}
	for _, stat := range inbound.ClientStats {
		if stat.Email == client.Email {
			return stat.Enable && (stat.ExpiryTime <= 0 || stat.ExpiryTime > time.Now().UnixMilli())
		}
	}
	return true
}

func exportObject(value any) map[string]any { v, _ := value.(map[string]any); return v }
func exportString(value any) string         { s, _ := value.(string); return s }

// Keep subscription callers and their tests on the existing contract. The
// authenticated single-client route uses the same serialization implementation.
func nativeClientOutbounds(inbound *model.Inbound, client model.Client, host string) ([]map[string]any, error) {
	return native_client.ClientOutbounds(inbound, client, host)
}

func exportPublicCertificateTrust(serverTLS map[string]any) ([]any, error) {
	return native_client.PublicCertificateTrust(serverTLS)
}

func (s *SubJsonService) getNativeConfig(inbound *model.Inbound, client model.Client, host string) ([]json_util.RawMessage, error) {
	outbounds, err := nativeClientOutbounds(inbound, client, host)
	if err != nil {
		return nil, err
	}
	all := make([]json_util.RawMessage, 0, len(outbounds)+len(s.defaultOutbounds))
	for _, outbound := range outbounds {
		encoded, err := json.Marshal(outbound)
		if err != nil {
			return nil, errors.New("unable to encode native outbound")
		}
		all = append(all, encoded)
	}
	all = append(all, s.defaultOutbounds...)
	config := make(map[string]any, len(s.configJson)+2)
	maps.Copy(config, s.configJson)
	config["outbounds"] = all
	config["remarks"] = s.SubService.genRemark(inbound, client.Email, "")
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("unable to encode native subscription: %w", err)
	}
	return []json_util.RawMessage{encoded}, nil
}
