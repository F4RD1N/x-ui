package conf

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Native protocols own their transport and cryptographic framing. Prevent an
// accidental second transport/TLS layer while leaving every stock path alone.
func validateNativeStream(name string, settings *json.RawMessage, stream *StreamConfig, inbound bool) error {
	name = strings.ToLower(name)
	switch name {
	case "anytls", "shadowtls", "mieru", "orbit", "openvpn", "ov", "dnstt":
	case "dns":
		// DNS has no stock inbound. On the outbound side it remains stock
		// unless the caller explicitly requests a native tunnel.
		if !inbound {
			if settings == nil {
				return nil
			}
			var fields map[string]json.RawMessage
			if json.Unmarshal(*settings, &fields) != nil || fields["tunnel"] == nil {
				return nil
			}
		}
	default:
		return nil
	}
	security, network := "", ""
	if stream != nil {
		security = strings.ToLower(stream.Security)
		if stream.Network != nil {
			network = strings.ToLower(string(*stream.Network))
		}
	}
	if network != "" && network != "tcp" && network != "raw" {
		return fmt.Errorf("%s manages its own transport; outer streamSettings.network must be tcp or omitted", name)
	}
	if name == "anytls" && inbound {
		if security != "tls" {
			return fmt.Errorf("anytls inbound requires streamSettings.security=tls")
		}
		return nil
	}
	if security != "" && security != "none" {
		return fmt.Errorf("%s manages its own security; outer streamSettings.security must be none or omitted", name)
	}
	return nil
}
