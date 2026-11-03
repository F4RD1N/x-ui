package conf

import (
	"encoding/json"
	"github.com/xtls/xray-core/proxy/openvpn"
	"google.golang.org/protobuf/proto"
)

// OpenVPNInboundConfig preserves strict native server settings as portable JSON.
type OpenVPNInboundConfig struct{ Settings openvpn.ServerSettings }

func (c *OpenVPNInboundConfig) UnmarshalJSON(data []byte) error {
	s, e := openvpn.ParseServerSettings(data)
	if e != nil {
		return e
	}
	c.Settings = *s
	return nil
}
func (c *OpenVPNInboundConfig) Build() (proto.Message, error) {
	if e := c.Settings.Validate(); e != nil {
		return nil, e
	}
	b, e := json.Marshal(c.Settings)
	if e != nil {
		return nil, e
	}
	return &openvpn.ServerConfig{Settings: b}, nil
}

func (c OpenVPNInboundConfig) MarshalJSON() ([]byte, error) { return json.Marshal(c.Settings) }

// Registration is kept with this protocol so existing protocol loaders remain
// unchanged when the native OpenVPN package is absent.
func init() {
	for _, name := range []string{"ov", "openvpn"} {
		inboundConfigLoader.cache[name] = func() interface{} { return new(OpenVPNInboundConfig) }
		outboundConfigLoader.cache[name] = func() interface{} { return new(OpenVPNConfig) }
	}
}
