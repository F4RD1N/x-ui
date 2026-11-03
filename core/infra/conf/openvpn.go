package conf

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"unicode"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/openvpn"
	"google.golang.org/protobuf/proto"
)

// OpenVPNText is the "ovpn" setting: the client configuration as one string,
// or as an array of its lines (joined with "\n").
type OpenVPNText string

// UnmarshalJSON implements json.Unmarshaler.
func (t *OpenVPNText) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*t = OpenVPNText(s)
		return nil
	}
	var lines []string
	if err := json.Unmarshal(data, &lines); err == nil {
		*t = OpenVPNText(strings.Join(lines, "\n"))
		return nil
	}
	return errors.New(`"ovpn" must be a string or an array of lines`)
}

// OpenVPNConfig is the "ov" outbound (OpenVPN; "openvpn" is an alias):
//
//	{
//	  "ovpn": "client\nremote vpn.example.com 1194\n..." or ["client", "remote ...", ...],
//	  "ovpnBase64": "Y2xpZW50Cg...",  // instead of "ovpn"
//	  "username": "", "password": "",  // replace the .ovpn's credentials when username is set
//	  "mtu": 0,                        // 0: min(the server's tun-mtu, 1400)
//	  "domainStrategy": "ForceIP"      // ForceIP, ForceIPv4, ForceIPv6, ForceIPv4v6, ForceIPv6v4
//	}
//
// The .ovpn text must carry its certificates and keys inline. Instead of
// "ovpn", the configuration can be given field by field: see OpenVPNSettings.
type OpenVPNConfig struct {
	Ovpn           *OpenVPNText        `json:"ovpn"`
	OvpnBase64     string              `json:"ovpnBase64"`
	Username       string              `json:"username"`
	Password       string              `json:"password"`
	MTU            int32               `json:"mtu"`
	DomainStrategy string              `json:"domainStrategy"`
	ClientProof    *OpenVPNClientProof `json:"clientProof"`
	OpenVPNSettings
}

// Build implements Buildable.
func (c *OpenVPNConfig) Build() (proto.Message, error) {
	config := new(openvpn.Config)
	if c.ClientProof != nil {
		proof, err := c.ClientProof.build()
		if err != nil {
			return nil, err
		}
		config.ClientProof = proof
	}

	hasText := c.Ovpn != nil && *c.Ovpn != ""
	hasBase64 := c.OvpnBase64 != ""
	structured := c.OpenVPNSettings.used()
	switch {
	case structured && (hasText || hasBase64):
		return nil, errors.New(`OpenVPN: use either "ovpn"/"ovpnBase64" or "server"/"auth"/"crypto"/"certificates"/"advanced", not both`)
	case structured:
		text, err := c.OpenVPNSettings.ovpnText()
		if err != nil {
			return nil, errors.New("OpenVPN: ").Base(err)
		}
		config.Ovpn = text
	case hasText && hasBase64:
		return nil, errors.New(`OpenVPN: set only one of "ovpn" and "ovpnBase64"`)
	case hasText:
		config.Ovpn = string(*c.Ovpn)
	case hasBase64:
		text, err := decodeOpenVPNBase64(c.OvpnBase64)
		if err != nil {
			return nil, errors.New(`OpenVPN: "ovpnBase64" is not valid base64`).Base(err)
		}
		config.Ovpn = text
	default:
		return nil, errors.New(`OpenVPN: "ovpn", "ovpnBase64" or "server" is required`)
	}

	config.Username = c.Username
	config.Password = c.Password
	if a := c.Auth; a != nil && (a.User != "" || a.Pass != "") {
		if c.Username != "" || c.Password != "" {
			return nil, errors.New(`OpenVPN: set the credentials in "auth" or in "username"/"password", not both`)
		}
		config.Username, config.Password = a.User, a.Pass
	}
	config.Mtu = c.MTU
	if a := c.Advanced; a != nil && a.MTU != 0 {
		if c.MTU != 0 && c.MTU != a.MTU {
			return nil, errors.New(`OpenVPN: "mtu" and "advanced.mtu" differ`)
		}
		config.Mtu = a.MTU
	}

	switch strings.ToLower(c.DomainStrategy) {
	case "forceip", "":
		config.DomainStrategy = openvpn.Config_FORCE_IP
	case "forceipv4":
		config.DomainStrategy = openvpn.Config_FORCE_IP4
	case "forceipv6":
		config.DomainStrategy = openvpn.Config_FORCE_IP6
	case "forceipv4v6":
		config.DomainStrategy = openvpn.Config_FORCE_IP46
	case "forceipv6v4":
		config.DomainStrategy = openvpn.Config_FORCE_IP64
	default:
		return nil, errors.New("OpenVPN: unsupported domain strategy: ", c.DomainStrategy)
	}

	if _, err := config.ParseOptions(); err != nil {
		return nil, errors.New("OpenVPN: bad configuration").Base(err)
	}
	return config, nil
}

// decodeOpenVPNBase64 reads standard or URL-safe base64, padded or not, with
// any whitespace (line breaks) in it. Its errors never quote the input.
func decodeOpenVPNBase64(s string) (string, error) {
	s = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimRight(s, "=")
	enc := base64.RawURLEncoding
	if strings.ContainsAny(s, "+/") {
		enc = base64.RawStdEncoding
	}
	b, err := enc.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
