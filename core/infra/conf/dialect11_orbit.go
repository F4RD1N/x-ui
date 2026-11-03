//go:build !without_native_protocols

package conf

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"

	"github.com/xtls/xray-core/proxy/nativebridge"
	"github.com/xtls/xray-core/proxy/orbit"
	"google.golang.org/protobuf/proto"
)

// Registration is additive, like the other native outbounds: no existing
// parser, handler or default changes, and nothing starts until a request.
func init() {
	outboundConfigLoader.cache["orbit"] = func() interface{} { return new(OrbitConfig) }
}

// OrbitConfig is the "orbit" outbound: the client of the user's VPN-Core
// server. Either "link" (a private orbit:// link; VPN-Core's core:// spelling
// is accepted as an alias) or the separate fields, which use the link's names
// (fp and ua are accepted as the link spells them).
type OrbitConfig struct {
	Link             string            `json:"link"`
	Address          string            `json:"address"`
	Port             uint32            `json:"port"`
	Key              string            `json:"key"`
	Transport        string            `json:"transport"`
	Host             string            `json:"host"`
	Path             string            `json:"path"`
	Peer             string            `json:"peer"`
	Fingerprint      string            `json:"fingerprint"`
	FP               string            `json:"fp"`
	UserAgent        string            `json:"userAgent"`
	UA               string            `json:"ua"`
	Headers          map[string]string `json:"headers"`
	Browser          json.RawMessage   `json:"browser"`
	HandshakeTimeout uint32            `json:"handshakeTimeout"`
	Resolver         string            `json:"resolver"`
	// Security "reality" (tcp only) with the "reality" object is the JSON
	// form of a link's security=reality&sni=..&pbk=..&sid=..&fp=...
	Security string              `json:"security"`
	Reality  *OrbitRealityConfig `json:"reality"`
}

// OrbitRealityConfig is "settings.reality" of an orbit outbound. Unknown
// fields are refused like the outer ones.
type OrbitRealityConfig struct {
	ServerName  string `json:"serverName"`
	PublicKey   string `json:"publicKey"`
	ShortID     string `json:"shortId"`
	Fingerprint string `json:"fingerprint"`
}

// UnmarshalJSON rejects unknown settings, so a misspelled field is an error
// rather than a silently ignored option. Values never appear in errors.
func (c *OrbitConfig) UnmarshalJSON(data []byte) error {
	type plain OrbitConfig
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	var p plain
	if err := d.Decode(&p); err != nil {
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) {
			return errors.New(`orbit: "` + typeErr.Field + `": has the wrong JSON type`)
		}
		if strings.HasPrefix(err.Error(), "json: unknown field ") {
			return errors.New("orbit: unknown setting " + strings.TrimPrefix(err.Error(), "json: unknown field "))
		}
		return errors.New("orbit: settings are not a valid JSON object")
	}
	*c = OrbitConfig(p)
	return nil
}

func orbitBrowser(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		if b {
			return "", nil
		}
		return "off", nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil && (s == "on" || s == "off") {
		if s == "on" {
			return "", nil
		}
		return s, nil
	}
	return "", errors.New(`orbit: "browser": must be true/false (or "on"/"off")`)
}

func orbitAlias(name, alias, a, b string) (string, error) {
	if a != "" && b != "" {
		return "", errors.New(`orbit: "` + name + `" and "` + alias + `" are the same setting; give one`)
	}
	return a + b, nil
}

func (c *OrbitConfig) Build() (message proto.Message, err error) {
	defer nativebridge.Recover(&err, nil)
	fingerprint, err := orbitAlias("fingerprint", "fp", c.Fingerprint, c.FP)
	if err != nil {
		return nil, err
	}
	userAgent, err := orbitAlias("userAgent", "ua", c.UserAgent, c.UA)
	if err != nil {
		return nil, err
	}
	browser, err := orbitBrowser(c.Browser)
	if err != nil {
		return nil, err
	}
	var s orbit.Settings
	if c.Link != "" {
		for field, set := range map[string]bool{"address": c.Address != "", "port": c.Port != 0, "key": c.Key != "",
			"transport": c.Transport != "", "host": c.Host != "", "path": c.Path != "", "peer": c.Peer != "",
			"fingerprint": fingerprint != "", "userAgent": userAgent != "", "headers": c.Headers != nil, "browser": len(c.Browser) != 0,
			"security": c.Security != "", "reality": c.Reality != nil} {
			if set {
				return nil, errors.New(`orbit: "` + field + `": cannot be combined with "link"; give the link or the separate fields`)
			}
		}
		if s, err = orbit.ParseLink(c.Link); err != nil {
			return nil, err
		}
	} else {
		s = orbit.Settings{Address: c.Address, Port: c.Port, Key: c.Key, Transport: strings.ToLower(c.Transport),
			Host: c.Host, Path: c.Path, Peer: c.Peer, Fingerprint: fingerprint, UserAgent: userAgent,
			Headers: c.Headers, Browser: browser, Security: c.Security}
		if c.Reality != nil {
			if c.Security != "reality" {
				return nil, errors.New(`orbit: "security": must be "reality" when "reality" is given`)
			}
			s.Reality = orbit.RealitySettings{ServerName: c.Reality.ServerName, PublicKey: c.Reality.PublicKey,
				ShortID: c.Reality.ShortID, Fingerprint: c.Reality.Fingerprint}
		}
	}
	return s.Config(c.HandshakeTimeout, c.Resolver)
}
