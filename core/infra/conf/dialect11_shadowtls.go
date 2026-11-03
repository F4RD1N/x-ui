package conf

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/nativebridge"
	ss2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/shadowtls"
	"google.golang.org/protobuf/proto"
)

func init() {
	inboundConfigLoader.cache["shadowtls"] = func() interface{} { return new(ShadowTLSServerConfig) }
	outboundConfigLoader.cache["shadowtls"] = func() interface{} { return new(ShadowTLSConfig) }
}

type ShadowTLSConfig struct {
	Address          string `json:"address"`
	Port             uint32 `json:"port"`
	Password         string `json:"password"`
	Version          uint32 `json:"version"`
	ServerName       string `json:"serverName"`
	AllowInsecure    bool   `json:"allowInsecure"`
	Strict           *bool  `json:"strict"`
	UUIDSessionID    bool   `json:"uuidSessionId"`
	Fingerprint      string `json:"fingerprint"`
	CAPEM            string `json:"caPem"`
	HandshakeTimeout uint32 `json:"handshakeTimeout"`
}

func (c *ShadowTLSConfig) Build() (message proto.Message, err error) {
	defer nativebridge.Recover(&err, nil)
	if strings.TrimSpace(c.Address) == "" || c.Port == 0 || c.Port > 65535 || strings.TrimSpace(c.ServerName) == "" {
		return nil, errors.New("ShadowTLS requires address, port in 1..65535 and serverName")
	}
	v := c.Version
	if v == 0 {
		v = 3
	}
	if v < 1 || v > 3 {
		return nil, errors.New("ShadowTLS version must be 1, 2 or 3")
	}
	if v >= 2 && c.Password == "" {
		return nil, errors.New("ShadowTLS password is required")
	}
	if c.HandshakeTimeout > 300 {
		return nil, errors.New("ShadowTLS handshakeTimeout must not exceed 300 seconds")
	}
	if c.UUIDSessionID {
		if v != 3 {
			return nil, errors.New("uuidSessionId requires v3")
		}
		if _, err := uuid.Parse(c.Password); err != nil {
			return nil, errors.New("uuidSessionId requires a UUID password")
		}
	}
	strict := true
	if c.Strict != nil {
		strict = *c.Strict
	}
	return &shadowtls.Config{Address: c.Address, Port: c.Port, Password: c.Password, Version: v, ServerName: c.ServerName, AllowInsecure: c.AllowInsecure, Strict: strict, UuidSessionId: c.UUIDSessionID, Fingerprint: c.Fingerprint, CaPem: c.CAPEM, HandshakeTimeout: c.HandshakeTimeout}, nil
}

type ShadowTLSServerClient struct {
	Email                string `json:"email"`
	Password             string `json:"password"`
	Level                uint32 `json:"level"`
	RequireUUIDSessionID bool   `json:"requireUuidSessionId"`
}
type ShadowTLSHandshake struct {
	Address string `json:"address"`
	Port    uint32 `json:"port"`
}
type ShadowTLSInner struct {
	Protocol string          `json:"protocol"`
	Settings json.RawMessage `json:"settings"`
}
type ShadowTLSServerConfig struct {
	Version          uint32                   `json:"version"`
	Password         string                   `json:"password"`
	Strict           *bool                    `json:"strict"`
	Handshake        ShadowTLSHandshake       `json:"handshake"`
	Clients          []*ShadowTLSServerClient `json:"clients"`
	HandshakeTimeout uint32                   `json:"handshakeTimeout"`
	Inner            *ShadowTLSInner          `json:"inner"`
}

func (c *ShadowTLSServerConfig) Build() (message proto.Message, err error) {
	defer nativebridge.Recover(&err, nil)
	v := c.Version
	if v == 0 {
		v = 3
	}
	strict := true
	if c.Strict != nil {
		strict = *c.Strict
	}
	port := c.Handshake.Port
	if port == 0 {
		port = 443
	}
	if c.Inner == nil {
		return nil, errors.New("ShadowTLS requires inner protocol and settings")
	}
	name := strings.ToLower(c.Inner.Protocol)
	var inner Buildable
	switch name {
	case "socks":
		inner = new(SocksServerConfig)
	case "vless":
		inner = new(VLessInboundConfig)
	case "shadowsocks":
		var cipher struct {
			Method string `json:"method"`
		}
		if err := json.Unmarshal(c.Inner.Settings, &cipher); err != nil {
			return nil, err
		}
		if strings.EqualFold(cipher.Method, "none") || strings.EqualFold(cipher.Method, "plain") {
			return nil, errors.New("ShadowTLS inner Shadowsocks requires encryption")
		}
		inner = new(dialect11SSServer)
	default:
		return nil, errors.New("ShadowTLS inner protocol must be socks, vless or AEAD shadowsocks")
	}
	if err := json.Unmarshal(c.Inner.Settings, inner); err != nil {
		return nil, err
	}
	innerConfig, err := inner.Build()
	if err != nil {
		return nil, err
	}
	// Existing SS2022 parsing treats an empty user list as single-user mode.
	// Here an explicit list denotes managed identities even after all expire.
	if single, ok := innerConfig.(*ss2022.ServerConfig); ok && name == "shadowsocks" {
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(c.Inner.Settings, &raw); err != nil {
			return nil, err
		}
		if _, present := raw["clients"]; present {
			innerConfig = &ss2022.MultiUserServerConfig{Method: single.Method, Key: single.Key, Network: single.Network}
		}
	}
	cfg := &shadowtls.ServerConfig{Version: v, Password: c.Password, Strict: strict, HandshakeAddress: c.Handshake.Address, HandshakePort: port, HandshakeTimeout: c.HandshakeTimeout, Inner: serial.ToTypedMessage(innerConfig)}
	for _, u := range c.Clients {
		if u == nil {
			return nil, errors.New("ShadowTLS client must not be null")
		}
		cfg.Clients = append(cfg.Clients, &shadowtls.ServerUser{Email: u.Email, Password: u.Password, Level: u.Level, RequireUuidSessionId: u.RequireUUIDSessionID})
	}
	if err := shadowtls.ValidateServerConfig(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
