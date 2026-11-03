package conf

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/dnstt"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/proxy/vless"
	vlessin "github.com/xtls/xray-core/proxy/vless/inbound"
	"google.golang.org/protobuf/proto"
)

func init() {
	inboundConfigLoader.cache["dnstt"] = func() interface{} { return new(DNSTTInboundConfig) }
	inboundConfigLoader.cache["dns"] = func() interface{} { return new(DNSTTInboundConfig) }
	// Register an additive wrapper, leaving DNSOutboundConfig and its stock
	// Build implementation untouched when no tunnel has been requested.
	outboundConfigLoader.cache["dns"] = func() interface{} { return new(dialect11DNSOutboundConfig) }
}

type dialect11DNSOutboundConfig struct {
	DNSOutboundConfig
	Tunnel json.RawMessage `json:"tunnel"`
}

func (c *dialect11DNSOutboundConfig) Build() (proto.Message, error) {
	if c.Tunnel == nil {
		return c.DNSOutboundConfig.Build()
	}
	if c.Network != "" || c.Address != nil || c.Port != 0 || c.UserLevel != 0 || (c.NonIPQuery != "" && c.NonIPQuery != "drop") || len(c.BlockTypes) > 0 {
		return nil, errors.New("dns: tunnel cannot be combined with ordinary DNS outbound settings")
	}
	return buildDNSTunnel(c.Tunnel)
}

type DNSTTInboundClient struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
	Level    uint32 `json:"level"`
}
type DNSTTInboundInner struct {
	Protocol string `json:"protocol"`
}
type DNSTTInboundConfig struct {
	Domain           string                `json:"domain"`
	PrivateKey       string                `json:"privateKey"`
	Inner            *DNSTTInboundInner    `json:"inner"`
	Clients          []*DNSTTInboundClient `json:"clients"`
	MTU              uint32                `json:"mtu"`
	HandshakeTimeout uint32                `json:"handshakeTimeout"`
	MaxSessions      uint32                `json:"maxSessions"`
	MaxStreams       uint32                `json:"maxStreams"`
}

func (c *DNSTTInboundConfig) Build() (proto.Message, error) {
	if c == nil {
		return nil, errors.New("dnstt: inbound settings are required")
	}
	kind := "vless"
	if c.Inner != nil {
		kind = strings.ToLower(c.Inner.Protocol)
	}
	var inner proto.Message
	switch kind {
	case "vless":
		v := &vlessin.Config{Decryption: "none"}
		for _, u := range c.Clients {
			if u == nil || u.Username != "" || u.Password != "" {
				return nil, errors.New("dnstt: VLESS clients require UUID credentials")
			}
			v.Clients = append(v.Clients, &protocol.User{Email: u.Email, Level: u.Level, Account: serial.ToTypedMessage(&vless.Account{Id: u.ID})})
		}
		inner = v
	case "socks":
		v := &socks.ServerConfig{AuthType: socks.AuthType_PASSWORD, Accounts: make(map[string]string)}
		for i, u := range c.Clients {
			if u == nil || u.ID != "" {
				return nil, errors.New("dnstt: SOCKS clients require username and password")
			}
			if _, exists := v.Accounts[u.Username]; exists {
				return nil, errors.New("dnstt: duplicate SOCKS username")
			}
			if i > 0 && u.Level != v.UserLevel {
				return nil, errors.New("dnstt: SOCKS clients must share the same policy level")
			}
			v.UserLevel = u.Level
			v.Accounts[u.Username] = u.Password
		}
		inner = v
	default:
		return nil, errors.New("dnstt: inner protocol must be vless or socks")
	}
	return dnstt.NormalizeServerConfig(&dnstt.ServerConfig{Domain: c.Domain, PrivateKey: c.PrivateKey, Inner: serial.ToTypedMessage(inner), Mtu: c.MTU, HandshakeTimeout: c.HandshakeTimeout, MaxSessions: c.MaxSessions, MaxStreams: c.MaxStreams})
}
