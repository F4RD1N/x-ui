package dnstt

import (
	"encoding/hex"
	"net"
	"strings"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/proxy/vless"
	vlessin "github.com/xtls/xray-core/proxy/vless/inbound"
	"google.golang.org/protobuf/proto"
)

// NormalizeServerConfig validates before any listener or worker is created.
func NormalizeServerConfig(input *ServerConfig) (*ServerConfig, error) {
	if input == nil {
		return nil, settingError("settings", "are required")
	}
	c := proto.Clone(input).(*ServerConfig)
	c.Domain = strings.TrimSuffix(strings.ToLower(c.Domain), ".")
	if !validDomain(c.Domain) || net.ParseIP(c.Domain) != nil {
		return nil, settingError("domain", "must be an ASCII DNS tunnel domain")
	}
	if _, err := packetMTU(&Config{Domain: c.Domain}); err != nil {
		return nil, settingError("domain", "leaves insufficient room for DNS tunnel packets")
	}
	key, err := hex.DecodeString(c.PrivateKey)
	if err != nil || len(key) != 32 {
		return nil, settingError("privateKey", "must contain 64 hexadecimal digits")
	}
	var nonzero byte
	for _, b := range key {
		nonzero |= b
	}
	if nonzero == 0 {
		return nil, settingError("privateKey", "must not be zero")
	}
	c.PrivateKey = hex.EncodeToString(key)
	if c.Mtu == 0 {
		c.Mtu = 1232
	}
	if c.Mtu < 512 || c.Mtu > 4096 || computeMaxEncodedPayload(int(c.Mtu))-2 < 80 {
		return nil, settingError("mtu", "must be between 512 and 4096")
	}
	if c.HandshakeTimeout == 0 {
		c.HandshakeTimeout = 30
	}
	if c.HandshakeTimeout > 300 {
		return nil, settingError("handshakeTimeout", "must not exceed 300 seconds")
	}
	if c.MaxSessions == 0 {
		c.MaxSessions = 256
	}
	if c.MaxSessions > 4096 {
		return nil, settingError("maxSessions", "must not exceed 4096")
	}
	if c.MaxStreams == 0 {
		c.MaxStreams = 128
	}
	if c.MaxStreams > 1024 {
		return nil, settingError("maxStreams", "must not exceed 1024")
	}
	if c.Inner == nil {
		return nil, settingError("inner", "authenticated inner proxy is required")
	}
	inner, err := c.Inner.GetInstance()
	if err != nil {
		return nil, settingError("inner", "has invalid typed settings")
	}
	switch v := inner.(type) {
	case *vlessin.Config:
		if len(v.Clients) > 4096 || v.Decryption != "none" || len(v.Fallbacks) > 0 || len(v.Dialects) > 0 || len(v.MinClientVer) > 0 || len(v.MaxClientVer) > 0 {
			return nil, settingError("inner", "requires authenticated ordinary VLESS without fallbacks")
		}
		seen := make(map[string]bool)
		for _, u := range v.Clients {
			if u == nil || u.Account == nil {
				return nil, settingError("clients", "invalid VLESS user")
			}
			raw, err := u.Account.GetInstance()
			if err != nil {
				return nil, settingError("clients", "invalid VLESS account")
			}
			a, ok := raw.(*vless.Account)
			if !ok || a.Flow != "" || a.Encryption != "" || a.Reverse != nil || a.Dialect != 0 {
				return nil, settingError("clients", "only ordinary VLESS UUID authentication is supported")
			}
			id, err := uuid.Parse(a.Id)
			if err != nil || id == uuid.Nil || seen[id.String()] {
				return nil, settingError("clients", "UUIDs must be nonzero and unique")
			}
			seen[id.String()] = true
		}
	case *socks.ServerConfig:
		if v.AuthType != socks.AuthType_PASSWORD || v.UdpEnabled || len(v.Accounts) > 4096 {
			return nil, settingError("inner", "requires authenticated TCP SOCKS5")
		}
		for user, pass := range v.Accounts {
			if len(user) < 1 || len(user) > 255 || len(pass) < 1 || len(pass) > 255 {
				return nil, settingError("clients", "SOCKS username and password must contain 1..255 bytes")
			}
		}
	default:
		return nil, settingError("inner", "must be VLESS or SOCKS5")
	}
	return c, nil
}
