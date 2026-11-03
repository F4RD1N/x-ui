//go:build !without_native_protocols

package conf

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/orbit"
	"google.golang.org/protobuf/proto"
)

type OrbitServerClient struct {
	Email     string `json:"email"`
	Level     uint32 `json:"level"`
	Key       string `json:"key"`
	ExpiresAt int64  `json:"expiresAt,omitempty"`
}
type OrbitCertificate struct {
	Certificate []string `json:"certificate"`
	Key         []string `json:"key"`
}
type OrbitServerReality struct {
	PrivateKey  string   `json:"privateKey"`
	ServerNames []string `json:"serverNames"`
	ShortIds    []string `json:"shortIds"`
	Dest        string   `json:"dest"`
}
type OrbitServerConfig struct {
	Transport        string              `json:"transport"`
	Clients          []OrbitServerClient `json:"clients"`
	TLS              *OrbitCertificate   `json:"tls"`
	OuterTLS         *OrbitCertificate   `json:"outerTls"`
	Host             string              `json:"host"`
	Path             string              `json:"path"`
	Security         string              `json:"security"`
	Reality          *OrbitServerReality `json:"reality"`
	HandshakeTimeout uint32              `json:"handshakeTimeout"`
	MaxSessions      uint32              `json:"maxSessions"`
	MaxFlows         uint32              `json:"maxFlows"`
	UDPIdleTimeout   uint32              `json:"udpIdleTimeout"`
}

func (c *OrbitServerConfig) UnmarshalJSON(b []byte) error {
	type plain OrbitServerConfig
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	var p plain
	if e := decoder.Decode(&p); e != nil {
		return errors.New("orbit: invalid inbound settings or unknown field")
	}
	*c = OrbitServerConfig(p)
	return nil
}
func (c *OrbitServerConfig) Build() (proto.Message, error) {
	if c == nil {
		return nil, errors.New("orbit: inbound settings required")
	}
	p := &orbit.ServerConfig{Transport: c.Transport, Host: c.Host, Path: c.Path, Security: c.Security, HandshakeTimeout: c.HandshakeTimeout, MaxSessions: c.MaxSessions, MaxFlows: c.MaxFlows, UdpIdleTimeout: c.UDPIdleTimeout}
	if c.TLS != nil {
		p.Tls = &orbit.Certificate{Certificate: c.TLS.Certificate, Key: c.TLS.Key}
	}
	if c.OuterTLS != nil {
		p.OuterTls = &orbit.Certificate{Certificate: c.OuterTLS.Certificate, Key: c.OuterTLS.Key}
	}
	if c.Reality != nil {
		p.Reality = &orbit.ServerReality{PrivateKey: c.Reality.PrivateKey, ServerNames: c.Reality.ServerNames, ShortIds: c.Reality.ShortIds, Dest: c.Reality.Dest}
	}
	for _, u := range c.Clients {
		p.Users = append(p.Users, &protocol.User{Email: u.Email, Level: u.Level, Account: serial.ToTypedMessage(&orbit.Account{Key: u.Key, ExpiresAt: u.ExpiresAt})})
	}
	if e := orbit.ValidateServerConfig(p); e != nil {
		return nil, e
	}
	return p, nil
}
func init() {
	inboundConfigLoader.cache["orbit"] = func() interface{} { return new(OrbitServerConfig) }
}
