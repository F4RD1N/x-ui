package conf

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/anytls"
	"github.com/xtls/xray-core/proxy/nativebridge"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
	"google.golang.org/protobuf/proto"
)

func init() {
	inboundConfigLoader.cache["anytls"] = func() interface{} { return new(AnyTLSServerConfig) }
	outboundConfigLoader.cache["anytls"] = func() interface{} { return new(AnyTLSConfig) }
}

// AnyTLSConfig preserves the existing client JSON contract. TLS is provided
// internally by this outbound; an outer TLS stream would double encrypt it.
type AnyTLSConfig struct {
	Address                  string     `json:"address"`
	Port                     uint32     `json:"port"`
	Password                 string     `json:"password"`
	UUIDHashMiddle           bool       `json:"uuidHashMiddle"`
	IdleSessionCheckInterval uint32     `json:"idleSessionCheckInterval"`
	IdleSessionTimeout       uint32     `json:"idleSessionTimeout"`
	MinIdleSession           uint32     `json:"minIdleSession"`
	HandshakeTimeout         uint32     `json:"handshakeTimeout"`
	TLS                      *TLSConfig `json:"tlsSettings"`
}

func (c *AnyTLSConfig) UnmarshalJSON(b []byte) error {
	type plain AnyTLSConfig
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	return d.Decode((*plain)(c))
}
func (c *AnyTLSConfig) Build() (message proto.Message, err error) {
	defer nativebridge.Recover(&err, nil)
	if strings.TrimSpace(c.Address) == "" || c.Port == 0 || c.Port > 65535 {
		return nil, errors.New("AnyTLS requires address and port in 1..65535")
	}
	if c.Password == "" {
		return nil, errors.New("AnyTLS password is required")
	}
	t := c.TLS
	if t == nil {
		t = &TLSConfig{ServerName: c.Address}
	}
	// This protocol is ported from the existing native client, whose nested
	// TLS contract includes an explicit allowInsecure option. Preserve that
	// opt-in only here, without changing the newer core's shared TLS parser.
	tlsSettings := *t
	tlsSettings.AllowInsecure = false
	built, err := tlsSettings.Build()
	if err != nil {
		return nil, err
	}
	built.(*xtls.Config).AllowInsecure = t.AllowInsecure
	return &anytls.Config{Address: c.Address, Port: c.Port, Password: c.Password, UuidHashMiddle: c.UUIDHashMiddle, IdleSessionCheckInterval: c.IdleSessionCheckInterval, IdleSessionTimeout: c.IdleSessionTimeout, MinIdleSession: c.MinIdleSession, HandshakeTimeout: c.HandshakeTimeout, Tls: built.(*xtls.Config)}, nil
}

type AnyTLSUserConfig struct {
	Password       string `json:"password"`
	Email          string `json:"email"`
	Level          uint32 `json:"level"`
	UUIDHashMiddle bool   `json:"uuidHashMiddle"`
}
type AnyTLSServerConfig struct {
	Clients          []AnyTLSUserConfig `json:"clients"`
	HandshakeTimeout uint32             `json:"handshakeTimeout"`
	MaxStreams       uint32             `json:"maxStreams"`
}

func (c *AnyTLSServerConfig) UnmarshalJSON(b []byte) error {
	type plain AnyTLSServerConfig
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	return d.Decode((*plain)(c))
}
func (c *AnyTLSServerConfig) Build() (proto.Message, error) {
	if c.HandshakeTimeout > 300 || c.MaxStreams > 1024 {
		return nil, errors.New("AnyTLS handshakeTimeout must be <=300 and maxStreams <=1024")
	}
	cfg := &anytls.ServerConfig{HandshakeTimeout: c.HandshakeTimeout, MaxStreams: c.MaxStreams}
	identities := make(map[[32]byte]bool)
	emails := make(map[string]bool)
	for _, u := range c.Clients {
		a := &anytls.Account{Password: u.Password, UuidHashMiddle: u.UUIDHashMiddle}
		memory, err := a.AsAccount()
		if err != nil {
			return nil, err
		}
		key := memory.(*anytls.MemoryAccount).Key
		if identities[key] {
			return nil, errors.New("duplicate AnyTLS authentication identity")
		}
		identities[key] = true
		if u.Email != "" && emails[u.Email] {
			return nil, errors.New("duplicate AnyTLS email")
		}
		emails[u.Email] = true
		cfg.Users = append(cfg.Users, &protocol.User{Email: u.Email, Level: u.Level, Account: serial.ToTypedMessage(a)})
	}
	return cfg, nil
}
