//go:build !without_native_protocols

package conf

import (
	"errors"
	"strings"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/mieru"
	"google.golang.org/protobuf/proto"
)

func init() {
	inboundConfigLoader.cache["mieru"] = func() interface{} { return new(MieruServerConfig) }
	outboundConfigLoader.cache["mieru"] = func() interface{} { return new(MieruConfig) }
}

type MieruConfig struct {
	Address             string `json:"address"`
	Port                uint32 `json:"port"`
	Username            string `json:"username"`
	Password            string `json:"password"`
	Transport           string `json:"transport"`
	UUIDMetadataTrailer bool   `json:"uuidMetadataTrailer"`
	HandshakeTimeout    uint32 `json:"handshakeTimeout"`
}

func mieruTransport(t string, timeout uint32) (string, error) {
	t = strings.ToLower(t)
	if t == "" {
		t = "tcp"
	}
	if t != "tcp" && t != "udp" {
		return "", errors.New("Mieru transport must be tcp or udp")
	}
	if timeout > 300 {
		return "", errors.New("Mieru handshakeTimeout must not exceed 300 seconds")
	}
	return t, nil
}
func (c *MieruConfig) Build() (proto.Message, error) {
	if strings.TrimSpace(c.Address) == "" || c.Port == 0 || c.Port > 65535 {
		return nil, errors.New("Mieru server address and port in 1..65535 are required")
	}
	t, e := mieruTransport(c.Transport, c.HandshakeTimeout)
	if e != nil {
		return nil, e
	}
	a := &mieru.Account{Username: c.Username, Password: c.Password, UuidMetadataTrailer: c.UUIDMetadataTrailer}
	if _, e = a.AsAccount(); e != nil {
		return nil, e
	}
	return &mieru.Config{Address: c.Address, Port: c.Port, Username: c.Username, Password: c.Password, Transport: t, UuidMetadataTrailer: c.UUIDMetadataTrailer, HandshakeTimeout: c.HandshakeTimeout}, nil
}

type MieruUser struct {
	Email               string `json:"email"`
	Level               uint32 `json:"level"`
	Username            string `json:"username"`
	Password            string `json:"password"`
	UUIDMetadataTrailer bool   `json:"uuidMetadataTrailer"`
}
type MieruServerConfig struct {
	Clients          []MieruUser `json:"clients"`
	Transport        string      `json:"transport"`
	HandshakeTimeout uint32      `json:"handshakeTimeout"`
}

func (c *MieruServerConfig) Build() (proto.Message, error) {
	t, e := mieruTransport(c.Transport, c.HandshakeTimeout)
	if e != nil {
		return nil, e
	}
	if len(c.Clients) == 0 || len(c.Clients) > 1024 {
		return nil, errors.New("Mieru requires 1..1024 clients")
	}
	config := &mieru.ServerConfig{Transport: t, HandshakeTimeout: c.HandshakeTimeout}
	users, emails := map[string]bool{}, map[string]bool{}
	for _, u := range c.Clients {
		a := &mieru.Account{Username: u.Username, Password: u.Password, UuidMetadataTrailer: u.UUIDMetadataTrailer}
		if _, e = a.AsAccount(); e != nil {
			return nil, e
		}
		email := strings.ToLower(u.Email)
		if users[u.Username] || (email != "" && emails[email]) {
			return nil, errors.New("duplicate Mieru client")
		}
		users[u.Username], emails[email] = true, true
		config.Users = append(config.Users, &protocol.User{Email: u.Email, Level: u.Level, Account: serial.ToTypedMessage(a)})
	}
	return config, nil
}
