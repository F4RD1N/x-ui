//go:build !without_native_protocols

package conf_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/mieru"
	"google.golang.org/protobuf/proto"
)

func TestMieruInboundOutboundConfigRoundTrip(t *testing.T) {
	for _, network := range []string{"", "tcp", "udp", "TCP", "UDP"} {
		for _, custom := range []bool{false, true} {
			name := network
			if name == "" {
				name = "default"
			}
			if custom {
				name += "/custom"
			}
			t.Run(name, func(t *testing.T) {
				user := "test-user"
				if custom {
					user = "a3ac6533-7c27-45c4-93f2-9192745e218b"
				}
				in := conf.MieruServerConfig{Transport: network, HandshakeTimeout: 9, Clients: []conf.MieruUser{{Email: "first@test", Level: 5, Username: user, Password: "synthetic-secret", UUIDMetadataTrailer: custom}, {Email: "second@test", Level: 6, Username: "other", Password: "different-secret"}}}
				out := conf.MieruConfig{Address: "server.invalid", Port: 2027, Transport: network, Username: user, Password: "synthetic-secret", UUIDMetadataTrailer: custom, HandshakeTimeout: 9}
				for _, c := range []conf.Buildable{&in, &out} {
					b, err := c.Build()
					if err != nil {
						t.Fatal(err)
					}
					wire, err := proto.Marshal(b)
					if err != nil {
						t.Fatal(err)
					}
					restored := b.ProtoReflect().New().Interface()
					if err = proto.Unmarshal(wire, restored); err != nil {
						t.Fatal(err)
					}
					if !proto.Equal(b, restored) {
						t.Fatal("protobuf roundtrip changed settings")
					}
					transport := strings.ToLower(network)
					if transport == "" {
						transport = "tcp"
					}
					switch cfg := restored.(type) {
					case *mieru.ServerConfig:
						if cfg.Transport != transport || cfg.HandshakeTimeout != 9 || len(cfg.Users) != 2 {
							t.Fatalf("incorrect inbound config: %+v", cfg)
						}
						a, err := cfg.Users[0].GetTypedAccount()
						if err != nil {
							t.Fatal(err)
						}
						account := a.(*mieru.Account)
						if account.Username != user || account.Password != "synthetic-secret" || account.UuidMetadataTrailer != custom || cfg.Users[0].Email != "first@test" || cfg.Users[0].Level != 5 {
							t.Fatal("first user's authentication or identity changed")
						}
						second, err := cfg.Users[1].GetTypedAccount()
						if err != nil {
							t.Fatal(err)
						}
						if second.(*mieru.Account).UuidMetadataTrailer {
							t.Fatal("custom auth flag leaked to another user")
						}
					case *mieru.Config:
						if cfg.Transport != transport || cfg.HandshakeTimeout != 9 || cfg.Address != "server.invalid" || cfg.Port != 2027 || cfg.Username != user || cfg.Password != "synthetic-secret" || cfg.UuidMetadataTrailer != custom {
							t.Fatal("incorrect outbound config")
						}
					default:
						t.Fatalf("wrong protobuf %T", cfg)
					}
				}
			})
		}
	}
}

func TestMieruInvalidOutboundConfig(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*conf.MieruConfig)
	}{
		{"no-address", func(c *conf.MieruConfig) { c.Address = "" }},
		{"blank-address", func(c *conf.MieruConfig) { c.Address = " " }},
		{"zero-port", func(c *conf.MieruConfig) { c.Port = 0 }},
		{"large-port", func(c *conf.MieruConfig) { c.Port = 65536 }},
		{"transport", func(c *conf.MieruConfig) { c.Transport = "quic" }},
		{"long-timeout", func(c *conf.MieruConfig) { c.HandshakeTimeout = 301 }},
		{"no-username", func(c *conf.MieruConfig) { c.Username = "" }},
		{"no-password", func(c *conf.MieruConfig) { c.Password = "" }},
		{"long-username", func(c *conf.MieruConfig) { c.Username = strings.Repeat("u", 257) }},
		{"long-password", func(c *conf.MieruConfig) { c.Password = strings.Repeat("p", 4097) }},
		{"custom-non-uuid", func(c *conf.MieruConfig) { c.UUIDMetadataTrailer = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := conf.MieruConfig{Address: "server.invalid", Port: 2027, Username: "user", Password: "synthetic-secret"}
			tc.mutate(&c)
			if _, err := c.Build(); err == nil {
				t.Fatal("invalid outbound accepted")
			}
		})
	}
}

func TestMieruInvalidInboundConfig(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*conf.MieruServerConfig)
	}{
		{"empty-users", func(c *conf.MieruServerConfig) { c.Clients = nil }},
		{"many-users", func(c *conf.MieruServerConfig) { c.Clients = make([]conf.MieruUser, 1025) }},
		{"transport", func(c *conf.MieruServerConfig) { c.Transport = "tls" }},
		{"timeout", func(c *conf.MieruServerConfig) { c.HandshakeTimeout = 301 }},
		{"empty-username", func(c *conf.MieruServerConfig) { c.Clients[0].Username = "" }},
		{"empty-password", func(c *conf.MieruServerConfig) { c.Clients[0].Password = "" }},
		{"custom-non-uuid", func(c *conf.MieruServerConfig) { c.Clients[0].UUIDMetadataTrailer = true }},
		{"duplicate-username", func(c *conf.MieruServerConfig) {
			c.Clients = append(c.Clients, conf.MieruUser{Username: "first", Password: "different", Email: "second@test"})
		}},
		{"duplicate-email", func(c *conf.MieruServerConfig) {
			c.Clients = append(c.Clients, conf.MieruUser{Username: "second", Password: "different", Email: "FIRST@TEST"})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := conf.MieruServerConfig{Clients: []conf.MieruUser{{Username: "first", Password: "synthetic-secret", Email: "first@test"}}}
			tc.mutate(&c)
			if _, err := c.Build(); err == nil {
				t.Fatal("invalid inbound accepted")
			}
		})
	}
}

func TestMieruJSONTypesAndRegistration(t *testing.T) {
	for _, field := range []string{`"uuidMetadataTrailer":"true"`, `"uuidMetadataTrailer":1`, `"port":"2027"`, `"handshakeTimeout":-1`, `"port":4294967296`} {
		var c conf.MieruConfig
		if err := json.Unmarshal([]byte(`{"address":"server.invalid","port":2027,"username":"user","password":"synthetic-secret",`+field+`}`), &c); err == nil {
			t.Fatalf("wrong JSON type accepted: %s", field)
		}
	}
	var inbound conf.InboundDetourConfig
	if err := json.Unmarshal([]byte(`{"listen":"127.0.0.1","port":2027,"protocol":"mieru","settings":{"transport":"udp","clients":[{"username":"user","password":"synthetic-secret","email":"user@test"}]}}`), &inbound); err != nil {
		t.Fatal(err)
	}
	built, err := inbound.Build()
	if err != nil {
		t.Fatal(err)
	}
	p, err := built.ProxySettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	if cfg, ok := p.(*mieru.ServerConfig); !ok || cfg.Transport != "udp" {
		t.Fatalf("inbound protocol registration failed: %T", p)
	}
	var outbound conf.OutboundDetourConfig
	if err = json.Unmarshal([]byte(`{"protocol":"mieru","settings":{"address":"server.invalid","port":2027,"username":"user","password":"synthetic-secret"}}`), &outbound); err != nil {
		t.Fatal(err)
	}
	ob, err := outbound.Build()
	if err != nil {
		t.Fatal(err)
	}
	p, err = ob.ProxySettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	if cfg, ok := p.(*mieru.Config); !ok || cfg.Transport != "tcp" {
		t.Fatalf("outbound protocol registration failed: %T", p)
	}
}
