package conf_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/dnstt"
	"github.com/xtls/xray-core/proxy/socks"
	vlessin "github.com/xtls/xray-core/proxy/vless/inbound"
)

// This matrix exercises the panel's complete DNSTT inbound setting surface
// without opening sockets. Runtime interoperability is covered separately.
func TestDNSTTInboundOptionMatrix(t *testing.T) {
	base := func() *conf.DNSTTInboundConfig {
		return &conf.DNSTTInboundConfig{
			Domain: "tunnel.example.test", PrivateKey: strings.Repeat("ab", 32),
			Clients: []*conf.DNSTTInboundClient{{ID: "00112233-4455-6677-8899-aabbccddeeff", Email: "matrix@example.test", Level: 7}},
		}
	}
	for _, tc := range []struct {
		name  string
		edit  func(*conf.DNSTTInboundConfig)
		valid bool
	}{
		{"defaults", func(c *conf.DNSTTInboundConfig) {}, true},
		{"explicit_vless", func(c *conf.DNSTTInboundConfig) { c.Inner = &conf.DNSTTInboundInner{Protocol: "VLESS"} }, true},
		{"domain_case_and_root", func(c *conf.DNSTTInboundConfig) { c.Domain = "TuNnEl.Example.TEST." }, true},
		{"single_label", func(c *conf.DNSTTInboundConfig) { c.Domain = "tunnel" }, true},
		{"key_case", func(c *conf.DNSTTInboundConfig) { c.PrivateKey = strings.ToUpper(c.PrivateKey) }, true},
		{"minimum_limits", func(c *conf.DNSTTInboundConfig) {
			c.MTU, c.HandshakeTimeout, c.MaxSessions, c.MaxStreams = 512, 1, 1, 1
		}, true},
		{"maximum_limits", func(c *conf.DNSTTInboundConfig) {
			c.MTU, c.HandshakeTimeout, c.MaxSessions, c.MaxStreams = 4096, 300, 4096, 1024
		}, true},
		{"disable_all_vless_users", func(c *conf.DNSTTInboundConfig) { c.Clients = nil }, true},
		{"max_policy_level", func(c *conf.DNSTTInboundConfig) { c.Clients[0].Level = ^uint32(0) }, true},
		{"invalid_domain_ip", func(c *conf.DNSTTInboundConfig) { c.Domain = "127.0.0.1" }, false},
		{"invalid_domain_unicode", func(c *conf.DNSTTInboundConfig) { c.Domain = "تونل.example" }, false},
		{"invalid_domain_empty_label", func(c *conf.DNSTTInboundConfig) { c.Domain = "tunnel..test" }, false},
		{"invalid_key_zero", func(c *conf.DNSTTInboundConfig) { c.PrivateKey = strings.Repeat("0", 64) }, false},
		{"invalid_key_length", func(c *conf.DNSTTInboundConfig) { c.PrivateKey = strings.Repeat("a", 63) }, false},
		{"invalid_key_hex", func(c *conf.DNSTTInboundConfig) { c.PrivateKey = strings.Repeat("z", 64) }, false},
		{"mtu_below", func(c *conf.DNSTTInboundConfig) { c.MTU = 511 }, false},
		{"mtu_above", func(c *conf.DNSTTInboundConfig) { c.MTU = 4097 }, false},
		{"handshake_above", func(c *conf.DNSTTInboundConfig) { c.HandshakeTimeout = 301 }, false},
		{"sessions_above", func(c *conf.DNSTTInboundConfig) { c.MaxSessions = 4097 }, false},
		{"streams_above", func(c *conf.DNSTTInboundConfig) { c.MaxStreams = 1025 }, false},
		{"inner_unknown", func(c *conf.DNSTTInboundConfig) { c.Inner = &conf.DNSTTInboundInner{Protocol: "vmess"} }, false},
		{"inner_empty", func(c *conf.DNSTTInboundConfig) { c.Inner = &conf.DNSTTInboundInner{} }, false},
		{"nil_user", func(c *conf.DNSTTInboundConfig) { c.Clients = []*conf.DNSTTInboundClient{nil} }, false},
		{"zero_uuid", func(c *conf.DNSTTInboundConfig) { c.Clients[0].ID = "00000000-0000-0000-0000-000000000000" }, false},
		{"mixed_credentials", func(c *conf.DNSTTInboundConfig) { c.Clients[0].Password = "matrix-secret" }, false},
		{"duplicate_uuid_case", func(c *conf.DNSTTInboundConfig) {
			c.Clients = append(c.Clients, &conf.DNSTTInboundClient{ID: strings.ToUpper(c.Clients[0].ID)})
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			tc.edit(c)
			before, _ := json.Marshal(c)
			got, err := c.Build()
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
			after, _ := json.Marshal(c)
			if string(before) != string(after) {
				t.Fatal("Build mutated caller settings")
			}
			if !tc.valid {
				return
			}
			server := got.(*dnstt.ServerConfig)
			inner, err := server.Inner.GetInstance()
			if err != nil {
				t.Fatal(err)
			}
			users := inner.(*vlessin.Config).Clients
			if len(users) != len(c.Clients) {
				t.Fatal("client count changed")
			}
			for i, user := range users {
				if user.Email != c.Clients[i].Email || user.Level != c.Clients[i].Level {
					t.Fatal("client policy metadata was lost")
				}
			}
		})
	}
	for _, count := range []int{4096, 4097} {
		t.Run(fmt.Sprintf("vless_account_limit_%d", count), func(t *testing.T) {
			c := base()
			c.Clients = nil
			for i := 1; i <= count; i++ {
				c.Clients = append(c.Clients, &conf.DNSTTInboundClient{ID: fmt.Sprintf("00112233-4455-6677-8899-%012x", i)})
			}
			_, err := c.Build()
			if (err == nil) != (count <= 4096) {
				t.Fatalf("account count %d: %v", count, err)
			}
		})
	}
}

func TestDNSTTInboundSocksOptionMatrix(t *testing.T) {
	for _, tc := range []struct {
		name    string
		clients []*conf.DNSTTInboundClient
		valid   bool
	}{
		{"disabled", nil, true},
		{"one_byte_credentials", []*conf.DNSTTInboundClient{{Username: "u", Password: "p", Level: 3}}, true},
		{"max_byte_credentials", []*conf.DNSTTInboundClient{{Username: strings.Repeat("u", 255), Password: strings.Repeat("p", 255)}}, true},
		{"same_levels", []*conf.DNSTTInboundClient{{Username: "a", Password: "p", Level: 3}, {Username: "b", Password: "q", Level: 3}}, true},
		{"different_levels", []*conf.DNSTTInboundClient{{Username: "a", Password: "p", Level: 3}, {Username: "b", Password: "q", Level: 4}}, false},
		{"duplicate_username", []*conf.DNSTTInboundClient{{Username: "a", Password: "p"}, {Username: "a", Password: "q"}}, false},
		{"empty_username", []*conf.DNSTTInboundClient{{Password: "p"}}, false},
		{"empty_password", []*conf.DNSTTInboundClient{{Username: "u"}}, false},
		{"long_username", []*conf.DNSTTInboundClient{{Username: strings.Repeat("u", 256), Password: "p"}}, false},
		{"utf8_byte_limit", []*conf.DNSTTInboundClient{{Username: "u", Password: strings.Repeat("é", 128)}}, false},
		{"vless_credentials", []*conf.DNSTTInboundClient{{ID: "00112233-4455-6677-8899-aabbccddeeff", Username: "u", Password: "p"}}, false},
		{"nil_user", []*conf.DNSTTInboundClient{nil}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &conf.DNSTTInboundConfig{Domain: "tunnel.example.test", PrivateKey: strings.Repeat("ab", 32), Inner: &conf.DNSTTInboundInner{Protocol: "SOCKS"}, Clients: tc.clients}
			got, err := c.Build()
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
			if !tc.valid {
				return
			}
			inner, err := got.(*dnstt.ServerConfig).Inner.GetInstance()
			if err != nil {
				t.Fatal(err)
			}
			s := inner.(*socks.ServerConfig)
			if s.AuthType != socks.AuthType_PASSWORD || s.UdpEnabled || len(s.Accounts) != len(tc.clients) {
				t.Fatal("SOCKS authentication or TCP-only contract changed")
			}
			for _, u := range tc.clients {
				if s.Accounts[u.Username] != u.Password || s.UserLevel != u.Level {
					t.Fatal("SOCKS user data lost")
				}
			}
		})
	}
}
