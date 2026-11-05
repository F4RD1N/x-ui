//go:build !without_native_protocols

package conf_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/mieru"
)

// Exercise the full advertised timeout range with each transport/authentication
// mode. These are configuration tests: they do not open sockets or wait for a
// timeout, and must not be mistaken for the separate client runtime matrix.
func TestMieruMatrixAllTimeoutValues(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		for _, custom := range []bool{false, true} {
			for timeout := uint32(0); timeout <= 300; timeout++ {
				t.Run(fmt.Sprintf("%s/custom=%v/timeout=%d", transport, custom, timeout), func(t *testing.T) {
					username := "synthetic-user"
					if custom {
						username = "a3ac6533-7c27-45c4-93f2-9192745e218b"
					}
					in := conf.MieruServerConfig{Transport: transport, HandshakeTimeout: timeout, Clients: []conf.MieruUser{{Username: username, Password: "synthetic-password", UUIDMetadataTrailer: custom}}}
					out := conf.MieruConfig{Address: "127.0.0.1", Port: 2027, Transport: transport, HandshakeTimeout: timeout, Username: username, Password: "synthetic-password", UUIDMetadataTrailer: custom}
					builtIn, err := in.Build()
					if err != nil {
						t.Fatal(err)
					}
					builtOut, err := out.Build()
					if err != nil {
						t.Fatal(err)
					}
					if builtIn.(*mieru.ServerConfig).HandshakeTimeout != timeout || builtOut.(*mieru.Config).HandshakeTimeout != timeout {
						t.Fatal("inbound/outbound timeout was not preserved")
					}
				})
			}
		}
	}
}

func TestMieruMatrixCredentialByteBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, username, password string
		valid                    bool
	}{
		{"one-byte", "u", "p", true},
		{"ascii-maximum", strings.Repeat("u", 256), strings.Repeat("p", 4096), true},
		{"utf8-maximum", strings.Repeat("ü", 128), strings.Repeat("密", 1365) + "p", true},
		{"utf8-username-too-long", strings.Repeat("ü", 129), "p", false},
		{"utf8-password-too-long", "u", strings.Repeat("密", 1366), false},
		{"uuid-ordinary-auth", "a3ac6533-7c27-45c4-93f2-9192745e218b", "p", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := conf.MieruServerConfig{Clients: []conf.MieruUser{{Username: tc.username, Password: tc.password}}}
			out := conf.MieruConfig{Address: "127.0.0.1", Port: 2027, Username: tc.username, Password: tc.password}
			for _, cfg := range []conf.Buildable{&in, &out} {
				_, err := cfg.Build()
				if (err == nil) != tc.valid {
					t.Fatalf("%T accepted=%v, want=%v: %v", cfg, err == nil, tc.valid, err)
				}
			}
		})
	}
}

func TestMieruMatrixMaximumUsersAndCaseSensitiveIdentity(t *testing.T) {
	config := conf.MieruServerConfig{Clients: make([]conf.MieruUser, 1024)}
	for i := range config.Clients {
		config.Clients[i] = conf.MieruUser{Username: fmt.Sprintf("user-%04d", i), Password: "synthetic-password"}
	}
	built, err := config.Build()
	if err != nil {
		t.Fatal(err)
	}
	if len(built.(*mieru.ServerConfig).Users) != 1024 {
		t.Fatal("maximum supported client list was truncated")
	}
	// Usernames feed the authentication key byte-for-byte, whereas email is a
	// case-insensitive management identity. Keep these two rules distinct.
	config.Clients = []conf.MieruUser{{Username: "User", Password: "p"}, {Username: "user", Password: "p"}}
	if _, err = config.Build(); err != nil {
		t.Fatal("distinct case-sensitive usernames with no emails rejected:", err)
	}
	config.Clients[0].Email, config.Clients[1].Email = "User@Example.invalid", "user@example.invalid"
	if _, err = config.Build(); err == nil {
		t.Fatal("duplicate management email accepted")
	}
}

func TestMieruMatrixJSONRejectsFractionalAndWrongTypes(t *testing.T) {
	for _, fragment := range []string{
		`"handshakeTimeout":0.5`, `"handshakeTimeout":"10"`, `"handshakeTimeout":true`,
		`"transport":7`, `"transport":[]`, `"username":{}`, `"password":[]`,
		`"uuidMetadataTrailer":[]`, `"port":1.5`,
	} {
		var config conf.MieruConfig
		raw := `{"address":"127.0.0.1","port":2027,"username":"user","password":"synthetic-password",` + fragment + `}`
		if err := json.Unmarshal([]byte(raw), &config); err == nil {
			t.Fatalf("malformed typed field accepted: %s", fragment)
		}
	}
}
