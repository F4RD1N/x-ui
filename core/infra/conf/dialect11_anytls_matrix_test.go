package conf

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/xtls/xray-core/proxy/anytls"
)

// These cases exercise panel-supported boundaries, including JSON values that
// bypass the browser's numeric widgets through restore/import/API requests.
func TestDialect11AnyTLSInboundOptionMatrix(t *testing.T) {
	for _, timeout := range []uint32{0, 1, 10, 300} {
		for _, streams := range []uint32{0, 1, 128, 1024} {
			t.Run(fmt.Sprintf("timeout_%d_streams_%d", timeout, streams), func(t *testing.T) {
				input := fmt.Sprintf(`{"handshakeTimeout":%d,"maxStreams":%d,"clients":[{"password":"boundary","level":4294967295,"email":"boundary@test"}]}`, timeout, streams)
				var cfg AnyTLSServerConfig
				if err := json.Unmarshal([]byte(input), &cfg); err != nil {
					t.Fatal(err)
				}
				raw, err := cfg.Build()
				if err != nil {
					t.Fatal(err)
				}
				built := raw.(*anytls.ServerConfig)
				if built.HandshakeTimeout != timeout || built.MaxStreams != streams || built.Users[0].Level != ^uint32(0) {
					t.Fatal("inbound boundary settings were not preserved")
				}
			})
		}
	}
	for _, field := range []string{"handshakeTimeout", "maxStreams"} {
		for _, value := range []string{"-1", "0.5", `"1"`, "true", "4294967296"} {
			t.Run(field+"_invalid_"+value, func(t *testing.T) {
				var cfg AnyTLSServerConfig
				if err := json.Unmarshal([]byte(`{"`+field+`":`+value+`}`), &cfg); err == nil {
					t.Fatal("malformed numeric option accepted")
				}
			})
		}
	}
}

func TestDialect11AnyTLSAccountOptionMatrix(t *testing.T) {
	const id = "00112233-4455-6677-8899-aabbccddeeff"
	for _, tc := range []struct {
		name      string
		users     []AnyTLSUserConfig
		wantError bool
	}{
		{"one_byte", []AnyTLSUserConfig{{Password: "p"}}, false},
		{"4096_bytes", []AnyTLSUserConfig{{Password: strings.Repeat("p", 4096)}}, false},
		{"4097_bytes", []AnyTLSUserConfig{{Password: strings.Repeat("p", 4097)}}, true},
		{"unicode_4096_bytes", []AnyTLSUserConfig{{Password: strings.Repeat("é", 2048)}}, false},
		{"unicode_4098_bytes", []AnyTLSUserConfig{{Password: strings.Repeat("é", 2049)}}, true},
		{"uuid_separate_modes", []AnyTLSUserConfig{{Password: id}, {Password: id, UUIDHashMiddle: true}}, false},
		{"text_flag_same_identity", []AnyTLSUserConfig{{Password: "text"}, {Password: "text", UUIDHashMiddle: true}}, true},
		{"different_users_empty_email", []AnyTLSUserConfig{{Password: "p"}, {Password: "q"}}, false},
		{"duplicate_nonempty_email", []AnyTLSUserConfig{{Password: "p", Email: "x"}, {Password: "q", Email: "x"}}, true},
		{"empty_password", []AnyTLSUserConfig{{Password: ""}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := AnyTLSServerConfig{Clients: tc.users}
			raw, err := cfg.Build()
			if (err != nil) != tc.wantError {
				t.Fatalf("error = %v; want error %t", err, tc.wantError)
			}
			if err != nil {
				return
			}
			for i, user := range raw.(*anytls.ServerConfig).Users {
				memory, err := user.ToMemoryUser()
				if err != nil {
					t.Fatal(err)
				}
				account := memory.Account.(*anytls.MemoryAccount)
				if account.Password != tc.users[i].Password || account.UUIDHashMiddle != tc.users[i].UUIDHashMiddle || account.Key != anytls.Auth(tc.users[i].Password, tc.users[i].UUIDHashMiddle) {
					t.Fatal("account authentication options changed")
				}
			}
		})
	}
}

func TestDialect11AnyTLSOutboundNumericOptionMatrix(t *testing.T) {
	fields := []string{"idleSessionCheckInterval", "idleSessionTimeout", "minIdleSession", "handshakeTimeout"}
	for _, field := range fields {
		for _, value := range []uint32{0, 1, ^uint32(0)} {
			t.Run(fmt.Sprintf("%s_%d", field, value), func(t *testing.T) {
				var cfg AnyTLSConfig
				input := fmt.Sprintf(`{"address":"127.0.0.1","port":443,"password":"p","%s":%d}`, field, value)
				if err := json.Unmarshal([]byte(input), &cfg); err != nil {
					t.Fatal(err)
				}
				raw, err := cfg.Build()
				if err != nil {
					t.Fatal(err)
				}
				built := raw.(*anytls.Config)
				values := map[string]uint32{"idleSessionCheckInterval": built.IdleSessionCheckInterval, "idleSessionTimeout": built.IdleSessionTimeout, "minIdleSession": built.MinIdleSession, "handshakeTimeout": built.HandshakeTimeout}
				if values[field] != value {
					t.Fatal("outbound option lost")
				}
			})
		}
		for _, value := range []string{"-1", "1.25", `"1"`, "true", "4294967296"} {
			t.Run(field+"_invalid_"+value, func(t *testing.T) {
				var cfg AnyTLSConfig
				input := `{"address":"127.0.0.1","port":443,"password":"p","` + field + `":` + value + `}`
				if err := json.Unmarshal([]byte(input), &cfg); err == nil {
					t.Fatal("malformed option accepted")
				}
			})
		}
	}
}

func TestDialect11AnyTLSTLSOptionMatrix(t *testing.T) {
	for _, insecure := range []bool{false, true} {
		for _, version := range []string{"1.2", "1.3"} {
			t.Run(fmt.Sprintf("TLS_%s_insecure_%t", version, insecure), func(t *testing.T) {
				var cfg AnyTLSConfig
				input := fmt.Sprintf(`{"address":"127.0.0.1","port":443,"password":"p","tlsSettings":{"serverName":"anytls.test","allowInsecure":%t,"minVersion":"%s","maxVersion":"%s","fingerprint":"chrome","disableSystemRoot":true,"enableSessionResumption":true,"alpn":["h2","http/1.1"]}}`, insecure, version, version)
				if err := json.Unmarshal([]byte(input), &cfg); err != nil {
					t.Fatal(err)
				}
				raw, err := cfg.Build()
				if err != nil {
					t.Fatal(err)
				}
				tls := raw.(*anytls.Config).Tls
				if tls.ServerName != "anytls.test" || tls.AllowInsecure != insecure || tls.MinVersion != version || tls.MaxVersion != version || tls.Fingerprint != "chrome" || !tls.DisableSystemRoot || !tls.EnableSessionResumption || len(tls.NextProtocol) != 2 {
					t.Fatalf("nested TLS option dropped: %+v", tls)
				}
				if cfg.TLS.AllowInsecure != insecure {
					t.Fatal("Build mutated original TLS settings")
				}
			})
		}
	}
}
