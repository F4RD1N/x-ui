package conf

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	ss2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/shadowtls"
	vlessin "github.com/xtls/xray-core/proxy/vless/inbound"
	"google.golang.org/protobuf/proto"
)

// Exercise the distinct inner authentication modes through the public JSON
// parser. In particular an absent managed account list must not be confused
// with an explicitly empty list when a backup is restored.
func TestDialect11ShadowTLSInboundOptionMatrix(t *testing.T) {
	const id = "00112233-4455-6677-8899-aabbccddeeff"
	inners := map[string]map[string]interface{}{
		"socks":         {"protocol": "socks", "settings": map[string]interface{}{"auth": "password", "accounts": []interface{}{map[string]interface{}{"user": "matrix", "pass": "inner-secret"}}, "udp": false}},
		"vless":         {"protocol": "vless", "settings": map[string]interface{}{"clients": []interface{}{map[string]interface{}{"email": "inner@example.invalid", "id": id, "level": 7}}, "decryption": "none"}},
		"vless-dialect": {"protocol": "vless", "settings": map[string]interface{}{"clients": []interface{}{map[string]interface{}{"email": "inner@example.invalid", "id": id}}, "decryption": "none", "dialects": []uint32{0, 120}}},
	}
	for _, method := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
		key := "inner-secret"
		is2022 := strings.HasPrefix(method, "2022-")
		if is2022 {
			size := 32
			if method == "2022-blake3-aes-128-gcm" {
				size = 16
			}
			key = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x23}, size))
		}
		inners[method+"-single"] = map[string]interface{}{"protocol": "shadowsocks", "settings": map[string]interface{}{"method": method, "password": key, "network": "tcp"}}
		if method != "2022-blake3-chacha20-poly1305" {
			account := map[string]interface{}{"email": "inner@example.invalid", "password": key, "level": 7}
			if !is2022 {
				account["method"] = method
			}
			inners[method+"-multi"] = map[string]interface{}{"protocol": "shadowsocks", "settings": map[string]interface{}{"method": method, "password": key, "network": "tcp", "clients": []interface{}{account}}}
		}
	}
	for version := 1; version <= 3; version++ {
		for _, strict := range []bool{false, true} {
			for name, inner := range inners {
				t.Run(fmt.Sprintf("v%d/strict-%t/%s", version, strict, name), func(t *testing.T) {
					c := shadowTLSTestInbound()
					c["version"], c["strict"], c["inner"], c["handshakeTimeout"] = version, strict, inner, 300
					c["handshake"] = map[string]interface{}{"address": "127.0.0.1", "port": 8443}
					if version == 3 {
						c["clients"] = []interface{}{map[string]interface{}{"email": "outer@example.invalid", "password": id, "level": 7, "requireUuidSessionId": true}}
					} else {
						delete(c, "clients")
						if version == 2 {
							c["password"] = "outer-secret"
						}
					}
					built, err := buildShadowTLSTestJSON(t, c)
					if err != nil {
						t.Fatal(err)
					}
					if built.Version != uint32(version) || built.Strict != strict || built.HandshakeTimeout != 300 || built.HandshakeAddress != "127.0.0.1" || built.HandshakePort != 8443 {
						t.Fatal("carrier options were changed")
					}
					if version == 3 && (built.Clients[0].Email != "outer@example.invalid" || built.Clients[0].Level != 7 || !built.Clients[0].RequireUuidSessionId) {
						t.Fatal("outer account options were changed")
					}
					if version == 2 && built.Password != "outer-secret" {
						t.Fatal("v2 shared password lost")
					}
					if name == "vless-dialect" {
						p, err := built.Inner.GetInstance()
						if err != nil {
							t.Fatal(err)
						}
						got := p.(*vlessin.Config).Dialects
						if len(got) != 2 || got[0] != 0 || got[1] != 120 {
							t.Fatalf("inner dialects lost: %v", got)
						}
					}
					encoded, err := proto.Marshal(built)
					if err != nil {
						t.Fatal(err)
					}
					var restored shadowtls.ServerConfig
					if err := proto.Unmarshal(encoded, &restored); err != nil {
						t.Fatal(err)
					}
					if !proto.Equal(built, &restored) {
						t.Fatal("restore changed effective options")
					}
					if err := shadowtls.ValidateServerConfig(&restored); err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}

func TestDialect11ShadowTLSManaged2022Modes(t *testing.T) {
	for _, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
		size := 32
		if method == "2022-blake3-aes-128-gcm" {
			size = 16
		}
		key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, size))
		for _, mode := range []string{"absent", "empty", "null", "populated"} {
			t.Run(method+"/"+mode, func(t *testing.T) {
				settings := map[string]interface{}{"method": method, "password": key, "network": "tcp"}
				switch mode {
				case "empty":
					settings["clients"] = []interface{}{}
				case "null":
					settings["clients"] = nil
				case "populated":
					settings["clients"] = []interface{}{map[string]interface{}{"email": "a", "password": key}}
				}
				c := shadowTLSTestInbound()
				c["inner"] = map[string]interface{}{"protocol": "shadowsocks", "settings": settings}
				built, err := buildShadowTLSTestJSON(t, c)
				if method == "2022-blake3-chacha20-poly1305" && mode != "absent" {
					if err == nil {
						t.Fatal("multi-user ChaCha20 accepted")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				p, err := built.Inner.GetInstance()
				if err != nil {
					t.Fatal(err)
				}
				if mode == "absent" {
					if _, ok := p.(*ss2022.ServerConfig); !ok {
						t.Fatal("single-user credentials lost")
					}
				} else {
					multi, ok := p.(*ss2022.MultiUserServerConfig)
					if !ok {
						t.Fatal("managed accounts became shared server-key access")
					}
					if mode != "populated" && len(multi.Users) != 0 {
						t.Fatal("empty managed list is not deny-all")
					}
				}
			})
		}
	}
}

func TestDialect11ShadowTLSOutboundOptionMatrix(t *testing.T) {
	for version := uint32(1); version <= 3; version++ {
		for _, strict := range []bool{false, true} {
			for _, timeout := range []uint32{0, 1, 300} {
				t.Run(fmt.Sprintf("v%d/strict-%t/timeout-%d", version, strict, timeout), func(t *testing.T) {
					c := ShadowTLSConfig{Address: "127.0.0.1", Port: 8443, Version: version, Password: "00112233-4455-6677-8899-aabbccddeeff", ServerName: "cover.example.invalid", AllowInsecure: true, Strict: &strict, UUIDSessionID: version == 3, Fingerprint: "firefox", CAPEM: "fixture-preservation-only", HandshakeTimeout: timeout}
					p, err := c.Build()
					if err != nil {
						t.Fatal(err)
					}
					want := &shadowtls.Config{Address: c.Address, Port: c.Port, Password: c.Password, Version: version, ServerName: c.ServerName, AllowInsecure: true, Strict: strict, UuidSessionId: version == 3, Fingerprint: c.Fingerprint, CaPem: c.CAPEM, HandshakeTimeout: timeout}
					if !proto.Equal(p, want) {
						t.Fatal("outbound options were lost in parsing")
					}
				})
			}
		}
	}
	for _, timeout := range []uint32{301, ^uint32(0)} {
		c := ShadowTLSConfig{Address: "127.0.0.1", Port: 443, ServerName: "example.invalid", Version: 3, Password: "secret", HandshakeTimeout: timeout}
		if _, err := c.Build(); err == nil {
			t.Fatalf("unbounded outbound timeout %d accepted", timeout)
		}
	}
}
