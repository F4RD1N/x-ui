package conf

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

	ss2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/shadowtls"
	"google.golang.org/protobuf/proto"
)

func shadowTLSTestInbound() map[string]interface{} {
	return map[string]interface{}{
		"handshake": map[string]interface{}{"address": "example.invalid"},
		"clients":   []interface{}{map[string]interface{}{"email": "a@example.invalid", "password": "00112233-4455-6677-8899-aabbccddeeff", "requireUuidSessionId": true}},
		"inner":     map[string]interface{}{"protocol": "socks", "settings": map[string]interface{}{"auth": "password", "accounts": []interface{}{map[string]interface{}{"user": "inner", "pass": "secret"}}, "udp": false}},
	}
}

func TestDialect11ShadowTLSEncryptedInnerConfig(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16))
	makeConfig := func(settings map[string]interface{}) map[string]interface{} {
		c := shadowTLSTestInbound()
		c["inner"] = map[string]interface{}{"protocol": "shadowsocks", "settings": settings}
		return c
	}
	for _, method := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305"} {
		if _, err := buildShadowTLSTestJSON(t, makeConfig(map[string]interface{}{"method": method, "password": "password", "network": "tcp"})); err != nil {
			t.Fatal(method, err)
		}
	}
	empty, err := buildShadowTLSTestJSON(t, makeConfig(map[string]interface{}{"method": "2022-blake3-aes-128-gcm", "password": key, "network": "tcp", "clients": []interface{}{}}))
	if err != nil {
		t.Fatal(err)
	}
	inner, err := empty.Inner.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := inner.(*ss2022.MultiUserServerConfig); !ok {
		t.Fatal("empty managed identities fell back to shared server-key access")
	}
	for name, settings := range map[string]map[string]interface{}{
		"none": {"method": "none", "password": "password"}, "plain": {"method": "plain", "password": "password"}, "legacy": {"method": "aes-128-cfb", "password": "password"},
		"wrong-key-size": {"method": "2022-blake3-aes-256-gcm", "password": key},
		"udp-listener":   {"method": "aes-128-gcm", "password": "password", "network": "udp"},
		"bad-multi-key":  {"method": "2022-blake3-aes-128-gcm", "password": key, "clients": []interface{}{map[string]interface{}{"password": "invalid"}}},
		"relay":          {"method": "2022-blake3-aes-128-gcm", "password": key, "clients": []interface{}{map[string]interface{}{"password": key, "address": "127.0.0.1", "port": 80}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := buildShadowTLSTestJSON(t, makeConfig(settings)); err == nil {
				t.Fatal("invalid encrypted inner accepted")
			}
		})
	}
}

func buildShadowTLSTestJSON(t *testing.T, config map[string]interface{}) (*shadowtls.ServerConfig, error) {
	t.Helper()
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	var c ShadowTLSServerConfig
	if err = json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	built, err := c.Build()
	if err != nil {
		return nil, err
	}
	return built.(*shadowtls.ServerConfig), nil
}

func TestDialect11ShadowTLSConfigRoundTrip(t *testing.T) {
	c, err := buildShadowTLSTestJSON(t, shadowTLSTestInbound())
	if err != nil {
		t.Fatal(err)
	}
	if c.Version != 3 || !c.Strict || c.HandshakePort != 443 || !c.Clients[0].RequireUuidSessionId {
		t.Fatal("defaults or optional authentication lost")
	}
	encoded, err := proto.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var restored shadowtls.ServerConfig
	if err := proto.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(c, &restored) {
		t.Fatal("protobuf backup round trip changed effective settings")
	}
	if err := shadowtls.ValidateServerConfig(&restored); err != nil {
		t.Fatal(err)
	}
	// All accounts may be filtered by expiry/quota. The listener remains a
	// safe deny-all state without preventing unrelated inbounds from starting.
	empty := shadowTLSTestInbound()
	empty["clients"] = []interface{}{}
	empty["inner"].(map[string]interface{})["settings"].(map[string]interface{})["accounts"] = []interface{}{}
	if _, err := buildShadowTLSTestJSON(t, empty); err != nil {
		t.Fatal(err)
	}
	empty["inner"] = map[string]interface{}{"protocol": "vless", "settings": map[string]interface{}{"clients": []interface{}{}, "decryption": "none"}}
	if _, err := buildShadowTLSTestJSON(t, empty); err != nil {
		t.Fatal(err)
	}
	for _, version := range []int{1, 2} {
		settings := shadowTLSTestInbound()
		settings["version"] = version
		delete(settings, "clients")
		if version == 2 {
			settings["password"] = "shared-password"
		}
		if _, err := buildShadowTLSTestJSON(t, settings); err != nil {
			t.Fatalf("version%d: %v", version, err)
		}
	}
}

func TestDialect11ShadowTLSRejectInvalidInbound(t *testing.T) {
	cases := map[string]func(map[string]interface{}){
		"unsupported-version": func(c map[string]interface{}) { c["version"] = 4 },
		"missing-handshake":   func(c map[string]interface{}) { delete(c, "handshake") },
		"invalid-port": func(c map[string]interface{}) {
			c["handshake"] = map[string]interface{}{"address": "test.invalid", "port": 65536}
		},
		"null-client":    func(c map[string]interface{}) { c["clients"] = []interface{}{nil} },
		"empty-password": func(c map[string]interface{}) { c["clients"] = []interface{}{map[string]interface{}{"password": ""}} },
		"uuid-required-with-text": func(c map[string]interface{}) {
			c["clients"] = []interface{}{map[string]interface{}{"password": "text", "requireUuidSessionId": true}}
		},
		"duplicate-password": func(c map[string]interface{}) {
			c["clients"] = []interface{}{map[string]interface{}{"password": "text", "email": "a"}, map[string]interface{}{"password": "text", "email": "b"}}
		},
		"duplicate-email": func(c map[string]interface{}) {
			c["clients"] = []interface{}{map[string]interface{}{"password": "one", "email": "A"}, map[string]interface{}{"password": "two", "email": "a"}}
		},
		"v2-clients":          func(c map[string]interface{}) { c["version"] = 2; c["password"] = "outer" },
		"v2-missing-password": func(c map[string]interface{}) { c["version"] = 2; delete(c, "clients") },
		"unbounded-timeout":   func(c map[string]interface{}) { c["handshakeTimeout"] = 301 },
		"missing-inner":       func(c map[string]interface{}) { delete(c, "inner") },
		"recursive-inner": func(c map[string]interface{}) {
			c["inner"] = map[string]interface{}{"protocol": "shadowtls", "settings": map[string]interface{}{}}
		},
		"unauthenticated-inner": func(c map[string]interface{}) {
			c["inner"] = map[string]interface{}{"protocol": "socks", "settings": map[string]interface{}{"auth": "noauth"}}
		},
		"socks-udp": func(c map[string]interface{}) {
			c["inner"].(map[string]interface{})["settings"].(map[string]interface{})["udp"] = true
		},
		"vless-vision": func(c map[string]interface{}) {
			c["inner"] = map[string]interface{}{"protocol": "vless", "settings": map[string]interface{}{"decryption": "none", "clients": []interface{}{map[string]interface{}{"id": "00112233-4455-6677-8899-aabbccddeeff", "flow": "xtls-rprx-vision"}}}}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := shadowTLSTestInbound()
			mutate(c)
			if _, err := buildShadowTLSTestJSON(t, c); err == nil {
				t.Fatal("invalid settings accepted")
			}
		})
	}
}

func TestDialect11ShadowTLSOutboundOptions(t *testing.T) {
	c := ShadowTLSConfig{Address: "127.0.0.1", Port: 443, ServerName: "example.invalid", Password: "00112233-4455-6677-8899-aabbccddeeff", UUIDSessionID: true}
	p, err := c.Build()
	if err != nil {
		t.Fatal(err)
	}
	built := p.(*shadowtls.Config)
	if built.Version != 3 || !built.Strict || !built.UuidSessionId {
		t.Fatal("outbound defaults not preserved")
	}
	c.Version = 2
	if _, err := c.Build(); err == nil {
		t.Fatal("v2 uuidSessionId accepted")
	}
	c.Version = 3
	c.Password = "invalid-uuid"
	if _, err := c.Build(); err == nil {
		t.Fatal("non-UUID custom password accepted")
	}
	c.UUIDSessionID = false
	if _, err := c.Build(); err != nil {
		t.Fatal(err)
	}
	c.Version = 1
	c.Password = ""
	if _, err := c.Build(); err != nil {
		t.Fatal(err)
	}
}
