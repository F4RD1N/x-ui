package conf

import (
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/proxy/anytls"
)

func TestDialect11AnyTLSInboundSchema(t *testing.T) {
	var settings AnyTLSServerConfig
	if err := json.Unmarshal([]byte(`{"clients":[{"password":"00112233-4455-6677-8899-aabbccddeeff","email":"test","level":2,"uuidHashMiddle":true}],"handshakeTimeout":12,"maxStreams":64}`), &settings); err != nil {
		t.Fatal(err)
	}
	raw, err := settings.Build()
	if err != nil {
		t.Fatal(err)
	}
	built := raw.(*anytls.ServerConfig)
	if built.HandshakeTimeout != 12 || built.MaxStreams != 64 || len(built.Users) != 1 || built.Users[0].Email != "test" || built.Users[0].Level != 2 {
		t.Fatalf("settings lost: %+v", built)
	}
	user, err := built.Users[0].ToMemoryUser()
	if err != nil {
		t.Fatal(err)
	}
	if !user.Account.(*anytls.MemoryAccount).UUIDHashMiddle {
		t.Fatal("custom auth flag dropped")
	}
	for _, j := range []string{
		`{"clients":[{"password":""}]}`,
		`{"clients":[{"password":"p"},{"password":"p"}]}`,
		`{"clients":[{"password":"p","email":"same"},{"password":"q","email":"same"}]}`,
		`{"maxStreams":1025}`,
		`{"handshakeTimeout":301}`,
		`{"unsupported":true}`,
		`{"clients":[{"password":"p","unsupported":true}]}`,
	} {
		var invalid AnyTLSServerConfig
		err := json.Unmarshal([]byte(j), &invalid)
		if err == nil {
			_, err = invalid.Build()
		}
		if err == nil {
			t.Fatalf("unsupported or invalid setting accepted: %s", j)
		}
	}
}

func TestDialect11AnyTLSOutboundPreservesClientContract(t *testing.T) {
	var settings AnyTLSConfig
	if err := json.Unmarshal([]byte(`{"address":"example.test","port":443,"password":"p","uuidHashMiddle":true,"idleSessionCheckInterval":4,"idleSessionTimeout":9,"minIdleSession":2,"handshakeTimeout":7}`), &settings); err != nil {
		t.Fatal(err)
	}
	raw, err := settings.Build()
	if err != nil {
		t.Fatal(err)
	}
	c := raw.(*anytls.Config)
	if !c.UuidHashMiddle || c.Tls.ServerName != "example.test" || c.IdleSessionCheckInterval != 4 || c.IdleSessionTimeout != 9 || c.MinIdleSession != 2 || c.HandshakeTimeout != 7 {
		t.Fatalf("outbound contract changed: %+v", c)
	}
	settings.TLS = &TLSConfig{ServerName: "example.test", AllowInsecure: true}
	raw, err = settings.Build()
	if err != nil || !raw.(*anytls.Config).Tls.AllowInsecure {
		t.Fatalf("explicit existing client TLS option lost: %v", err)
	}
	for _, j := range []string{`{"address":"","port":443,"password":"p"}`, `{"address":"x","port":65536,"password":"p"}`, `{"address":"x","port":1}`, `{"address":"x","port":1,"password":"p","unsupported":true}`, `{"address":"x","port":1,"password":"p","tlsSettings":{"certificates":[null]}}`} {
		var invalid AnyTLSConfig
		err := json.Unmarshal([]byte(j), &invalid)
		if err == nil {
			_, err = invalid.Build()
		}
		if err == nil {
			t.Fatalf("invalid outbound accepted: %s", j)
		}
	}
}
