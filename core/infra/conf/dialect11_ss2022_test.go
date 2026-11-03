package conf_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"google.golang.org/protobuf/proto"
)

const ssUUIDFixture = "00112233-4455-6677-8899-aabbccddeeff"

func TestSS2022UUIDIdentityVectors(t *testing.T) {
	for _, tc := range []struct {
		method string
		size   int
	}{{"2022-blake3-aes-128-gcm", 16}, {"2022-blake3-aes-256-gcm", 32}, {"2022-blake3-chacha20-poly1305", 32}} {
		id := uuid.MustParse(ssUUIDFixture)
		want := append([]byte(nil), id[:]...)
		if tc.size == 32 {
			want = append(want, id[:]...)
		}
		for _, input := range []string{ssUUIDFixture, "urn:uuid:" + ssUUIDFixture, "{" + ssUUIDFixture + "}"} {
			got, err := conf.NormalizeSS2022IdentityKey(tc.method, input)
			if err != nil || got != base64.StdEncoding.EncodeToString(want) {
				t.Fatalf("%s UUID vector failed: %v", tc.method, err)
			}
		}
		got, err := conf.NormalizeSS2022IdentityKey(tc.method, "already-canonical")
		if err != nil || got != "already-canonical" {
			t.Fatal("non-UUID key changed")
		}
	}
	for _, method := range []string{"aes-128-gcm", "2022-BLAKE3-AES-128-GCM", "2022-blake3-unknown"} {
		if _, err := conf.NormalizeSS2022IdentityKey(method, ssUUIDFixture); err == nil {
			t.Fatal("accepted wrong method")
		}
	}
}

func ssProxyBuild(t *testing.T, settings string, inbound bool) (proto.Message, error) {
	t.Helper()
	raw := json.RawMessage(settings)
	if inbound {
		c := &conf.InboundDetourConfig{Protocol: "shadowsocks", PortList: &conf.PortList{Range: []conf.PortRange{{From: 32123, To: 32123}}}, Settings: &raw}
		p, e := c.Build()
		if e != nil {
			return nil, e
		}
		return p.ProxySettings.GetInstance()
	}
	c := &conf.OutboundDetourConfig{Protocol: "shadowsocks", Settings: &raw}
	p, e := c.Build()
	if e != nil {
		return nil, e
	}
	return p.ProxySettings.GetInstance()
}

func TestSS2022UUIDImportAndStockEquivalence(t *testing.T) {
	psk := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{42}, 16))
	identity, _ := conf.NormalizeSS2022IdentityKey("2022-blake3-aes-128-gcm", ssUUIDFixture)
	stock := `{"address":"127.0.0.1","port":1234,"method":"2022-blake3-aes-128-gcm","password":"` + psk + `:` + identity + `"}`
	var original conf.ShadowsocksClientConfig
	if err := json.Unmarshal([]byte(stock), &original); err != nil {
		t.Fatal(err)
	}
	want, err := original.Build()
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{stock, stock[:len(stock)-1] + `,"uuidIdentityKeys":false}`, `{"address":"127.0.0.1","port":1234,"method":"2022-blake3-aes-128-gcm","password":"` + psk + `:` + ssUUIDFixture + `","uuidIdentityKeys":true}`, `{"servers":[{"address":"127.0.0.1","port":1234,"method":"2022-blake3-aes-128-gcm","password":"` + psk + `:` + ssUUIDFixture + `","uuidIdentityKeys":true}]}`} {
		got, err := ssProxyBuild(t, input, false)
		if err != nil || !proto.Equal(got, want) {
			t.Fatalf("SS2022 outbound changed canonical behavior: %v", err)
		}
	}
	in := `{"method":"2022-blake3-aes-128-gcm","password":"` + psk + `","clients":[{"email":"uuid@test","password":"` + ssUUIDFixture + `","uuidIdentityKeys":true}]}`
	got, err := ssProxyBuild(t, in, true)
	if err != nil {
		t.Fatal(err)
	}
	account, err := got.(*shadowsocks_2022.MultiUserServerConfig).Users[0].Account.GetInstance()
	if err != nil || account.(*shadowsocks_2022.Account).Key != identity {
		t.Fatal("inbound UUID key not normalized")
	}
	legacy := `{"method":"aes-128-gcm","password":"legacy-password"}`
	var old conf.ShadowsocksServerConfig
	json.Unmarshal([]byte(legacy), &old)
	originalServer, _ := old.Build()
	actualServer, err := ssProxyBuild(t, legacy, true)
	if err != nil || !proto.Equal(originalServer, actualServer) {
		t.Fatal("stock shadowsocks changed")
	}
	for _, bad := range []string{`{"uuidIdentityKeys":"true"}`, `{"uuidIdentityKeys":null}`, `{"uuidIdentityKeys":true,"method":"aes-128-gcm","password":"invalid"}`, `{"uuidIdentityKeys":true,"method":"2022-blake3-aes-128-gcm","password":"short:` + ssUUIDFixture + `"}`} {
		if _, err := ssProxyBuild(t, bad, false); err == nil {
			t.Fatal("accepted malformed UUID option")
		}
	}
}

func TestSS2022UUIDRealTraffic(t *testing.T) {
	for _, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"} {
		t.Run(method, func(t *testing.T) {
			size := 16
			if method == "2022-blake3-aes-256-gcm" {
				size = 32
			}
			psk := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{73}, size))
			port := availablePort(t)
			target, _ := nativeEchoTarget(t)
			startNativeCore(t, map[string]any{"log": map[string]any{"loglevel": "error"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "shadowsocks", "settings": map[string]any{"method": method, "password": psk, "clients": []any{map[string]any{"password": ssUUIDFixture, "uuidIdentityKeys": true, "email": "uuid@test"}}}}}, "outbounds": []any{map[string]any{"protocol": "freedom"}}})
			for _, custom := range []bool{false, true} {
				identity := ssUUIDFixture
				if !custom {
					identity, _ = conf.NormalizeSS2022IdentityKey(method, identity)
				}
				client := startNativeCore(t, map[string]any{"log": map[string]any{"loglevel": "error"}, "outbounds": []any{map[string]any{"protocol": "shadowsocks", "settings": map[string]any{"address": "127.0.0.1", "port": port, "method": method, "password": psk + ":" + identity, "uuidIdentityKeys": custom}}}})
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				conn, err := core.Dial(ctx, client, xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(target)))
				if err != nil {
					t.Fatal(err)
				}
				payload := bytes.Repeat([]byte("native-ss2022-"), 256)
				if _, err = conn.Write(payload); err != nil {
					conn.Close()
					t.Fatal(err)
				}
				got := make([]byte, len(payload))
				_, err = io.ReadFull(conn, got)
				conn.Close()
				if err != nil || !bytes.Equal(got, payload) {
					t.Fatalf("routed TCP mismatch: %v", err)
				}
			}
		})
	}
}
