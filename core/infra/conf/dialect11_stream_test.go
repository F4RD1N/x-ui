package conf

import (
	"encoding/json"
	"testing"
)

func TestNativeTransportSecurityIsolation(t *testing.T) {
	settings := json.RawMessage(`{}`)
	tunnel := json.RawMessage(`{"tunnel":{}}`)
	for _, p := range []string{"orbit", "dnstt", "openvpn", "ov", "anytls", "shadowtls", "mieru", "dns"} {
		raw := &settings
		if p == "dns" {
			raw = &tunnel
		}
		for _, network := range []string{"", "tcp", "raw"} {
			n := TransportProtocol(network)
			if err := validateNativeStream(p, raw, &StreamConfig{Network: &n}, false); err != nil {
				t.Fatal(err)
			}
		}
		n := TransportProtocol("ws")
		if validateNativeStream(p, raw, &StreamConfig{Network: &n}, false) == nil {
			t.Fatalf("%s accepted double transport", p)
		}
		if validateNativeStream(p, raw, &StreamConfig{Security: "tls"}, false) == nil {
			t.Fatalf("%s accepted double TLS", p)
		}
	}
	if validateNativeStream("anytls", &settings, nil, true) == nil {
		t.Fatal("AnyTLS inbound accepted plaintext")
	}
	if err := validateNativeStream("anytls", &settings, &StreamConfig{Security: "tls"}, true); err != nil {
		t.Fatal(err)
	}
	if validateNativeStream("dns", &settings, &StreamConfig{Security: "tls"}, true) == nil {
		t.Fatal("DNS tunnel inbound alias accepted outer TLS")
	}
	ws := TransportProtocol("ws")
	if validateNativeStream("dns", &settings, &StreamConfig{Network: &ws}, true) == nil {
		t.Fatal("DNS tunnel inbound alias accepted outer WebSocket")
	}
	for _, p := range []string{"vmess", "vless", "trojan", "shadowsocks", "dns", "socks", "freedom"} {
		n := TransportProtocol("ws")
		if err := validateNativeStream(p, &settings, &StreamConfig{Network: &n, Security: "tls"}, false); err != nil {
			t.Fatalf("existing %s behavior changed", p)
		}
	}
}
