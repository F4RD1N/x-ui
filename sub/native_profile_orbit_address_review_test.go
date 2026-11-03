package sub

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/xtls/xray-core/proxy/orbit"
)

func TestNativeProfileReviewOrbitNumericExportEndpoint(t *testing.T) {
	pki := makeNativeExportPKI(t)
	key, err := orbit.GenerateConnectionKey(pki.serverCert)
	if err != nil {
		t.Fatal(err)
	}
	client := model.Client{Email: exportEmail, Key: key, Enable: true}
	for _, tc := range []struct {
		name     string
		supplied bool
		value    any
		want     string
	}{
		{"absent", false, nil, "192.0.2.7"},
		{"ipv4", true, "198.51.100.37", "198.51.100.37"},
		{"loopback", true, "127.0.0.1", "127.0.0.1"},
		{"private-unicast", true, "10.23.45.67", "10.23.45.67"},
		{"ipv6", true, "2001:db8::123", "2001:db8::123"},
		{"ipv6-expanded", true, "2001:0db8:0:0:0:0:0:123", "2001:db8::123"},
		{"ipv6-bracketed", true, "[2001:db8::123]", "2001:db8::123"},
		{"ipv6-loopback", true, "::1", "::1"},
		{"ipv4-mapped", true, "::ffff:192.0.2.88", "192.0.2.88"},
		{"hostname", true, "vpn.example.test", ""},
		{"url", true, "https://198.51.100.37", ""},
		{"port", true, "198.51.100.37:443", ""},
		{"ipv6-port", true, "[2001:db8::123]:443", ""},
		{"unspecified4", true, "0.0.0.0", ""},
		{"unspecified6", true, "::", ""},
		{"multicast4", true, "224.0.0.1", ""},
		{"multicast6", true, "ff02::1", ""},
		{"broadcast4", true, "255.255.255.255", ""},
		{"linklocal4", true, "169.254.1.2", ""},
		{"linklocal6", true, "fe80::1", ""},
		{"zone", true, "fe80::1%eth0", ""},
		{"empty", true, "", ""},
		{"null", true, nil, ""},
		{"number", true, 42, ""},
		{"array", true, []any{"198.51.100.37"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			meta := map[string]any{}
			if tc.supplied {
				meta["address"] = tc.value
			}
			inbound := nativeTestInbound(t, "orbit", map[string]any{"transport": "tcp", "tls": map[string]any{"certificate": pki.serverCert, "key": pki.serverKey}, "clientExport": meta}, client)
			stored := inbound.Settings
			outs, err := nativeClientOutbounds(inbound, client, "192.0.2.7")
			if tc.want == "" {
				if err == nil || len(outs) != 0 {
					t.Fatal("invalid explicit Orbit endpoint was accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			nativeTestOutboundsBuild(t, outs)
			cfg := nativeTestSettings(t, outs[0])
			if cfg["address"] != tc.want || cfg["key"] != key || cfg["transport"] != "tcp" || cfg["port"] != float64(inbound.Port) {
				t.Fatal("endpoint override altered credential, transport or port")
			}
			if _, present := cfg["peer"]; present {
				t.Fatal("direct TCP numeric endpoint added a WebSocket peer")
			}
			raw, _ := json.Marshal(outs)
			if strings.Contains(string(raw), "PRIVATE KEY") || strings.Contains(string(raw), "clientExport") || inbound.Settings != stored {
				t.Fatal("export leaked metadata/private key or changed stored material")
			}
		})
	}
}
