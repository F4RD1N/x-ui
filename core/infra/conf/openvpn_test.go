package conf_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/openvpn"
	"google.golang.org/protobuf/proto"
)

// testOVPN is a minimal client configuration the options parser accepts.
// testCA is a self-signed P-256 certificate (valid until 2126) that
// makes testOVPN pass the TLS checks.
const testCA = `-----BEGIN CERTIFICATE-----
MIIBhDCCASugAwIBAgIUHD30Y4uRGPc/YjiWoyy/V3rTn0swCgYIKoZIzj0EAwIw
FzEVMBMGA1UEAwwMb3Zwbi10ZXN0LWNhMCAXDTI2MTAwOTAyMDAwMloYDzIxMjYw
OTE1MDIwMDAyWjAXMRUwEwYDVQQDDAxvdnBuLXRlc3QtY2EwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAARJUhV+m0C9fbu4bpwLbIbqSwHRoWEhzNoQWioyHINKtqt7
o3WY8A1X6kQTEa5ozQiTnCvMBPtj6aelWIm1C8eEo1MwUTAdBgNVHQ4EFgQUPuge
DMNAr1CVasIAGt0Xe+nS4GowHwYDVR0jBBgwFoAUPugeDMNAr1CVasIAGt0Xe+nS
4GowDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiB1PUsrOWXOY0ES
AGE45uOcnoxNOCi1iyNObiguEJ93yQIgIB9M8OKG3OWB6OIVJ2XhkP49gQFQXEKz
Uy/fcozAlmc=
-----END CERTIFICATE-----`

const testOVPN = "client\ndev tun\nproto udp\nremote 192.0.2.10 1194\nremote-cert-tls server\n<ca>\n" + testCA + "\n</ca>\n"

func jsonString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func jsonLines(s string) string {
	b, err := json.Marshal(strings.Split(s, "\n"))
	if err != nil {
		panic(err)
	}
	return string(b)
}

func TestOpenVPNConfig(t *testing.T) {
	creator := func() Buildable {
		return new(OpenVPNConfig)
	}
	b64 := base64.StdEncoding.EncodeToString([]byte(testOVPN))
	urlB64 := base64.RawURLEncoding.EncodeToString([]byte(testOVPN))
	wrapped := b64[:20] + "\n" + b64[20:40] + "\r\n " + b64[40:]

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"ovpn": ` + jsonString(testOVPN) + `,
				"username": "alice",
				"password": "pw",
				"mtu": 1300,
				"domainStrategy": "ForceIPv6v4"
			}`,
			Parser: loadJSON(creator),
			Output: &openvpn.Config{
				Ovpn:           testOVPN,
				Username:       "alice",
				Password:       "pw",
				Mtu:            1300,
				DomainStrategy: openvpn.Config_FORCE_IP64,
			},
		},
		{
			// An array of lines is joined with "\n".
			Input:  `{"ovpn": ` + jsonLines(testOVPN) + `}`,
			Parser: loadJSON(creator),
			Output: &openvpn.Config{Ovpn: testOVPN},
		},
		{
			Input:  `{"ovpnBase64": ` + jsonString(b64) + `, "domainStrategy": "forceipv4"}`,
			Parser: loadJSON(creator),
			Output: &openvpn.Config{Ovpn: testOVPN, DomainStrategy: openvpn.Config_FORCE_IP4},
		},
		{
			// Line breaks inside the base64 and the URL-safe alphabet.
			Input:  `{"ovpnBase64": ` + jsonString(wrapped) + `, "domainStrategy": "FORCEIPV6"}`,
			Parser: loadJSON(creator),
			Output: &openvpn.Config{Ovpn: testOVPN, DomainStrategy: openvpn.Config_FORCE_IP6},
		},
		{
			Input:  `{"ovpnBase64": ` + jsonString(urlB64) + `, "domainStrategy": "ForceIPv4v6", "ovpn": ""}`,
			Parser: loadJSON(creator),
			Output: &openvpn.Config{Ovpn: testOVPN, DomainStrategy: openvpn.Config_FORCE_IP46},
		},
		{
			Input:  `{"ovpn": ` + jsonString(testOVPN) + `, "domainStrategy": "ForceIP"}`,
			Parser: loadJSON(creator),
			Output: &openvpn.Config{Ovpn: testOVPN, DomainStrategy: openvpn.Config_FORCE_IP},
		},
	})
}

func TestOpenVPNConfigErrors(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte(testOVPN))
	cases := []struct {
		name, input, want string
	}{
		{"nothing", `{}`, "required"},
		{"empty ovpn", `{"ovpn": ""}`, "required"},
		{"both", `{"ovpn": ` + jsonString(testOVPN) + `, "ovpnBase64": ` + jsonString(b64) + `}`, "only one"},
		{"bad base64", `{"ovpnBase64": "*not base64*"}`, "not valid base64"},
		{"ovpn not text", `{"ovpn": 12}`, "string or an array"},
		{"ovpn array of non-strings", `{"ovpn": [1, 2]}`, "string or an array"},
		{"domain strategy", `{"ovpn": ` + jsonString(testOVPN) + `, "domainStrategy": "AsIs"}`, "unsupported domain strategy"},
		{"no remote", `{"ovpn": "client\ndev tun\n"}`, "no remote"},
		{"tap", `{"ovpn": ` + jsonString(testOVPN+"dev tap\n") + `}`, "bad configuration"},
		{"password without username", `{"ovpn": ` + jsonString(testOVPN) + `, "password": "pw"}`, "without a username"},
		{"auth-user-pass without credentials", `{"ovpn": ` + jsonString(testOVPN+"auth-user-pass\n") + `}`, "auth-user-pass"},
		{"mtu too small", `{"ovpn": ` + jsonString(testOVPN) + `, "mtu": 100}`, "out of range"},
		{"mtu negative", `{"ovpn": ` + jsonString(testOVPN) + `, "mtu": -1}`, "out of range"},
		{"bad ca", `{"ovpn": ` + jsonString(strings.Replace(testOVPN, testCA, "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----", 1)) + `}`, "unusable certificate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := new(OpenVPNConfig)
			err := json.Unmarshal([]byte(tc.input), c)
			if err == nil {
				_, err = c.Build()
			}
			if err == nil {
				t.Fatalf("no error, want one mentioning %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// Credentials given in the outbound satisfy auth-user-pass; so does an
// inline <auth-user-pass> block.
func TestOpenVPNConfigCredentials(t *testing.T) {
	for _, input := range []string{
		`{"ovpn": ` + jsonString(testOVPN+"auth-user-pass\n") + `, "username": "u", "password": "p"}`,
		`{"ovpn": ` + jsonString(testOVPN+"<auth-user-pass>\nu\np\n</auth-user-pass>\n") + `}`,
	} {
		c := new(OpenVPNConfig)
		if err := json.Unmarshal([]byte(input), c); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Build(); err != nil {
			t.Fatalf("%s: %v", input, err)
		}
	}
}

// The base64 error never echoes the configuration (it holds keys).
func TestOpenVPNConfigErrorHidesSecrets(t *testing.T) {
	secret := "PRIVATEKEYMATERIAL"
	c := &OpenVPNConfig{OvpnBase64: "!!" + secret}
	_, err := c.Build()
	if err == nil {
		t.Fatal("no error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaks the input: %v", err)
	}
}

func TestOpenVPNOutboundRegistered(t *testing.T) {
	var ob OutboundDetourConfig
	input := `{"protocol": "openvpn", "tag": "vpn", "settings": {"ovpn": ` + jsonString(testOVPN) + `}}`
	if err := json.Unmarshal([]byte(input), &ob); err != nil {
		t.Fatal(err)
	}
	hc, err := ob.Build()
	if err != nil {
		t.Fatal(err)
	}
	msg, err := hc.ProxySettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	c, ok := msg.(*openvpn.Config)
	if !ok {
		t.Fatalf("proxy settings are %T, want *openvpn.Config", msg)
	}
	if c.Ovpn != testOVPN {
		t.Fatalf("ovpn = %q", c.Ovpn)
	}
}

// "ov" is the OpenVPN outbound's name and "openvpn" its alias: the same
// outbound under either name (in any case, as Xray folds protocol names)
// builds the same handler configuration, byte for byte, with both the .ovpn
// text and the structured settings.
func TestOVAndOpenVPNBuildTheSameOutbound(t *testing.T) {
	structured := `{"server": {"address": "vpn.example.com", "port": 1194, "network": "tcp"},
		"certificates": {"ca": ` + jsonString(testCA) + `}, "advanced": {"dev": "tun", "nobind": true}}`
	for _, settings := range []string{`{"ovpn": ` + jsonString(testOVPN) + `, "mtu": 1300}`, structured} {
		var want []byte
		for _, name := range []string{"ov", "openvpn", "OV", "OpenVPN"} {
			var ob OutboundDetourConfig
			input := `{"protocol": "` + name + `", "tag": "vpn", "settings": ` + settings + `}`
			if err := json.Unmarshal([]byte(input), &ob); err != nil {
				t.Fatal(err)
			}
			hc, err := ob.Build()
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			msg, err := hc.ProxySettings.GetInstance()
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := msg.(*openvpn.Config); !ok {
				t.Fatalf("%s: proxy settings are %T, want *openvpn.Config", name, msg)
			}
			got, err := proto.MarshalOptions{Deterministic: true}.Marshal(hc)
			if err != nil {
				t.Fatal(err)
			}
			if want == nil {
				want = got
			} else if string(got) != string(want) {
				t.Fatalf("%q builds another configuration than \"ov\"", name)
			}
		}
	}
	// A near miss is still an unknown protocol.
	for _, name := range []string{"o v", "ovpn", "open-vpn"} {
		var ob OutboundDetourConfig
		if err := json.Unmarshal([]byte(`{"protocol": "`+name+`", "settings": {"ovpn": `+jsonString(testOVPN)+`}}`), &ob); err != nil {
			t.Fatal(err)
		}
		if _, err := ob.Build(); err == nil {
			t.Fatalf("%q was accepted as a protocol", name)
		}
	}
}

func FuzzOpenVPNConfig(f *testing.F) {
	f.Add([]byte(`{"ovpn": ` + jsonString(testOVPN) + `}`))
	f.Add([]byte(`{"ovpn": ` + jsonLines(testOVPN) + `, "mtu": 1400}`))
	f.Add([]byte(`{"ovpnBase64": "` + base64.StdEncoding.EncodeToString([]byte(testOVPN)) + `"}`))
	f.Add([]byte(`{"ovpn": [null, "x"], "domainStrategy": "forceipv6v4"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		c := new(OpenVPNConfig)
		if json.Unmarshal(data, c) != nil {
			return
		}
		msg, err := c.Build()
		if err != nil {
			return
		}
		if _, err := msg.(*openvpn.Config).ParseOptions(); err != nil {
			t.Fatalf("Build accepted a configuration ParseOptions rejects: %v", err)
		}
	})
}
