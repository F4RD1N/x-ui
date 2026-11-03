package conf_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/openvpn"
)

// testStaticKey is a well-formed OpenVPN static key (bytes 0..255).
func testStaticKey() string {
	raw := make([]byte, 256)
	for i := range raw {
		raw[i] = byte(i)
	}
	h := hex.EncodeToString(raw)
	var b strings.Builder
	b.WriteString("-----BEGIN OpenVPN Static key V1-----\n")
	for i := 0; i < len(h); i += 32 {
		b.WriteString(h[i:i+32] + "\n")
	}
	b.WriteString("-----END OpenVPN Static key V1-----")
	return b.String()
}

// testClientPair is a self-signed client certificate and its PKCS#8 key.
func testClientPair(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	p8, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))),
		strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p8})))
}

func buildOpenVPN(t *testing.T, settings string) (*openvpn.Config, error) {
	t.Helper()
	c := new(OpenVPNConfig)
	if err := json.Unmarshal([]byte(settings), c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	msg, err := c.Build()
	if err != nil {
		return nil, err
	}
	return msg.(*openvpn.Config), nil
}

// The structured form, as the template documents it, becomes the .ovpn text
// the same settings would be written as, and loads.
func TestOpenVPNSettingsStructured(t *testing.T) {
	key := testStaticKey()
	cert, priv := testClientPair(t)
	for _, tc := range []struct {
		name       string
		cert, priv string
	}{
		{"username and password only", "", ""},
		{"certificate too", cert, priv},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := `{
				"server": {"address": "vpn.example.com", "port": 1194, "network": "udp"},
				"auth": {"user": "alice", "pass": "secret"},
				"crypto": {
					"cipher": "AES-256-GCM",
					"dataCiphers": ["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"],
					"authHash": "SHA256"
				},
				"certificates": {
					"ca": ` + jsonString(testCA) + `,
					"cert": ` + jsonString(tc.cert) + `,
					"key": ` + jsonString(tc.priv) + `,
					"tlsCrypt": ` + jsonString(key) + `
				},
				"advanced": {"dev": "tun", "nobind": true, "remoteCertTls": "server", "mtu": 1400}
			}`
			c, err := buildOpenVPN(t, settings)
			if err != nil {
				t.Fatal(err)
			}
			want := "client\ndev tun\nremote vpn.example.com 1194 udp\nnobind\nremote-cert-tls server\n" +
				"cipher AES-256-GCM\ndata-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305\nauth SHA256\n" +
				"auth-user-pass\n<ca>\n" + testCA + "\n</ca>\n"
			if tc.cert != "" {
				want += "<cert>\n" + tc.cert + "\n</cert>\n<key>\n" + tc.priv + "\n</key>\n"
			}
			want += "<tls-crypt>\n" + key + "\n</tls-crypt>\n"
			if c.Ovpn != want {
				t.Fatalf("ovpn text:\n%s\nwant:\n%s", c.Ovpn, want)
			}
			if c.Username != "alice" || c.Password != "secret" || c.Mtu != 1400 || c.DomainStrategy != openvpn.Config_FORCE_IP {
				t.Fatalf("username %q, mtu %d, strategy %v", c.Username, c.Mtu, c.DomainStrategy)
			}
			o, err := c.ParseOptions()
			if err != nil {
				t.Fatal(err)
			}
			if len(o.Remotes) != 1 || o.Remotes[0].Host != "vpn.example.com" || o.Remotes[0].Port != 1194 || o.Remotes[0].Network != "udp" {
				t.Fatalf("remotes %+v", o.Remotes)
			}
			if o.Cipher != "AES-256-GCM" || strings.Join(o.DataCiphers, ":") != "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305" || o.Auth != "SHA256" {
				t.Fatalf("cipher %q, data-ciphers %q, auth %q", o.Cipher, o.DataCiphers, o.Auth)
			}
			if !o.AuthUserPass || len(o.TLSCrypt) == 0 || o.RemoteCertTLS != "server" || len(o.CA) == 0 {
				t.Fatalf("auth-user-pass %v, tls-crypt %d bytes, remote-cert-tls %q", o.AuthUserPass, len(o.TLSCrypt), o.RemoteCertTLS)
			}
			if (len(o.Cert) > 0) != (tc.cert != "") || (len(o.Key) > 0) != (tc.cert != "") {
				t.Fatalf("cert %d bytes, key %d bytes", len(o.Cert), len(o.Key))
			}
		})
	}
}

// The other template: "ovpn" as an array whose entries may hold whole
// multi-line blocks.
func TestOpenVPNSettingsLinesWithBlocks(t *testing.T) {
	key := testStaticKey()
	cert, priv := testClientPair(t)
	lines := []string{
		"client", "dev tun", "proto udp", "remote vpn.example.com 1194", "nobind",
		"remote-cert-tls server", "cipher AES-256-GCM",
		"data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305", "auth SHA256", "auth-user-pass",
		"<ca>\n" + testCA + "\n</ca>",
		"<cert>\n" + cert + "\n</cert>",
		"<key>\n" + priv + "\n</key>",
		"<tls-crypt>\n" + key + "\n</tls-crypt>",
	}
	b, _ := json.Marshal(lines)
	c, err := buildOpenVPN(t, `{"username": "alice", "password": "secret", "mtu": 1400, "domainStrategy": "ForceIP", "ovpn": `+string(b)+`}`)
	if err != nil {
		t.Fatal(err)
	}
	o, err := c.ParseOptions()
	if err != nil {
		t.Fatal(err)
	}
	if len(o.Cert) == 0 || len(o.Key) == 0 || len(o.TLSCrypt) == 0 || !o.AuthUserPass || c.Username != "alice" || c.Mtu != 1400 {
		t.Fatalf("cert %d, key %d, tls-crypt %d, auth-user-pass %v, username %q, mtu %d",
			len(o.Cert), len(o.Key), len(o.TLSCrypt), o.AuthUserPass, c.Username, c.Mtu)
	}
}

func TestOpenVPNSettingsOptionalFields(t *testing.T) {
	key := testStaticKey()
	c, err := buildOpenVPN(t, `{
		"server": {"address": "2001:db8::1", "port": 443, "network": "TCP"},
		"username": "bob", "password": "pw", "domainStrategy": "ForceIPv4",
		"certificates": {"ca": `+jsonString(strings.ReplaceAll(testCA, "\n", "\r\n"))+`, "tlsAuth": `+jsonString(key)+`, "keyDirection": 1}
	}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(c.Ovpn, "remote 2001:db8::1 443 tcp\n") || !strings.Contains(c.Ovpn, "key-direction 1\n") || strings.Contains(c.Ovpn, "\r") {
		t.Fatalf("ovpn text:\n%s", c.Ovpn)
	}
	// Credentials outside "auth" do not add auth-user-pass; the .ovpn
	// meaning is unchanged (the client sends them when the server asks).
	if strings.Contains(c.Ovpn, "auth-user-pass") || c.Username != "bob" {
		t.Fatalf("ovpn text:\n%s", c.Ovpn)
	}
	o, err := c.ParseOptions()
	if err != nil {
		t.Fatal(err)
	}
	if o.Remotes[0].Network != "tcp" || len(o.TLSAuth) == 0 || o.KeyDirection != 1 {
		t.Fatalf("network %q, tls-auth %d bytes, key-direction %d", o.Remotes[0].Network, len(o.TLSAuth), o.KeyDirection)
	}
	// Defaults: udp, and only the directives given.
	c, err = buildOpenVPN(t, `{"server": {"address": "192.0.2.1", "port": 1194}, "certificates": {"ca": `+jsonString(testCA)+`}}`)
	if err != nil {
		t.Fatal(err)
	}
	if c.Ovpn != "client\ndev tun\nremote 192.0.2.1 1194 udp\n<ca>\n"+testCA+"\n</ca>\n" {
		t.Fatalf("ovpn text:\n%s", c.Ovpn)
	}
}

func TestOpenVPNSettingsErrors(t *testing.T) {
	ca := `"certificates": {"ca": ` + jsonString(testCA) + `}`
	server := `"server": {"address": "vpn.example.com", "port": 1194}`
	key := jsonString(testStaticKey())
	for _, tc := range []struct{ name, input, want string }{
		{"no address", `{"server": {"port": 1194}, ` + ca + `}`, "server.address"},
		{"no server", `{` + ca + `}`, "server.address"},
		{"no port", `{"server": {"address": "vpn.example.com"}, ` + ca + `}`, "server.port"},
		{"bad network", `{"server": {"address": "a", "port": 1, "network": "quic"}, ` + ca + `}`, "server.network"},
		{"address injects a directive", `{"server": {"address": "a 1\nscript-security 2", "port": 1}, ` + ca + `}`, "server.address"},
		{"cipher injects", `{` + server + `, "crypto": {"cipher": "AES-256-GCM\nup /bin/sh"}, ` + ca + `}`, "crypto.cipher"},
		{"data cipher list in one entry", `{` + server + `, "crypto": {"dataCiphers": ["AES-256-GCM:AES-128-GCM"]}, ` + ca + `}`, "dataCiphers"},
		{"tap", `{` + server + `, "advanced": {"dev": "tap"}, ` + ca + `}`, "only tun"},
		{"pem with tags", `{` + server + `, "certificates": {"ca": ` + jsonString("<ca>\n"+testCA+"\n</ca>") + `}}`, "PEM text only"},
		{"pem closes the block", `{` + server + `, "certificates": {"ca": ` + jsonString(testCA+"\n</ca>\nscript-security 2\n<ca>") + `}}`, "PEM text only"},
		{"two wrappers", `{` + server + `, "certificates": {"ca": ` + jsonString(testCA) + `, "tlsCrypt": ` + key + `, "tlsAuth": ` + key + `}}`, "only one of"},
		{"key direction", `{` + server + `, "certificates": {"ca": ` + jsonString(testCA) + `, "tlsAuth": ` + key + `, "keyDirection": 2}}`, "keyDirection"},
		{"both forms", `{"ovpn": ` + jsonString(testOVPN) + `, ` + server + `}`, "not both"},
		{"both credentials", `{` + server + `, ` + ca + `, "auth": {"user": "a", "pass": "b"}, "username": "c"}`, "not both"},
		{"mtu conflict", `{` + server + `, ` + ca + `, "mtu": 1300, "advanced": {"mtu": 1400}}`, "differ"},
		{"no ca", `{` + server + `}`, "certificate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := buildOpenVPN(t, tc.input)
			if err == nil {
				t.Fatalf("no error, want one mentioning %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "script-security") || strings.Contains(err.Error(), "/bin/sh") {
				t.Fatalf("error echoes the value: %v", err)
			}
		})
	}
}

// The template as a whole outbound, the way an app hands it to the core.
func TestOpenVPNSettingsOutbound(t *testing.T) {
	input := `{
		"tag": "proxy",
		"protocol": "ov",
		"settings": {
			"server": {"address": "vpn.example.com", "port": 1194, "network": "udp"},
			"auth": {"user": "YOUR_USERNAME", "pass": "YOUR_PASSWORD"},
			"crypto": {"cipher": "AES-256-GCM", "dataCiphers": ["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"], "authHash": "SHA256"},
			"certificates": {"ca": ` + jsonString(testCA) + `, "cert": "", "key": "", "tlsCrypt": ` + jsonString(testStaticKey()) + `},
			"advanced": {"dev": "tun", "nobind": true, "remoteCertTls": "server", "mtu": 1400}
		}
	}`
	var ob OutboundDetourConfig
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
	if c := msg.(*openvpn.Config); !strings.HasPrefix(c.Ovpn, "client\ndev tun\nremote vpn.example.com 1194 udp\n") || c.Username != "YOUR_USERNAME" {
		t.Fatalf("ovpn %q, username %q", c.Ovpn, c.Username)
	}
}

func FuzzOpenVPNSettings(f *testing.F) {
	f.Add(`vpn.example.com`, uint16(1194), `udp`, `AES-256-GCM`, `SHA256`, testCA)
	f.Add("a 1\nremote b", uint16(1), `tcp`, "x\n<ca>", ``, "</ca>")
	f.Fuzz(func(t *testing.T, address string, port uint16, network, cipher, auth, ca string) {
		s := map[string]any{
			"server":       map[string]any{"address": address, "port": port, "network": network},
			"crypto":       map[string]any{"cipher": cipher, "authHash": auth},
			"certificates": map[string]any{"ca": ca},
		}
		data, err := json.Marshal(s)
		if err != nil {
			return
		}
		c := new(OpenVPNConfig)
		if json.Unmarshal(data, c) != nil {
			return
		}
		msg, err := c.Build()
		if err != nil {
			return
		}
		o, err := msg.(*openvpn.Config).ParseOptions()
		if err != nil {
			t.Fatalf("Build accepted a configuration ParseOptions rejects: %v", err)
		}
		// A value can never turn into extra remotes.
		if len(o.Remotes) != 1 {
			t.Fatalf("remotes %+v from address %q", o.Remotes, address)
		}
	})
}
