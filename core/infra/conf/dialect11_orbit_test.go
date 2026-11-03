//go:build !without_native_protocols

package conf

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xtls/xray-core/proxy/orbit"
	"google.golang.org/protobuf/proto"
)

func orbitTestKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "vck1_" + base64.RawURLEncoding.EncodeToString(b)
}

func buildOrbit(raw string) (*orbit.Config, error) {
	c, err := outboundConfigLoader.LoadWithID([]byte(raw), "orbit")
	if err != nil {
		return nil, err
	}
	m, err := c.(interface{ Build() (proto.Message, error) }).Build()
	if err != nil {
		return nil, err
	}
	return m.(*orbit.Config), nil
}

func TestOrbitConfigBuilds(t *testing.T) {
	key := orbitTestKey(t)
	c, err := buildOrbit(`{"address":"203.0.113.7","port":8443,"key":"` + key + `","transport":"tcp"}`)
	if err != nil || c.Address != "203.0.113.7" || c.Port != 8443 || c.Key != key || c.Transport != "tcp" {
		t.Fatal(c, err)
	}
	c, err = buildOrbit(`{"address":"chatgpt.com","port":443,"key":"` + key + `","transport":"wss","host":"cdn.example.com","path":"/core","browser":true,"fingerprint":"chrome"}`)
	if err != nil || c.Host != "cdn.example.com" || c.Path != "/core" || c.Peer != "cdn.example.com" || c.Fingerprint != "chrome" || c.Browser != "" {
		t.Fatal(c, err)
	}
	c, err = buildOrbit(`{"address":"chatgpt.com","port":80,"key":"` + key + `","transport":"WS","host":"cdn.example.com","peer":"178.105.9.151",
		"ua":"Agent/1","headers":{"x-test":"1"},"browser":false,"handshakeTimeout":20,"resolver":"8.8.8.8:53"}`)
	if err != nil || c.Transport != "ws" || c.Path != "/core" || c.Peer != "178.105.9.151" || c.UserAgent != "Agent/1" ||
		c.Headers["X-Test"] != "1" || c.Browser != "off" || c.HandshakeTimeout != 20 || c.Resolver != "8.8.8.8:53" {
		t.Fatal(c, err)
	}
	c, err = buildOrbit(`{"link":"orbit://chatgpt.com:443@` + key + `&transport=wss&host=cdn.multi2fun.com&path=%2Fcore#CDN%20WSS","handshakeTimeout":5}`)
	if err != nil || c.Address != "chatgpt.com" || c.Port != 443 || c.Transport != "wss" || c.Host != "cdn.multi2fun.com" || c.HandshakeTimeout != 5 {
		t.Fatal(c, err)
	}
	c, err = buildOrbit(`{"link":"orbit://[2001:db8::5]:8443@` + key + `&transport=quic"}`)
	if err != nil || c.Address != "2001:db8::5" || c.Transport != "quic" {
		t.Fatal(c, err)
	}
}

func TestOrbitConfigErrorsNameTheField(t *testing.T) {
	key := orbitTestKey(t)
	for _, tc := range []struct{ json, field string }{
		{`{"port":8443,"key":"` + key + `","transport":"tcp"}`, `"address"`},
		{`{"address":"203.0.113.7","key":"` + key + `","transport":"tcp"}`, `"port"`},
		{`{"address":"203.0.113.7","port":8443,"transport":"tcp"}`, `"key"`},
		{`{"address":"203.0.113.7","port":8443,"key":"vck1_secretbutbroken","transport":"tcp"}`, `"key"`},
		{`{"address":"203.0.113.7","port":8443,"key":"` + key + `"}`, `"transport"`},
		{`{"address":"203.0.113.7","port":8443,"key":"` + key + `","transport":"auto"}`, `"transport"`},
		{`{"address":"vpn.example.com","port":8443,"key":"` + key + `","transport":"tcp"}`, `"address"`},
		{`{"address":"203.0.113.7","port":8443,"key":"` + key + `","transport":"tcp","host":"cdn.example.com"}`, `"host"`},
		{`{"address":"a.example","port":443,"key":"` + key + `","transport":"wss"}`, `"host"`},
		{`{"address":"a.example","port":443,"key":"` + key + `","transport":"wss","host":"b.example","path":"/a/../b"}`, `"path"`},
		{`{"address":"a.example","port":80,"key":"` + key + `","transport":"ws","host":"b.example","fingerprint":"chrome"}`, `"fingerprint"`},
		{`{"address":"a.example","port":443,"key":"` + key + `","transport":"wss","host":"b.example","fp":"chrome","fingerprint":"chrome"}`, `"fingerprint"`},
		{`{"address":"a.example","port":443,"key":"` + key + `","transport":"wss","host":"b.example","headers":{"Origin":"x"}}`, `"headers"`},
		{`{"address":"a.example","port":443,"key":"` + key + `","transport":"wss","host":"b.example","browser":"sometimes"}`, `"browser"`},
		{`{"address":"203.0.113.7","port":8443,"key":"` + key + `","transport":"tcp","handshakeTimeout":600}`, `"handshakeTimeout"`},
		{`{"address":"203.0.113.7","port":8443,"key":"` + key + `","transport":"tcp","resolver":"dns.google"}`, `"resolver"`},
		{`{"address":"203.0.113.7","port":8443,"key":"` + key + `","transport":"tcp","fingerPrint2":"x"}`, `"fingerPrint2"`},
		{`{"address":"203.0.113.7","port":"8443","key":"` + key + `","transport":"tcp"}`, `"port"`},
		{`{"link":"orbit://203.0.113.7:8443@` + key + `&transport=tcp","port":8443}`, `"port"`},
		{`{"link":"orbit://203.0.113.7:8443@` + key + `"}`, `"transport"`},
		{`{"link":"orbit://203.0.113.7:8443@` + key + `&transport=tcp","key":"` + key + `"}`, `"key"`},
		{`{"link":"orbit://203.0.113.7:8443?key=` + key + `&transport=tcp"}`, `"link"`},
		{`{"link":"vpncore://203.0.113.7:8443@` + key + `&transport=tcp"}`, `"link"`},
		{`{"link":"vless://x"}`, `"link"`},
	} {
		_, err := buildOrbit(tc.json)
		if err == nil || !strings.Contains(err.Error(), tc.field) {
			t.Errorf("%s: got %v, want an error naming %s", strings.ReplaceAll(tc.json, key, "KEY"), err, tc.field)
			continue
		}
		if strings.Contains(err.Error(), "vck1_") || strings.Contains(err.Error(), "secretbutbroken") {
			t.Errorf("error leaked the key: %v", err)
		}
	}
}

func TestOrbitBuilderPanicIsContained(t *testing.T) {
	if _, e := (*OrbitConfig)(nil).Build(); e == nil || e.Error() != "native outbound internal failure" {
		t.Fatalf("builder panic escaped: %v", e)
	}
}

// The two config forms -- the separate fields and "link" -- are one server:
// for every carrier they build the same protobuf, and the legacy core://
// spelling of the link builds it too.
func TestOrbitJSONAndLinkFormsBuildTheSameConfig(t *testing.T) {
	key := orbitTestKey(t)
	for _, tc := range []struct{ fields, link string }{
		{`{"address":"203.0.113.7","port":8443,"key":"` + key + `","transport":"tcp","handshakeTimeout":8}`,
			`{"link":"orbit://203.0.113.7:8443@` + key + `&transport=tcp#TCP","handshakeTimeout":8}`},
		{`{"address":"203.0.113.7","port":8443,"key":"` + key + `","transport":"quic","resolver":"1.1.1.1:53"}`,
			`{"link":"orbit://203.0.113.7:8443@` + key + `&transport=quic#QUIC","resolver":"1.1.1.1:53"}`},
		{`{"address":"chatgpt.com","port":80,"key":"` + key + `","transport":"ws","host":"cdn.example.com","path":"/core"}`,
			`{"link":"orbit://chatgpt.com:80@` + key + `&transport=ws&host=cdn.example.com&path=%2Fcore#CDN%20WS"}`},
		{`{"address":"chatgpt.com","port":443,"key":"` + key + `","transport":"wss","host":"cdn.example.com","path":"/core","peer":"203.0.113.7","fingerprint":"firefox","userAgent":"Agent/1","headers":{"x-test":"1"},"browser":false}`,
			`{"link":"orbit://chatgpt.com:443@` + key + `&transport=wss&host=cdn.example.com&path=%2Fcore&peer=203.0.113.7&fp=firefox&ua=Agent%2F1&headers=%7B%22x-test%22%3A%221%22%7D&browser=off#CDN%20WSS"}`},
	} {
		byFields, err := buildOrbit(tc.fields)
		if err != nil {
			t.Fatal(err)
		}
		for _, link := range []string{tc.link, strings.Replace(tc.link, "orbit://", "core://", 1)} {
			byLink, err := buildOrbit(link)
			if err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(byFields, byLink) {
				t.Fatalf("%s: the link builds another config than the fields:\n%v\n%v", byFields.Transport, byFields, byLink)
			}
		}
	}
}

func TestOrbitInFullConfig(t *testing.T) {
	key := orbitTestKey(t)
	for _, settings := range []string{
		`{"address":"203.0.113.7","port":8443,"key":"` + key + `","transport":"quic"}`,
		`{"link":"orbit://203.0.113.7:8443@` + key + `&transport=quic#Q"}`,
	} {
		c := &Config{}
		raw := `{"outbounds":[{"tag":"proxy","protocol":"orbit","settings":` + settings + `}]}`
		if err := json.Unmarshal([]byte(raw), c); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Build(); err != nil {
			t.Fatal(err)
		}
	}
}
