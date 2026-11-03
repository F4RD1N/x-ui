package orbit

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/orbit/internal/connectionkey"
)

func testKey(t *testing.T) string {
	t.Helper()
	key, _, err := connectionkey.Generate(sha256.Sum256([]byte("orbit test origin")))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestParseLinkKeyModeExamples(t *testing.T) {
	key := testKey(t)
	for _, tc := range keyModeExamples(key) {
		got, err := ParseLink(tc.link)
		if err != nil {
			t.Fatalf("%s: %v", strings.Replace(tc.link, key, "KEY", 1), err)
		}
		assertSettings(t, tc.link, key, got, tc.want)
	}
}

// VPN-Core's own tools write the same links as core://; that spelling is an
// alias and reads exactly as the orbit:// one.
func TestParseLinkLegacyCoreScheme(t *testing.T) {
	key := testKey(t)
	for _, tc := range keyModeExamples(key) {
		legacy := "core://" + strings.TrimPrefix(tc.link, "orbit://")
		got, err := ParseLink(legacy)
		if err != nil {
			t.Fatalf("%s: %v", strings.Replace(legacy, key, "KEY", 1), err)
		}
		assertSettings(t, legacy, key, got, tc.want)
	}
	if !IsLink("orbit://x") || !IsLink("core://x") || IsLink("Orbit://x") || IsLink(" orbit://x") || IsLink("vless://x") {
		t.Fatal("IsLink")
	}
}

type linkExample struct {
	link string
	want Settings
}

func keyModeExamples(key string) []linkExample {
	return []linkExample{
		{"orbit://192.0.2.1:8443@" + key + "&transport=tcp#My%20Server",
			Settings{Address: "192.0.2.1", Port: 8443, Key: key, Transport: "tcp", Remarks: "My Server"}},
		{"orbit://192.0.2.1:8443@" + key + "&transport=quic#My%20Server%20QUIC",
			Settings{Address: "192.0.2.1", Port: 8443, Key: key, Transport: "quic", Remarks: "My Server QUIC"}},
		{"orbit://chatgpt.com:80@" + key + "&transport=ws&host=cdn.multi2fun.com&path=%2Fcore#CDN%20WS",
			Settings{Address: "chatgpt.com", Port: 80, Key: key, Transport: "ws", Host: "cdn.multi2fun.com", Path: "/core", Peer: "cdn.multi2fun.com", Remarks: "CDN WS"}},
		{"orbit://chatgpt.com:443@" + key + "&transport=wss&host=cdn.multi2fun.com&path=%2Fcore&peer=178.105.9.151&fp=firefox&ua=Test%20Agent&headers=%7B%22x-test%22%3A%221%22%7D&browser=off",
			Settings{Address: "chatgpt.com", Port: 443, Key: key, Transport: "wss", Host: "cdn.multi2fun.com", Path: "/core", Peer: "178.105.9.151",
				Fingerprint: "firefox", UserAgent: "Test Agent", Headers: map[string]string{"X-Test": "1"}, Browser: "off"}},
		{"orbit://[2001:db8::1]:8443@" + key + "&transport=tcp",
			Settings{Address: "2001:db8::1", Port: 8443, Key: key, Transport: "tcp"}},
		{"orbit://Example.COM:443@" + key + "&transport=wss&host=CDN.Example.com&browser=on",
			Settings{Address: "example.com", Port: 443, Key: key, Transport: "wss", Host: "cdn.example.com", Path: "/core", Peer: "cdn.example.com"}},
	}
}

func assertSettings(t *testing.T, link, key string, got, want Settings) {
	t.Helper()
	if got.Address != want.Address || got.Port != want.Port || got.Key != want.Key || got.Transport != want.Transport ||
		got.Host != want.Host || got.Path != want.Path || got.Peer != want.Peer || got.Fingerprint != want.Fingerprint ||
		got.UserAgent != want.UserAgent || got.Browser != want.Browser || got.Remarks != want.Remarks || len(got.Headers) != len(want.Headers) {
		t.Fatalf("%s:\n got %+v\nwant %+v", strings.Replace(link, key, "KEY", 1), redact(got), redact(want))
	}
	for k, v := range want.Headers {
		if got.Headers[k] != v {
			t.Fatalf("header %s", k)
		}
	}
}

func redact(s Settings) Settings { s.Key = "KEY"; return s }

func TestParseLinkRejectsNamingTheField(t *testing.T) {
	key := testKey(t)
	base := "orbit://192.0.2.1:8443@" + key
	ws := "orbit://cdn.example:443@" + key + "&transport=wss&host=cdn.example"
	for _, tc := range []struct{ link, field string }{
		{"http://192.0.2.1:8443@" + key + "&transport=tcp", "link"},
		{"ORBIT://192.0.2.1:8443@" + key + "&transport=tcp", "link"},
		{"orbits://192.0.2.1:8443@" + key + "&transport=tcp", "link"},
		{"orbit:192.0.2.1:8443@" + key + "&transport=tcp", "link"},
		{" orbit://192.0.2.1:8443@" + key + "&transport=tcp", "link"},
		{"orbit://192.0.2.1:8443?" + key + "&transport=tcp", "link"},
		{base, "transport"}, // a missing transport means auto
		{base + "&transport=auto", "transport"},
		{base + "&transport=udp", "transport"},
		{"orbit://192.0.2.1@" + key + "&transport=tcp", "address"},
		{"orbit://192.0.2.1:0@" + key + "&transport=tcp", "port"},
		{"orbit://192.0.2.1:70000@" + key + "&transport=tcp", "port"},
		{"orbit://example.com:8443@" + key + "&transport=tcp", "address"},
		{"orbit://224.0.0.1:8443@" + key + "&transport=quic", "address"},
		{"orbit://[192.0.2.1]:8443@" + key + "&transport=tcp", "address"},
		{"orbit://192.0.2.1:8443@vck1_short&transport=tcp", "key"},
		{base + "&transport=tcp&host=cdn.example", "host"},
		{base + "&transport=tcp&transport=tcp", "transport"},
		{base + "&transport=tcp&bogus=1", "link"},
		{base + "&transport=tcp#a#b", "link"},
		{base + "&transport=tcp#%ZZ", "remarks"},
		{"orbit://cdn.example:443@" + key + "&transport=wss", "host"},
		{ws + "&path=core", "path"},
		{ws + "&path=%2Fa%2F..%2Fb", "path"},
		{ws + "&path=%2Fa%3Fq", "path"},
		{ws + "&fp=opera", "fingerprint"},
		{"orbit://cdn.example:80@" + key + "&transport=ws&host=cdn.example&fp=chrome", "fingerprint"},
		{ws + "&browser=maybe", "browser"},
		{ws + "&headers=%7B%22Host%22%3A%22x%22%7D", "headers"},
		{ws + "&headers=notjson", "headers"},
		{ws + "&ua=%01", "userAgent"},
		{ws + "&peer=bad_name", "peer"},
		{"orbit://cdn.example:443@" + key + "&transport=wss&host=cdn.example:443", "host"},
		{base + " &transport=tcp", "link"},
	} {
		_, err := ParseLink(tc.link)
		var fe *FieldError
		if !errors.As(err, &fe) || fe.Field != tc.field {
			t.Errorf("%s: got %v, want an error about %q", strings.Replace(tc.link, key, "KEY", 1), err, tc.field)
			continue
		}
		if strings.Contains(err.Error(), key) || strings.Contains(err.Error(), "vck1_") {
			t.Errorf("error leaked the key: %v", err)
		}
	}
}

// The #Name after a link is not used by the outbound, but it is checked: an
// app that passes a share link through as-is gets the whole link refused when
// the name breaks the rule NATIVE-PROTOCOLS.md states (at most 256 bytes of
// UTF-8, no control characters, no U+2028/U+2029).
func TestParseLinkRemarksAreCheckedNotIgnored(t *testing.T) {
	key := testKey(t)
	base := "orbit://192.0.2.1:8443@" + key + "&transport=tcp#"
	for _, name := range []string{
		"",
		"CDN%20TLS",
		"%D8%B3%D8%B1%D9%88%D8%B1",    // non-ASCII is fine
		strings.Repeat("a", 256),      // exactly the limit
		strings.Repeat("%C3%A9", 128), // 256 bytes once decoded
	} {
		if _, err := ParseLink(base + name); err != nil {
			t.Errorf("name %.40q: %v", name, err)
		}
	}
	for _, name := range []string{
		strings.Repeat("a", 257),
		strings.Repeat("%C3%A9", 128) + "a",
		"a%0Ab",
		"a%09b",
		"a%7Fb",
		"a%C2%85b",    // C1 control
		"a%E2%80%A8b", // U+2028
		"a%E2%80%A9b", // U+2029
		"a%C3",        // not UTF-8
		"a%2",         // malformed escape
	} {
		_, err := ParseLink(base + name)
		var fe *FieldError
		if !errors.As(err, &fe) || fe.Field != "remarks" {
			t.Errorf("name %.40q: got %v, want an error about \"remarks\"", name, err)
		}
	}
}

func TestSettingsConfig(t *testing.T) {
	key := testKey(t)
	c, err := Settings{Address: "203.0.113.7", Port: 8443, Key: key, Transport: "tcp"}.Config(0, "")
	if err != nil || c.Address != "203.0.113.7" || c.Transport != "tcp" || c.Path != "" {
		t.Fatal(c, err)
	}
	c, err = Settings{Address: "chatgpt.com", Port: 443, Key: key, Transport: "wss", Host: "cdn.example.com"}.Config(10, "9.9.9.9:53")
	if err != nil || c.Path != "/core" || c.Peer != "cdn.example.com" || c.HandshakeTimeout != 10 || c.Resolver != "9.9.9.9:53" {
		t.Fatal(c, err)
	}
	for _, tc := range []struct {
		s        Settings
		timeout  uint32
		resolver string
		field    string
	}{
		{Settings{Address: "203.0.113.7", Port: 8443, Key: key, Transport: "tcp"}, 91, "", "handshakeTimeout"},
		{Settings{Address: "203.0.113.7", Port: 8443, Key: key, Transport: "tcp"}, 0, "dns.google:53", "resolver"},
		{Settings{Address: "203.0.113.7", Port: 8443, Key: key, Transport: "tcp"}, 0, "[2001:db8::1]:53", "resolver"},
		{Settings{Address: "203.0.113.7", Port: 8443, Transport: "tcp"}, 0, "", "key"},
		{Settings{Port: 8443, Key: key, Transport: "tcp"}, 0, "", "address"},
		{Settings{Address: "203.0.113.7", Key: key, Transport: "tcp"}, 0, "", "port"},
		{Settings{Address: "203.0.113.7", Port: 8443, Key: key}, 0, "", "transport"},
		{Settings{Address: "203.0.113.7", Port: 8443, Key: key, Transport: "tcp", Browser: "off"}, 0, "", "browser"},
	} {
		_, err := tc.s.Config(tc.timeout, tc.resolver)
		var fe *FieldError
		if !errors.As(err, &fe) || fe.Field != tc.field {
			t.Errorf("got %v, want an error about %q", err, tc.field)
		}
	}
}

func TestNewNeedsNoNetwork(t *testing.T) {
	// The builder validates and allocates the channel identity; it opens no
	// socket and starts no goroutine until a request arrives.
	key := testKey(t)
	c, err := Settings{Address: "203.0.113.7", Port: 8443, Key: key, Transport: "quic"}.Config(0, "")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := newDialPlan(c)
	if err != nil || plan.timeout.Seconds() != 15 || plan.innerName() != "203.0.113.7" || plan.serverAddress() != "203.0.113.7:8443" {
		t.Fatal(plan, err)
	}
	if plan.user.UID == "" || plan.user.Token == "" || plan.user.DeviceID == "" || plan.channelID == ([16]byte{}) {
		t.Fatal("credentials or channel identity missing")
	}
	c.Key = "vck1_x"
	if _, err = newDialPlan(c); err == nil || strings.Contains(err.Error(), "vck1_") {
		t.Fatal("bad key accepted or echoed:", err)
	}
	ws, _ := Settings{Address: "chatgpt.com", Port: 443, Key: key, Transport: "wss", Host: "cdn.example.com", Peer: "178.105.9.151"}.Config(0, "")
	if plan, err = newDialPlan(ws); err != nil || plan.innerName() != "178.105.9.151" {
		t.Fatal(err)
	}
}

func TestTargetHost(t *testing.T) {
	for in, want := range map[string]string{"203.0.113.7": "203.0.113.7", "2001:db8::1": "2001:db8::1", "Example.com": "Example.com", "::ffff:192.0.2.1": "192.0.2.1"} {
		if got := targetHost(xnet.ParseAddress(in)); got != want {
			t.Errorf("targetHost(%s) = %s, want %s", in, got, want)
		}
	}
}
