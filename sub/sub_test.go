package sub

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/op/go-logging"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"

	xconf "github.com/xtls/xray-core/infra/conf"
)

// The logger is a nil pointer until initialised. Its file goes to a
// temporary folder, and nothing below CRITICAL reaches syslog.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "sub-test-log")
	if err != nil {
		panic(err)
	}
	os.Setenv("XUI_LOG_FOLDER", dir)
	logger.InitLogger(logging.CRITICAL)
	code := m.Run()
	logger.CloseLogger()
	os.RemoveAll(dir)
	os.Exit(code)
}

const testUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

const plainStream = `{"network":"tcp","security":"none","tcpSettings":{"header":{"type":"none"}}}`

func vlessSettings(extra string) string {
	return `{"clients":[{"id":"` + testUUID + `","email":"u1","enable":true,"subId":"s1","flow":""}],"decryption":"none"` + extra + `}`
}

func initTestDB(t *testing.T) {
	t.Helper()
	if err := database.InitDB(filepath.Join(t.TempDir(), "x-ui.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.CloseDB() })
}

func link(t *testing.T, s *SubService, in *model.Inbound) (out string) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s link panicked: %v", in.Protocol, r)
		}
	}()
	return s.getLink(in, "u1")
}

// One service answers every request; each one's links carry its own host.
func TestGetSubsUsesEachRequestsHost(t *testing.T) {
	initTestDB(t)
	in := &model.Inbound{UserId: 1, Protocol: model.VLESS, Port: 30443, Enable: true, Tag: "inbound-30443",
		Settings:       `{"clients":[{"id":"` + testUUID + `","email":"u2","enable":true,"subId":"s2"}],"decryption":"none","encryption":"none"}`,
		StreamSettings: plainStream}
	if err := database.GetDB().Create(in).Error; err != nil {
		t.Fatal(err)
	}
	s := NewSubService(false, "-ieo")
	var wg sync.WaitGroup
	var mu sync.Mutex
	wrong := 0
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			host := fmt.Sprintf("h%d.example.com", g)
			for i := 0; i < 25; i++ {
				links, _, _, err := s.GetSubs("s2", host)
				if err != nil {
					t.Error(err)
					return
				}
				for _, l := range links {
					if !strings.Contains(l, "@"+host+":") {
						mu.Lock()
						wrong++
						mu.Unlock()
					}
				}
			}
		}(g)
	}
	wg.Wait()
	if wrong > 0 {
		t.Fatalf("%d links carry another request's host", wrong)
	}
}

// The panel saves mKCP without a header or a seed.
func TestLinksOverKcp(t *testing.T) {
	stream := `{"network":"kcp","security":"none","kcpSettings":{"mtu":1350,"tti":20,"uplinkCapacity":5,"downlinkCapacity":20,"cwndMultiplier":1,"maxSendingWindow":2097152}}`
	s := NewSubService(false, "-ieo")
	s.address = "h.example.com"
	for _, c := range []struct {
		p   model.Protocol
		set string
	}{
		{model.VLESS, vlessSettings(`,"encryption":"none"`)},
		{model.Trojan, `{"clients":[{"password":"pw","email":"u1","enable":true,"subId":"s1"}]}`},
		{model.Shadowsocks, `{"method":"aes-128-gcm","password":"x","clients":[{"password":"pw","method":"","email":"u1","enable":true,"subId":"s1"}]}`},
		{model.VMESS, `{"clients":[{"id":"` + testUUID + `","email":"u1","enable":true,"subId":"s1"}]}`},
	} {
		out := link(t, s, &model.Inbound{Protocol: c.p, Port: 443, Settings: c.set, StreamSettings: stream})
		if out == "" {
			t.Errorf("%s: no link", c.p)
		}
		if strings.Contains(out, "headerType=") || strings.Contains(out, "seed=") {
			t.Errorf("%s: empty kcp header or seed in %s", c.p, out)
		}
	}
}

func jsonStreams(t *testing.T, js *SubJsonService, in *model.Inbound) []map[string]any {
	t.Helper()
	cl := model.Client{ID: testUUID, Email: "u1", Enable: true, SubID: "s1"}
	var out []map[string]any
	for _, c := range js.getConfig(in, cl, "h.example.com") {
		var m map[string]any
		if err := json.Unmarshal(c, &m); err != nil {
			t.Fatal(err)
		}
		ob := m["outbounds"].([]any)[0].(map[string]any)
		out = append(out, ob)
	}
	return out
}

// forceTls of one external proxy does not carry over into the next.
func TestJsonExternalProxiesKeepTheirOwnSecurity(t *testing.T) {
	js := NewSubJsonService("", "", "", "", NewSubService(false, "-ieo"))
	tlsIn := &model.Inbound{Protocol: model.VLESS, Port: 443, Settings: vlessSettings(`,"encryption":"none"`), StreamSettings: `{"network":"tcp","security":"tls",
		"tlsSettings":{"serverName":"real.example.com","alpn":["h2"],"settings":{"fingerprint":"chrome"}},"tcpSettings":{"header":{"type":"none"}},
		"externalProxy":[{"forceTls":"none","dest":"plain.example.com","port":80,"remark":"plain"},{"forceTls":"same","dest":"cdn.example.com","port":443,"remark":"same"}]}`}
	obs := jsonStreams(t, js, tlsIn)
	if len(obs) != 2 {
		t.Fatalf("%d configs, want 2", len(obs))
	}
	if ss := obs[0]["streamSettings"].(map[string]any); ss["security"] != "none" || ss["tlsSettings"] != nil {
		t.Errorf("forceTls none: %v", ss)
	}
	if ss := obs[1]["streamSettings"].(map[string]any); ss["security"] != "tls" || ss["tlsSettings"] == nil {
		t.Errorf("forceTls same on a TLS inbound lost its TLS: %v", ss)
	}
	if tlsIn.Listen != "" || tlsIn.Port != 443 {
		t.Errorf("the inbound was changed: listen %q port %d", tlsIn.Listen, tlsIn.Port)
	}

	plainIn := &model.Inbound{Protocol: model.VLESS, Port: 80, Settings: vlessSettings(`,"encryption":"none"`), StreamSettings: `{"network":"tcp","security":"none","tcpSettings":{"header":{"type":"none"}},
		"externalProxy":[{"forceTls":"tls","dest":"cdn.example.com","port":443,"remark":"tls"},{"forceTls":"same","dest":"192.0.2.4","port":80,"remark":"same"}]}`}
	obs = jsonStreams(t, js, plainIn)
	if ss := obs[1]["streamSettings"].(map[string]any); ss["security"] != "none" {
		t.Errorf("forceTls same on a plain inbound got security %v", ss["security"])
	}
}

func TestResolveRequestIgnoresXRealIP(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/sub/x", nil)
	c.Request.Host = "sub.example.com:2096"
	c.Request.Header.Set("X-Real-IP", "198.51.100.8")
	_, host, hostWithPort, hostHeader := NewSubService(false, "-ieo").ResolveRequest(c)
	if host != "sub.example.com" || hostWithPort != "sub.example.com:2096" || hostHeader != "sub.example.com" {
		t.Fatalf("host %q, hostWithPort %q, hostHeader %q", host, hostWithPort, hostHeader)
	}
}

func clashProxies(in *model.Inbound, host string) []map[string]any {
	cl := model.Client{ID: testUUID, Email: "u1", Enable: true, SubID: "s1"}
	return NewSubClashService(NewSubService(false, "-ieo")).getProxies(in, cl, host)
}

func TestClashVlessEncryption(t *testing.T) {
	enc := "mlkem768x25519plus.native.0rtt.AAAA"
	ps := clashProxies(&model.Inbound{Protocol: model.VLESS, Port: 443, Remark: "de", Settings: vlessSettings(`,"encryption":"` + enc + `"`), StreamSettings: plainStream}, "h.example.com")
	if len(ps) != 1 || ps[0]["encryption"] != enc || ps[0]["packet-encoding"] != nil {
		t.Errorf("VLESS encryption inbound: %v", ps)
	}
	ps = clashProxies(&model.Inbound{Protocol: model.VLESS, Port: 443, Remark: "de", Settings: vlessSettings(`,"encryption":"none"`), StreamSettings: plainStream}, "h.example.com")
	if len(ps) != 1 || ps[0]["encryption"] != nil || ps[0]["packet-encoding"] != nil {
		t.Errorf("plain VLESS inbound: %v", ps)
	}
}

// An inbound that turns stock VLESS away gets no Clash proxy, which could
// never connect.
func TestClashSkipsDialectOnlyVless(t *testing.T) {
	if ps := clashProxies(&model.Inbound{Protocol: model.VLESS, Port: 443, Settings: vlessSettings(`,"encryption":"none","dialects":[5]`), StreamSettings: plainStream}, "h.example.com"); len(ps) != 0 {
		t.Errorf("dialects [5]: %v", ps)
	}
	if ps := clashProxies(&model.Inbound{Protocol: model.VLESS, Port: 443, Settings: vlessSettings(`,"encryption":"none","dialects":[5,0]`), StreamSettings: plainStream}, "h.example.com"); len(ps) != 1 {
		t.Errorf("dialects [5,0]: %v", ps)
	}
}

func TestClashNamesAreUnique(t *testing.T) {
	initTestDB(t)
	in := &model.Inbound{UserId: 1, Protocol: model.VLESS, Port: 30443, Enable: true, Tag: "inbound-30443", Remark: "de",
		Settings: vlessSettings(`,"encryption":"none"`),
		StreamSettings: `{"network":"tcp","security":"none","tcpSettings":{"header":{"type":"none"}},
			"externalProxy":[{"forceTls":"same","dest":"cdn.example.com","port":443,"remark":""},{"forceTls":"same","dest":"192.0.2.4","port":443,"remark":""}]}`}
	if err := database.GetDB().Create(in).Error; err != nil {
		t.Fatal(err)
	}
	out, _, err := NewSubClashService(NewSubService(false, "-ieo")).GetClash("s1", "h.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "name: de-u1\n") || !strings.Contains(out, "name: de-u1 2\n") {
		t.Fatalf("names not made unique:\n%s", out)
	}
}

// An inbound bound to one address is reached there by every format.
func TestJsonAndClashUseListenAddress(t *testing.T) {
	in := &model.Inbound{Protocol: model.VLESS, Port: 30443, Listen: "10.9.8.7", Remark: "de", Settings: vlessSettings(`,"encryption":"none"`), StreamSettings: plainStream}
	s := NewSubService(false, "-ieo")
	s.address = "sub.example.com"
	if l := link(t, s, in); !strings.Contains(l, "@10.9.8.7:30443") {
		t.Errorf("link %s", l)
	}
	if ps := clashProxies(in, "sub.example.com"); len(ps) != 1 || ps[0]["server"] != "10.9.8.7" {
		t.Errorf("clash %v", ps)
	}
	obs := jsonStreams(t, NewSubJsonService("", "", "", "", s), in)
	vnext := obs[0]["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
	if vnext["address"] != "10.9.8.7" {
		t.Errorf("json address %v", vnext["address"])
	}
}

func TestLinkCredentialsAreEscaped(t *testing.T) {
	s := NewSubService(false, "-ieo")
	s.address = "h.example.com"
	for _, pw := range []string{"p%w", "p#w", "p?w", "p/w", "p@w", "p%41w", "p:w"} {
		in := &model.Inbound{Protocol: model.Trojan, Port: 443, Settings: `{"clients":[{"password":"` + pw + `","email":"u1","enable":true,"subId":"s1"}]}`, StreamSettings: plainStream}
		u, err := url.Parse(link(t, s, in))
		if err != nil {
			t.Errorf("trojan %q: %v", pw, err)
			continue
		}
		if u.User.Username() != pw || u.Host != "h.example.com:443" {
			t.Errorf("trojan %q: user %q host %q", pw, u.User.Username(), u.Host)
		}
	}
	in := &model.Inbound{Protocol: model.Hysteria, Port: 443, Settings: `{"version":2,"clients":[{"auth":"a%b","email":"u1","enable":true,"subId":"s1"}]}`,
		StreamSettings: `{"network":"hysteria","security":"tls","tlsSettings":{"serverName":"x"}}`}
	u, err := url.Parse(link(t, s, in))
	if err != nil || u.User.Username() != "a%b" {
		t.Errorf("hysteria: %v %v", u, err)
	}
}

func TestLinksBracketIPv6(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/sub/x", nil)
	c.Request.Host = "[2001:db8::1]:2096"
	s := NewSubService(false, "-ieo")
	_, s.address, _, _ = s.ResolveRequest(c)
	ss := `{"method":"aes-128-gcm","password":"x","clients":[{"password":"pw","method":"","email":"u1","enable":true,"subId":"s1"}]}`
	for _, in := range []*model.Inbound{
		{Protocol: model.VLESS, Port: 443, Settings: vlessSettings(`,"encryption":"none"`), StreamSettings: plainStream},
		{Protocol: model.Shadowsocks, Port: 443, Settings: ss, StreamSettings: plainStream},
	} {
		if l := link(t, s, in); !strings.Contains(l, "@[2001:db8::1]:443") {
			t.Errorf("%s: %s", in.Protocol, l)
		}
	}
	in := &model.Inbound{Protocol: model.VLESS, Port: 443, Listen: "2001:db8::5", Settings: vlessSettings(`,"encryption":"none"`), StreamSettings: plainStream}
	if l := link(t, s, in); !strings.Contains(l, "@[2001:db8::5]:443") {
		t.Errorf("listen: %s", l)
	}
}

// Inbounds saved before VLESS encryption existed have no such key; the core
// refuses a user without it.
func TestJsonVlessWithoutEncryptionBuilds(t *testing.T) {
	js := NewSubJsonService("", "", "", "", NewSubService(false, "-ieo"))
	for _, set := range []string{vlessSettings(""), vlessSettings(`,"encryption":"none"`), vlessSettings(`,"encryption":"none","dialects":[5]`)} {
		in := &model.Inbound{Protocol: model.VLESS, Port: 443, Settings: set, StreamSettings: plainStream}
		ob, _ := json.Marshal(jsonStreams(t, js, in)[0])
		var oc xconf.OutboundDetourConfig
		if err := json.Unmarshal(ob, &oc); err != nil {
			t.Fatal(err)
		}
		if _, err := oc.Build(); err != nil {
			t.Errorf("%s: %v", set, err)
		}
	}
}

// Paths that clash make gin panic while the routes are set up; Start has to
// get an error instead.
func TestBuildRouterReportsClashingPaths(t *testing.T) {
	initTestDB(t)
	db := database.GetDB()
	for k, v := range map[string]string{"subPath": "/sub/", "subJsonPath": "/sub/", "subJsonEnable": "true"} {
		if err := db.Create(&model.Setting{Key: k, Value: v}).Error; err != nil {
			t.Fatal(err)
		}
	}
	if _, err := NewServer().buildRouter(); err == nil {
		t.Fatal("no error for the JSON path equal to the subscription path")
	}
}
