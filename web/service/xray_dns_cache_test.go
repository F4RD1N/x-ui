package service

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/util/json_util"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

// Tests never see this machine's own DNS cache.
func init() {
	dnsCacheState = filepath.Join(os.TempDir(), "x-ui-test-no-dns-cache")
}

// stubDNSCache makes the cache on (its state there, answering) or off.
func stubDNSCache(t *testing.T, state, answers bool) {
	t.Helper()
	oldState, oldProbe, oldTries := dnsCacheState, dnsCacheProbe, dnsCacheTries
	dnsCacheState = filepath.Join(t.TempDir(), "dns")
	if state {
		if err := os.Mkdir(dnsCacheState, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	dnsCacheProbe = func() bool { return answers }
	dnsCacheTries = 1
	t.Cleanup(func() { dnsCacheState, dnsCacheProbe, dnsCacheTries = oldState, oldProbe, oldTries })
}

func dnsCacheConfig(routing, outbounds string) *xray.Config {
	return &xray.Config{RouterConfig: json_util.RawMessage(routing), OutboundConfigs: json_util.RawMessage(outbounds)}
}

func ruleTags(t *testing.T, cfg *xray.Config) []string {
	t.Helper()
	var r struct {
		Rules []map[string]any `json:"rules"`
	}
	if err := json.Unmarshal(cfg.RouterConfig, &r); err != nil {
		t.Fatalf("routing: %v: %s", err, cfg.RouterConfig)
	}
	var tags []string
	for _, rule := range r.Rules {
		tag, _ := rule["ruleTag"].(string)
		if tag == "" {
			tag, _ = rule["outboundTag"].(string)
		}
		tags = append(tags, tag)
	}
	return tags
}

func TestWithDNSCache(t *testing.T) {
	stubDNSCache(t, true, true)
	cfg := dnsCacheConfig(
		`{"domainStrategy":"AsIs","rules":[{"type":"field","inboundTag":["api"],"outboundTag":"api"},{"type":"field","ip":["geoip:private"],"outboundTag":"blocked"},{"type":"field","port":"53","network":"udp","outboundTag":"direct"}]}`,
		`[{"tag":"direct","protocol":"freedom","streamSettings":{"sockopt":{"mark":4242}}},{"tag":"blocked","protocol":"blackhole"}]`)
	withDNSCache(cfg)
	if got := strings.Join(ruleTags(t, cfg), ","); got != "api,xui-dns-cache,blocked,direct" {
		t.Errorf("rules: %s", got)
	}
	if !strings.Contains(string(cfg.RouterConfig), `"domainStrategy":"AsIs"`) {
		t.Errorf("routing lost its settings: %s", cfg.RouterConfig)
	}
	var obs []map[string]any
	if err := json.Unmarshal(cfg.OutboundConfigs, &obs); err != nil || len(obs) != 3 {
		t.Fatalf("outbounds: %v %s", err, cfg.OutboundConfigs)
	}
	if obs[0]["tag"] != "direct" {
		t.Errorf("the first outbound (the default) changed: %v", obs[0])
	}
	last := obs[2]
	settings, _ := last["settings"].(map[string]any)
	if last["tag"] != dnsCacheTag || last["protocol"] != "freedom" || settings["redirect"] != "127.0.0.1:53" {
		t.Errorf("cache outbound: %v", last)
	}
	// It is not marked: the direct guard lets it reach the loopback.
	marked := string(withDirectMark(cfg.OutboundConfigs))
	if strings.Count(marked, "4242") != 1 {
		t.Errorf("the cache outbound got the direct mark: %s", marked)
	}
	// Built again from its own output, nothing is added twice.
	before := string(cfg.RouterConfig) + string(cfg.OutboundConfigs)
	withDNSCache(cfg)
	if string(cfg.RouterConfig)+string(cfg.OutboundConfigs) != before {
		t.Errorf("added twice: %s %s", cfg.RouterConfig, cfg.OutboundConfigs)
	}
}

func TestWithDNSCacheNoRouting(t *testing.T) {
	stubDNSCache(t, true, true)
	for _, routing := range []string{``, `null`, `{}`, `{"rules":null}`} {
		cfg := dnsCacheConfig(routing, `[{"tag":"direct","protocol":"freedom"}]`)
		withDNSCache(cfg)
		if got := strings.Join(ruleTags(t, cfg), ","); got != "xui-dns-cache" {
			t.Errorf("routing %q: rules: %s", routing, got)
		}
	}
	cfg := dnsCacheConfig(``, `[{"tag":"direct","protocol":"freedom"}]`)
	cfg = dnsCacheConfig(`{"rules":[{"type":"field","inboundTag":"api","outboundTag":"api"}]}`, `[{"tag":"direct","protocol":"freedom"}]`)
	withDNSCache(cfg)
	if got := strings.Join(ruleTags(t, cfg), ","); got != "api,xui-dns-cache" {
		t.Errorf("rules after an api rule given as a string: %s", got)
	}
}

func TestWithDNSCacheOff(t *testing.T) {
	routing := `{"rules":[{"type":"field","port":"53","outboundTag":"direct"}]}`
	outbounds := `[{"tag":"direct","protocol":"freedom"}]`
	for _, c := range []struct {
		name           string
		state, answers bool
	}{
		{"x-ui dns is off", false, true},
		{"the cache does not answer", true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			stubDNSCache(t, c.state, c.answers)
			cfg := dnsCacheConfig(routing, outbounds)
			withDNSCache(cfg)
			if string(cfg.RouterConfig) != routing || string(cfg.OutboundConfigs) != outbounds {
				t.Errorf("changed: %s %s", cfg.RouterConfig, cfg.OutboundConfigs)
			}
		})
	}
	// Copied from a running config while the cache was on, then the cache
	// went off: the cache's outbound and rule are taken out.
	stubDNSCache(t, false, false)
	cfg := dnsCacheConfig(`{"rules":[{"type":"field","ruleTag":"xui-dns-cache","port":"53","outboundTag":"xui-dns-cache"},{"type":"field","port":"53","outboundTag":"direct"}]}`,
		`[{"tag":"direct","protocol":"freedom"},{"tag":"xui-dns-cache","protocol":"freedom","settings":{"redirect":"127.0.0.1:53"}}]`)
	withDNSCache(cfg)
	if strings.Contains(string(cfg.RouterConfig)+string(cfg.OutboundConfigs), dnsCacheTag) || !strings.Contains(string(cfg.RouterConfig), `"outboundTag":"direct"`) {
		t.Errorf("not taken out: %s %s", cfg.RouterConfig, cfg.OutboundConfigs)
	}
	// A template without outbounds, or one that is not JSON, is left alone.
	stubDNSCache(t, true, true)
	for _, cfg := range []*xray.Config{dnsCacheConfig(routing, ``), dnsCacheConfig(routing, `[]`), dnsCacheConfig(routing, `null`), dnsCacheConfig(`{bad`, outbounds)} {
		r, o := string(cfg.RouterConfig), string(cfg.OutboundConfigs)
		withDNSCache(cfg)
		if string(cfg.RouterConfig) != r || string(cfg.OutboundConfigs) != o {
			t.Errorf("changed: %s %s", cfg.RouterConfig, cfg.OutboundConfigs)
		}
	}
}

// The probe takes any DNS answer and nothing else.
func TestProbeDNSCache(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer pc.Close()
	answer := true
	go func() {
		b := make([]byte, 512)
		for {
			n, a, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			if answer {
				b[2] |= 0x80 // a response
				b[3] = 0x02  // SERVFAIL counts
			} else {
				b[0] ^= 0xff // not the query's ID
			}
			pc.WriteTo(b[:n], a)
		}
	}()
	if !probeDNS(pc.LocalAddr().String()) {
		t.Error("an answer was not taken")
	}
	answer = false
	if probeDNS(pc.LocalAddr().String()) {
		t.Error("a wrong ID was taken")
	}
}

// The config the core is built from sends DNS to the cache when it is on.
func TestXrayConfigSendsDNSToCache(t *testing.T) {
	stubMarkProbe(t, true)
	stubDNSCache(t, true, true)
	if err := database.InitDB(filepath.Join(t.TempDir(), "x-ui.db")); err != nil {
		t.Fatal(err)
	}
	defer database.CloseDB()
	cfg, err := (&XrayService{}).GetXrayConfigFor(`{"routing":{"rules":[{"type":"field","inboundTag":["api"],"outboundTag":"api"}]},"outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"blocked","protocol":"blackhole"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(ruleTags(t, cfg), ","); got != "api,xui-dns-cache" {
		t.Errorf("rules: %s", got)
	}
	if !strings.Contains(string(cfg.OutboundConfigs), `"redirect":"127.0.0.1:53"`) || !strings.Contains(string(cfg.OutboundConfigs), `"mark":4242`) {
		t.Errorf("outbounds: %s", cfg.OutboundConfigs)
	}
}
