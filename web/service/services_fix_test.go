package service

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

// unitDB gives the test a fresh panel database of its own.
func unitDB(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XUI_DB_FOLDER", dir)
	t.Setenv("XUI_BIN_FOLDER", dir)
	if err := database.InitDB(filepath.Join(dir, "x-ui.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.CloseDB() })
}

// Moving an inbound to another address moves its sub-inbounds with it, so
// their ports are checked there too, and a unix socket is refused.
func TestUpdateInboundListenChecksSubInboundPorts(t *testing.T) {
	unitDB(t)
	var is InboundService
	base := freeRun(t, 2)
	mk := func(listen string, port int) *model.Inbound {
		in := vlessInbound(t, "", 0)
		in.Listen, in.Port, in.Tag = listen, port, fmt.Sprintf("inbound-%s:%d", listen, port)
		in, _, err := is.AddInbound(in)
		if err != nil {
			t.Fatal(err)
		}
		return in
	}
	a := mk("127.0.0.2", base)
	mk("127.0.0.3", base+1)
	subs := fmt.Sprintf(`[{"port":%d,"instance":"xray-9","cores":0,"enable":true}]`, base+1)
	if err := database.GetDB().Model(model.Inbound{}).Where("id = ?", a.Id).Update("sub_inbounds", subs).Error; err != nil {
		t.Fatal(err)
	}
	update := func(listen string) error {
		in, err := is.GetInbound(a.Id)
		if err != nil {
			t.Fatal(err)
		}
		in.Listen = listen
		_, _, err = is.UpdateInbound(in)
		return err
	}
	if err := update(""); err == nil || !strings.Contains(err.Error(), fmt.Sprintf("port %d of a sub-inbound", base+1)) {
		t.Fatalf("wildcard listen over another inbound's port of a sub-inbound: err=%v", err)
	}
	if err := update("/run/xui-test.sock"); err == nil || !strings.Contains(err.Error(), "unix socket") {
		t.Fatalf("unix socket listen with sub-inbounds: err=%v", err)
	}
	if err := update("127.0.0.4"); err != nil {
		t.Fatalf("a free address was refused: %v", err)
	}
}

// An inbound on a unix socket gets no sub-inbounds, and rows it already has
// put nothing in any core.
func TestSocketInboundHasNoSubInbounds(t *testing.T) {
	unitDB(t)
	var is InboundService
	in := vlessInbound(t, "", 0)
	in.Listen, in.Tag = "@xui-test", "inbound-@xui-test:"+fmt.Sprint(in.Port)
	in, _, err := is.AddInbound(in)
	if err != nil {
		t.Fatal(err)
	}
	sub := model.SubInbound{Port: freeTCPPort(t), Instance: "xray-2", Enable: true}
	if _, _, err := is.SaveSubInbounds(in.Id, []model.SubInbound{sub}); err == nil || !strings.Contains(err.Error(), "unix socket") {
		t.Fatalf("SaveSubInbounds on a socket inbound: err=%v", err)
	}
	if _, _, err := is.SaveSubInbounds(in.Id, nil); err != nil {
		t.Fatalf("clearing the sub-inbounds of a socket inbound: %v", err)
	}
	plan, err := is.PlanSubInbounds(in.Id, nil, 1, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.Error, "unix socket") {
		t.Fatalf("plan error %q", plan.Error)
	}

	// A row saved before this check runs nowhere.
	b, _ := json.Marshal([]model.SubInbound{sub})
	database.GetDB().Model(model.Inbound{}).Where("id = ?", in.Id).Update("sub_inbounds", string(b))
	var xs XrayService
	full, inbounds, err := xs.buildXrayConfigAndInbounds(xrayTemplateConfig)
	if err != nil {
		t.Fatal(err)
	}
	for _, ic := range full.InboundConfigs {
		if ic.Tag != in.Tag && ic.Tag != "api" {
			t.Errorf("config has %s", ic.Tag)
		}
	}
	if len(inbounds) != 1 {
		t.Errorf("planned %d inbounds, want the socket inbound alone", len(inbounds))
	}
}

// A routing rule naming an inbound covers its sub-inbounds too, in the core
// that runs them; the routing of a core without sub-inbounds is left alone.
func TestSubInboundsFollowRoutingRules(t *testing.T) {
	unitDB(t)
	const template = `{"api":{"tag":"api","services":["HandlerService","StatsService"]},
"inbounds":[{"tag":"api","listen":"127.0.0.1","port":62789,"protocol":"tunnel","settings":{"address":"127.0.0.1"}}],
"outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"warp","protocol":"freedom"}],
"routing":{"domainStrategy":"AsIs","rules":[{"type":"field","inboundTag":["api"],"outboundTag":"api"},{"type":"field","inboundTag":["inbound-44301"],"outboundTag":"warp"},{"type":"field","inboundTag":"inbound-44301","port":12345678901234567890,"outboundTag":"direct"}]},
"stats":{}}`
	in := &model.Inbound{UserId: 1, Enable: true, Remark: "r", Port: 44301, Protocol: model.VLESS, Tag: "inbound-44301",
		XrayInstance:   "xray-1",
		Settings:       `{"clients":[{"id":"6b0e9c1c-2d6f-4c6e-9b8a-000000000001","email":"u1@test","enable":true}],"decryption":"none"}`,
		StreamSettings: `{"network":"tcp","security":"none"}`, Sniffing: `{"enabled":false}`,
		SubInbounds: `[{"port":44302,"instance":"xray-2","cores":0,"enable":true},{"port":44303,"instance":"xray-1","cores":0,"enable":true}]`}
	if err := database.GetDB().Create(in).Error; err != nil {
		t.Fatal(err)
	}
	var xs XrayService
	full, inbounds, err := xs.buildXrayConfigAndInbounds(template)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := buildPlan(full, inbounds, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	type rule struct {
		InboundTag any    `json:"inboundTag"`
		Outbound   string `json:"outboundTag"`
		Port       any    `json:"port"`
	}
	rules := func(name string) []rule {
		var r struct{ Rules []rule }
		if err := json.Unmarshal(plan.configs[name].RouterConfig, &r); err != nil {
			t.Fatal(err)
		}
		return r.Rules
	}
	x1, x2 := rules("xray-1"), rules("xray-2")
	if got := fmt.Sprint(x1[1].InboundTag); got != "[inbound-44301 inbound-44301~sub44303]" {
		t.Errorf("xray-1 warp rule names %s", got)
	}
	if got := fmt.Sprint(x2[1].InboundTag); got != "[inbound-44301 inbound-44301~sub44302]" {
		t.Errorf("xray-2 warp rule names %s", got)
	}
	if got := fmt.Sprint(x2[2].InboundTag); got != "[inbound-44301 inbound-44301~sub44302]" {
		t.Errorf("xray-2 single-tag rule names %s", got)
	}
	if fmt.Sprint(x2[0].InboundTag) != "[api]" {
		t.Errorf("api rule changed: %v", x2[0].InboundTag)
	}
	if !strings.Contains(string(plan.configs["xray-2"].RouterConfig), "12345678901234567890") {
		t.Errorf("a number was rewritten: %s", plan.configs["xray-2"].RouterConfig)
	}

	// No sub-inbound in a core: its routing is the template's, byte for byte.
	full.RouterConfig = []byte(`{"rules":[{"inboundTag":["inbound-1"],"outboundTag":"warp"}]}`)
	if got := withSubInboundTags(full.RouterConfig, []xray.InboundConfig{{Tag: "inbound-44301"}}); string(got) != string(full.RouterConfig) {
		t.Errorf("routing rewritten without a sub-inbound: %s", got)
	}
}

// A template the Xray page stored re-indented is the same config: no core
// restarts for it.
func TestSameRunningIgnoresLayout(t *testing.T) {
	raw := `{"outbounds":[{"tag":"direct","protocol":"freedom"}],"routing":{"rules":[]},"observatory":{"subjectSelector":["a"]}}`
	var indented bytes.Buffer
	json.Indent(&indented, []byte(raw), "", "  ") // as JSON.stringify(obj, null, 2) has it
	a, b := &xray.Config{}, &xray.Config{}
	json.Unmarshal([]byte(raw), a)
	json.Unmarshal(indented.Bytes(), b)
	if !sameRunning(a, b, nil) {
		t.Error("a re-indented template restarts the cores")
	}
	b.RouterConfig = []byte(`{"rules":[{"outboundTag":"direct"}]}`)
	if sameRunning(a, b, nil) {
		t.Error("a changed routing does not restart the cores")
	}
}

// The panel certificate can be given as links: they are fetched before the
// pair is checked, and the local paths are stored.
func TestUpdateAllSettingCertURL(t *testing.T) {
	unitDB(t)
	certPEM, keyPEM := selfSignedPair(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cert.pem":
			w.Write(certPEM)
		case "/key.pem":
			w.Write(keyPEM)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	var ss SettingService
	all, err := ss.GetAllSetting()
	if err != nil {
		t.Fatal(err)
	}
	all.WebCertFile, all.WebKeyFile = srv.URL+"/cert.pem", srv.URL+"/key.pem"
	if err := ss.UpdateAllSetting(all); err != nil {
		t.Fatalf("UpdateAllSetting: %v", err)
	}
	cert, _ := ss.GetCertFile()
	key, _ := ss.GetKeyFile()
	if IsCertURL(cert) || IsCertURL(key) || cert == "" || key == "" {
		t.Errorf("stored %q and %q, want local paths", cert, key)
	}
}

func selfSignedPair(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
}

// The user handed to the core has every field AddUser reads, whatever the
// stored client lacks.
func TestClientAPIUser(t *testing.T) {
	settings := map[string]any{"method": "aes-256-gcm"}
	ss := ClientAPIUser(settings, map[string]any{"email": "s@x", "password": "p", "enable": true})
	if ss["cipher"] != "aes-256-gcm" || ss["password"] != "p" || ss["flow"] != "" || ss["id"] != "" {
		t.Errorf("shadowsocks user %v", ss)
	}
	own := ClientAPIUser(settings, map[string]any{"email": "s@x", "password": "p", "method": "chacha20-ietf-poly1305"})
	if own["cipher"] != "chacha20-ietf-poly1305" {
		t.Errorf("the client's own cipher was not kept: %v", own)
	}
	vl := ClientAPIUser(map[string]any{}, map[string]any{"email": "v@x", "id": "u", "flow": "xtls-rprx-vision-udp443"})
	if vl["flow"] != "xtls-rprx-vision" || vl["auth"] != "" || vl["security"] != "" {
		t.Errorf("vless user %v", vl)
	}
}

func TestNewerVersion(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"2.9.0-dialect.5", "2.9.0-dialect.4", true},
		{"2.9.0-dialect.4", "2.9.0-dialect.5", false},
		{"2.9.0-dialect.4", "2.9.0-dialect.4", false},
		{"2.9.0-dialect.4", "2.9.0-dialect.4-instances", false},
		{"2.10.0", "2.9.9-dialect.9", true},
		{"2.9.0-dialect.1", "2.9.0", true},
		{"2.9.0", "2.9.0-dialect.1", false},
	}
	for _, c := range cases {
		if got := newerVersion(c.a, c.b); got != c.want {
			t.Errorf("newerVersion(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

// The updater fetches the installer into a private directory of its own,
// runs it from there and removes it.
func TestPanelUpdateScript(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	os.MkdirAll(bin, 0o755)
	// curl stand-in: the "installer" it saves reports where it ran from.
	os.WriteFile(filepath.Join(bin, "curl"), []byte("#!/bin/sh\nwhile [ \"$1\" != -o ]; do shift; done\nprintf 'echo \"$XUI_MODE $0\"\\n' > \"$2\"\n"), 0o755)
	tmp := filepath.Join(dir, "tmp")
	os.MkdirAll(tmp, 0o755)
	cmd := exec.Command("/bin/bash", "-c", panelUpdateScript())
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "TMPDIR="+tmp)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	mode, ran, _ := strings.Cut(strings.TrimSpace(string(out)), " ")
	if mode != "update" || !strings.HasPrefix(ran, tmp+"/tmp.") || filepath.Base(ran) != "install.sh" {
		t.Errorf("installer ran as %q", out)
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Errorf("left behind %v", left)
	}
}
