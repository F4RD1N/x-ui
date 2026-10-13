package service

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/logger"

	"github.com/op/go-logging"
)

// The package logs at ERROR under test, into a folder of its own: InitLogger
// truncates the log file, which by default is the installed panel's.
func TestMain(m *testing.M) {
	dir, _ := os.MkdirTemp("", "xui-service-log-")
	os.Setenv("XUI_LOG_FOLDER", dir)
	logger.InitLogger(logging.ERROR)
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func TestIsCertURL(t *testing.T) {
	cases := map[string]bool{
		"https://example.com/fullchain.pem": true,
		"http://example.com/cert.crt":       true,
		"  https://example.com/a.pem  ":     true,
		"/etc/ssl/cert.pem":                 false,
		"":                                  false,
		"ftp://example.com/cert.pem":        false,
		"cert.pem":                          false,
	}
	for value, want := range cases {
		if got := IsCertURL(value); got != want {
			t.Errorf("IsCertURL(%q) = %v, want %v", value, got, want)
		}
	}
}

// A path is left exactly as it was, so an inbound saved with real paths is
// untouched by this feature.
func TestDownloadCertLeavesPathsAlone(t *testing.T) {
	const p = "/etc/ssl/private/server.key"
	got, err := DownloadCert(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != p {
		t.Errorf("DownloadCert(%q) = %q, want it unchanged", p, got)
	}
}

func TestDownloadCertSavesFile(t *testing.T) {
	const body = "-----BEGIN CERTIFICATE-----\nnot a real certificate\n-----END CERTIFICATE-----\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer srv.Close()

	dir := t.TempDir()
	t.Setenv("XUI_DB_FOLDER", dir)

	got, err := DownloadCert(srv.URL + "/fullchain.pem")
	if err != nil {
		t.Fatalf("DownloadCert: %v", err)
	}
	if !strings.HasPrefix(got, filepath.Join(dir, "certs")) {
		t.Errorf("saved to %q, want it under %q", got, filepath.Join(dir, "certs"))
	}
	if !strings.Contains(filepath.Base(got), "fullchain") {
		t.Errorf("saved as %q, want the URL's basename kept", filepath.Base(got))
	}
	data, err := os.ReadFile(got)
	if err != nil {
		t.Fatalf("reading saved file: %v", err)
	}
	if string(data) != body {
		t.Errorf("saved contents = %q, want %q", data, body)
	}

	// The same URL must land on the same file rather than accumulating copies.
	again, err := DownloadCert(srv.URL + "/fullchain.pem")
	if err != nil {
		t.Fatalf("second DownloadCert: %v", err)
	}
	if again != got {
		t.Errorf("second download went to %q, want the same file %q", again, got)
	}
}

// A server that answers with an error must not overwrite anything.
func TestDownloadCertRefusesBadResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer srv.Close()
	t.Setenv("XUI_DB_FOLDER", t.TempDir())

	if _, err := DownloadCert(srv.URL + "/cert.pem"); err == nil {
		t.Error("expected an error for a 404 response")
	}
}

// Stream settings carrying certificate URLs come back with local paths; the
// rest of the document is left alone.
func TestMaterializeStreamCerts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("material for " + r.URL.Path))
	}))
	defer srv.Close()
	dir := t.TempDir()
	t.Setenv("XUI_DB_FOLDER", dir)

	in := `{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com","certificates":[{"certificateFile":"` +
		srv.URL + `/a.crt","keyFile":"` + srv.URL + `/a.key"}]}}`

	out, err := MaterializeStreamCerts(in)
	if err != nil {
		t.Fatalf("MaterializeStreamCerts: %v", err)
	}
	if strings.Contains(out, srv.URL) {
		t.Errorf("output still holds a URL: %s", out)
	}
	if !strings.Contains(out, filepath.Join(dir, "certs")) {
		t.Errorf("output does not point at the download folder: %s", out)
	}
	if !strings.Contains(out, "example.com") {
		t.Errorf("unrelated settings were lost: %s", out)
	}
}

// Settings with no certificate URL must come back byte-identical, so saving an
// ordinary inbound does not rewrite its stream settings.
func TestMaterializeStreamCertsLeavesPlainSettings(t *testing.T) {
	in := `{"network":"ws","wsSettings":{"path":"/http-is-in-this-path"}}`
	out, err := MaterializeStreamCerts(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != in {
		t.Errorf("settings were rewritten:\n got %s\nwant %s", out, in)
	}
}

// A template that parses but names no outbound would start the core and then
// route nothing, which is the failure the plain unmarshal check cannot see.
// One without the API and stats the panel runs every core through would leave
// one core up, the rest failing on its API port, and no traffic counted.
func TestCheckXrayTemplateUsable(t *testing.T) {
	s := &XraySettingService{}

	const (
		api      = `"api":{"tag":"api","services":["HandlerService","LoggerService","StatsService"]}`
		inbound  = `"inbounds":[{"tag":"api","listen":"127.0.0.1","port":62789,"protocol":"tunnel","settings":{"address":"127.0.0.1"}}]`
		out      = `"outbounds":[{"protocol":"freedom","tag":"direct"}]`
		routing  = `"routing":{"rules":[{"type":"field","inboundTag":["api"],"outboundTag":"api"}]}`
		stats    = `"stats":{}`
		policy   = `"policy":{"levels":{"0":{"statsUserDownlink":true,"statsUserUplink":true}}}`
		template = `{"log":{"loglevel":"warning"},` + api + `,` + inbound + `,` + out + `,` + routing + `,` + stats + `,` + policy + `}`
	)
	without := func(part string) string { return strings.Replace(template, part+`,`, ``, 1) }

	refused := map[string]string{
		"an error page that happens to be JSON": `{"hello":"world"}`,
		"an empty object":                       `{}`,
		"outbounds present but empty":           `{"outbounds":[]}`,
		"only outbounds":                        `{"log":{"loglevel":"warning"},"outbounds":[{"protocol":"freedom","tag":"direct"}]}`,
		"no api section":                        without(api),
		"no api inbound":                        without(inbound),
		"no api route":                          without(routing),
		"no stats":                              without(stats),
		"no user stats":                         strings.Replace(template, policy, `"policy":{}`, 1),
		"api.listen":                            strings.Replace(template, `"tag":"api","services"`, `"tag":"api","listen":"127.0.0.1:10085","services"`, 1),
		"no StatsService":                       strings.Replace(template, `"LoggerService","StatsService"`, `"LoggerService"`, 1),
	}
	for name, cfg := range refused {
		if err := s.CheckXrayTemplateUsable(cfg); err == nil {
			t.Errorf("%s was accepted: %s", name, cfg)
		}
	}

	if err := s.CheckXrayTemplateUsable(template); err != nil {
		t.Errorf("a usable template was refused: %v", err)
	}
	if err := s.CheckXrayTemplateUsable(xrayTemplateConfig); err != nil {
		t.Errorf("the default template was refused: %v", err)
	}

	if err := s.CheckXrayTemplateUsable(`{not json`); err == nil {
		t.Error("invalid JSON was accepted")
	}
}
