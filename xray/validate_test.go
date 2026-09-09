package xray

import (
	"os"
	"strings"
	"testing"
)

// These run against the installed core, which is what the panel would use.
func requireCore(t *testing.T) {
	t.Helper()
	// The core folder is resolved relative to the working directory, which
	// under test is the package directory; point it at the installed core.
	if os.Getenv("XUI_BIN_FOLDER") == "" {
		t.Setenv("XUI_BIN_FOLDER", "/usr/local/x-ui/bin")
	}
	if _, err := os.Stat(GetBinaryPath()); err != nil {
		t.Skipf("no core binary at %s", GetBinaryPath())
	}
}

func TestTestConfigAcceptsAWorkingConfig(t *testing.T) {
	requireCore(t)
	good := `{
	  "log": {"loglevel": "warning"},
	  "inbounds": [{"listen":"127.0.0.1","port":14321,"protocol":"vless",
	    "settings":{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}],"decryption":"none","dialects":[4,5]},
	    "streamSettings":{"network":"tcp"}}],
	  "outbounds": [{"protocol":"freedom"}]
	}`
	if err := TestConfig(good); err != nil {
		t.Errorf("a working config was refused: %v", err)
	}
}

// The cases that motivated this check: each of these passes a plain JSON
// unmarshal into the config struct, and each would stop the core.
//
// A config that merely parses to nothing (an error page that happens to be
// JSON) is not here: the core accepts it, because a config with no outbounds is
// startable. That one is caught before this, by CheckXrayTemplateUsable.
func TestTestConfigRefusesConfigsThatWouldStopTheCore(t *testing.T) {
	requireCore(t)
	cases := map[string]string{
		"a nonsense protocol": `{"inbounds":[{"listen":"127.0.0.1","port":14322,"protocol":"nonsense-protocol"}],` +
			`"outbounds":[{"protocol":"freedom"}]}`,
		"a vless inbound with no decryption": `{"inbounds":[{"listen":"127.0.0.1","port":14323,"protocol":"vless",` +
			`"settings":{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}}],"outbounds":[{"protocol":"freedom"}]}`,
		"a dialect outside a byte": `{"inbounds":[{"listen":"127.0.0.1","port":14324,"protocol":"vless",` +
			`"settings":{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}],"decryption":"none","dialects":[300]}}],` +
			`"outbounds":[{"protocol":"freedom"}]}`,
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			err := TestConfig(cfg)
			if err == nil {
				t.Errorf("accepted a config that would stop the core: %s", cfg)
				return
			}
			t.Logf("refused, as it should be: %v", err)
		})
	}
}

func TestConfigErrorCarriesTheCoresComplaint(t *testing.T) {
	requireCore(t)
	err := TestConfig(`{"inbounds":[{"listen":"127.0.0.1","port":14325,"protocol":"nonsense-protocol"}],"outbounds":[{"protocol":"freedom"}]}`)
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.HasPrefix(err.Error(), "xray rejected the config: Xray ") {
		t.Errorf("the banner leaked instead of the reason: %v", err)
	}
}
