package orbit

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func testRealityKey(t *testing.T) string {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes())
}

// VPN-Core 0.12's REALITY link (REALITY.md), under orbit:// and core://.
func TestParseLinkReality(t *testing.T) {
	key, pbk := testKey(t), testRealityKey(t)
	for _, tc := range []struct {
		link string
		want RealitySettings
	}{
		{"orbit://192.0.2.9:443@" + key + "&transport=tcp&security=reality&sni=cover.example&pbk=" + pbk + "&sid=0123456789abcdef&fp=chrome#Owned%20REALITY",
			RealitySettings{ServerName: "cover.example", PublicKey: pbk, ShortID: "0123456789abcdef", Fingerprint: "chrome"}},
		// sid and fp may be omitted; SNI and short ID are lower-cased.
		{"orbit://192.0.2.9:443@" + key + "&transport=tcp&security=reality&sni=Cover.EXAMPLE&pbk=" + pbk,
			RealitySettings{ServerName: "cover.example", PublicKey: pbk}},
		{"orbit://192.0.2.9:443@" + key + "&pbk=" + pbk + "&sid=ABCD&fp=safari&sni=www.cover-1.example&security=reality&transport=tcp",
			RealitySettings{ServerName: "www.cover-1.example", PublicKey: pbk, ShortID: "abcd", Fingerprint: "safari"}},
		{"orbit://192.0.2.9:443@" + key + "&transport=tcp&security=reality&sni=cover.example&pbk=" + pbk + "&fp=firefox",
			RealitySettings{ServerName: "cover.example", PublicKey: pbk, Fingerprint: "firefox"}},
	} {
		for _, link := range []string{tc.link, "core://" + strings.TrimPrefix(tc.link, "orbit://")} {
			got, err := ParseLink(link)
			if err != nil {
				t.Fatalf("%s: %v", strings.Replace(link, key, "KEY", 1), err)
			}
			if got.Security != "reality" || got.Reality != tc.want || got.Fingerprint != "" || got.Transport != "tcp" || got.Address != "192.0.2.9" || got.Port != 443 {
				t.Fatalf("%s:\n got %+v\nwant %+v", strings.Replace(link, key, "KEY", 1), got.Reality, tc.want)
			}
			c, err := got.Config(0, "")
			if err != nil || c.Reality == nil || c.Reality.ServerName != tc.want.ServerName || c.Reality.PublicKey != pbk ||
				c.Reality.ShortId != tc.want.ShortID || c.Reality.Fingerprint != tc.want.Fingerprint {
				t.Fatalf("config: %v %v", c.GetReality(), err)
			}
			if back := settingsOf(c); back.Security != "reality" || back.Reality != tc.want {
				t.Fatalf("settingsOf lost REALITY: %+v", back.Reality)
			}
		}
	}
	// An ordinary link builds no REALITY message.
	c, err := Settings{Address: "192.0.2.9", Port: 443, Key: key, Transport: "tcp"}.Config(0, "")
	if err != nil || c.Reality != nil || settingsOf(c).Security != "" {
		t.Fatal(c, err)
	}
}

func TestParseLinkRealityRejectsNamingTheField(t *testing.T) {
	key, pbk := testKey(t), testRealityKey(t)
	base := "orbit://192.0.2.9:443@" + key + "&transport=tcp&security=reality&pbk=" + pbk
	r := base + "&sni=cover.example"
	lowOrder := base64.RawURLEncoding.EncodeToString(make([]byte, 32)) // the all-zero point
	for _, tc := range []struct{ link, field string }{
		{base, "reality.serverName"}, // sni is required
		{base + "&sni=192.0.2.1", "reality.serverName"},
		{base + "&sni=123.456", "reality.serverName"}, // no letter
		{base + "&sni=cover.example.", "reality.serverName"},
		{base + "&sni=*.cover.example", "reality.serverName"},
		{base + "&sni=cover.example:443", "reality.serverName"},
		{base + "&sni=c%C3%B6ver.example", "reality.serverName"},
		{base + "&sni=-cover.example", "reality.serverName"},
		{"orbit://192.0.2.9:443@" + key + "&transport=tcp&security=reality&sni=cover.example", "reality.publicKey"},
		{"orbit://192.0.2.9:443@" + key + "&transport=tcp&security=reality&sni=cover.example&pbk=" + pbk[:42], "reality.publicKey"},
		{"orbit://192.0.2.9:443@" + key + "&transport=tcp&security=reality&sni=cover.example&pbk=" + pbk + "=", "reality.publicKey"},
		{"orbit://192.0.2.9:443@" + key + "&transport=tcp&security=reality&sni=cover.example&pbk=" + strings.NewReplacer("-", "+", "_", "/").Replace(pbk) + "+", "reality.publicKey"},
		{"orbit://192.0.2.9:443@" + key + "&transport=tcp&security=reality&sni=cover.example&pbk=" + lowOrder, "reality.publicKey"},
		{r + "&sid=", "link"}, // an explicit empty sid= is refused
		{r + "&sid=abc", "reality.shortId"},
		{r + "&sid=0123456789abcdef00", "reality.shortId"},
		{r + "&sid=zz", "reality.shortId"},
		{r + "&fp=ios", "reality.fingerprint"},
		{r + "&fp=random", "reality.fingerprint"},
		{r + "&fp=unsafe", "reality.fingerprint"},
		{r + "&security=reality", "security"},
		{strings.Replace(r, "security=reality", "security=tls", 1), "security"},
		{strings.Replace(r, "transport=tcp", "transport=quic", 1), "security"},
		{"orbit://cdn.example:443@" + key + "&transport=wss&host=cdn.example&security=reality&sni=cover.example&pbk=" + pbk, "security"},
		{"orbit://192.0.2.9:443@" + key + "&transport=tcp&sni=cover.example&pbk=" + pbk, "security"}, // sni/pbk without security
		{"orbit://192.0.2.9:443@" + key + "&transport=tcp&sid=abcd", "security"},
		{r + "&host=cdn.example", "host"},
		{r + "&path=%2Fcore", "path"},
		{r + "&browser=off", "browser"},
		{"orbit://cover.example:443@" + key + "&transport=tcp&security=reality&sni=cover.example&pbk=" + pbk, "address"},
	} {
		_, err := ParseLink(tc.link)
		var fe *FieldError
		if !errors.As(err, &fe) || fe.Field != tc.field {
			t.Errorf("%s: got %v, want an error about %q", strings.Replace(tc.link, key, "KEY", 1), err, tc.field)
			continue
		}
		if strings.Contains(err.Error(), key) || strings.Contains(err.Error(), "vck1_") || strings.Contains(err.Error(), pbk) {
			t.Errorf("error leaked a key: %v", err)
		}
	}
}

func TestSettingsRealityRules(t *testing.T) {
	key, pbk := testKey(t), testRealityKey(t)
	good := RealitySettings{ServerName: "cover.example", PublicKey: pbk}
	for _, tc := range []struct {
		s     Settings
		field string
	}{
		{Settings{Address: "192.0.2.9", Port: 443, Key: key, Transport: "tcp", Reality: good}, "security"},
		{Settings{Address: "192.0.2.9", Port: 443, Key: key, Transport: "tcp", Security: "REALITY", Reality: good}, "security"},
		{Settings{Address: "192.0.2.9", Port: 443, Key: key, Transport: "quic", Security: "reality", Reality: good}, "security"},
		{Settings{Address: "192.0.2.9", Port: 443, Key: key, Transport: "tcp", Security: "reality", Reality: good, Fingerprint: "chrome"}, "fingerprint"},
		{Settings{Address: "192.0.2.9", Port: 443, Transport: "tcp", Security: "reality", Reality: good}, "key"},
	} {
		_, err := tc.s.Normalize()
		var fe *FieldError
		if !errors.As(err, &fe) || fe.Field != tc.field {
			t.Errorf("got %v, want an error about %q", err, tc.field)
		}
	}
	n, err := Settings{Address: "192.0.2.9", Port: 443, Key: key, Transport: "tcp", Security: "reality",
		Reality: RealitySettings{ServerName: "COVER.example", PublicKey: pbk, ShortID: "ABCDEF"}}.Normalize()
	if err != nil || n.Reality.ServerName != "cover.example" || n.Reality.ShortID != "abcdef" {
		t.Fatal(n.Reality, err)
	}
}

// The builder does what VPN-Core's engine does for a REALITY profile: the
// plan keeps the REALITY settings and the account credentials; it dials
// nothing.
func TestNewDialPlanReality(t *testing.T) {
	key, pbk := testKey(t), testRealityKey(t)
	s, err := ParseLink("orbit://192.0.2.9:443@" + key + "&transport=tcp&security=reality&sni=cover.example&pbk=" + pbk + "&sid=01")
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.Config(0, "")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := newDialPlan(c)
	if err != nil || plan.settings.Security != "reality" || plan.settings.Reality.PublicKey != pbk || plan.settings.Reality.ShortID != "01" || plan.user.UID == "" {
		t.Fatal(err)
	}
}
