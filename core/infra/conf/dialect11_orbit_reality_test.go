//go:build !without_native_protocols

package conf

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
)

func orbitRealityTestKey(t *testing.T) string {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes())
}

// The "reality" object is the JSON form of a link's security=reality&sni=&pbk=
// &sid=&fp=; both build the same message.
func TestOrbitRealityJSONAndLinkFormsBuildTheSameConfig(t *testing.T) {
	key, pbk := orbitTestKey(t), orbitRealityTestKey(t)
	for _, tc := range []struct{ fields, link string }{
		{`"reality":{"serverName":"Cover.Example","publicKey":"` + pbk + `","shortId":"0123456789ABCDEF","fingerprint":"firefox"}`,
			`&security=reality&sni=Cover.Example&pbk=` + pbk + `&sid=0123456789ABCDEF&fp=firefox`},
		{`"reality":{"serverName":"cover.example","publicKey":"` + pbk + `"}`,
			`&security=reality&sni=cover.example&pbk=` + pbk},
	} {
		byFields, err := buildOrbit(`{"address":"203.0.113.7","port":443,"key":"` + key + `","transport":"tcp","security":"reality",` + tc.fields + `}`)
		if err != nil {
			t.Fatal(err)
		}
		byLink, err := buildOrbit(`{"link":"orbit://203.0.113.7:443@` + key + `&transport=tcp` + tc.link + `"}`)
		if err != nil {
			t.Fatal(err)
		}
		if !proto.Equal(byFields, byLink) {
			t.Fatalf("JSON and link forms differ:\n%v\n%v", byFields, byLink)
		}
		r := byFields.GetReality()
		if r == nil || r.ServerName != "cover.example" || r.PublicKey != pbk || byFields.Fingerprint != "" {
			t.Fatal(byFields)
		}
	}
	c, err := buildOrbit(`{"address":"203.0.113.7","port":443,"key":"` + key + `","transport":"tcp","security":"reality",
		"reality":{"serverName":"cover.example","publicKey":"` + pbk + `","shortId":"0123456789ABCDEF","fingerprint":"safari"}}`)
	if err != nil || c.GetReality().ShortId != "0123456789abcdef" || c.GetReality().Fingerprint != "safari" {
		t.Fatal(c, err)
	}
	// No REALITY: the message carries none.
	c, err = buildOrbit(`{"address":"203.0.113.7","port":443,"key":"` + key + `","transport":"tcp"}`)
	if err != nil || c.GetReality() != nil {
		t.Fatal(c, err)
	}
}

func TestOrbitRealityErrorsNameTheField(t *testing.T) {
	key, pbk := orbitTestKey(t), orbitRealityTestKey(t)
	base := `"address":"203.0.113.7","port":443,"key":"` + key + `"`
	reality := `"reality":{"serverName":"cover.example","publicKey":"` + pbk + `"}`
	for _, tc := range []struct{ json, want string }{
		{`{` + base + `,"transport":"tcp",` + reality + `}`, `"security"`},
		{`{` + base + `,"transport":"tcp","security":"tls",` + reality + `}`, `"security"`},
		{`{` + base + `,"transport":"quic","security":"reality",` + reality + `}`, `"security"`},
		{`{` + base + `,"transport":"wss","host":"cdn.example.com","security":"reality",` + reality + `}`, `"security"`},
		{`{` + base + `,"transport":"tcp","security":"reality"}`, `"reality.serverName"`},
		{`{` + base + `,"transport":"tcp","security":"reality","reality":{"serverName":"cover.example","publicKey":"short"}}`, `"reality.publicKey"`},
		{`{` + base + `,"transport":"tcp","security":"reality","reality":{"serverName":"cover.example","publicKey":"` + pbk + `","shortId":"abc"}}`, `"reality.shortId"`},
		{`{` + base + `,"transport":"tcp","security":"reality","reality":{"serverName":"cover.example","publicKey":"` + pbk + `","fingerprint":"edge"}}`, `"reality.fingerprint"`},
		{`{` + base + `,"transport":"tcp","security":"reality","fingerprint":"chrome",` + reality + `}`, `"fingerprint"`},
		{`{` + base + `,"transport":"tcp","security":"reality","reality":{"serverName":"cover.example","publicKey":"` + pbk + `","spiderX":"/"}}`, `spiderX`},
		{`{"link":"orbit://203.0.113.7:443@` + key + `&transport=tcp",` + reality + `}`, `"reality"`},
		{`{"link":"orbit://203.0.113.7:443@` + key + `&transport=tcp","security":"reality"}`, `"security"`},
	} {
		_, err := buildOrbit(tc.json)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: got %v, want an error naming %s", tc.json, err, tc.want)
		}
		if strings.Contains(err.Error(), pbk) || strings.Contains(err.Error(), key) {
			t.Fatalf("error leaks a value: %v", err)
		}
	}
}
