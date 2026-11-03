//go:build !without_native_protocols

package conf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/orbit"
	"google.golang.org/protobuf/proto"
)

func orbitInboundFixture(t *testing.T) OrbitServerConfig {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test.invalid"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	secret, err := orbit.GenerateConnectionKey(cert)
	if err != nil {
		t.Fatal(err)
	}
	return OrbitServerConfig{Transport: "tcp", Clients: []OrbitServerClient{{Email: "user@test.invalid", Key: secret, Level: 2, ExpiresAt: time.Now().Add(time.Hour).Unix()}}, TLS: &OrbitCertificate{Certificate: []string{cert}, Key: []string{string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}))}}}
}

func TestDialect11OrbitInboundRoundTrip(t *testing.T) {
	for _, mode := range []string{"tcp", "quic", "ws", "wss"} {
		t.Run(mode, func(t *testing.T) {
			c := orbitInboundFixture(t)
			c.Transport = mode
			if mode == "ws" || mode == "wss" {
				c.Host = "test.invalid"
				c.Path = "/core"
			}
			if mode == "wss" {
				c.OuterTLS = c.TLS
			}
			before, err := c.Build()
			if err != nil {
				t.Fatal(err)
			}
			wire, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := inboundConfigLoader.LoadWithID(wire, "orbit")
			if err != nil {
				t.Fatal(err)
			}
			after, err := loaded.(*OrbitServerConfig).Build()
			if err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(before, after) {
				t.Fatal("JSON backup roundtrip changed keys, certificate or settings")
			}
			binary, err := proto.Marshal(after)
			if err != nil {
				t.Fatal(err)
			}
			restored := new(orbit.ServerConfig)
			if err = proto.Unmarshal(binary, restored); err != nil || !proto.Equal(restored, after) {
				t.Fatal("protobuf roundtrip changed native server", err)
			}
		})
	}
}

func TestDialect11OrbitInboundRejectsInvalidSettings(t *testing.T) {
	mutations := map[string]func(*OrbitServerConfig){
		"wrong-pin":             func(c *OrbitServerConfig) { c.Clients[0].Key = orbitTestKey(t) },
		"duplicate-key":         func(c *OrbitServerConfig) { c.Clients = append(c.Clients, c.Clients[0]) },
		"invalid-key":           func(c *OrbitServerConfig) { c.Clients[0].Key = "secret-do-not-leak" },
		"negative-expiry":       func(c *OrbitServerConfig) { c.Clients[0].ExpiresAt = -1 },
		"missing-tls":           func(c *OrbitServerConfig) { c.TLS = nil },
		"wrong-keypair":         func(c *OrbitServerConfig) { c.TLS.Key = []string{"secret-do-not-leak"} },
		"unsupported-carrier":   func(c *OrbitServerConfig) { c.Transport = "auto" },
		"unexpected-ws":         func(c *OrbitServerConfig) { c.Path = "/core" },
		"wss-missing-outer-tls": func(c *OrbitServerConfig) { c.Transport = "wss"; c.Host = "test.invalid" },
		"path-traversal":        func(c *OrbitServerConfig) { c.Transport = "ws"; c.Host = "test.invalid"; c.Path = "/../private" },
		"quic-reality": func(c *OrbitServerConfig) {
			c.Transport = "quic"
			c.Security = "reality"
			c.Reality = &OrbitServerReality{}
		},
		"excessive-limit": func(c *OrbitServerConfig) { c.MaxFlows = 100000 },
	}
	for name, change := range mutations {
		t.Run(name, func(t *testing.T) {
			c := orbitInboundFixture(t)
			change(&c)
			_, err := c.Build()
			if err == nil {
				t.Fatal("invalid settings accepted")
			}
			if strings.Contains(err.Error(), "secret-do-not-leak") || strings.Contains(err.Error(), "vck1_") {
				t.Fatal("validation exposed credential")
			}
		})
	}
	for _, raw := range []string{`{"transport":"tcp","unknown":"secret-do-not-leak"}`, `{"clients":[{"email":"a","unknown":"secret-do-not-leak"}]}`, `{"tls":{"certificate":[],"unknown":"secret-do-not-leak"}}`} {
		var c OrbitServerConfig
		if err := json.Unmarshal([]byte(raw), &c); err == nil {
			t.Fatal("unknown fields accepted")
		}
	}
}

func TestDialect11OrbitKeyGeneration(t *testing.T) {
	c := orbitInboundFixture(t)
	a, err := orbit.GenerateConnectionKey(c.TLS.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	b, err := orbit.GenerateConnectionKey(c.TLS.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if a == b || len(a) != 91 || len(b) != 91 {
		t.Fatal("keys were not fresh canonical v1 keys")
	}
	c.Clients[0].Key = a
	if _, err = c.Build(); err != nil {
		t.Fatal("generated key does not match certificate", err)
	}
	if _, err = orbit.GenerateConnectionKey(c.TLS.Key[0]); err == nil {
		t.Fatal("private key accepted as certificate")
	}
}
