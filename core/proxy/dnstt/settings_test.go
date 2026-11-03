package dnstt

import (
	"encoding/hex"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"www.bamsoftware.com/git/dnstt.git/noise"
)

const testUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

func testConfig(t *testing.T) *Config {
	t.Helper()
	key, err := noise.GeneratePrivkey()
	if err != nil {
		t.Fatal(err)
	}
	return &Config{Domain: "tunnel.example", PublicKey: hex.EncodeToString(noise.PubkeyFromPrivkey(key)),
		Resolvers: []*Resolver{{Transport: "udp", Address: "127.0.0.1:5353"}},
		Inner:     &Inner{Protocol: "vless", Uuid: testUUID}}
}

func TestNormalizeDoesNotMutateInput(t *testing.T) {
	c := testConfig(t)
	c.Domain, c.Inner.Protocol = "TuNnEl.ExAmPlE.", "VLESS"
	c.PublicKey = strings.ToUpper(c.PublicKey)
	before := proto.Clone(c)
	n, err := NormalizeConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(c, before) {
		t.Fatal("normalization modified caller-owned config")
	}
	if n.Domain != "tunnel.example" || n.Inner.Protocol != "vless" || n.PublicKey != strings.ToLower(c.PublicKey) {
		t.Fatal("settings were not canonicalized")
	}
	if n.HandshakeTimeout != 30 || n.QueryTimeout != 5 || n.MaxConcurrentQueries != 32 || n.EdnsPayloadSize != 1232 || n.MaxQnameLength != 255 || n.LabelMin != 63 || n.LabelMax != 63 {
		t.Fatal("unexpected defaults")
	}
	n.Resolvers[0].Address = "127.0.0.1:1"
	if c.Resolvers[0].Address == n.Resolvers[0].Address {
		t.Fatal("resolver objects are shared with caller")
	}
}

func TestRejectUnsafeOrUnusableConfig(t *testing.T) {
	cases := map[string]func(*Config){
		"empty domain":      func(c *Config) { c.Domain = "" },
		"bad domain":        func(c *Config) { c.Domain = "has space.example" },
		"literal IP domain": func(c *Config) { c.Domain = "192.0.2.1" },
		"long domain":       func(c *Config) { c.Domain = strings.Repeat("a.", 120) + "test" },
		"missing key":       func(c *Config) { c.PublicKey = "" },
		"low order pin":     func(c *Config) { c.PublicKey = strings.Repeat("0", 64) },
		"missing resolver":  func(c *Config) { c.Resolvers = nil },
		"nil resolver":      func(c *Config) { c.Resolvers = []*Resolver{nil} },
		"too many resolvers": func(c *Config) {
			for len(c.Resolvers) < 17 {
				c.Resolvers = append(c.Resolvers, proto.Clone(c.Resolvers[0]).(*Resolver))
			}
		},
		"missing inner":         func(c *Config) { c.Inner = nil },
		"invalid UUID":          func(c *Config) { c.Inner.Uuid = "not-a-uuid" },
		"zero UUID":             func(c *Config) { c.Inner.Uuid = "00000000-0000-0000-0000-000000000000" },
		"mixed auth":            func(c *Config) { c.Inner.Password = "private-password" },
		"unauthenticated socks": func(c *Config) { c.Inner = &Inner{Protocol: "socks"} },
		"oversize password": func(c *Config) {
			c.Inner = &Inner{Protocol: "socks", Username: "user", Password: strings.Repeat("x", 256)}
		},
		"handshake bound":    func(c *Config) { c.HandshakeTimeout = 301 },
		"query bound":        func(c *Config) { c.QueryTimeout = 61 },
		"parallel bound":     func(c *Config) { c.MaxConcurrentQueries = 257 },
		"interval bound":     func(c *Config) { c.MinQueryIntervalMs = 60001 },
		"EDNS small":         func(c *Config) { c.EdnsPayloadSize = 511 },
		"EDNS large":         func(c *Config) { c.EdnsPayloadSize = 4097 },
		"QNAME large":        func(c *Config) { c.MaxQnameLength = 256 },
		"QNAME insufficient": func(c *Config) { c.MaxQnameLength = 64 },
		"label order":        func(c *Config) { c.LabelMin, c.LabelMax = 41, 40 },
		"label large":        func(c *Config) { c.LabelMax = 64 },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			c := testConfig(t)
			change(c)
			if err := ValidateConfig(c); err == nil {
				t.Fatal("invalid config accepted")
			} else if strings.Contains(err.Error(), "private-password") {
				t.Fatal("validation error exposed credentials")
			}
		})
	}
}

func TestResolverValidation(t *testing.T) {
	good := []*Resolver{
		{Transport: "udp", Address: "127.0.0.1:5353"},
		{Transport: "udp", Address: "resolver.example:53", Bootstrap: "192.0.2.1"},
		{Transport: "dot", Address: "resolver.example:853", Bootstrap: "2001:db8::1", Fingerprint: "chrome"},
		{Transport: "dot", Address: "192.0.2.1:853", ServerName: "resolver.example"},
		{Transport: "doh", Address: "https://resolver.example/dns-query", Bootstrap: "192.0.2.1"},
		{Transport: "doh", Address: "https://[2001:db8::1]:8443/dns-query"},
	}
	for _, r := range good {
		if err := ValidateResolver(r); err != nil {
			t.Errorf("valid %s rejected: %v", r.Transport, err)
		}
	}
	bad := []*Resolver{
		nil,
		{Transport: "udp", Address: "127.0.0.1:0"},
		{Transport: "udp", Address: "127.0.0.1:65536"},
		{Transport: "udp", Address: "resolver.example:53"},
		{Transport: "udp", Address: "127.0.0.1:53", Fingerprint: "chrome"},
		{Transport: "dot", Address: "192.0.2.1:853", Bootstrap: "bootstrap.example"},
		{Transport: "dot", Address: "192.0.2.1:853", CaPem: "not a certificate"},
		{Transport: "dot", Address: "192.0.2.1:853", Fingerprint: "random"},
		{Transport: "dot", Address: "0.0.0.0:853"},
		{Transport: "dot", Address: "224.0.0.1:853"},
		{Transport: "doh", Address: "http://192.0.2.1/dns-query"},
		{Transport: "doh", Address: "https://private:password@192.0.2.1/dns-query"},
		{Transport: "doh", Address: "https://192.0.2.1/dns-query#fragment"},
		{Transport: "doh", Address: "https://192.0.2.1:0/dns-query"},
	}
	for i, r := range bad {
		if err := ValidateResolver(r); err == nil {
			t.Errorf("invalid resolver %d accepted", i)
		} else if strings.Contains(err.Error(), "password") {
			t.Fatal("resolver error exposed URL credentials")
		}
	}
}
