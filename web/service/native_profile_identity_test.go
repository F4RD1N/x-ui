package service

import (
	"crypto/x509"
	"net"
	"testing"
)

func profileIdentityLeaf(t *testing.T, profile *NativeInboundProfile) *x509.Certificate {
	t.Helper()
	switch profile.Protocol {
	case "anytls":
		tlsSettings := profileTestObject(t, profile.StreamSettings["tlsSettings"])
		certificates, ok := tlsSettings["certificates"].([]any)
		if !ok || len(certificates) != 1 {
			t.Fatal("AnyTLS generated certificate is missing")
		}
		material := profileTestObject(t, certificates[0])
		return profileTestKeyPair(t, material["certificate"], material["key"])
	case "openvpn":
		material := profileTestObject(t, profile.Settings["certificates"])
		return profileTestKeyPair(t, material["cert"], material["key"])
	case "orbit":
		material := profileTestObject(t, profile.Settings["tls"])
		return profileTestKeyPair(t, material["certificate"], material["key"])
	default:
		t.Fatal("unsupported identity fixture protocol")
		return nil
	}
}

func TestNativeProfileExplicitIdentityNormalization(t *testing.T) {
	for _, tc := range []struct {
		name, protocol, serverName, serverAddress string
		wantDNS, wantIPs                          []string
		wantExport                                string
	}{
		{name: "anytls bracketed IPv6", protocol: "anytls", serverName: " \t[2001:0db8:0:0::7]\n", wantIPs: []string{"2001:db8::7"}, wantExport: "2001:db8::7"},
		{name: "openvpn bracketed IPv6", protocol: "openvpn", serverName: " \t[2001:0db8:0:0::7]\n", wantIPs: []string{"2001:db8::7"}},
		{name: "anytls DNS", protocol: "anytls", serverName: " \tVPN.Example.Test.\n", wantDNS: []string{"vpn.example.test"}, wantExport: "vpn.example.test"},
		{name: "openvpn DNS", protocol: "openvpn", serverName: " \tVPN.Example.Test.\n", wantDNS: []string{"vpn.example.test"}},
		{name: "anytls IPv4", protocol: "anytls", serverName: " 192.0.2.7 ", wantIPs: []string{"192.0.2.7"}, wantExport: "192.0.2.7"},
		{name: "openvpn IPv4", protocol: "openvpn", serverName: " 192.0.2.7 ", wantIPs: []string{"192.0.2.7"}},
		{name: "orbit bracketed endpoint", protocol: "orbit", serverAddress: " \t[2001:0db8:0:0::7]\n", wantIPs: []string{"2001:db8::7"}, wantExport: "2001:db8::7"},
		{name: "orbit bracketed name endpoint", protocol: "orbit", serverName: " \t[2001:0db8:0:0::7]\n", wantIPs: []string{"2001:db8::7"}, wantExport: "2001:db8::7"},
		{name: "orbit IPv6 endpoint plus DNS", protocol: "orbit", serverAddress: " [2001:db8::7] ", serverName: " VPN.Example.Test. ", wantDNS: []string{"vpn.example.test"}, wantIPs: []string{"2001:db8::7"}, wantExport: "2001:db8::7"},
		{name: "orbit IPv4 endpoint", protocol: "orbit", serverAddress: " 192.0.2.7 ", wantIPs: []string{"192.0.2.7"}, wantExport: "192.0.2.7"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile, err := GenerateNativeInboundProfile(NativeCredentialRequest{Protocol: tc.protocol, ServerName: tc.serverName, ServerAddress: tc.serverAddress})
			if err != nil || profile == nil {
				t.Fatalf("explicit identity normalization failed: %v", err)
			}
			if len(profile.Requirements) != 0 {
				t.Fatal("provided explicit identity was treated as missing")
			}
			leaf := profileIdentityLeaf(t, profile)
			if len(leaf.DNSNames) != len(tc.wantDNS) || len(leaf.IPAddresses) != len(tc.wantIPs) {
				t.Fatal("certificate gained or lost an explicit deployment identity")
			}
			for i, dns := range tc.wantDNS {
				if leaf.DNSNames[i] != dns || leaf.VerifyHostname(dns) != nil {
					t.Fatal("certificate DNS identity was not normalized")
				}
			}
			for i, address := range tc.wantIPs {
				if !leaf.IPAddresses[i].Equal(net.ParseIP(address)) || leaf.VerifyHostname(address) != nil {
					t.Fatal("certificate IP identity was not normalized")
				}
			}
			if tc.wantExport != "" {
				field := "serverName"
				if tc.protocol == "orbit" {
					field = "address"
				}
				if profileTestObject(t, profile.Settings["clientExport"])[field] != tc.wantExport {
					t.Fatal("export metadata did not preserve the canonical explicit identity")
				}
			}
		})
	}
}

func TestNativeProfileExplicitIdentityRejectsMalformedInput(t *testing.T) {
	invalid := []string{
		"[2001:db8::7", "2001:db8::7]", "[[2001:db8::7]]", "[192.0.2.7]", "[vpn.example.test]",
		"[2001:db8::7]:443", "vpn.example.test:443", "192.0.2.7:443", "https://vpn.example.test",
	}
	for _, protocol := range []string{"anytls", "openvpn", "orbit"} {
		for _, value := range invalid {
			t.Run(protocol+"/name/"+value, func(t *testing.T) {
				r := NativeCredentialRequest{Protocol: protocol, ServerName: value}
				if protocol == "orbit" {
					r.ServerAddress = "192.0.2.7"
				}
				if profile, err := GenerateNativeInboundProfile(r); err == nil || profile != nil {
					t.Fatal("malformed explicit server identity returned generated credentials")
				}
			})
		}
	}
	for _, value := range append(invalid, "[ff02::1]", " 224.0.0.1 ", "[::]", "[fe80::1]") {
		t.Run("orbit/address/"+value, func(t *testing.T) {
			if profile, err := GenerateNativeInboundProfile(NativeCredentialRequest{Protocol: "orbit", ServerAddress: value}); err == nil || profile != nil {
				t.Fatal("malformed or non-unicast explicit endpoint returned generated credentials")
			}
		})
	}
}
