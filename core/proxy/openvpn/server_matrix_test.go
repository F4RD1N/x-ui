package openvpn

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/ctlwrap"
)

// This matrix checks values exposed by the panel before any socket is opened.
// Data transfer and negotiation are deliberately tested by the binary harness.
func TestNativeServerOptionMatrixCrypto(t *testing.T) {
	p := makeNativePKI(t)
	ciphers := []string{"AES-128-GCM", "AES-192-GCM", "AES-256-GCM", "CHACHA20-POLY1305", "AES-128-CBC", "AES-192-CBC", "AES-256-CBC", "BF-CBC"}
	hashes := []string{"MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512"}
	for _, cipher := range ciphers {
		for _, hash := range hashes {
			t.Run(cipher+"/"+hash, func(t *testing.T) {
				s := nativeSettings(p)
				s.Crypto = ServerCrypto{DataCiphers: []string{cipher}, AuthHash: hash}
				got, err := ParseServerSettings(serverJSON(t, s))
				if err != nil {
					t.Fatal(err)
				}
				if got.Crypto.DataCiphers[0] != cipher || got.Crypto.AuthHash != hash {
					t.Fatal("selected cipher or digest changed")
				}
			})
		}
	}
}

func TestNativeServerOptionMatrixBoundaries(t *testing.T) {
	p := makeNativePKI(t)
	checks := []struct {
		name string
		good bool
		edit func(*ServerSettings)
	}{
		{"tcp", true, func(s *ServerSettings) { s.Network = "tcp" }},
		{"udp", true, func(s *ServerSettings) { s.Network = "udp" }},
		{"family-specific-server-network", false, func(s *ServerSettings) { s.Network = "tcp4" }},
		{"ipv4-min-prefix", true, func(s *ServerSettings) { s.Tunnel.IPv4 = "10.0.0.0/8" }},
		{"ipv4-max-prefix-one-client", true, func(s *ServerSettings) { s.Tunnel.IPv4 = "10.0.0.0/30"; s.Limits.MaxSessions = 1 }},
		{"ipv4-host-bits", false, func(s *ServerSettings) { s.Tunnel.IPv4 = "10.0.0.1/24" }},
		{"ipv4-prefix-too-wide", false, func(s *ServerSettings) { s.Tunnel.IPv4 = "10.0.0.0/7" }},
		{"ipv4-prefix-too-small", false, func(s *ServerSettings) { s.Tunnel.IPv4 = "10.0.0.0/31" }},
		{"ipv6-min-prefix", true, func(s *ServerSettings) { s.Tunnel.IPv6 = "fd00::/48" }},
		{"ipv6-max-prefix", true, func(s *ServerSettings) { s.Tunnel.IPv6 = "fd00::/120" }},
		{"ipv6-host-bits", false, func(s *ServerSettings) { s.Tunnel.IPv6 = "fd00::1/64" }},
		{"ipv6-prefix-too-wide", false, func(s *ServerSettings) { s.Tunnel.IPv6 = "fd00::/47" }},
		{"ipv6-prefix-too-small", false, func(s *ServerSettings) { s.Tunnel.IPv6 = "fd00::/121" }},
		{"ipv6-mapped-v4", false, func(s *ServerSettings) { s.Tunnel.IPv6 = "::ffff:10.0.0.0/120" }},
		{"dns-empty", true, func(s *ServerSettings) { s.Tunnel.DNS = []string{} }},
		{"dns-v4-v6", true, func(s *ServerSettings) { s.Tunnel.DNS = []string{"127.0.0.1", "::1"} }},
		{"dns-eight", true, func(s *ServerSettings) { s.Tunnel.DNS = strings.Fields(strings.Repeat("127.0.0.1 ", 8)) }},
		{"dns-nine", false, func(s *ServerSettings) { s.Tunnel.DNS = strings.Fields(strings.Repeat("127.0.0.1 ", 9)) }},
		{"dns-hostname", false, func(s *ServerSettings) { s.Tunnel.DNS = []string{"resolver.example"} }},
		{"dns-with-port", false, func(s *ServerSettings) { s.Tunnel.DNS = []string{"127.0.0.1:53"} }},
		{"cipher-unknown", false, func(s *ServerSettings) { s.Crypto.DataCiphers = []string{"AES-512-GCM"} }},
		{"hash-unknown", false, func(s *ServerSettings) { s.Crypto.AuthHash = "SHA3" }},
		{"max-clients", true, func(s *ServerSettings) {
			s.Clients = make([]ServerUser, 4096)
			for i := range s.Clients {
				s.Clients[i] = ServerUser{Email: fmt.Sprintf("user%d", i), CommonName: fmt.Sprintf("cn%d", i)}
			}
		}},
		{"too-many-clients", false, func(s *ServerSettings) { s.Clients = make([]ServerUser, 4097) }},
		{"empty-clients-fail-closed-config", true, func(s *ServerSettings) { s.Clients = nil }},
	}
	for _, spec := range []struct {
		name     string
		min, max int
		set      func(*ServerSettings, int)
	}{
		{"mtu", 1280, 8000, func(s *ServerSettings, n int) { s.Tunnel.MTU = n }},
		{"sessions", 1, 4096, func(s *ServerSettings, n int) { s.Tunnel.IPv4 = "10.88.0.0/16"; s.Limits.MaxSessions = n }},
		{"sessions-per-ip", 1, 128, func(s *ServerSettings, n int) { s.Limits.MaxSessionsPerIP = n }},
		{"flows", 1, 4096, func(s *ServerSettings, n int) { s.Limits.MaxFlowsPerSession = n }},
		{"handshake", 1, 120, func(s *ServerSettings, n int) { s.Limits.HandshakeSeconds = n }},
		{"idle", 10, 86400, func(s *ServerSettings, n int) { s.Limits.IdleSeconds = n }},
		{"rekey", 1, 86400, func(s *ServerSettings, n int) { s.RenegotiationSeconds = n }},
	} {
		for _, n := range []int{-1, 0, spec.min, spec.max, spec.max + 1} {
			n := n
			checks = append(checks, struct {
				name string
				good bool
				edit func(*ServerSettings)
			}{
				fmt.Sprintf("%s-%d", spec.name, n), n == 0 || n >= spec.min && n <= spec.max,
				func(s *ServerSettings) { spec.set(s, n) },
			})
		}
		if spec.min > 1 {
			checks = append(checks, struct {
				name string
				good bool
				edit func(*ServerSettings)
			}{
				spec.name + "-below-min", false, func(s *ServerSettings) { spec.set(s, spec.min-1) },
			})
		}
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			s := nativeSettings(p)
			tc.edit(&s)
			_, err := ParseServerSettings(serverJSON(t, s))
			if (err == nil) != tc.good {
				t.Fatalf("accepted=%v, want=%v; error=%v", err == nil, tc.good, err)
			}
		})
	}
}

func TestNativeServerOptionMatrixControlWrappers(t *testing.T) {
	p := makeNativePKI(t)
	static := nativeStaticKeyText(t)
	v2, err := ctlwrap.GenerateTLSCryptV2ServerKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"none", "tls-auth", "tls-crypt", "tls-crypt-v2"} {
		for _, direction := range []int{-1, 0, 1, 2} {
			t.Run(fmt.Sprintf("%s/direction=%d", mode, direction), func(t *testing.T) {
				s := nativeSettings(p)
				switch mode {
				case "tls-auth":
					s.Certificates.TLSAuth = static
				case "tls-crypt":
					s.Certificates.TLSCrypt = static
				case "tls-crypt-v2":
					s.Certificates.TLSCryptV2 = string(v2.MarshalPEM())
				}
				if direction != -1 {
					s.Certificates.KeyDirection = &direction
				}
				_, err := ParseServerSettings(serverJSON(t, s))
				good := direction == -1 || mode == "tls-auth" && direction <= 1
				if (err == nil) != good {
					t.Fatalf("accepted=%v, want=%v; error=%v", err == nil, good, err)
				}
			})
		}
	}
	for _, mode := range []string{"tls-auth+tls-crypt", "tls-auth+tls-crypt-v2", "tls-crypt+tls-crypt-v2"} {
		t.Run(mode, func(t *testing.T) {
			s := nativeSettings(p)
			for _, part := range strings.Split(mode, "+") {
				switch part {
				case "tls-auth":
					s.Certificates.TLSAuth = static
				case "tls-crypt":
					s.Certificates.TLSCrypt = static
				case "tls-crypt-v2":
					s.Certificates.TLSCryptV2 = string(v2.MarshalPEM())
				}
			}
			if _, err := ParseServerSettings(serverJSON(t, s)); err == nil {
				t.Fatal("multiple wrappers accepted")
			}
		})
	}
}

func TestNativeServerOptionMatrixAuthentication(t *testing.T) {
	p := makeNativePKI(t)
	for _, password := range []bool{false, true} {
		for _, proof := range []bool{false, true} {
			for _, required := range []bool{false, true} {
				t.Run(fmt.Sprintf("password=%t/proof=%t/required=%t", password, proof, required), func(t *testing.T) {
					s := nativeSettings(p)
					if password {
						s.Clients[0].Username = "matrix-user"
						s.Clients[0].Password = "matrix-password"
					}
					if proof {
						s.Clients[0].ClientProof = &ServerUserProof{KeyID: "matrix-proof", Key: strings.Repeat("a5", 32)}
					}
					s.ClientProof.Required = required
					_, err := ParseServerSettings(serverJSON(t, s))
					good := !required || proof
					if (err == nil) != good {
						t.Fatalf("accepted=%v, want=%v; error=%v", err == nil, good, err)
					}
				})
			}
		}
	}
}
