package native_client

import "testing"

func TestRequestHostUsesOnlyValidServerAuthorities(t *testing.T) {
	for input, want := range map[string]string{
		"vpn.example.test": "vpn.example.test", "VPN.Example.Test.:443": "vpn.example.test",
		"127.0.0.1:2053": "127.0.0.1", "192.0.2.7": "192.0.2.7", "10.0.0.7:8080": "10.0.0.7",
		"[::1]:443": "::1", "[2001:db8::7]": "2001:db8::7", "::1": "::1",
	} {
		t.Run(input, func(t *testing.T) {
			got, err := RequestHost(input)
			if err != nil || got != want {
				t.Fatalf("got %q, %v; want %q", got, err, want)
			}
		})
	}
	for _, input := range []string{
		"", " ", "vpn.test ", "https://vpn.test", "user@vpn.test", "vpn.test/path", "vpn.test?x", "vpn.test#x",
		"vpn.test\\path", "vpn.test:0", "vpn.test:65536", "vpn.test:abc", "vpn.test:", "vpn.test:443:80",
		"vpn.test:443/", "vpn.test,other.test", "bad..test", "-bad.test", "bad-.test", "bad_host.test", "127.0.0.999",
		"0.0.0.0", "[::]:443", "224.0.0.1", "255.255.255.255", "ff02::1", "fe80::1%eth0", "[127.0.0.1]",
		"[::1", "::1]", "vpn.test\n", "vpn.test\x00", "[::1]:-1", "[::1]:+443",
	} {
		t.Run("reject-"+input, func(t *testing.T) {
			if host, err := RequestHost(input); err == nil || host != "" {
				t.Fatalf("accepted invalid authority as %q", host)
			}
		})
	}
}

func TestHostNeverTreatsTransportPortOrURLAsAnAddress(t *testing.T) {
	for _, value := range []string{"vpn.test:443", "https://vpn.test", "[::1]:443", "0.0.0.0", "224.0.0.1"} {
		if _, err := Host(value); err == nil {
			t.Fatalf("accepted non-endpoint host %q", value)
		}
	}
}
