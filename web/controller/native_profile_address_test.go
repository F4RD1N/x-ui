package controller

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/web/service"
)

func TestNativeProfileAddressLiteralAndExplicit(t *testing.T) {
	for _, tc := range []struct {
		host, name, address, wantName, wantAddress string
	}{
		{"127.0.0.1:2053", "", "", "127.0.0.1", "127.0.0.1"},
		{"[::1]:2053", "", "", "::1", "::1"},
		{"ignored.invalid", "192.0.2.8", "", "192.0.2.8", "192.0.2.8"},
		{"vpn.example.test:2053", "", "192.0.2.8", "vpn.example.test", "192.0.2.8"},
		{"vpn.example.test", "explicit.example.test", "2001:db8::8", "explicit.example.test", "2001:db8::8"},
	} {
		request := service.NativeCredentialRequest{Protocol: "orbit", ServerName: tc.name, ServerAddress: tc.address}
		err := prepareNativeProfileAddress(context.Background(), tc.host, &request, func(context.Context, string) ([]net.IPAddr, error) {
			t.Fatal("literal or explicit endpoint unexpectedly triggered DNS")
			return nil, errors.New("unexpected lookup")
		})
		if err != nil || request.ServerName != tc.wantName || request.ServerAddress != tc.wantAddress {
			t.Fatalf("wrong selected endpoint: %v", err)
		}
	}
}

func TestNativeProfileAddressLookupValidationAndDeadline(t *testing.T) {
	request := service.NativeCredentialRequest{Protocol: "orbit"}
	err := prepareNativeProfileAddress(context.Background(), "VPN.Example.Test:2053", &request, func(ctx context.Context, host string) ([]net.IPAddr, error) {
		if host != "VPN.Example.Test" {
			t.Fatal("HTTP host port was not removed")
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 3*time.Second || time.Until(deadline) <= 0 {
			t.Fatal("lookup has no bounded deadline")
		}
		return []net.IPAddr{{IP: net.ParseIP("ff02::1")}, {IP: net.ParseIP("2001:db8::8")}, {IP: net.ParseIP("192.0.2.8")}}, nil
	})
	if err != nil || request.ServerName != "vpn.example.test" || request.ServerAddress != "192.0.2.8" {
		t.Fatal("DNS selection must prefer valid IPv4 and retain normalized DNS identity")
	}
	request = service.NativeCredentialRequest{Protocol: "orbit", ServerName: "vpn.example.test"}
	err = prepareNativeProfileAddress(context.Background(), "", &request, func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("fe80::1"), Zone: "eth0"}, {IP: net.ParseIP("2001:db8::8")}}, nil
	})
	if err != nil || request.ServerAddress != "2001:db8::8" {
		t.Fatal("IPv6-only endpoint should remain usable without scoped addresses")
	}
	for _, host := range []string{"bad name", "https://bad.test/path", "bad.test:443:9", "bad..test", "-bad.test", strings.Repeat("x", 64) + ".test"} {
		request = service.NativeCredentialRequest{Protocol: "orbit", ServerName: host}
		err = prepareNativeProfileAddress(context.Background(), "", &request, func(context.Context, string) ([]net.IPAddr, error) {
			t.Fatal("invalid DNS host reached resolver")
			return nil, nil
		})
		if err == nil {
			t.Fatal("malformed DNS host accepted")
		}
	}
	for _, address := range []string{"0.0.0.0", "::", "255.255.255.255", "224.0.0.1", "ff02::1", "fe80::1", "vpn.example.test", "127.0.0.1:443"} {
		request = service.NativeCredentialRequest{Protocol: "orbit", ServerName: "vpn.example.test", ServerAddress: address}
		if prepareNativeProfileAddress(context.Background(), "", &request, nil) == nil {
			t.Fatal("invalid explicit unicast endpoint accepted")
		}
	}
	for _, failed := range []nativeProfileLookup{
		func(context.Context, string) ([]net.IPAddr, error) { return nil, errors.New("PRIVATE-RESOLVER-ERROR") },
		func(context.Context, string) ([]net.IPAddr, error) { return []net.IPAddr{{IP: net.IPv4zero}}, nil },
	} {
		request = service.NativeCredentialRequest{Protocol: "orbit", ServerName: "vpn.example.test"}
		err := prepareNativeProfileAddress(context.Background(), "", &request, failed)
		if err == nil || strings.Contains(err.Error(), "PRIVATE-") || request.ServerAddress != "" {
			t.Fatal("failed resolver accepted or diagnostic exposed")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request = service.NativeCredentialRequest{Protocol: "orbit", ServerName: "vpn.example.test"}
	if err := prepareNativeProfileAddress(ctx, "", &request, func(ctx context.Context, _ string) ([]net.IPAddr, error) { return nil, ctx.Err() }); err == nil {
		t.Fatal("cancelled lookup accepted")
	}
}

func TestNativeProfileHTTPUsesLocalRequestAddress(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:2053/panel/api/server/native/credentials", strings.NewReader(`{"kind":"inbound-profile","protocol":"orbit"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	credentialRouter(true).ServeHTTP(response, request)
	var decoded struct {
		Success bool `json:"success"`
		Obj     struct {
			Settings map[string]any `json:"settings"`
		} `json:"obj"`
	}
	if json.Unmarshal(response.Body.Bytes(), &decoded) != nil || !decoded.Success {
		t.Fatal("HTTP generation with omitted name failed for a local numeric endpoint")
	}
	metadata, ok := decoded.Obj.Settings["clientExport"].(map[string]any)
	if !ok || metadata["address"] != "127.0.0.1" || metadata["serverName"] != nil {
		t.Fatal("HTTP generation failed to preserve the direct numeric endpoint")
	}
}
