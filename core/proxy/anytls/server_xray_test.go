//go:build !without_native_protocols

package anytls_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
)

func startAnyTLSXray(t *testing.T, config map[string]any) *core.Instance {
	t.Helper()
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := serial.LoadJSONConfig(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	instance, err := core.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = instance.Start(); err != nil {
		instance.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { instance.Close() })
	return instance
}

func TestAnyTLSXrayRoutingUDPAndUserAccounting(t *testing.T) {
	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()
	crt, _ := cert.MustGenerate(nil, cert.DNSNames("anytls.test"))
	pemCert, pemKey := crt.ToPEM()
	certificate := map[string]any{"certificate": strings.Split(strings.TrimSpace(string(pemCert)), "\n"), "key": strings.Split(strings.TrimSpace(string(pemKey)), "\n")}
	password := "00112233-4455-6677-8899-aabbccddeeff"
	server := startAnyTLSXray(t, map[string]any{
		"log":       map[string]any{"loglevel": "none"},
		"stats":     map[string]any{},
		"policy":    map[string]any{"levels": map[string]any{"0": map[string]any{"statsUserUplink": true, "statsUserDownlink": true}}},
		"inbounds":  []any{map[string]any{"tag": "native-anytls", "listen": "127.0.0.1", "port": port, "protocol": "anytls", "settings": map[string]any{"clients": []any{map[string]any{"email": "accounting@test", "password": password, "uuidHashMiddle": true}}}, "streamSettings": map[string]any{"network": "tcp", "security": "tls", "tlsSettings": map[string]any{"certificates": []any{certificate}}}}},
		"outbounds": []any{map[string]any{"tag": "direct", "protocol": "freedom"}, map[string]any{"tag": "blocked", "protocol": "blackhole"}},
		"routing":   map[string]any{"rules": []any{map[string]any{"type": "field", "domain": []string{"full:blocked.anytls.test"}, "outboundTag": "blocked"}}},
	})
	client := startAnyTLSXray(t, map[string]any{"log": map[string]any{"loglevel": "none"}, "outbounds": []any{map[string]any{"tag": "proxy", "protocol": "anytls", "settings": map[string]any{"address": "127.0.0.1", "port": port, "password": password, "uuidHashMiddle": true, "tlsSettings": map[string]any{"serverName": "anytls.test", "allowInsecure": true}}}}})
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("native-xray-http-round-trip")) }))
	defer target.Close()
	targetAddr := target.Listener.Addr().(*net.TCPAddr)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	conn, err := core.Dial(ctx, client, xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(targetAddr.Port)))
	if err != nil {
		t.Fatal(err)
	}
	context.AfterFunc(ctx, func() { conn.Close() })
	_, err = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: fixture.test\r\nConnection: close\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(conn)
	conn.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(response, []byte("native-xray-http-round-trip")) {
		t.Fatalf("HTTP via two Xray instances failed: %q", response)
	}
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		p := make([]byte, 4096)
		n, addr, e := udp.ReadFrom(p)
		if e == nil {
			_, _ = udp.WriteTo(p[:n], addr)
		}
	}()
	udpPort := udp.LocalAddr().(*net.UDPAddr).Port
	datagram, err := core.Dial(ctx, client, xnet.UDPDestination(xnet.LocalHostIP, xnet.Port(udpPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer datagram.Close()
	context.AfterFunc(ctx, func() { datagram.Close() })
	if _, err = datagram.Write([]byte("native-udp-routing")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4096)
	n, err := datagram.Read(reply)
	if err != nil {
		t.Fatal(err)
	}
	if string(reply[:n]) != "native-udp-routing" {
		t.Fatal("UDP payload differs")
	}
	blocked, err := core.Dial(ctx, client, xnet.TCPDestination(xnet.DomainAddress("blocked.anytls.test"), 80))
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Close()
	context.AfterFunc(ctx, func() { blocked.Close() })
	_, _ = blocked.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	n, err = blocked.Read(make([]byte, 1))
	if n != 0 || err == nil {
		t.Fatal("server block route was bypassed")
	}
	manager := server.GetFeature(stats.ManagerType()).(stats.Manager)
	for _, direction := range []string{"uplink", "downlink"} {
		counter := manager.GetCounter("user>>>accounting@test>>>traffic>>>" + direction)
		if counter == nil || counter.Value() == 0 {
			t.Fatalf("authenticated user %s traffic not accounted", direction)
		}
	}
}
