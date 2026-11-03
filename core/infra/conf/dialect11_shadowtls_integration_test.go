package conf_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/core"
	featureInbound "github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy"
	_ "github.com/xtls/xray-core/proxy/blackhole"
	_ "github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/shadowtls"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/udp"
)

func startNativeCore(t *testing.T, config map[string]interface{}) *core.Instance {
	t.Helper()
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	var parsed conf.Config
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	pb, err := parsed.Build()
	if err != nil {
		t.Fatal(err)
	}
	instance, err := core.New(pb)
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		instance.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { instance.Close() })
	return instance
}

func availablePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}

func nativeEchoTarget(t *testing.T) (int, *atomic.Int64) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var hits atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	t.Cleanup(func() { l.Close(); <-done; wg.Wait() })
	return l.Addr().(*net.TCPAddr).Port, &hits
}

func TestNativeXrayShadowTLSInnerRouting(t *testing.T) {
	for _, innerName := range []string{"socks", "vless"} {
		t.Run(innerName, func(t *testing.T) {
			// A genuine TLS 1.3 server supplies the handshake, but never sees proxy
			// targets or the authenticated data stream.
			camouflage := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("camouflage")) }))
			camouflage.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
			camouflage.StartTLS()
			t.Cleanup(camouflage.Close)
			host, portString, _ := net.SplitHostPort(camouflage.Listener.Addr().String())
			hsPort, _ := strconv.Atoi(portString)
			listenPort := availablePort(t)
			targetPort, _ := nativeEchoTarget(t)
			blockedPort, blockedHits := nativeEchoTarget(t)
			const password = "test-native-carrier-password"
			const id = "c7689b9c-b62c-4257-a9bb-62d58baf7ed0"
			innerSettings := map[string]interface{}{"auth": "password", "accounts": []interface{}{map[string]interface{}{"user": "inner", "pass": "inner-secret"}}, "udp": false}
			clientSettings := map[string]interface{}{"servers": []interface{}{map[string]interface{}{"address": "127.0.0.1", "port": listenPort, "users": []interface{}{map[string]interface{}{"user": "inner", "pass": "inner-secret"}}}}}
			if innerName == "vless" {
				innerSettings = map[string]interface{}{"clients": []interface{}{map[string]interface{}{"id": id, "email": "inner@example.invalid"}}, "decryption": "none"}
				clientSettings = map[string]interface{}{"vnext": []interface{}{map[string]interface{}{"address": "127.0.0.1", "port": listenPort, "users": []interface{}{map[string]interface{}{"id": id, "encryption": "none"}}}}}
			}
			server := startNativeCore(t, map[string]interface{}{
				"log": map[string]interface{}{"loglevel": "error"},
				"inbounds": []interface{}{map[string]interface{}{"listen": "127.0.0.1", "port": listenPort, "protocol": "shadowtls", "tag": "carrier-in", "settings": map[string]interface{}{
					"version": 3, "strict": true, "handshake": map[string]interface{}{"address": host, "port": hsPort},
					"clients": []interface{}{map[string]interface{}{"email": "carrier@example.invalid", "password": password}},
					"inner":   map[string]interface{}{"protocol": innerName, "settings": innerSettings}}}},
				"outbounds": []interface{}{map[string]interface{}{"tag": "direct", "protocol": "freedom"}, map[string]interface{}{"tag": "blocked", "protocol": "blackhole"}},
				"routing":   map[string]interface{}{"rules": []interface{}{map[string]interface{}{"type": "field", "port": strconv.Itoa(blockedPort), "user": []interface{}{"carrier@example.invalid"}, "outboundTag": "blocked"}}},
			})
			client := startNativeCore(t, map[string]interface{}{
				"log": map[string]interface{}{"loglevel": "error"},
				"outbounds": []interface{}{
					map[string]interface{}{"tag": "proxy", "protocol": innerName, "settings": clientSettings, "proxySettings": map[string]interface{}{"tag": "outer", "transportLayer": true}},
					map[string]interface{}{"tag": "outer", "protocol": "shadowtls", "settings": map[string]interface{}{"address": "127.0.0.1", "port": listenPort, "password": password, "serverName": "example.com", "allowInsecure": true, "version": 3, "strict": true}},
				},
			})
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			conn, err := core.Dial(ctx, client, xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(targetPort)))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			payload := bytes.Repeat([]byte("routed-shadowtls-"), 6000)
			written := make(chan error, 1)
			go func() { _, err := conn.Write(payload); written <- err }()
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, got); err != nil {
				t.Fatal(err)
			}
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(payload, got) {
				t.Fatal("TCP payload differs")
			}
			conn.Close()
			blocked, err := core.Dial(ctx, client, xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(blockedPort)))
			if err != nil {
				t.Fatal(err)
			}
			_, _ = blocked.Write([]byte("must not arrive"))
			_, err = blocked.Read(make([]byte, 1))
			blocked.Close()
			if err == nil || blockedHits.Load() != 0 {
				t.Fatalf("blocked route reached target: err=%v hits=%d", err, blockedHits.Load())
			}
			if innerName == "vless" {
				udp, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer udp.Close()
				done := make(chan struct{})
				go func() {
					defer close(done)
					b := make([]byte, 65535)
					for {
						n, addr, err := udp.ReadFrom(b)
						if err != nil {
							return
						}
						_, _ = udp.WriteTo(b[:n], addr)
					}
				}()
				defer func() { udp.Close(); <-done }()
				uc, err := core.Dial(ctx, client, xnet.UDPDestination(xnet.LocalHostIP, xnet.Port(udp.LocalAddr().(*net.UDPAddr).Port)))
				if err != nil {
					t.Fatal(err)
				}
				defer uc.Close()
				for _, size := range []int{1, 512, 1400, 4096} {
					p := bytes.Repeat([]byte{byte(size)}, size)
					if _, err := uc.Write(p); err != nil {
						t.Fatal(err)
					}
					b := make([]byte, 65535)
					n, err := uc.Read(b)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(p, b[:n]) {
						t.Fatalf("UDP packet boundary/payload differs for %d bytes: got %d", size, n)
					}
				}
			}
			// Dynamic native revocation must terminate a live stream even when
			// called directly, without relying on a panel-wide config reload.
			manager := server.GetFeature(featureInbound.ManagerType()).(featureInbound.Manager)
			handler, err := manager.GetHandler(ctx, "carrier-in")
			if err != nil {
				t.Fatal(err)
			}
			native := handler.(proxy.GetInbound).GetInbound().(*shadowtls.Server)
			live, err := core.Dial(ctx, client, xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(targetPort)))
			if err != nil {
				t.Fatal(err)
			}
			_, _ = live.Write([]byte("live"))
			before := make([]byte, 4)
			if _, err := io.ReadFull(live, before); err != nil {
				t.Fatal(err)
			}
			if err := native.RemoveUser(ctx, "carrier@example.invalid"); err != nil {
				t.Fatal(err)
			}
			if _, err := live.Read(make([]byte, 1)); err == nil {
				t.Fatal("revoked active stream remains usable")
			}
			live.Close()
			account, err := (&shadowtls.ServerUser{Password: password}).AsAccount()
			if err != nil {
				t.Fatal(err)
			}
			if err := native.AddUser(ctx, &protocol.MemoryUser{Email: "carrier@example.invalid", Account: account}); err != nil {
				t.Fatal(err)
			}
			fresh, err := core.Dial(ctx, client, xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(targetPort)))
			if err != nil {
				t.Fatal(err)
			}
			_, _ = fresh.Write([]byte("new!"))
			if _, err := io.ReadFull(fresh, before); err != nil {
				t.Fatal("re-added user cannot establish a fresh session:", err)
			}
			fresh.Close()
			// A reload/stop must also own connections that never finish their
			// first TLS record, rather than waiting for the handshake timeout.
			stalled, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(listenPort)))
			if err != nil {
				t.Fatal(err)
			}
			defer stalled.Close()
			_, _ = stalled.Write([]byte{22, 3, 3, 0, 128, 1})
			stopped := make(chan error, 1)
			go func() { stopped <- server.Close() }()
			select {
			case err := <-stopped:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("native inbound stop did not cancel stalled handshake")
			}
		})
	}
}
