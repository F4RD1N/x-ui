package conf_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
)

type shadowTLSTap struct {
	mu   sync.Mutex
	data []byte
}

func (c *shadowTLSTap) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.data)+len(p) < 2<<20 {
		c.data = append(c.data, p...)
	}
	return len(p), nil
}
func (c *shadowTLSTap) contains(p []byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Contains(c.data, p)
}

func shadowTLSTestTap(t *testing.T, target string) (int, *shadowTLSTap) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	capture := new(shadowTLSTap)
	var mu sync.Mutex
	active := make(map[net.Conn]bool)
	closing := false
	var wg sync.WaitGroup
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			active[conn] = true
			wg.Add(1)
			mu.Unlock()
			go func() {
				defer wg.Done()
				defer conn.Close()
				defer func() { mu.Lock(); delete(active, conn); mu.Unlock() }()
				peer, err := net.DialTimeout("tcp", target, time.Second)
				if err != nil {
					return
				}
				defer peer.Close()
				mu.Lock()
				if closing {
					mu.Unlock()
					return
				}
				active[peer] = true
				mu.Unlock()
				defer func() { mu.Lock(); delete(active, peer); mu.Unlock() }()
				done := make(chan struct{})
				go func() {
					_, _ = io.Copy(io.MultiWriter(capture, peer), conn)
					if tcp, ok := peer.(*net.TCPConn); ok {
						_ = tcp.CloseWrite()
					}
					close(done)
				}()
				_, _ = io.Copy(conn, peer)
				conn.Close()
				peer.Close()
				<-done
			}()
		}
	}()
	t.Cleanup(func() {
		l.Close()
		<-stopped
		mu.Lock()
		closing = true
		for c := range active {
			c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return l.Addr().(*net.TCPAddr).Port, capture
}

func shadowTLSUDPEcho(t *testing.T) (int, *atomic.Int64) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	count := new(atomic.Int64)
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 65535)
		for {
			n, addr, err := conn.ReadFrom(b)
			if err != nil {
				return
			}
			count.Add(1)
			_, _ = conn.WriteTo(b[:n], addr)
		}
	}()
	t.Cleanup(func() { conn.Close(); <-done })
	return conn.LocalAddr().(*net.UDPAddr).Port, count
}

func TestNativeXrayShadowTLSShadowsocks(t *testing.T) {
	cases := []struct {
		method     string
		multi      bool
		uotVersion int
		uuid       bool
	}{
		{"aes-128-gcm", true, 0, false}, {"aes-256-gcm", true, 0, false}, {"chacha20-ietf-poly1305", true, 0, false}, {"xchacha20-ietf-poly1305", true, 0, false},
		{"2022-blake3-aes-128-gcm", true, 2, false}, {"2022-blake3-aes-256-gcm", true, 1, false}, {"2022-blake3-chacha20-poly1305", false, 2, false},
		{"2022-blake3-aes-128-gcm", true, 2, true},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s-uot%d-uuid%v", tc.method, tc.uotVersion, tc.uuid), func(t *testing.T) {
			camouflage := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("camouflage")) }))
			camouflage.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
			camouflage.StartTLS()
			t.Cleanup(camouflage.Close)
			_, hsPortString, _ := net.SplitHostPort(camouflage.Listener.Addr().String())
			hsPort, _ := strconv.Atoi(hsPortString)
			serverPort := availablePort(t)
			tcpPort, tcpHits := nativeEchoTarget(t)
			blockedPort, blockedHits := nativeEchoTarget(t)
			udpPort, _ := shadowTLSUDPEcho(t)
			blockedUDP, blockedUDPHits := shadowTLSUDPEcho(t)
			const email = "outer@example.invalid"
			const outerPassword = "outer-auth-password"
			const uuidKey = "00112233-4455-6677-8899-aabbccddeeff"
			keySize := 32
			if strings.Contains(tc.method, "128") {
				keySize = 16
			}
			serverKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{31}, keySize))
			userKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{47}, keySize))
			innerSettings := map[string]interface{}{"network": "tcp"}
			clientPassword := "inner-aead-password"
			if strings.HasPrefix(tc.method, "2022-") {
				innerSettings["method"], innerSettings["password"] = tc.method, serverKey
				clientPassword = serverKey
				if tc.multi {
					if tc.uuid {
						userKey = uuidKey
					}
					innerSettings["clients"] = []interface{}{map[string]interface{}{"email": email, "password": userKey, "uuidIdentityKeys": tc.uuid}}
					clientPassword = serverKey + ":" + userKey
				} else {
					innerSettings["email"] = email
				}
			} else {
				innerSettings["clients"] = []interface{}{map[string]interface{}{"email": email, "method": tc.method, "password": clientPassword}}
			}
			startNativeCore(t, map[string]interface{}{
				"log": map[string]interface{}{"loglevel": "error"},
				"inbounds": []interface{}{map[string]interface{}{"tag": "carrier-in", "listen": "127.0.0.1", "port": serverPort, "protocol": "shadowtls", "settings": map[string]interface{}{
					"version": 3, "strict": true, "handshake": map[string]interface{}{"address": "127.0.0.1", "port": hsPort}, "clients": []interface{}{map[string]interface{}{"email": email, "password": outerPassword}}, "inner": map[string]interface{}{"protocol": "shadowsocks", "settings": innerSettings}}}},
				"outbounds": []interface{}{map[string]interface{}{"tag": "direct", "protocol": "freedom"}, map[string]interface{}{"tag": "block", "protocol": "blackhole"}},
				"routing":   map[string]interface{}{"rules": []interface{}{map[string]interface{}{"type": "field", "port": fmt.Sprintf("%d,%d", blockedPort, blockedUDP), "user": []interface{}{email}, "outboundTag": "block"}}},
			})
			tapPort, tap := shadowTLSTestTap(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(serverPort)))
			newClient := func(password string) *core.Instance {
				return startNativeCore(t, map[string]interface{}{"log": map[string]interface{}{"loglevel": "error"}, "outbounds": []interface{}{
					map[string]interface{}{"tag": "proxy", "protocol": "shadowsocks", "settings": map[string]interface{}{"address": "127.0.0.1", "port": serverPort, "method": tc.method, "password": password, "uuidIdentityKeys": tc.uuid, "uot": tc.uotVersion != 0, "uotVersion": tc.uotVersion}, "proxySettings": map[string]interface{}{"tag": "outer", "transportLayer": true}},
					map[string]interface{}{"tag": "outer", "protocol": "shadowtls", "settings": map[string]interface{}{"address": "127.0.0.1", "port": tapPort, "version": 3, "strict": true, "password": outerPassword, "serverName": "example.com", "allowInsecure": true}},
				}})
			}
			client := newClient(clientPassword)
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			conn, err := core.Dial(ctx, client, xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(tcpPort)))
			if err != nil {
				t.Fatal(err)
			}
			stopPositive := context.AfterFunc(ctx, func() { _ = conn.Close() })
			defer stopPositive()
			marker := []byte("SHADOWTLS_INNER_ENCRYPTION_FIXTURE_MUST_NOT_APPEAR_ON_WIRE_")
			payload := bytes.Repeat(marker, 1700)
			written := make(chan error, 1)
			go func() { _, err := conn.Write(payload); written <- err }()
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, got); err != nil {
				t.Fatal(err)
			}
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			conn.Close()
			if !bytes.Equal(got, payload) {
				t.Fatal("encrypted TCP payload mismatch")
			}
			if tap.contains(marker) {
				t.Fatal("application plaintext appeared in captured carrier traffic")
			}
			blocked, err := core.Dial(ctx, client, xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(blockedPort)))
			if err != nil {
				t.Fatal(err)
			}
			_, _ = blocked.Write([]byte("blocked"))
			stopBlocked := time.AfterFunc(400*time.Millisecond, func() { _ = blocked.Close() })
			_, err = blocked.Read(make([]byte, 1))
			stopBlocked.Stop()
			blocked.Close()
			if err == nil || blockedHits.Load() != 0 {
				t.Fatal("encrypted inner bypassed user routing")
			}
			if tc.uotVersion != 0 {
				udp, err := core.Dial(ctx, client, xnet.UDPDestination(xnet.LocalHostIP, xnet.Port(udpPort)))
				if err != nil {
					t.Fatal(err)
				}
				stopUDP := context.AfterFunc(ctx, func() { _ = udp.Close() })
				defer stopUDP()
				for _, size := range []int{1, 512, 1400, 4096, 8192} {
					p := bytes.Repeat([]byte{byte(size)}, size)
					if _, err := udp.Write(p); err != nil {
						t.Fatal(err)
					}
					b := make([]byte, 65535)
					n, err := udp.Read(b)
					if err != nil {
						t.Fatalf("UoT%d packet%d: %v", tc.uotVersion, size, err)
					}
					if !bytes.Equal(p, b[:n]) {
						t.Fatalf("UoT%d boundary mismatch size%d got%d", tc.uotVersion, size, n)
					}
				}
				udp.Close()
				blockCtx, blockCancel := context.WithTimeout(ctx, 400*time.Millisecond)
				bad, err := core.Dial(blockCtx, client, xnet.UDPDestination(xnet.LocalHostIP, xnet.Port(blockedUDP)))
				if err != nil {
					t.Fatal(err)
				}
				_, _ = bad.Write([]byte("blocked-udp"))
				stopBad := time.AfterFunc(time.Second, func() { _ = bad.Close() })
				_, err = bad.Read(make([]byte, 1))
				stopBad.Stop()
				bad.Close()
				blockCancel()
				if err == nil || blockedUDPHits.Load() != 0 {
					t.Fatal("UoT bypassed UDP routing")
				}
			}
			before := tcpHits.Load()
			wrong := clientPassword + "-wrong"
			if strings.HasPrefix(tc.method, "2022-") {
				wrong = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{99}, keySize))
				if tc.multi {
					wrong = serverKey + ":" + wrong
				}
				if tc.uuid {
					wrong = serverKey + ":11112233-4455-6677-8899-aabbccddeeff"
				}
			}
			badClient := newClient(wrong)
			badCtx, badCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer badCancel()
			bad, err := core.Dial(badCtx, badClient, xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(tcpPort)))
			if err != nil {
				t.Fatal(err)
			}
			_, _ = bad.Write([]byte("bad-inner-key"))
			stopBad := time.AfterFunc(time.Second, func() { _ = bad.Close() })
			_, err = bad.Read(make([]byte, 1))
			stopBad.Stop()
			bad.Close()
			if err == nil || tcpHits.Load() != before {
				t.Fatal("wrong inner credential reached destination")
			}
		})
	}
}
