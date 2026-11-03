package conf_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
)

// This matrix exercises the existing SS2022 single-user, multi-user and relay
// inbounds through real UDP listeners. No compatibility options are enabled.
func TestSS2022StockUDPPacketLifecycle(t *testing.T) {
	for _, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
		modes := []string{"single"}
		if method != "2022-blake3-chacha20-poly1305" {
			modes = append(modes, "multi", "relay")
		}
		for _, mode := range modes {
			t.Run(method+"/"+mode, func(t *testing.T) {
				size := 32
				if method == "2022-blake3-aes-128-gcm" {
					size = 16
				}
				key := func(v byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{v}, size)) }
				serverKey, firstKey, secondKey := key(17), key(29), key(47)
				port := ss2022UDPAvailablePort(t)
				settings := map[string]any{"method": method, "password": serverKey, "network": "udp", "email": "single@local.invalid"}
				inbounds := []any{}
				passwords := []string{serverKey}
				switch mode {
				case "multi":
					settings["clients"] = []any{map[string]any{"password": firstKey, "email": "first@local.invalid"}, map[string]any{"password": secondKey, "email": "second@local.invalid"}}
					passwords = []string{serverKey + ":" + firstKey, serverKey + ":" + secondKey}
				case "relay":
					finalPort := ss2022UDPAvailablePort(t)
					// The identity key selects the final server; it is also that server's PSK.
					settings["clients"] = []any{map[string]any{"password": firstKey, "address": "127.0.0.1", "port": finalPort, "email": "relay@local.invalid"}}
					inbounds = append(inbounds, map[string]any{"tag": "ss-final", "listen": "127.0.0.1", "port": finalPort, "protocol": "shadowsocks", "settings": map[string]any{"method": method, "password": firstKey, "network": "udp"}})
					passwords = []string{serverKey + ":" + firstKey}
				}
				inbounds = append(inbounds, map[string]any{"tag": "ss-entry", "listen": "127.0.0.1", "port": port, "protocol": "shadowsocks", "settings": settings})
				server := startNativeCore(t, map[string]any{
					"log": map[string]any{"loglevel": "none"}, "inbounds": inbounds,
					// A default block makes successful echo depend on the real inbound route.
					"outbounds": []any{map[string]any{"tag": "blocked", "protocol": "blackhole"}, map[string]any{"tag": "routed", "protocol": "freedom"}},
					"routing":   map[string]any{"rules": []any{map[string]any{"type": "field", "inboundTag": []string{"ss-entry", "ss-final"}, "network": "udp", "outboundTag": "routed"}}},
				})
				targets := []*net.UDPAddr{ss2022UDPEcho(t), ss2022UDPEcho(t)}
				for user, password := range passwords {
					t.Run(fmt.Sprintf("user-%d", user), func(t *testing.T) {
						client := startNativeCore(t, map[string]any{"log": map[string]any{"loglevel": "none"}, "outbounds": []any{map[string]any{"protocol": "shadowsocks", "settings": map[string]any{"address": "127.0.0.1", "port": port, "method": method, "password": password}}}})
						for n, target := range targets {
							t.Run(fmt.Sprintf("destination-%d", n), func(t *testing.T) {
								ctx, cancel := context.WithCancel(context.Background())
								defer cancel()
								conn, err := core.Dial(ctx, client, xnet.UDPDestination(xnet.LocalHostIP, xnet.Port(target.Port)))
								if err != nil {
									t.Fatal(err)
								}
								defer conn.Close()
								// Send a burst before reading so the bridge sees queued datagrams.
								// Different lengths and identifiers detect merges, drops and duplicates.
								want := make(map[string]bool)
								for packet := 0; packet < 8; packet++ {
									payload := append([]byte(fmt.Sprintf("user=%d,target=%d,packet=%d:", user, n, packet)), bytes.Repeat([]byte{byte(packet + 1)}, 31+packet*173)...)
									want[string(payload)] = true
									if written, err := conn.Write(payload); err != nil || written != len(payload) {
										t.Fatalf("UDP write: %d/%d %v", written, len(payload), err)
									}
								}
								for len(want) > 0 {
									got, err := ss2022UDPRead(t, conn)
									if err != nil {
										t.Fatal("routed UDP read:", err)
									}
									if !want[string(got)] {
										t.Fatalf("changed, merged or duplicate UDP payload (%d bytes)", len(got))
									}
									delete(want, string(got))
								}
								// Exercise both close and context cancellation while the transport is
								// blocked waiting for another datagram, after genuine encrypted traffic.
								blocked := make(chan error, 1)
								go func() { b := make([]byte, 2048); _, err := conn.Read(b); blocked <- err }()
								if n == 0 {
									conn.Close()
								} else {
									cancel()
								}
								select {
								case err := <-blocked:
									if err == nil {
										t.Fatal("idle UDP read succeeded after shutdown")
									}
								case <-time.After(3 * time.Second):
									conn.Close()
									t.Fatal("idle UDP read did not end after close/cancellation")
								}
							})
						}
						ss2022CloseCore(t, client)
					})
				}
				ss2022CloseCore(t, server)
				// Closing a real inbound must release its UDP listening socket promptly.
				rebound, err := net.ListenPacket("udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
				if err != nil {
					t.Fatalf("server retained UDP listener after close: %v", err)
				}
				rebound.Close()
			})
		}
	}
}

func ss2022UDPAvailablePort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := c.LocalAddr().(*net.UDPAddr).Port
	c.Close()
	return p
}

func ss2022UDPEcho(t *testing.T) *net.UDPAddr {
	t.Helper()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var packets atomic.Int64
	go func() {
		defer close(done)
		b := make([]byte, 65535)
		for {
			n, a, err := c.ReadFrom(b)
			if err != nil {
				return
			}
			packets.Add(1)
			if _, err = c.WriteTo(b[:n], a); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		c.Close()
		<-done
		if packets.Load() == 0 {
			t.Error("UDP echo never received routed traffic")
		}
	})
	return c.LocalAddr().(*net.UDPAddr)
}

func ss2022UDPRead(t *testing.T, c net.Conn) ([]byte, error) {
	t.Helper()
	type result struct {
		data []byte
		err  error
	}
	done := make(chan result, 1)
	go func() { b := make([]byte, 4096); n, err := c.Read(b); done <- result{b[:n], err} }()
	select {
	case r := <-done:
		return r.data, r.err
	case <-time.After(5 * time.Second):
		c.Close()
		t.Fatal("routed UDP echo timed out")
		return nil, context.DeadlineExceeded
	}
}

func ss2022CloseCore(t *testing.T, c *core.Instance) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- c.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("core shutdown:", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("core shutdown hung with idle UDP sessions")
	}
}
