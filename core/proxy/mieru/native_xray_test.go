//go:build !without_native_protocols

package mieru_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
	socksdial "golang.org/x/net/proxy"
)

func xrayFreePort(t *testing.T, network string) int {
	t.Helper()
	if network == "udp" {
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		p := pc.LocalAddr().(*net.UDPAddr).Port
		_ = pc.Close()
		return p
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return p
}
func TestMieruRealXrayListenersAndRouting(t *testing.T) {
	for _, underlay := range []string{"tcp", "udp"} {
		for _, custom := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/custom=%v", underlay, custom), func(t *testing.T) {
				tcp, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer tcp.Close()
				tcpDone := make(chan struct{})
				go func() {
					defer close(tcpDone)
					for {
						conn, e := tcp.Accept()
						if e != nil {
							return
						}
						go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
					}
				}()
				udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer udp.Close()
				udpDone := make(chan struct{})
				go func() {
					defer close(udpDone)
					b := make([]byte, 65535)
					for {
						n, from, e := udp.ReadFrom(b)
						if e != nil {
							return
						}
						_, _ = udp.WriteTo(b[:n], from)
					}
				}()
				serverPort, socksPort, udpPort := xrayFreePort(t, underlay), xrayFreePort(t, "tcp"), xrayFreePort(t, "udp")
				username := "synthetic-xray-user"
				if custom {
					username = "a3ac6533-7c27-45c4-93f2-9192745e218b"
				}
				cfg := map[string]any{
					"log": map[string]any{"loglevel": "none"},
					"inbounds": []any{
						map[string]any{"tag": "native-in", "listen": "127.0.0.1", "port": serverPort, "protocol": "mieru", "settings": map[string]any{"transport": underlay, "clients": []any{map[string]any{"username": username, "password": "synthetic-xray-secret", "email": "real-worker@test", "uuidMetadataTrailer": custom}}}},
						map[string]any{"tag": "socks-in", "listen": "127.0.0.1", "port": socksPort, "protocol": "socks", "settings": map[string]any{"auth": "noauth"}},
						map[string]any{"tag": "udp-in", "listen": "127.0.0.1", "port": udpPort, "protocol": "dokodemo-door", "settings": map[string]any{"network": "udp", "address": "127.0.0.1", "port": udp.LocalAddr().(*net.UDPAddr).Port}},
					},
					"outbounds": []any{
						map[string]any{"tag": "through-mieru", "protocol": "mieru", "settings": map[string]any{"address": "127.0.0.1", "port": serverPort, "transport": underlay, "username": username, "password": "synthetic-xray-secret", "uuidMetadataTrailer": custom}},
						map[string]any{"tag": "direct", "protocol": "freedom", "settings": map[string]any{}},
					},
					"routing": map[string]any{"rules": []any{map[string]any{"type": "field", "inboundTag": []string{"native-in"}, "outboundTag": "direct"}, map[string]any{"type": "field", "inboundTag": []string{"socks-in", "udp-in"}, "outboundTag": "through-mieru"}}},
				}
				raw, err := json.Marshal(cfg)
				if err != nil {
					t.Fatal(err)
				}
				instance, err := core.StartInstance("json", raw)
				if err != nil {
					t.Fatal(err)
				}
				closed := false
				defer func() {
					if !closed {
						_ = instance.Close()
					}
				}()
				dialer, err := socksdial.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), nil, &net.Dialer{Timeout: 3 * time.Second})
				if err != nil {
					t.Fatal(err)
				}
				conn, err := dialer.Dial("tcp", tcp.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
				want := bytes.Repeat([]byte("real-xray-routed-mieru\x00"), 2048)
				wrote := make(chan error, 1)
				go func() { _, e := conn.Write(want); wrote <- e }()
				got := make([]byte, len(want))
				if _, err = io.ReadFull(conn, got); err != nil {
					conn.Close()
					t.Fatal(err)
				}
				if err = <-wrote; err != nil {
					conn.Close()
					t.Fatal(err)
				}
				if !bytes.Equal(want, got) {
					conn.Close()
					t.Fatal("TCP corrupt through real Xray listeners")
				}
				conn.Close()
				packet, err := net.Dial("udp4", fmt.Sprintf("127.0.0.1:%d", udpPort))
				if err != nil {
					t.Fatal(err)
				}
				defer packet.Close()
				_ = packet.SetDeadline(time.Now().Add(8 * time.Second))
				want = []byte("real Xray UDP routing and packet boundaries")
				if _, err = packet.Write(want); err != nil {
					t.Fatal(err)
				}
				got = make([]byte, 2048)
				n, err := packet.Read(got)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(want, got[:n]) {
					t.Fatal("UDP corrupt through real Xray listeners")
				}
				// Closing the real inbound manager must terminate its internal handlers.
				closed = true
				if err = instance.Close(); err != nil {
					t.Fatal(err)
				}
				tcp.Close()
				udp.Close()
				<-tcpDone
				<-udpDone
			})
		}
	}
}
