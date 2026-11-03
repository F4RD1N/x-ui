package inbound_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/vmess"
	"github.com/xtls/xray-core/proxy/vmess/inbound"
	"github.com/xtls/xray-core/proxy/vmess/outbound"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
)

func rawCoreStart(t *testing.T, config *core.Config) *core.Instance {
	t.Helper()
	config.App = []*serial.TypedMessage{
		serial.ToTypedMessage(&dispatcher.Config{}),
		serial.ToTypedMessage(&proxyman.InboundConfig{}),
		serial.ToTypedMessage(&proxyman.OutboundConfig{}),
	}
	v, err := core.New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err = v.Start(); err != nil {
		v.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := v.Close(); err != nil {
			t.Error(err)
		}
	})
	return v
}

// TestRawUUIDAuthCoreLoopback uses actual inbound/outbound handlers, the
// dispatcher and freedom outbound. All sockets and payloads stay on loopback.
func TestRawUUIDAuthCoreLoopback(t *testing.T) {
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); c.SetDeadline(time.Now().Add(20 * time.Second)); io.Copy(c, c) }()
		}
	}()
	tcpDestination := net.TCPDestination(net.LocalHostIP, net.Port(listener.Addr().(*stdnet.TCPAddr).Port))
	packetConn, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { packetConn.Close() })
	go func() {
		b := make([]byte, 2048)
		for {
			n, addr, e := packetConn.ReadFrom(b)
			if e != nil {
				return
			}
			if _, e = packetConn.WriteTo(b[:n], addr); e != nil {
				return
			}
		}
	}()
	udpDestination := net.UDPDestination(net.LocalHostIP, net.Port(packetConn.LocalAddr().(*stdnet.UDPAddr).Port))
	reservation, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverPort := net.Port(reservation.Addr().(*stdnet.TCPAddr).Port)
	reservation.Close()
	const id = "00112233-4455-6677-8899-aabbccddeeff"
	rawCoreStart(t, &core.Config{
		Inbound: []*core.InboundHandlerConfig{{
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{Listen: net.NewIPOrDomain(net.LocalHostIP), PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}}}),
			ProxySettings: serial.ToTypedMessage(&inbound.Config{User: []*protocol.User{
				{Email: "standard", Account: serial.ToTypedMessage(&vmess.Account{Id: id})},
				{Email: "raw", Account: serial.ToTypedMessage(&vmess.Account{Id: id, RawUuidAuth: true})},
			}}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{ProxySettings: serial.ToTypedMessage(&freedom.Config{})}},
	})
	for _, raw := range []bool{false, true} {
		for _, security := range []protocol.SecurityType{protocol.SecurityType_AES128_GCM, protocol.SecurityType_CHACHA20_POLY1305, protocol.SecurityType_NONE} {
			t.Run(fmt.Sprintf("raw=%v/%v", raw, security), func(t *testing.T) {
				client := rawCoreStart(t, &core.Config{Outbound: []*core.OutboundHandlerConfig{{ProxySettings: serial.ToTypedMessage(&outbound.Config{Receiver: &protocol.ServerEndpoint{
					Address: net.NewIPOrDomain(net.LocalHostIP), Port: uint32(serverPort),
					User: &protocol.User{Account: serial.ToTypedMessage(&vmess.Account{Id: id, RawUuidAuth: raw, SecuritySettings: &protocol.SecurityConfig{Type: security}})},
				}})}}})
				for _, dest := range []net.Destination{tcpDestination, udpDestination} {
					t.Run(dest.Network.String(), func(t *testing.T) {
						for attempt := 0; attempt < 2; attempt++ {
							ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
							conn, e := core.Dial(ctx, client, dest)
							if e != nil {
								cancel()
								t.Fatal(e)
							}
							size := 16 * 1024
							if dest.Network == net.Network_UDP {
								size = 1024
							}
							payload := bytes.Repeat([]byte{byte(attempt + 1)}, size)
							if _, e = conn.Write(payload); e == nil {
								var got = make([]byte, len(payload))
								_, e = io.ReadFull(conn, got)
								if e == nil && !bytes.Equal(got, payload) {
									e = fmt.Errorf("payload corrupted")
								}
							}
							conn.Close()
							cancel()
							if e != nil {
								t.Fatalf("attempt %d: %v", attempt, e)
							}
						}
					})
				}
			})
		}
	}
}
