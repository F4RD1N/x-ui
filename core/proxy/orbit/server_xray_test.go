package orbit

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	policyapp "github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/app/router"
	statsapp "github.com/xtls/xray-core/app/stats"
	xnet "github.com/xtls/xray-core/common/net"
	xprotocol "github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/blackhole"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/orbit/internal/connectionkey"
	"github.com/xtls/xray-core/proxy/orbit/internal/protocol"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
)

func d11OrbitRealEcho(t *testing.T) (netip.AddrPort, netip.AddrPort, *atomic.Int64) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		tcp.Close()
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	accepted := new(atomic.Int64)
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				stop := context.AfterFunc(ctx, func() { conn.Close() })
				defer stop()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	go func() {
		defer wg.Done()
		data := make([]byte, 4096)
		for {
			n, remote, err := udp.ReadFromUDP(data)
			if err != nil {
				return
			}
			_, _ = udp.WriteToUDP(data[:n], remote)
		}
	}()
	t.Cleanup(func() { cancel(); tcp.Close(); udp.Close(); wg.Wait() })
	return netip.MustParseAddrPort(tcp.Addr().String()), netip.MustParseAddrPort(udp.LocalAddr().String()), accepted
}

func d11OrbitRealCore(t *testing.T, carrier string) (*core.Instance, Settings, string, int) {
	t.Helper()
	id := d11OrbitNewIdentity(t)
	blockedKey, _, err := connectionkey.Generate(id.pin)
	if err != nil {
		t.Fatal(err)
	}
	var port int
	if carrier == "quic" {
		listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			t.Fatal(err)
		}
		port = listener.LocalAddr().(*net.UDPAddr).Port
		listener.Close()
	} else {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port = listener.Addr().(*net.TCPAddr).Port
		listener.Close()
	}
	server := &ServerConfig{Transport: carrier, Tls: &Certificate{Certificate: []string{id.certificate}, Key: []string{id.privateKey}}, HandshakeTimeout: 3,
		Users: []*xprotocol.User{
			{Email: "allowed@example.invalid", Level: 7, Account: serial.ToTypedMessage(&Account{Key: id.key})},
			{Email: "blocked@example.invalid", Level: 7, Account: serial.ToTypedMessage(&Account{Key: blockedKey})},
		}}
	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&statsapp.Config{}),
			serial.ToTypedMessage(&policyapp.Config{Level: map[uint32]*policyapp.Policy{7: {Stats: &policyapp.Policy_Stats{UserUplink: true, UserDownlink: true}}},
				System: &policyapp.SystemPolicy{Stats: &policyapp.SystemPolicy_Stats{InboundUplink: true, InboundDownlink: true}}}),
			serial.ToTypedMessage(&router.Config{Rule: []*router.RoutingRule{{TargetTag: &router.RoutingRule_Tag{Tag: "allowed-direct"}, InboundTag: []string{"orbit-framework"}, UserEmail: []string{"allowed@example.invalid"}}}}),
		},
		Inbound: []*core.InboundHandlerConfig{{Tag: "orbit-framework",
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{Listen: xnet.NewIPOrDomain(xnet.LocalHostIP), PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(xnet.Port(port))}}}),
			ProxySettings:    serial.ToTypedMessage(server)}},
		// Blackhole is deliberately the default: only the authenticated email
		// and native inbound tag rule permits the real echo destination.
		Outbound: []*core.OutboundHandlerConfig{
			{Tag: "default-block", ProxySettings: serial.ToTypedMessage(&blackhole.Config{})},
			{Tag: "allowed-direct", ProxySettings: serial.ToTypedMessage(&freedom.Config{})},
		},
	}
	v, err := core.New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Start(); err != nil {
		v.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return v, Settings{Address: "127.0.0.1", Port: uint32(port), Key: id.key, Transport: carrier}, blockedKey, port
}

func d11OrbitRealClient(t *testing.T, v *core.Instance, s Settings) (*Client, *generation) {
	t.Helper()
	config, err := s.Config(3, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), core.XrayKey(1), v)
	c, err := New(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	g, err := c.session(dialCtx, new(netDialer))
	if err != nil {
		t.Fatal("real Xray inbound handshake:", err)
	}
	return c, g
}

func TestD11OrbitRealXrayRoutingUDPAndStats(t *testing.T) {
	for _, carrier := range []string{"tcp", "quic"} {
		t.Run(carrier, func(t *testing.T) {
			tcpTarget, udpTarget, accepted := d11OrbitRealEcho(t)
			v, settings, blockedKey, port := d11OrbitRealCore(t, carrier)
			_, g := d11OrbitRealClient(t, v, settings)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			stream, err := g.peer.Open(ctx, tcpTarget.Addr().String(), tcpTarget.Port())
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			_ = stream.SetDeadline(time.Now().Add(4 * time.Second))
			payload := bytes.Repeat([]byte("real-xray-routing"), 16384)
			written := make(chan error, 1)
			go func() { _, err := stream.Write(payload); written <- err }()
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(stream, got); err != nil {
				t.Fatal("real freedom routed response:", err)
			}
			if err := <-written; err != nil || !bytes.Equal(got, payload) {
				t.Fatal("real routed payload changed", err)
			}
			expectedAccepted := int64(1)
			if carrier == "quic" {
				half, err := g.peer.Open(ctx, tcpTarget.Addr().String(), tcpTarget.Port())
				if err != nil {
					t.Fatal(err)
				}
				_ = half.SetDeadline(time.Now().Add(3 * time.Second))
				message := []byte("QUIC request complete, response still readable")
				if _, err := half.Write(message); err != nil {
					t.Fatal(err)
				}
				closeWriter, ok := half.(interface{ CloseWrite() error })
				if !ok {
					t.Fatal("QUIC flow has no native independent FIN")
				}
				if err := closeWriter.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				response, err := io.ReadAll(half)
				half.Close()
				if err != nil || !bytes.Equal(response, message) {
					t.Fatal("native QUIC half-close lost response", err)
				}
				expectedAccepted++
			}
			association, err := g.udp.Open(netip.AddrPort{}, protocol.UDPKindData)
			if err != nil {
				t.Fatal(err)
			}
			defer association.Close()
			if err := association.Send(ctx, udpTarget, []byte("real UDP echo")); err != nil {
				t.Fatal(err)
			}
			packet, err := association.Receive(ctx)
			if err != nil || string(packet.Data) != "real UDP echo" || packet.Source != udpTarget {
				t.Fatal("real Xray UDP route or metadata failed", err)
			}

			settings.Key = blockedKey
			_, blocked := d11OrbitRealClient(t, v, settings)
			conn, err := blocked.peer.Open(ctx, tcpTarget.Addr().String(), tcpTarget.Port())
			if err == nil {
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				_, _ = conn.Write([]byte("must be blackholed"))
				var data [32]byte
				if n, _ := conn.Read(data[:]); n != 0 {
					t.Fatal("blocked user received destination payload")
				}
				conn.Close()
			}
			if accepted.Load() != expectedAccepted {
				t.Fatal("authenticated user routing did not enforce default blackhole")
			}
			manager := v.GetFeature(stats.ManagerType()).(stats.Manager)
			for _, name := range []string{"user>>>allowed@example.invalid>>>traffic>>>uplink", "user>>>allowed@example.invalid>>>traffic>>>downlink", "inbound>>>orbit-framework>>>traffic>>>uplink", "inbound>>>orbit-framework>>>traffic>>>downlink"} {
				counter := manager.GetCounter(name)
				if counter == nil || counter.Value() <= 0 {
					t.Fatalf("missing native Xray traffic counter %s", name)
				}
			}
			_ = v.Close()
			// The real proxyman worker must release the actual listening port.
			address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
			if carrier == "quic" {
				l, err := net.ListenPacket("udp", address)
				if err != nil {
					t.Fatal("native QUIC inbound leaked listening port:", err)
				}
				l.Close()
			} else {
				l, err := net.Listen("tcp", address)
				if err != nil {
					t.Fatal("native TCP inbound leaked listening port:", err)
				}
				l.Close()
			}
		})
	}
}
