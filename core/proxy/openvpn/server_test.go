package openvpn

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strings"
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
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/blackhole"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/client"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/clientproof"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/handshake"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/options"
)

type nativePKI struct{ ca, serverCert, serverKey, clientCert, clientKey string }

func makeNativePKI(t testing.TB) nativePKI {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "OpenVPN test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	ca, e = x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	leaf := func(serial int64, name string, usage x509.ExtKeyUsage) (string, string) {
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		c := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{usage}, KeyUsage: x509.KeyUsageDigitalSignature}
		b, e := x509.CreateCertificate(rand.Reader, c, ca, &k.PublicKey, key)
		if e != nil {
			t.Fatal(e)
		}
		kb, e := x509.MarshalPKCS8PrivateKey(k)
		if e != nil {
			t.Fatal(e)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}))
	}
	p := nativePKI{ca: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
	p.serverCert, p.serverKey = leaf(2, "server", x509.ExtKeyUsageServerAuth)
	p.clientCert, p.clientKey = leaf(3, "client", x509.ExtKeyUsageClientAuth)
	return p
}
func nativeSettings(p nativePKI) ServerSettings {
	return ServerSettings{Certificates: ServerCertificates{CA: p.ca, Cert: p.serverCert, Key: p.serverKey}, Clients: []ServerUser{{Email: "native@test", CommonName: "client", Level: 1}}}
}
func serverJSON(t testing.TB, s ServerSettings) []byte {
	t.Helper()
	b, e := json.Marshal(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestNativeServerSettings(t *testing.T) {
	p := makeNativePKI(t)
	base := nativeSettings(p)
	b := serverJSON(t, base)
	parsed, e := ParseServerSettings(b)
	if e != nil {
		t.Fatal(e)
	}
	if parsed.Network != "udp" || parsed.Limits.MaxSessions != 128 || parsed.Tunnel.MTU != 1400 {
		t.Fatal("bad defaults")
	}
	cases := []struct {
		name string
		edit func(*ServerSettings)
	}{
		{"duplicate CN", func(s *ServerSettings) {
			s.Clients = append(s.Clients, ServerUser{Email: "other@test", CommonName: "client"})
		}},
		{"unknown network", func(s *ServerSettings) { s.Network = "icmp" }}, {"bad password", func(s *ServerSettings) { s.Clients[0].Username = "name" }},
		{"proof required", func(s *ServerSettings) { s.ClientProof.Required = true }}, {"proof malformed", func(s *ServerSettings) { s.Clients[0].ClientProof = &ServerUserProof{KeyID: "ok", Key: "aa"} }},
		{"keyDirection without wrapper", func(s *ServerSettings) { v := 1; s.Certificates.KeyDirection = &v }}, {"bad v2 key", func(s *ServerSettings) { s.Certificates.TLSCryptV2 = "bad" }},
		{"pool too small", func(s *ServerSettings) { s.Tunnel.IPv4 = "10.0.0.0/30" }}, {"ipv6 pool too small", func(s *ServerSettings) { s.Tunnel.IPv6 = "fd00::/120"; s.Limits.MaxSessions = 300 }},
		{"MTU too big", func(s *ServerSettings) { s.Tunnel.MTU = 9000 }}, {"bad cipher", func(s *ServerSettings) { s.Crypto.DataCiphers = []string{"none"} }},
		{"duplicate cipher alias", func(s *ServerSettings) { s.Crypto.DataCiphers = []string{"AES256", "AES-256-CBC"} }},
		{"duplicate cipher", func(s *ServerSettings) { s.Crypto.DataCiphers = []string{"AES-256-GCM", "AES-256-GCM"} }}, {"bad certificate", func(s *ServerSettings) { s.Certificates.Cert = p.clientCert }},
		{"invalid max sessions", func(s *ServerSettings) { s.Limits.MaxSessions = 9999 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := nativeSettings(p)
			tc.edit(&s)
			if _, e := ParseServerSettings(serverJSON(t, s)); e == nil {
				t.Fatal("accepted invalid config")
			}
		})
	}
	for _, bad := range []string{string(b) + "{}", strings.Replace(string(b), "{", "{\"network\":\"udp\",\"network\":\"tcp\",", 1), strings.Replace(string(b), "{", "{\"unknown\":true,", 1)} {
		if _, e := ParseServerSettings([]byte(bad)); e == nil {
			t.Fatal("accepted invalid JSON")
		}
	}
}
func TestNativeServerSourceValidation(t *testing.T) {
	v4 := netip.MustParseAddr("10.88.0.2")
	v6 := netip.MustParseAddr("fd88::2")
	a := make([]byte, 20)
	a[0] = 0x45
	a[3] = 20
	copy(a[12:16], v4.AsSlice())
	if !validClientPacket(a, v4, v6, 1400) {
		t.Fatal("valid IPv4 rejected")
	}
	a[15]++
	if validClientPacket(a, v4, v6, 1400) {
		t.Fatal("IPv4 spoof admitted")
	}
	b := make([]byte, 40)
	b[0] = 0x60
	copy(b[8:24], v6.AsSlice())
	if !validClientPacket(b, v4, v6, 1400) {
		t.Fatal("valid IPv6 rejected")
	}
	b[23]++
	if validClientPacket(b, v4, v6, 1400) {
		t.Fatal("IPv6 spoof admitted")
	}
	for _, pkt := range [][]byte{nil, {0x45}, {0x40}, make([]byte, 1401)} {
		if validClientPacket(pkt, v4, v6, 1400) {
			t.Fatal("malformed packet accepted")
		}
	}
}
func TestNativeServerLeaseAndUserLifecycle(t *testing.T) {
	sconf := nativeSettings(makeNativePKI(t))
	sconf.Limits = ServerLimits{MaxSessions: 2, MaxSessionsPerIP: 1}
	s, e := newServer(&ServerConfig{Settings: serverJSON(t, sconf)}, policy.DefaultManager{})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, e := s.acquire(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, cancel)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.acquire(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2}, func() {}); e == nil {
		t.Fatal("per-IP cap ignored")
	}
	p.user = sconf.Clients[0]
	if e = s.RemoveUser(ctx, "native@test"); e != nil {
		t.Fatal(e)
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("removed user's session not cancelled")
	}
	s.release(p)
	u := &protocol.MemoryUser{Email: "new@test", Account: &MemoryServerAccount{User: ServerUser{Email: "new@test", CommonName: "new"}}}
	if e = s.AddUser(context.Background(), u); e != nil {
		t.Fatal(e)
	}
	if s.GetUsersCount(context.Background()) != 1 {
		t.Fatal("wrong users count")
	}
	if e = s.AddUser(context.Background(), u); e == nil {
		t.Fatal("duplicate user accepted")
	}
}
func nativeClient(t testing.TB, p nativePKI, network string, port int, proof *clientproof.Key) (*client.Client, *tunnel) {
	t.Helper()
	text := fmt.Sprintf("client\ndev tun\nremote 127.0.0.1 %d %s\nremote-cert-tls server\ncipher AES-256-GCM\ndata-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305\nauth SHA256\n<ca>\n%s</ca>\n<cert>\n%s</cert>\n<key>\n%s</key>\n", port, network, p.ca, p.clientCert, p.clientKey)
	opt, e := options.Parse(text)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	c, e := client.Dial(ctx, client.Config{Options: opt, ClientProof: proof, HandshakeTimeout: 4 * time.Second, Dial: (&net.Dialer{}).DialContext})
	if e != nil {
		t.Fatal(e)
	}
	tun, e := newTunnel(ctx, cancel, c, 1400)
	if e != nil {
		c.Close()
		t.Fatal(e)
	}
	tun.start()
	t.Cleanup(tun.close)
	return c, tun
}
func nativeCore(t *testing.T, s ServerSettings, blockPort int, sniff bool) (*core.Instance, *Server, int) {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	cfg := &core.Config{App: []*serial.TypedMessage{serial.ToTypedMessage(&dispatcher.Config{}), serial.ToTypedMessage(&proxyman.InboundConfig{}), serial.ToTypedMessage(&proxyman.OutboundConfig{}), serial.ToTypedMessage(&policyapp.Config{Level: map[uint32]*policyapp.Policy{1: {Stats: &policyapp.Policy_Stats{UserUplink: true, UserDownlink: true, UserOnline: true}}}}), serial.ToTypedMessage(&statsapp.Config{}), serial.ToTypedMessage(&router.Config{Rule: []*router.RoutingRule{{TargetTag: &router.RoutingRule_Tag{Tag: "block"}, InboundTag: []string{"openvpn-test"}, UserEmail: []string{"native@test"}, PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(xnet.Port(blockPort))}}}}})}, Inbound: []*core.InboundHandlerConfig{{Tag: "openvpn-test", ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{Listen: xnet.NewIPOrDomain(xnet.LocalHostIP), PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(xnet.Port(port))}}, SniffingSettings: &proxyman.SniffingConfig{Enabled: sniff, DestinationOverride: []string{"http", "tls"}, RouteOnly: true}}), ProxySettings: serial.ToTypedMessage(&ServerConfig{Settings: serverJSON(t, s)})}}, Outbound: []*core.OutboundHandlerConfig{{Tag: "direct", ProxySettings: serial.ToTypedMessage(&freedom.Config{})}, {Tag: "block", ProxySettings: serial.ToTypedMessage(&blackhole.Config{})}}}
	v, e := core.New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	if e = v.Start(); e != nil {
		v.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { v.Close() })
	h, e := v.GetFeature(inbound.ManagerType()).(inbound.Manager).GetHandler(context.Background(), "openvpn-test")
	if e != nil {
		t.Fatal(e)
	}
	// The inbound Manager uses a proxyman handler; locate the native instance via
	// the explicit GetInbound interface rather than relying on implementation type.
	var srv *Server
	if g, ok := h.(interface{ GetInbound() proxy.Inbound }); ok {
		srv = g.GetInbound().(*Server)
	}
	if srv == nil {
		t.Fatal("native inbound unavailable")
	}
	return v, srv, port
}

func TestNativeServerRoutedPayloads(t *testing.T) {
	p := makeNativePKI(t)
	tcpEcho, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer tcpEcho.Close()
	go func() {
		for {
			c, e := tcpEcho.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	udpEcho, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer udpEcho.Close()
	go func() {
		b := make([]byte, 8192)
		for {
			n, a, e := udpEcho.ReadFromUDP(b)
			if e != nil {
				return
			}
			udpEcho.WriteToUDP(b[:n], a)
		}
	}()
	denied, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer denied.Close()
	var deniedAccepted atomic.Int64
	go func() {
		for {
			c, e := denied.Accept()
			if e != nil {
				return
			}
			deniedAccepted.Add(1)
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	deniedTarget := netip.MustParseAddrPort(denied.Addr().String())
	tcpTarget := netip.MustParseAddrPort(tcpEcho.Addr().String())
	udpTarget := netip.MustParseAddrPort(udpEcho.LocalAddr().String())
	for _, network := range []string{"tcp", "udp"} {
		for _, protected := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/proof=%t", network, protected), func(t *testing.T) {
				settings := nativeSettings(p)
				settings.Network = network
				settings.RenegotiationSeconds = 1
				settings.Tunnel.IPv6 = "fd88::/64"
				var proof *clientproof.Key
				if protected {
					secret := bytes.Repeat([]byte{0xa5}, 32)
					settings.ClientProof.Required = true
					settings.Clients[0].ClientProof = &ServerUserProof{KeyID: "client-key", Key: hex.EncodeToString(secret)}
					proof, _ = clientproof.New("client-key", secret)
				}
				v, srv, port := nativeCore(t, settings, int(deniedTarget.Port()), true)
				clientSession, tun := nativeClient(t, p, network, port, proof)
				for round := 0; round < 3; round++ {
					ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
					c, e := tun.net.DialContextTCPAddrPort(ctx, tcpTarget)
					cancel()
					if e != nil {
						t.Fatal(e)
					}
					c.SetDeadline(time.Now().Add(4 * time.Second))
					payload := bytes.Repeat([]byte("native routed tcp "), 10000)
					go func() { _, _ = c.Write(payload) }()
					got := make([]byte, len(payload))
					_, e = io.ReadFull(c, got)
					c.Close()
					if e != nil || !bytes.Equal(got, payload) {
						t.Fatalf("TCP payload: %v", e)
					}
					u, e := tun.net.DialUDPAddrPort(netip.AddrPort{}, udpTarget)
					if e != nil {
						t.Fatal(e)
					}
					u.SetDeadline(time.Now().Add(3 * time.Second))
					msg := []byte(fmt.Sprintf("UDP routed payload %d", round))
					if _, e = u.Write(msg); e != nil {
						t.Fatal(e)
					}
					b := make([]byte, 1024)
					n, e := u.Read(b)
					online := v.GetFeature(stats.ManagerType()).(stats.Manager).GetOnlineMap("user>>>native@test>>>online")
					if online == nil {
						t.Fatal("online user map missing")
					}
					for _, ip := range online.List() {
						if ip != "127.0.0.1" {
							t.Fatalf("online stats contain tunnel source %s", ip)
						}
					}
					u.Close()
					if e != nil || !bytes.Equal(b[:n], msg) {
						t.Fatalf("UDP payload: %v", e)
					}
					if round < 2 {
						time.Sleep(1100 * time.Millisecond)
					}
				}
				// User/tag routing matches the native identity and rejects this port.
				ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
				blocked, e := tun.net.DialContextTCPAddrPort(ctx, deniedTarget)
				cancel()
				if e == nil {
					blocked.SetDeadline(time.Now().Add(time.Second))
					_, _ = blocked.Write([]byte("blocked"))
					b := make([]byte, 1)
					if _, e = blocked.Read(b); e == nil {
						t.Fatal("blocked route passed payload")
					}
					blocked.Close()
				}
				if deniedAccepted.Load() != 0 {
					t.Fatal("blocked destination listener was reached")
				}
				sm := v.GetFeature(stats.ManagerType()).(stats.Manager)
				for _, dir := range []string{"uplink", "downlink"} {
					counter := sm.GetCounter("user>>>native@test>>>traffic>>>" + dir)
					if counter == nil || counter.Value() < 1000 {
						t.Fatalf("%s accounting missing", dir)
					}
				}
				if e = srv.RemoveUser(context.Background(), "native@test"); e != nil {
					t.Fatal(e)
				}
				select {
				case <-clientSession.Done():
				case <-time.After(3 * time.Second):
					if network == "tcp" {
						t.Fatal("removed TCP session remains open")
					}
				}
			})
		}
	}
}

func TestNativeServerSecretFormatting(t *testing.T) {
	secret := "SECRET-THAT-MUST-NOT-BE-LOGGED"
	values := []any{ServerSettings{Certificates: ServerCertificates{Key: secret}}, ServerUser{Password: secret}, ServerUserProof{Key: secret}, ServerCertificates{Key: secret}, &ServerConfig{Settings: []byte(secret)}, &ServerAccount{Settings: []byte(secret)}, &MemoryServerAccount{User: ServerUser{Password: secret}}}
	for _, v := range values {
		for _, verb := range []string{"%v", "%+v", "%#v", "%x"} {
			if strings.Contains(fmt.Sprintf(verb, v), secret) {
				t.Fatalf("secret leaked for %T", v)
			}
		}
	}
}

func TestNativeServerOutboundEndToEnd(t *testing.T) {
	p := makeNativePKI(t)
	echo, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer echo.Close()
	go func() {
		for {
			c, e := echo.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	udpEcho, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer udpEcho.Close()
	go func() {
		b := make([]byte, 8192)
		for {
			n, a, e := udpEcho.ReadFromUDP(b)
			if e != nil {
				return
			}
			udpEcho.WriteToUDP(b[:n], a)
		}
	}()
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			settings := nativeSettings(p)
			settings.Network = network
			secret := bytes.Repeat([]byte{0x59}, 32)
			settings.Clients[0].ClientProof = &ServerUserProof{KeyID: "proof", Key: hex.EncodeToString(secret)}
			_, _, port := nativeCore(t, settings, 1, false)
			profile := fmt.Sprintf("client\ndev tun\nremote 127.0.0.1 %d %s\nremote-cert-tls server\ncipher AES-256-GCM\ndata-ciphers AES-256-GCM\nauth SHA256\n<ca>\n%s</ca>\n<cert>\n%s</cert>\n<key>\n%s</key>\n", port, network, p.ca, p.clientCert, p.clientKey)
			outboundCore, e := core.New(&core.Config{App: []*serial.TypedMessage{serial.ToTypedMessage(&dispatcher.Config{}), serial.ToTypedMessage(&proxyman.InboundConfig{}), serial.ToTypedMessage(&proxyman.OutboundConfig{})}, Outbound: []*core.OutboundHandlerConfig{{Tag: "vpn", ProxySettings: serial.ToTypedMessage(&Config{Ovpn: profile, ClientProof: &ClientProofConfig{KeyId: "proof", Key: secret}})}}})
			if e != nil {
				t.Fatal(e)
			}
			if e = outboundCore.Start(); e != nil {
				t.Fatal(e)
			}
			defer outboundCore.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()
			dest := xnet.DestinationFromAddr(echo.Addr())
			c, e := core.Dial(ctx, outboundCore, dest)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			msg := []byte("full Xray OpenVPN outbound routed through native inbound")
			if _, e = c.Write(msg); e != nil {
				t.Fatal(e)
			}
			got := make([]byte, len(msg))
			if _, e = io.ReadFull(c, got); e != nil || !bytes.Equal(got, msg) {
				t.Fatalf("TCP: %v", e)
			}
			u, e := core.DialUDP(ctx, outboundCore)
			if e != nil {
				t.Fatal(e)
			}
			defer u.Close()
			if _, e = u.WriteTo(msg, udpEcho.LocalAddr()); e != nil {
				t.Fatal(e)
			}
			b := make([]byte, 1024)
			n, a, e := u.ReadFrom(b)
			if e != nil || !bytes.Equal(b[:n], msg) || a.String() != udpEcho.LocalAddr().String() {
				t.Fatalf("UDP: %v, %v", a, e)
			}
		})
	}
}

func TestNativeServerRejectsInvalidProofAndPassword(t *testing.T) {
	p := makeNativePKI(t)
	s := nativeSettings(p)
	s.Network = "tcp"
	secret := bytes.Repeat([]byte{0x31}, 32)
	s.ClientProof.Required = true
	s.Clients[0].ClientProof = &ServerUserProof{KeyID: "required", Key: hex.EncodeToString(secret)}
	s.Clients[0].Username = "account"
	s.Clients[0].Password = "test-only-password"
	_, _, port := nativeCore(t, s, 1, false)
	profile := fmt.Sprintf("client\ndev tun\nremote 127.0.0.1 %d tcp\nremote-cert-tls server\ndata-ciphers AES-256-GCM\nauth SHA256\n<ca>\n%s</ca>\n<cert>\n%s</cert>\n<key>\n%s</key>\n", port, p.ca, p.clientCert, p.clientKey)
	opt, e := options.Parse(profile)
	if e != nil {
		t.Fatal(e)
	}
	valid, _ := clientproof.New("required", secret)
	wrong, _ := clientproof.New("required", bytes.Repeat([]byte{0x32}, 32))
	unknown, _ := clientproof.New("unknown", secret)
	cases := []struct {
		name       string
		proof      *clientproof.Key
		user, pass string
		success    bool
	}{{"missing proof", nil, "account", "test-only-password", false}, {"wrong proof", wrong, "account", "test-only-password", false}, {"unknown key", unknown, "account", "test-only-password", false}, {"missing account", valid, "", "", false}, {"wrong password", valid, "account", "bad", false}, {"valid", valid, "account", "test-only-password", true}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			c, e := client.Dial(ctx, client.Config{Options: opt, ClientProof: tc.proof, Username: tc.user, Password: tc.pass, Dial: (&net.Dialer{}).DialContext, HandshakeTimeout: time.Second})
			if c != nil {
				defer c.Close()
			}
			if tc.success && e != nil {
				t.Fatal(e)
			}
			if !tc.success && e == nil {
				t.Fatal("invalid authentication accepted")
			}
		})
	}
}

func TestNativeServerRekeyCannotChangeIdentity(t *testing.T) {
	cfg := nativeSettings(makeNativePKI(t))
	cfg.Clients = append(cfg.Clients, ServerUser{Email: "other@test", CommonName: "other", Level: 9})
	s, e := newServer(&ServerConfig{Settings: serverJSON(t, cfg)}, policy.DefaultManager{})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, e := s.acquire(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, cancel)
	if e != nil {
		t.Fatal(e)
	}
	defer s.release(p)
	engine, e := s.engineConfig(ctx, p)
	if e != nil {
		t.Fatal(e)
	}
	state := func(cn string) tls.ConnectionState {
		c := &x509.Certificate{Subject: pkix.Name{CommonName: cn}}
		return tls.ConnectionState{PeerCertificates: []*x509.Certificate{c}, VerifiedChains: [][]*x509.Certificate{{c}}}
	}
	first, e := engine.Authenticate(ctx, &handshake.ClientMessage{}, state("client"))
	if e != nil || first.Identity != "native@test" {
		t.Fatal("initial admission failed", e)
	}
	if _, e = engine.Authenticate(ctx, &handshake.ClientMessage{}, state("other")); e == nil {
		t.Fatal("rekey changed authenticated identity")
	}
	s.mu.Lock()
	u := p.user
	s.mu.Unlock()
	if u.Email != "native@test" || u.Level != 1 {
		t.Fatal("rejected rekey changed flow user metadata")
	}
}

func TestNativeServerEmptyAccountsStartFailClosed(t *testing.T) {
	p := makeNativePKI(t)
	s := nativeSettings(p)
	s.Clients = nil
	s.Network = "tcp"
	_, srv, _ := nativeCore(t, s, 1, false)
	if srv.GetUsersCount(context.Background()) != 0 {
		t.Fatal("empty listener acquired default users")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	peer, e := srv.acquire(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 1}, cancel)
	if e != nil {
		t.Fatal(e)
	}
	defer srv.release(peer)
	cfg, e := srv.engineConfig(ctx, peer)
	if e != nil {
		t.Fatal(e)
	}
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "client"}}
	if _, e = cfg.Authenticate(ctx, &handshake.ClientMessage{}, tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}); e == nil {
		t.Fatal("empty account list admitted a client")
	}
}

func TestNativeServerConcurrentRoutedSessions(t *testing.T) {
	p := makeNativePKI(t)
	settings := nativeSettings(p)
	settings.Network = "tcp"
	v, srv, port := nativeCore(t, settings, 1, false)
	echo, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer echo.Close()
	go func() {
		for {
			c, e := echo.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	target := netip.MustParseAddrPort(echo.Addr().String())
	var tunnels []*tunnel
	var sessions []*client.Client
	ips := map[netip.Addr]bool{}
	for i := 0; i < 4; i++ {
		c, tun := nativeClient(t, p, "tcp", port, nil)
		a := c.Info().IPv4.Addr()
		if ips[a] {
			t.Fatal("two sessions received the same lease")
		}
		ips[a] = true
		sessions = append(sessions, c)
		tunnels = append(tunnels, tun)
	}
	transfer := func(tun *tunnel) error {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		c, e := tun.net.DialContextTCPAddrPort(ctx, target)
		if e != nil {
			return e
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		msg := bytes.Repeat([]byte("isolated-session"), 2000)
		go func() { _, _ = c.Write(msg) }()
		got := make([]byte, len(msg))
		_, e = io.ReadFull(c, got)
		if e == nil && !bytes.Equal(msg, got) {
			e = fmt.Errorf("session payload corrupt")
		}
		return e
	}
	done := make(chan error, len(tunnels))
	for _, tun := range tunnels {
		go func(tun *tunnel) { done <- transfer(tun) }(tun)
	}
	for range tunnels {
		if e := <-done; e != nil {
			t.Fatal(e)
		}
	}
	tunnels[0].close()
	if e := transfer(tunnels[1]); e != nil {
		t.Fatal("closing one session disrupted another", e)
	}
	if e = srv.Close(); e != nil {
		t.Fatal(e)
	}
	for _, c := range sessions {
		select {
		case <-c.Done():
		case <-time.After(3 * time.Second):
			t.Fatal("server close leaked a live TCP session")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, e := core.Dial(ctx, v, xnet.DestinationFromAddr(echo.Addr()))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	msg := []byte("existing freedom still works")
	if _, e = c.Write(msg); e != nil {
		t.Fatal(e)
	}
	got := make([]byte, len(msg))
	if _, e = io.ReadFull(c, got); e != nil || !bytes.Equal(got, msg) {
		t.Fatal("closing OpenVPN affected the existing freedom outbound", e)
	}
}

func TestNativeServerIPv6RoutedPayloads(t *testing.T) {
	echo, e := net.Listen("tcp6", "[::1]:0")
	if e != nil {
		t.Skip("host IPv6 loopback unavailable")
	}
	defer echo.Close()
	go func() {
		for {
			c, e := echo.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	udpEcho, e := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if e != nil {
		t.Fatal(e)
	}
	defer udpEcho.Close()
	go func() {
		b := make([]byte, 2048)
		for {
			n, a, e := udpEcho.ReadFromUDP(b)
			if e != nil {
				return
			}
			udpEcho.WriteToUDP(b[:n], a)
		}
	}()
	p := makeNativePKI(t)
	settings := nativeSettings(p)
	settings.Network = "tcp"
	settings.Tunnel.IPv6 = "fd88::/64"
	_, _, port := nativeCore(t, settings, 1, false)
	_, tun := nativeClient(t, p, "tcp", port, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, e := tun.net.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort(echo.Addr().String()))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	msg := []byte("real IPv6 routed TCP")
	if _, e = c.Write(msg); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, len(msg))
	if _, e = io.ReadFull(c, b); e != nil || !bytes.Equal(b, msg) {
		t.Fatal("IPv6 TCP", e)
	}
	u, e := tun.net.DialUDPAddrPort(netip.AddrPort{}, netip.MustParseAddrPort(udpEcho.LocalAddr().String()))
	if e != nil {
		t.Fatal(e)
	}
	defer u.Close()
	u.SetDeadline(time.Now().Add(3 * time.Second))
	if _, e = u.Write(msg); e != nil {
		t.Fatal(e)
	}
	b = make([]byte, 1024)
	n, e := u.Read(b)
	if e != nil || !bytes.Equal(b[:n], msg) {
		t.Fatal("IPv6 UDP", e)
	}
}
