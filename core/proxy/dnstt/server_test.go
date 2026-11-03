package dnstt

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtaci/smux"
	"github.com/xtls/xray-core/app/dispatcher"
	xlog "github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/app/router"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	featurein "github.com/xtls/xray-core/features/inbound"
	xproxy "github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/blackhole"
	"github.com/xtls/xray-core/proxy/dnstt/internal/fixture"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/proxy/vless"
	vlessin "github.com/xtls/xray-core/proxy/vless/inbound"
	socksdial "golang.org/x/net/proxy"
	"google.golang.org/protobuf/proto"
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/noise"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

func nativeServerConfig(t *testing.T) *ServerConfig {
	t.Helper()
	key, e := noise.GeneratePrivkey()
	if e != nil {
		t.Fatal(e)
	}
	return &ServerConfig{Domain: "tunnel.dnstt.test", PrivateKey: hex.EncodeToString(key), HandshakeTimeout: 2, Inner: serial.ToTypedMessage(&vlessin.Config{Decryption: "none", Clients: []*protocol.User{{Email: "test@example.test", Account: serial.ToTypedMessage(&vless.Account{Id: testUUID})}}})}
}

func TestNativeServerSettings(t *testing.T) {
	good := nativeServerConfig(t)
	for name, mutate := range map[string]func(*ServerConfig){
		"key": func(c *ServerConfig) { c.PrivateKey = "secret" }, "zero key": func(c *ServerConfig) { c.PrivateKey = string(bytes.Repeat([]byte("0"), 64)) },
		"domain":      func(c *ServerConfig) { c.Domain = "127.0.0.1" },
		"long domain": func(c *ServerConfig) { c.Domain = strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + ".example" }, "small mtu": func(c *ServerConfig) { c.Mtu = 511 }, "large mtu": func(c *ServerConfig) { c.Mtu = 4097 },
		"handshake": func(c *ServerConfig) { c.HandshakeTimeout = 301 }, "sessions": func(c *ServerConfig) { c.MaxSessions = 4097 }, "streams": func(c *ServerConfig) { c.MaxStreams = 1025 },
		"missing inner": func(c *ServerConfig) { c.Inner = nil }, "no auth": func(c *ServerConfig) { c.Inner = serial.ToTypedMessage(&socks.ServerConfig{}) },
	} {
		t.Run(name, func(t *testing.T) {
			c := proto.Clone(good).(*ServerConfig)
			mutate(c)
			if _, e := NormalizeServerConfig(c); e == nil {
				t.Fatal("invalid setting accepted")
			}
		})
	}
	normalized, e := NormalizeServerConfig(good)
	if e != nil {
		t.Fatal(e)
	}
	if good.Mtu != 0 || normalized.Mtu != 1232 || normalized.MaxSessions != 256 || normalized.MaxStreams != 128 {
		t.Fatal("defaults mutate caller or incorrect")
	}
	empty := proto.Clone(good).(*ServerConfig)
	empty.Inner = serial.ToTypedMessage(&vlessin.Config{Decryption: "none"})
	if _, e = NormalizeServerConfig(empty); e != nil {
		t.Fatalf("disabled clients should permit deny-all inbound: %v", e)
	}
}

func TestNativeServerBoundedQueueLifecycle(t *testing.T) {
	q := newAuthorityQueue(context.Background(), 2)
	q.pendingLimit = 2
	defer q.Close()
	var a, b, c turbotunnel.ClientID
	a[0] = 1
	b[0] = 2
	c[0] = 3
	pa, _ := q.admit(a, context.Background(), nil, nil)
	pb, _ := q.admit(b, context.Background(), nil, nil)
	pc, _ := q.admit(c, context.Background(), nil, nil)
	// Three pending peers exceed the provisional budget, so admit fresh peers
	// after first promoting the users that must be protected.
	if pa == nil || pb == nil || pc == nil {
		t.Fatal("pending admission failed")
	}
	pa, _ = q.admit(a, context.Background(), nil, nil)
	if !q.promote(pa) {
		t.Fatal("first authenticated admission failed")
	}
	pb, _ = q.admit(b, context.Background(), nil, nil)
	if !q.promote(pb) {
		t.Fatal("second authenticated admission failed")
	}
	pc, _ = q.admit(c, context.Background(), nil, nil)
	if q.promote(pc) {
		t.Fatal("active identity bound not enforced")
	}
	if p, _ := q.admit(a, context.Background(), nil, nil); p != pa {
		t.Fatal("existing active peer replaced")
	}
	q.queue([]byte("payload"), a)
	dst := make([]byte, 20)
	n, addr, e := q.ReadFrom(dst)
	if e != nil || addr != a || string(dst[:n]) != "payload" {
		t.Fatal("incoming packet corrupted")
	}
	if _, e = q.WriteTo([]byte("reply"), a); e != nil {
		t.Fatal(e)
	}
	if string(<-pa.outgoing) != "reply" {
		t.Fatal("outgoing packet corrupted")
	}
	q.mu.Lock()
	pb.lastSeen = time.Now().Add(-3 * time.Minute)
	q.mu.Unlock()
	if len(q.expire(time.Now())) != 1 || !q.promote(pc) {
		t.Fatal("idle active capacity not recovered")
	}
	done := make(chan struct{})
	go func() { q.ReadFrom(dst); close(done) }()
	q.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("close did not unblock reader")
	}
	if p, _ := q.admit(a, context.Background(), nil, nil); p != nil {
		t.Fatal("closed queue admitted client")
	}
}

func TestNativeServerPendingPeersCannotPinCapacity(t *testing.T) {
	q := newAuthorityQueue(context.Background(), 1)
	q.pendingLimit = 2
	defer q.Close()
	var a, b, c turbotunnel.ClientID
	a[0] = 1
	b[0] = 2
	c[0] = 3
	pa, _ := q.admit(a, context.Background(), nil, nil)
	_, _ = q.admit(b, context.Background(), nil, nil)
	q.mu.Lock()
	pa.created = time.Now().Add(-time.Second)
	q.mu.Unlock()
	// A fresh poll updates lastSeen but cannot change pending admission age.
	_, _ = q.admit(a, context.Background(), nil, nil)
	pc, evicted := q.admit(c, context.Background(), nil, nil)
	if evicted != pa || q.peer(a) != nil || !q.promote(pc) {
		t.Fatal("polls pinned unauthenticated capacity")
	}
	for i := 0; i < 64; i++ {
		var id turbotunnel.ClientID
		id[0] = byte(i + 10)
		_, _ = q.admit(id, context.Background(), nil, nil)
	}
	if q.peer(c) != pc {
		t.Fatal("unauthenticated churn evicted authenticated client")
	}
	q.mu.Lock()
	if len(q.peers) > q.limit+q.pendingLimit {
		t.Fatal("peer table exceeded hard bound")
	}
	for _, p := range q.peers {
		if !p.authenticated {
			p.created = time.Now().Add(-time.Minute)
			p.lastSeen = time.Now()
		}
	}
	q.mu.Unlock()
	if len(q.expire(time.Now())) != 2 || q.peer(c) != pc {
		t.Fatal("pending lifetime can be extended by polling")
	}
}

func TestNativeServerContextIsolation(t *testing.T) {
	old := &session.Inbound{Tag: "dns", User: &protocol.MemoryUser{Email: "outer"}}
	ctx := session.ContextWithInbound(context.Background(), old)
	ctx = session.ContextWithContent(ctx, &session.Content{Attributes: map[string]string{"x": "outer"}})
	a, b := privateServerContext(ctx), privateServerContext(ctx)
	session.InboundFromContext(a).User = &protocol.MemoryUser{Email: "a"}
	session.ContentFromContext(a).Attributes["x"] = "a"
	if old.User.Email != "outer" || session.InboundFromContext(b).User != nil || session.ContentFromContext(b).Attributes["x"] != "outer" {
		t.Fatal("stream contexts share mutable state")
	}
}

func TestNativeServerDNSMalformed(t *testing.T) {
	domain, _ := dns.ParseName("tunnel.test")
	good := &dns.Message{Question: []dns.Question{{Name: domain, Type: dns.RRTypeTXT, Class: 1}}, Additional: []dns.RR{{Type: dns.RRTypeOPT, Class: 1232}}}
	for name, mutate := range map[string]func(*dns.Message){
		"wrong domain":   func(q *dns.Message) { q.Question[0].Name, _ = dns.ParseName("other.test") },
		"wrong type":     func(q *dns.Message) { q.Question[0].Type = 1 },
		"small edns":     func(q *dns.Message) { q.Additional[0].Class = 512 },
		"duplicate edns": func(q *dns.Message) { q.Additional = append(q.Additional, q.Additional[0]) },
		"no question":    func(q *dns.Message) { q.Question = nil },
	} {
		t.Run(name, func(t *testing.T) {
			wire, _ := good.WireFormat()
			q, e := dns.MessageFromWireFormat(wire)
			if e != nil {
				t.Fatal(e)
			}
			mutate(&q)
			resp, _ := responseFor(&q, domain, 1232)
			if resp == nil || resp.Rcode() == 0 {
				t.Fatal("malformed DNS accepted")
			}
		})
	}
	for _, payload := range [][]byte{{2, 1}, {224 + 3, 1}, {1}} {
		if _, e := nextPacket(bytes.NewReader(payload)); e == nil {
			t.Fatal("truncated payload accepted")
		}
	}
	for mtu := 512; mtu <= 4096; mtu += 128 {
		if n := computeMaxEncodedPayload(mtu); n < 80 || n >= mtu {
			t.Fatalf("bad payload budget mtu=%d n=%d", mtu, n)
		}
	}
}

func startNativeServer(t *testing.T, cfg *ServerConfig, blockedPort int) (*core.Instance, string) {
	t.Helper()
	p, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := p.LocalAddr().(*net.UDPAddr).Port
	p.Close()
	apps := []*serial.TypedMessage{serial.ToTypedMessage(&xlog.Config{}), serial.ToTypedMessage(&dispatcher.Config{}), serial.ToTypedMessage(&proxyman.InboundConfig{}), serial.ToTypedMessage(&proxyman.OutboundConfig{})}
	outs := []*core.OutboundHandlerConfig{{Tag: "direct", ProxySettings: serial.ToTypedMessage(&freedom.Config{})}, {Tag: "block", ProxySettings: serial.ToTypedMessage(&blackhole.Config{})}}
	if blockedPort > 0 {
		apps = append(apps, serial.ToTypedMessage(&router.Config{Rule: []*router.RoutingRule{{TargetTag: &router.RoutingRule_Tag{Tag: "block"}, PortList: &xnet.PortList{Range: []*xnet.PortRange{{From: uint32(blockedPort), To: uint32(blockedPort)}}}}}}))
	}
	c := &core.Config{App: apps, Inbound: []*core.InboundHandlerConfig{{Tag: "dnstt", ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{Listen: xnet.NewIPOrDomain(xnet.LocalHostIP), PortList: &xnet.PortList{Range: []*xnet.PortRange{{From: uint32(port), To: uint32(port)}}}}), ProxySettings: serial.ToTypedMessage(cfg)}}, Outbound: outs}
	instance, e := core.New(c)
	if e != nil {
		t.Fatal(e)
	}
	if e = instance.Start(); e != nil {
		instance.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() {
		done := make(chan struct{})
		go func() { instance.Close(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("native inbound shutdown leaked workers")
		}
	})
	return instance, net.JoinHostPort("127.0.0.1", fmtPort(port))
}

func fmtPort(port int) string {
	var b [16]byte
	return string(strconv.AppendInt(b[:0], int64(port), 10))
}

func nativeTCPServer(t *testing.T) net.Listener {
	t.Helper()
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return ln
}

func nativeClientConfig(t *testing.T, server *ServerConfig, resolver *Resolver) *Config {
	t.Helper()
	key, _ := hex.DecodeString(server.PrivateKey)
	cfg, e := NormalizeConfig(&Config{Domain: server.Domain, PublicKey: hex.EncodeToString(noise.PubkeyFromPrivkey(key)), Resolvers: []*Resolver{resolver}, Inner: &Inner{Protocol: "vless", Uuid: testUUID}, HandshakeTimeout: 3, QueryTimeout: 5})
	if e != nil {
		t.Fatal(e)
	}
	return cfg
}

func nativeEcho(ctx context.Context, g *generation, cfg *Config, address net.Addr, size int) error {
	raw, e := g.open(ctx)
	if e != nil {
		return e
	}
	defer raw.Close()
	dest := xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(address.(*net.TCPAddr).Port))
	conn, _, e := innerConnection(ctx, raw, dest, cfg)
	if e != nil {
		return e
	}
	deadline := time.Now().Add(60 * time.Second)
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	data := bytes.Repeat([]byte("DNS-native-test-"), size/16+1)
	data = data[:size]
	sent := make(chan error, 1)
	go func() {
		_, e := conn.Write(data)
		if e != nil {
			_ = raw.Close()
		}
		sent <- e
	}()
	got := make([]byte, len(data))
	n, e := io.ReadFull(conn, got)
	if e != nil {
		return fmt.Errorf("read %d/%d bytes: %w", n, len(got), e)
	}
	if e = <-sent; e != nil {
		return e
	}
	if !bytes.Equal(data, got) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func TestNativeServerCarriersAndConcurrentStreams(t *testing.T) {
	cfg := nativeServerConfig(t)
	_, authority := startNativeServer(t, cfg, 0)
	echo := nativeTCPServer(t)
	f, e := fixture.Start(t.TempDir(), cfg.Domain, authority)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	for _, mode := range []string{"udp", "dot", "doh"} {
		t.Run(mode, func(t *testing.T) {
			resolver := &Resolver{Transport: mode, Address: f.UDP}
			if mode == "dot" {
				resolver.Address = f.DoT
			}
			if mode == "doh" {
				resolver.Address = f.DoH
			}
			if mode != "udp" {
				resolver.ServerName = fixture.ServerName
				resolver.CaPem = f.CAPEM
			}
			c := nativeClientConfig(t, cfg, resolver)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			g, e := newGeneration(ctx, c, &wireTestDialer{})
			if e != nil {
				t.Fatal(e)
			}
			defer g.close()
			if e = nativeEcho(ctx, g, c, echo.Addr(), 1<<20); e != nil {
				t.Fatal(e)
			}
			errors := make(chan error, 8)
			for i := 0; i < 8; i++ {
				go func() { errors <- nativeEcho(ctx, g, c, echo.Addr(), 8192) }()
			}
			for i := 0; i < 8; i++ {
				if e = <-errors; e != nil {
					t.Fatal(e)
				}
			}
		})
	}
}

func TestNativeServerUDPAndRouting(t *testing.T) {
	echo := nativeTCPServer(t)
	blocked := nativeTCPServer(t)
	cfg := nativeServerConfig(t)
	_, authority := startNativeServer(t, cfg, blocked.Addr().(*net.TCPAddr).Port)
	c := nativeClientConfig(t, cfg, &Resolver{Transport: "udp", Address: authority})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	g, e := newGeneration(ctx, c, &wireTestDialer{})
	if e != nil {
		t.Fatal(e)
	}
	defer g.close()
	if e = nativeEcho(ctx, g, c, echo.Addr(), 8192); e != nil {
		t.Fatal(e)
	}
	if e = nativeEcho(ctx, g, c, blocked.Addr(), 10); e == nil {
		t.Fatal("server routing block was bypassed")
	}
	udp, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
	go func() {
		b := make([]byte, 2048)
		for {
			n, a, e := udp.ReadFrom(b)
			if e != nil {
				return
			}
			_, _ = udp.WriteTo(b[:n], a)
		}
	}()
	stream, e := g.open(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer stream.Close()
	target := xnet.UDPDestination(xnet.LocalHostIP, xnet.Port(udp.LocalAddr().(*net.UDPAddr).Port))
	conn, packets, e := innerConnection(ctx, stream, target, c)
	if e != nil {
		t.Fatal(e)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	for _, data := range [][]byte{[]byte("dns-inner-udp"), bytes.Repeat([]byte{0x91}, 1200)} {
		if e = packets.WritePacket(data, target); e != nil {
			t.Fatal(e)
		}
		got, d, e := packets.ReadPacket()
		if e != nil || d != target || !bytes.Equal(got, data) {
			t.Fatalf("UDP response mismatch: %v", e)
		}
	}
}

func TestNativeServerRejectsCredentials(t *testing.T) {
	cfg := nativeServerConfig(t)
	_, authority := startNativeServer(t, cfg, 0)
	echo := nativeTCPServer(t)
	for _, mode := range []string{"key", "domain", "uuid"} {
		t.Run(mode, func(t *testing.T) {
			c := nativeClientConfig(t, cfg, &Resolver{Transport: "udp", Address: authority})
			c.HandshakeTimeout = 1
			switch mode {
			case "key":
				k, _ := noise.GeneratePrivkey()
				c.PublicKey = hex.EncodeToString(noise.PubkeyFromPrivkey(k))
			case "domain":
				c.Domain = "wrong.test"
			case "uuid":
				c.Inner.Uuid = "ffeeddcc-bbaa-0988-7766-554433221100"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			g, e := newGeneration(ctx, c, &wireTestDialer{})
			if e != nil {
				return
			}
			defer g.close()
			if e = nativeEcho(ctx, g, c, echo.Addr(), 32); e == nil {
				t.Fatal("invalid authentication connected")
			}
		})
	}
}

func TestNativeServerSOCKSAndQueryLoss(t *testing.T) {
	cfg := nativeServerConfig(t)
	cfg.Inner = serial.ToTypedMessage(&socks.ServerConfig{AuthType: socks.AuthType_PASSWORD, Accounts: map[string]string{"tester": "local-secret"}})
	_, authority := startNativeServer(t, cfg, 0)
	echo := nativeTCPServer(t)
	f, e := fixture.Start(t.TempDir(), cfg.Domain, authority)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	f.DropEvery.Store(10)
	c := nativeClientConfig(t, cfg, &Resolver{Transport: "udp", Address: f.UDP})
	c.Inner = &Inner{Protocol: "socks", Username: "tester", Password: "local-secret"}
	c.HandshakeTimeout = 5
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	g, e := newGeneration(ctx, c, &wireTestDialer{})
	if e != nil {
		t.Fatal(e)
	}
	defer g.close()
	if e = nativeEcho(ctx, g, c, echo.Addr(), 128<<10); e != nil {
		t.Fatal(e)
	}
	if f.Dropped.Load() == 0 {
		t.Fatal("loss injection did not run")
	}
	bad := proto.Clone(c).(*Config)
	bad.Inner.Password = "wrong"
	if e = nativeEcho(ctx, g, bad, echo.Addr(), 32); e == nil {
		t.Fatal("wrong SOCKS password accepted")
	}
}

func TestNativeServerLifecycleConcurrentClose(t *testing.T) {
	cfg := nativeServerConfig(t)
	server, authority := startNativeServer(t, cfg, 0)
	echo := nativeTCPServer(t)
	c := nativeClientConfig(t, cfg, &Resolver{Transport: "udp", Address: authority})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	g, e := newGeneration(ctx, c, &wireTestDialer{})
	if e != nil {
		t.Fatal(e)
	}
	defer g.close()
	if e = nativeEcho(ctx, g, c, echo.Addr(), 1024); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); server.Close() }()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent close hangs")
	}
}

// The optional independent reference binary is built from the existing client
// source, not the package being tested. Its stdout contains no fixture keys.
func TestNativeServerIndependentReferenceClient(t *testing.T) {
	binary := os.Getenv("XRAY_DNSTT_REFERENCE_CLIENT")
	if binary == "" {
		t.Skip("XRAY_DNSTT_REFERENCE_CLIENT is not set")
	}
	cfg := nativeServerConfig(t)
	_, authority := startNativeServer(t, cfg, 0)
	echo := nativeTCPServer(t)
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	socksAddr := l.Addr().String()
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	key, _ := hex.DecodeString(cfg.PrivateKey)
	config := map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": map[string]any{"auth": "noauth"}}}, "outbounds": []any{map[string]any{"protocol": "dns", "settings": map[string]any{"tunnel": map[string]any{"domain": cfg.Domain, "publicKey": hex.EncodeToString(noise.PubkeyFromPrivkey(key)), "resolvers": []any{map[string]any{"transport": "udp", "address": authority}}, "inner": map[string]any{"protocol": "vless", "uuid": testUUID}}}}}}
	raw, e := json.Marshal(config)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "client.json")
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "run", "-config", path)
	cmd.Env = append(os.Environ(), "PATH=/nonexistent", "XRAY_ENDPOINT_MAPPING=off")
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { cancel(); _ = cmd.Wait() }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, e := net.DialTimeout("tcp", socksAddr, 100*time.Millisecond)
		if e == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("reference client did not listen")
		}
		time.Sleep(10 * time.Millisecond)
	}
	dialer, e := socksdial.SOCKS5("tcp", socksAddr, nil, &net.Dialer{Timeout: 3 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	conn, e := dialer.Dial("tcp", echo.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	payload := bytes.Repeat([]byte("independent-client-native-server"), 8192)
	done := make(chan error, 1)
	go func() { _, e := conn.Write(payload); done <- e }()
	got := make([]byte, len(payload))
	if _, e = io.ReadFull(conn, got); e != nil {
		t.Fatal(e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("independent client transfer corrupted")
	}
}

func TestNativeServerSOCKSRejectsHTTPAndAnonymous(t *testing.T) {
	for _, empty := range []bool{false, true} {
		name := "configured"
		accounts := map[string]string{"tester": "local-secret"}
		if empty {
			name = "disabled"
			accounts = map[string]string{}
		}
		t.Run(name, func(t *testing.T) {
			cfg := nativeServerConfig(t)
			cfg.Inner = serial.ToTypedMessage(&socks.ServerConfig{AuthType: socks.AuthType_PASSWORD, Accounts: accounts})
			_, authority := startNativeServer(t, cfg, 0)
			echo := nativeTCPServer(t)
			c := nativeClientConfig(t, cfg, &Resolver{Transport: "udp", Address: authority})
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			g, e := newGeneration(ctx, c, &wireTestDialer{})
			if e != nil {
				t.Fatal(e)
			}
			defer g.close()
			for _, prefix := range [][]byte{[]byte("CONNECT " + echo.Addr().String() + " HTTP/1.1\r\nHost: local\r\n\r\n"), {4, 1, 0, 80, 127, 0, 0, 1, 0}, {5, 1, 0}} {
				stream, e := g.open(ctx)
				if e != nil {
					t.Fatal(e)
				}
				stream.SetDeadline(time.Now().Add(time.Second))
				_, _ = stream.Write(prefix)
				response := make([]byte, 64)
				n, e := stream.Read(response)
				stream.Close()
				if prefix[0] == 5 {
					if e == nil && (n != 2 || response[0] != 5 || response[1] != 255) {
						t.Fatal("anonymous SOCKS5 accepted")
					}
				} else if e == nil && n > 0 {
					t.Fatal("non-SOCKS5 request reached fallback handler")
				}
			}
		})
	}
}

func TestNativeServerSessionAndStreamLimits(t *testing.T) {
	cfg := nativeServerConfig(t)
	cfg.MaxSessions = 1
	cfg.MaxStreams = 2
	_, authority := startNativeServer(t, cfg, 0)
	echo := nativeTCPServer(t)
	c := nativeClientConfig(t, cfg, &Resolver{Transport: "udp", Address: authority})
	c.HandshakeTimeout = 1
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	g, e := newGeneration(ctx, c, &wireTestDialer{})
	if e != nil {
		t.Fatal(e)
	}
	defer g.close()
	if e = nativeEcho(ctx, g, c, echo.Addr(), 64); e != nil {
		t.Fatal(e)
	}
	extra, e := newGeneration(ctx, c, &wireTestDialer{})
	if e != nil {
		t.Fatal(e)
	}
	if e = nativeEcho(ctx, extra, c, echo.Addr(), 64); e == nil {
		extra.close()
		t.Fatal("authenticated session limit was bypassed")
	}
	extra.close()
	time.Sleep(30 * time.Millisecond)
	first, e := g.open(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer first.Close()
	_, _ = first.Write([]byte{0})
	time.Sleep(30 * time.Millisecond)
	if e = nativeEcho(ctx, g, c, echo.Addr(), 64); e == nil {
		t.Fatal("stream limit was bypassed")
	}
	first.Close()
	deadline := time.Now().Add(2 * time.Second)
	for {
		e = nativeEcho(ctx, g, c, echo.Addr(), 64)
		if e == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("closed unauthenticated stream did not release its slot: %v", e)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestNativeServerMTUBoundaries(t *testing.T) {
	for _, mtu := range []uint32{512, 4096} {
		t.Run(strconv.Itoa(int(mtu)), func(t *testing.T) {
			cfg := nativeServerConfig(t)
			cfg.Mtu = mtu
			_, authority := startNativeServer(t, cfg, 0)
			echo := nativeTCPServer(t)
			c := nativeClientConfig(t, cfg, &Resolver{Transport: "udp", Address: authority})
			c.EdnsPayloadSize = mtu
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			g, e := newGeneration(ctx, c, &wireTestDialer{})
			if e != nil {
				t.Fatal(e)
			}
			defer g.close()
			if e = nativeEcho(ctx, g, c, echo.Addr(), 64<<10); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func FuzzNativeServerDNSWire(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', 0, 0, 16, 0, 1})
	domain, _ := dns.ParseName("tunnel.test")
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			return
		}
		query, e := dns.MessageFromWireFormat(data)
		if e != nil {
			return
		}
		response, payload := responseFor(&query, domain, 1232)
		if response != nil {
			_, _ = response.WireFormat()
		}
		reader := bytes.NewReader(payload)
		for reader.Len() > 0 {
			before := reader.Len()
			_, e := nextPacket(reader)
			if e != nil {
				break
			}
			if reader.Len() >= before {
				t.Fatal("decoder made no progress")
			}
		}
	})
}

func TestNativeServerLiveUsers(t *testing.T) {
	cfg := nativeServerConfig(t)
	instance, authority := startNativeServer(t, cfg, 0)
	echo := nativeTCPServer(t)
	handler, e := instance.GetFeature(featurein.ManagerType()).(featurein.Manager).GetHandler(context.Background(), "dnstt")
	if e != nil {
		t.Fatal(e)
	}
	server := handler.(xproxy.GetInbound).GetInbound().(*Server)
	if server.GetUsersCount(context.Background()) != 1 {
		t.Fatal("initial user missing")
	}
	if e = server.AddUser(context.Background(), nil); e == nil {
		t.Fatal("nil user accepted")
	}
	if e = server.AddUser(context.Background(), &protocol.MemoryUser{Account: &socks.Account{Username: "wrong", Password: "wrong"}}); e == nil {
		t.Fatal("wrong account type accepted")
	}
	c := nativeClientConfig(t, cfg, &Resolver{Transport: "udp", Address: authority})
	c.HandshakeTimeout = 1
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	g, e := newGeneration(ctx, c, &wireTestDialer{})
	if e != nil {
		t.Fatal(e)
	}
	defer g.close()
	if e = nativeEcho(ctx, g, c, echo.Addr(), 64); e != nil {
		t.Fatal(e)
	}
	if e = server.RemoveUser(ctx, "test@example.test"); e != nil {
		t.Fatal(e)
	}
	if server.GetUsersCount(ctx) != 0 || server.GetUser(ctx, "test@example.test") != nil {
		t.Fatal("removed user retained")
	}
	if e = nativeEcho(ctx, g, c, echo.Addr(), 64); e == nil {
		t.Fatal("removed user still authenticated")
	}
	u, e := (&protocol.User{Email: "test@example.test", Account: serial.ToTypedMessage(&vless.Account{Id: testUUID})}).ToMemoryUser()
	if e != nil {
		t.Fatal(e)
	}
	if e = server.AddUser(ctx, u); e != nil {
		t.Fatal(e)
	}
	if e = nativeEcho(ctx, g, c, echo.Addr(), 64); e != nil {
		t.Fatalf("added user cannot connect: %v", e)
	}
}

func TestNativeServerPollOnlyFloodDoesNotBlockClient(t *testing.T) {
	cfg := nativeServerConfig(t)
	cfg.MaxSessions = 1
	_, authority := startNativeServer(t, cfg, 0)
	echo := nativeTCPServer(t)
	conn, e := net.Dial("udp", authority)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	for i := 0; i < 64; i++ {
		var id turbotunnel.ClientID
		id[0] = byte(i + 1)
		name, e := dns.ParseName(base32Encoding.EncodeToString(id[:]) + "." + cfg.Domain)
		if e != nil {
			t.Fatal(e)
		}
		q := dns.Message{ID: uint16(i), Question: []dns.Question{{Name: name, Type: dns.RRTypeTXT, Class: 1}}, Additional: []dns.RR{{Type: dns.RRTypeOPT, Class: 1232}}}
		wire, _ := q.WireFormat()
		if _, e = conn.Write(wire); e != nil {
			t.Fatal(e)
		}
	}
	time.Sleep(30 * time.Millisecond)
	c := nativeClientConfig(t, cfg, &Resolver{Transport: "udp", Address: authority})
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	g, e := newGeneration(ctx, c, &wireTestDialer{})
	if e != nil {
		t.Fatal(e)
	}
	defer g.close()
	if e = nativeEcho(ctx, g, c, echo.Addr(), 1024); e != nil {
		t.Fatalf("unauthenticated polls blocked valid user: %v", e)
	}
}

func TestNativeServerIdleSourceDoesNotResetTunnel(t *testing.T) {
	cfg := nativeServerConfig(t)
	instance, authority := startNativeServer(t, cfg, 0)
	echo := nativeTCPServer(t)
	handler, e := instance.GetFeature(featurein.ManagerType()).(featurein.Manager).GetHandler(context.Background(), "dnstt")
	if e != nil {
		t.Fatal(e)
	}
	server := handler.(xproxy.GetInbound).GetInbound().(*Server)
	c := nativeClientConfig(t, cfg, &Resolver{Transport: "udp", Address: authority})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	g, e := newGeneration(ctx, c, &wireTestDialer{})
	if e != nil {
		t.Fatal(e)
	}
	defer g.close()
	if e = nativeEcho(ctx, g, c, echo.Addr(), 128); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(12 * time.Second)
	for {
		server.mu.Lock()
		sources := len(server.associations)
		sessions := len(server.sessions)
		server.mu.Unlock()
		if sources == 0 {
			if sessions != 1 {
				t.Fatal("source expiry removed logical session")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("idle source association did not expire")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !g.alive() {
		t.Fatal("source expiry reset client generation")
	}
	if e = nativeEcho(ctx, g, c, echo.Addr(), 4096); e != nil {
		t.Fatalf("same-source requery after expiry failed: %v", e)
	}
	server.mu.Lock()
	sessions := len(server.sessions)
	server.mu.Unlock()
	if sessions != 1 {
		t.Fatal("source requery replaced tunnel session")
	}
}

func TestNativeServerPendingStreamBudget(t *testing.T) {
	cfg := nativeServerConfig(t)
	cfg.MaxSessions = 2
	cfg.MaxStreams = 64
	instance, authority := startNativeServer(t, cfg, 0)
	echo := nativeTCPServer(t)
	handler, e := instance.GetFeature(featurein.ManagerType()).(featurein.Manager).GetHandler(context.Background(), "dnstt")
	if e != nil {
		t.Fatal(e)
	}
	server := handler.(xproxy.GetInbound).GetInbound().(*Server)
	c := nativeClientConfig(t, cfg, &Resolver{Transport: "udp", Address: authority})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	trusted, e := newGeneration(ctx, c, &wireTestDialer{})
	if e != nil {
		t.Fatal(e)
	}
	defer trusted.close()
	if e = nativeEcho(ctx, trusted, c, echo.Addr(), 256); e != nil {
		t.Fatal(e)
	}
	pending, e := newGeneration(ctx, c, &wireTestDialer{})
	if e != nil {
		t.Fatal(e)
	}
	defer pending.close()
	var streams []net.Conn
	defer func() {
		for _, stream := range streams {
			stream.Close()
		}
	}()
	for i := 0; i < cap(server.pendingStreams); i++ {
		stream, e := pending.open(ctx)
		if e != nil {
			t.Fatal(e)
		}
		streams = append(streams, stream)
		if _, e = stream.Write([]byte{0}); e != nil {
			t.Fatal(e)
		}
	}
	deadline := time.Now().Add(time.Second)
	for len(server.pendingStreams) < cap(server.pendingStreams) {
		if time.Now().After(deadline) {
			t.Fatal("pending streams were not admitted")
		}
		time.Sleep(5 * time.Millisecond)
	}
	overflow, e := pending.open(ctx)
	if e != nil {
		t.Fatal(e)
	}
	overflow.SetDeadline(time.Now().Add(time.Second))
	_, _ = overflow.Write([]byte{0})
	var b [1]byte
	if _, e = overflow.Read(b[:]); e == nil {
		t.Fatal("pending stream budget was bypassed")
	} else if timeout, ok := e.(net.Error); ok && timeout.Timeout() {
		t.Fatal("overflow stream was retained instead of rejected")
	}
	overflow.Close()
	if e = nativeEcho(ctx, trusted, c, echo.Addr(), 1024); e != nil {
		t.Fatalf("pending stream pressure blocked an authenticated peer: %v", e)
	}
	for _, stream := range streams {
		stream.Close()
	}
	deadline = time.Now().Add(2 * time.Second)
	for len(server.pendingStreams) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("pending stream tokens leaked")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type delayedFINConn struct {
	net.Conn
	blocked atomic.Bool
	entered chan struct{}
	release chan struct{}
	signal  sync.Once
	unblock sync.Once
}

func (c *delayedFINConn) Write(p []byte) (int, error) {
	if c.blocked.Load() {
		c.signal.Do(func() { close(c.entered) })
		<-c.release
	}
	return c.Conn.Write(p)
}
func (c *delayedFINConn) Close() error {
	c.unblock.Do(func() { close(c.release) })
	return c.Conn.Close()
}

func TestNativeServerCloseJoinsInFlightFIN(t *testing.T) {
	left, right := net.Pipe()
	carrier := &delayedFINConn{Conn: left, entered: make(chan struct{}), release: make(chan struct{})}
	cfg := smux.DefaultConfig()
	cfg.Version = 2
	cfg.KeepAliveDisabled = true
	server, e := smux.Server(carrier, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	client, e := smux.Client(right, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	remote, e := client.OpenStream()
	if e != nil {
		t.Fatal(e)
	}
	defer remote.Close()
	raw, e := server.AcceptStream()
	if e != nil {
		t.Fatal(e)
	}
	wrapped := &serverStream{Stream: raw}
	carrier.blocked.Store(true)
	first, second := make(chan struct{}), make(chan struct{})
	go func() { wrapped.Close(); close(first) }()
	select {
	case <-carrier.entered:
	case <-time.After(time.Second):
		t.Fatal("FIN did not enter blocked transport")
	}
	go func() { wrapped.Close(); close(second) }()
	select {
	case <-second:
		t.Fatal("second close escaped before first FIN completed")
	case <-time.After(30 * time.Millisecond):
	}
	carrier.unblock.Do(func() { close(carrier.release) })
	for _, done := range []chan struct{}{first, second} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("close did not complete after transport resumed")
		}
	}
}

func TestDNSTTPrivateDialContextPreservesRoutingMetadata(t *testing.T) {
	original := &session.Inbound{Tag: "original", Source: xnet.TCPDestination(xnet.LocalHostIP, 12345), Local: xnet.TCPDestination(xnet.LocalHostIP, 4567), VlessRoute: 42}
	ctx := session.ContextWithInbound(context.Background(), original)
	copied := session.InboundFromContext(privateInbound(ctx))
	if copied == original || copied.Local != original.Local || copied.VlessRoute != 42 || copied.Source != original.Source {
		t.Fatal("private dial context lost routing metadata")
	}
	copied.Tag = "changed"
	if original.Tag != "original" {
		t.Fatal("dial context mutates original inbound")
	}
}
