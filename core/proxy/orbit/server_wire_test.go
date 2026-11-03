package orbit

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	xprotocol "github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	xsession "github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/orbit/internal/connectionkey"
	"github.com/xtls/xray-core/proxy/orbit/internal/protocol"
	xtransport "github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

type d11OrbitFixture struct {
	server     *Server
	config     *ServerConfig
	settings   Settings
	dispatcher *d11OrbitDispatcher
	context    context.Context
	cancel     context.CancelFunc
	address    net.Addr
	close      func()
}

func d11OrbitStart(t *testing.T, id d11OrbitIdentity, mode string, configure ...func(*ServerConfig)) *d11OrbitFixture {
	t.Helper()
	instance, err := core.New(&core.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), core.XrayKey(1), instance))
	f := &d11OrbitFixture{context: ctx, cancel: cancel, dispatcher: &d11OrbitDispatcher{}}
	carrier := mode
	if mode == "reality" {
		carrier = "tcp"
	}
	f.config = &ServerConfig{
		Transport:        carrier,
		Users:            []*xprotocol.User{{Email: "orbit-test@example.invalid", Level: 7, Account: serial.ToTypedMessage(&Account{Key: id.key})}},
		Tls:              &Certificate{Certificate: []string{id.certificate}, Key: []string{id.privateKey}},
		HandshakeTimeout: 3, MaxSessions: 16, MaxFlows: 32, UdpIdleTimeout: 2,
	}
	f.settings = Settings{Address: "127.0.0.1", Key: id.key, Transport: carrier}
	if carrier == "ws" || carrier == "wss" {
		f.config.Host, f.config.Path = "orbit-owned.test", "/core"
		f.settings.Host, f.settings.Peer, f.settings.Path = "orbit-owned.test", "orbit-owned.test", "/core"
	}
	if carrier == "wss" {
		f.config.OuterTls = &Certificate{Certificate: []string{id.certificate}, Key: []string{id.privateKey}}
	}
	if mode == "reality" {
		cover := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("Orbit REALITY sent application traffic to the local cover")
		}))
		cover.TLS = &tls.Config{Certificates: []tls.Certificate{id.pair}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
		cover.StartTLS()
		t.Cleanup(cover.Close)
		private, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		f.config.Security = "reality"
		f.config.Tls = nil
		f.config.Reality = &ServerReality{PrivateKey: base64.RawURLEncoding.EncodeToString(private.Bytes()), ServerNames: []string{"cover.test"}, ShortIds: []string{"0123456789abcdef"}, Dest: cover.Listener.Addr().String()}
		f.settings.Security = "reality"
		f.settings.Reality = RealitySettings{ServerName: "cover.test", PublicKey: base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()), ShortID: "0123456789abcdef"}
	}
	for _, apply := range configure {
		apply(f.config)
	}
	f.server, err = NewServer(ctx, f.config)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var shutdownListener func()
	process := func(conn stat.Connection, network xnet.Network) {
		defer wg.Done()
		in := &xsession.Inbound{Tag: "orbit-owned", Source: xnet.DestinationFromAddr(conn.RemoteAddr()), Local: xnet.DestinationFromAddr(conn.LocalAddr()), CanSpliceCopy: 3}
		connectionCtx := xsession.ContextWithInbound(ctx, in)
		connectionCtx = xsession.ContextWithOutbounds(connectionCtx, []*xsession.Outbound{{Name: "initial"}})
		connectionCtx = xsession.ContextWithContent(connectionCtx, &xsession.Content{
			Protocol: "initial", Attributes: map[string]string{"flow": "initial"},
			SniffingRequest: xsession.SniffingRequest{ExcludeForDomain: []string{"initial"}, OverrideDestinationForProtocol: []string{"tls"}},
		})
		_ = f.server.Process(connectionCtx, network, conn, f.dispatcher)
		_ = conn.Close()
	}
	if carrier == "quic" {
		udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			t.Fatal(err)
		}
		f.address = udp.LocalAddr()
		shutdownListener = func() { _ = udp.Close() }
		wg.Add(1)
		go func() {
			defer wg.Done()
			peers := make(map[string]*d11OrbitPacketConn)
			defer func() {
				for _, p := range peers {
					_ = p.Close()
				}
			}()
			data := make([]byte, 65536)
			for {
				n, remote, err := udp.ReadFromUDP(data)
				if err != nil {
					return
				}
				p := peers[remote.String()]
				if p == nil || p.isClosed() {
					p = &d11OrbitPacketConn{raw: udp, remote: remote, packets: make(chan []byte, 256), done: make(chan struct{}), changed: make(chan struct{}, 1)}
					peers[remote.String()] = p
					wg.Add(1)
					go process(p, xnet.Network_UDP)
				}
				select {
				case p.packets <- append([]byte(nil), data[:n]...):
				case <-p.done:
				case <-ctx.Done():
					return
				}
			}
		}()
	} else {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		f.address = listener.Addr()
		shutdownListener = func() { _ = listener.Close() }
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				wg.Add(1)
				go process(conn, xnet.Network_TCP)
			}
		}()
	}
	_, port, _ := net.SplitHostPort(f.address.String())
	portNumber, _ := strconv.Atoi(port)
	f.settings.Port = uint32(portNumber)
	var once sync.Once
	f.close = func() {
		once.Do(func() {
			cancel()
			shutdownListener()
			_ = f.server.Close()
			_ = f.dispatcher.Close()
			done := make(chan struct{})
			go func() { wg.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(4 * time.Second):
				t.Error("Orbit Process/listener workers outlived fixture shutdown")
			}
		})
	}
	t.Cleanup(f.close)
	return f
}

func (f *d11OrbitFixture) client(t *testing.T, change ...func(*dialPlan)) (*Client, *generation, error) {
	t.Helper()
	config, err := f.settings.Config(3, "")
	if err != nil {
		return nil, nil, err
	}
	c, err := New(f.context, config)
	if err != nil {
		return nil, nil, err
	}
	for _, apply := range change {
		apply(c.plan)
	}
	t.Cleanup(func() { _ = c.Close() })
	ctx, cancel := context.WithTimeout(f.context, 5*time.Second)
	defer cancel()
	g, err := c.session(ctx, new(netDialer))
	return c, g, err
}

// d11OrbitPacketConn represents the same per-source packet connection supplied
// by Xray's UDP worker, including its buf.Reader interface. A ReadMultiBuffer
// must return complete datagrams, including back-to-back QUIC Initial packets.
type d11OrbitPacketConn struct {
	raw      *net.UDPConn
	remote   *net.UDPAddr
	packets  chan []byte
	done     chan struct{}
	once     sync.Once
	mu       sync.Mutex
	deadline time.Time
	changed  chan struct{}
}

func (p *d11OrbitPacketConn) isClosed() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}
func (p *d11OrbitPacketConn) packet() ([]byte, error) {
	for {
		p.mu.Lock()
		deadline := p.deadline
		p.mu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		select {
		case b := <-p.packets:
			if timer != nil {
				timer.Stop()
			}
			return b, nil
		case <-p.done:
			if timer != nil {
				timer.Stop()
			}
			return nil, net.ErrClosed
		case <-timeout:
			return nil, os.ErrDeadlineExceeded
		case <-p.changed:
			if timer != nil {
				timer.Stop()
			}
		}
	}
}
func (p *d11OrbitPacketConn) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b, err := p.packet()
	if err != nil {
		return nil, err
	}
	return buf.MultiBuffer{buf.FromBytes(b)}, nil
}
func (p *d11OrbitPacketConn) Read(b []byte) (int, error) {
	data, err := p.packet()
	if err != nil {
		return 0, err
	}
	if len(b) < len(data) {
		return 0, io.ErrShortBuffer
	}
	return copy(b, data), nil
}
func (p *d11OrbitPacketConn) Write(b []byte) (int, error) {
	if p.isClosed() {
		return 0, net.ErrClosed
	}
	return p.raw.WriteToUDP(b, p.remote)
}
func (p *d11OrbitPacketConn) Close() error                     { p.once.Do(func() { close(p.done) }); return nil }
func (p *d11OrbitPacketConn) LocalAddr() net.Addr              { return p.raw.LocalAddr() }
func (p *d11OrbitPacketConn) RemoteAddr() net.Addr             { return p.remote }
func (p *d11OrbitPacketConn) SetDeadline(t time.Time) error    { return p.SetReadDeadline(t) }
func (p *d11OrbitPacketConn) SetWriteDeadline(time.Time) error { return nil }
func (p *d11OrbitPacketConn) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	p.deadline = t
	p.mu.Unlock()
	select {
	case p.changed <- struct{}{}:
	default:
	}
	return nil
}

func d11OrbitRoundTrip(t *testing.T, f *d11OrbitFixture, g *generation) {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.context, 10*time.Second)
	defer cancel()
	stream, err := g.peer.Open(ctx, "dispatch-only.invalid", 443)
	if err != nil {
		t.Fatal("native routed TCP open:", err)
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(8 * time.Second))
	payload := bytes.Repeat([]byte("Orbit Xray dispatch\x00\xff"), 100000)
	written := make(chan error, 1)
	go func() { _, err := stream.Write(payload); written <- err }()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, got); err != nil {
		t.Fatal("native routed TCP read:", err)
	}
	if err := <-written; err != nil {
		t.Fatal("native routed TCP write:", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("native TCP payload changed")
	}
	for _, kind := range []byte{protocol.UDPKindData, protocol.UDPKindDNS} {
		association, err := g.udp.Open(netip.AddrPort{}, kind)
		if err != nil {
			t.Fatal(err)
		}
		to := netip.MustParseAddrPort("192.0.2.1:53")
		// Xray's shared pipe regards a zero-length MultiBuffer as empty. The
		// protocol transport's zero-datagram tests are separate; native routed
		// integration therefore tests ordinary nonempty UDP payloads here.
		for _, size := range []int{17, 512} {
			packet := bytes.Repeat([]byte{byte(size)}, size)
			if err := association.Send(ctx, to, packet); err != nil {
				t.Fatal("native routed UDP send:", err)
			}
			got, err := association.Receive(ctx)
			if err != nil {
				t.Fatal("native routed UDP read:", err)
			}
			if !bytes.Equal(got.Data, packet) || got.Source != to || got.Destination != association.Source() || got.Kind != kind {
				t.Fatalf("native UDP metadata/payload changed: kind=%d size=%d", kind, size)
			}
		}
		_ = association.Close()
	}
	records := f.dispatcher.snapshot()
	if len(records) < 3 {
		t.Fatalf("expected TCP and both UDP kinds to dispatch, got %d records", len(records))
	}
	for _, r := range records {
		if r.email != "orbit-test@example.invalid" || r.level != 7 || r.tag != "orbit-owned" || r.name != "orbit" {
			t.Fatalf("authenticated routing metadata not preserved: %+v", r)
		}
		if r.destination.Network == xnet.Network_TCP && r.destination.Address.Domain() != "dispatch-only.invalid" {
			t.Fatal("native TCP destination was changed")
		}
		if r.destination.Network == xnet.Network_UDP && r.destination.NetAddr() != "192.0.2.1:53" {
			t.Fatal("native UDP destination was changed")
		}
	}
}

func TestD11OrbitNativeTransportMatrix(t *testing.T) {
	for _, carrier := range []string{"tcp", "ws", "quic"} {
		t.Run(carrier, func(t *testing.T) {
			f := d11OrbitStart(t, d11OrbitNewIdentity(t), carrier)
			_, g, err := f.client(t)
			if err != nil {
				t.Fatal("current client handshake/reach:", err)
			}
			d11OrbitRoundTrip(t, f, g)
		})
	}
}

func TestD11OrbitNativeAuthenticationBeforeDispatch(t *testing.T) {
	for _, carrier := range []string{"tcp", "ws", "quic"} {
		for _, field := range []string{"account", "token", "device", "pin"} {
			t.Run(carrier+"/"+field, func(t *testing.T) {
				id := d11OrbitNewIdentity(t)
				f := d11OrbitStart(t, id, carrier)
				_, _, err := f.client(t, func(p *dialPlan) {
					switch field {
					case "account":
						_, c, e := connectionkey.Generate(id.pin)
						if e != nil {
							t.Fatal(e)
						}
						p.user.UID, p.user.Token, p.user.DeviceID = c.UID, c.Token, c.DeviceID
					case "token":
						p.user.Token = strings.Repeat("0", 32)
					case "device":
						p.user.DeviceID = strings.Repeat("0", 40)
					case "pin":
						p.pinHex = strings.Repeat("01", 32)
					}
				})
				if err == nil {
					t.Fatal("invalid credential produced a ready session")
				}
				if len(f.dispatcher.snapshot()) != 0 {
					t.Fatal("unauthenticated traffic reached dispatcher")
				}
			})
		}
	}
}

func TestD11OrbitNativeWebSocketRouteIsExact(t *testing.T) {
	for _, field := range []string{"host", "path"} {
		t.Run(field, func(t *testing.T) {
			f := d11OrbitStart(t, d11OrbitNewIdentity(t), "ws")
			if field == "host" {
				f.settings.Host = "different.test"
			} else {
				f.settings.Path = "/wrong"
			}
			if _, _, err := f.client(t); err == nil {
				t.Fatal("unexpected WebSocket route authenticated")
			}
			if len(f.dispatcher.snapshot()) != 0 {
				t.Fatal("wrong WebSocket route reached dispatcher")
			}
		})
	}
}

func TestD11OrbitNativeDeniedRouteAndRevoke(t *testing.T) {
	f := d11OrbitStart(t, d11OrbitNewIdentity(t), "tcp")
	c, g, err := f.client(t)
	if err != nil {
		t.Fatal(err)
	}
	f.dispatcher.mu.Lock()
	f.dispatcher.deny = true
	f.dispatcher.mu.Unlock()
	ctx, cancel := context.WithTimeout(f.context, 2*time.Second)
	defer cancel()
	if stream, err := g.peer.Open(ctx, "blocked.invalid", 80); err == nil {
		_ = stream.Close()
		t.Fatal("route denial did not reject native flow")
	}
	if len(f.dispatcher.snapshot()) != 1 {
		t.Fatal("native flow bypassed dispatch")
	}
	if err := f.server.RemoveUser(f.context, "orbit-test@example.invalid"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-g.peer.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("revocation did not terminate authenticated session")
	}
	_ = c.Close()
	if _, _, err := f.client(t); err == nil {
		t.Fatal("revoked account authenticated again")
	}
}

func TestD11OrbitNativeCloseCancelsUnauthenticated(t *testing.T) {
	f := d11OrbitStart(t, d11OrbitNewIdentity(t), "tcp", func(c *ServerConfig) { c.HandshakeTimeout = 30 })
	conn, err := net.Dial("tcp", f.address.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	deadline := time.Now().Add(2 * time.Second)
	for {
		f.server.mu.Lock()
		active := len(f.server.active)
		f.server.mu.Unlock()
		if active != 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("silent connection never entered native Process")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// A raw TCP connection intentionally sends no TLS or native auth bytes.
	// Shutdown must cancel it instead of waiting for the 30-second timeout.
	start := time.Now()
	f.close()
	if time.Since(start) > 2*time.Second {
		t.Fatal("shutdown waited for unauthenticated handshake timeout")
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := conn.Read(b[:]); err == nil {
		t.Fatal("closed native inbound still accepted traffic")
	}
}

func TestD11OrbitNativeOutboundProcessTCPAndUDP(t *testing.T) {
	for _, carrier := range []string{"tcp", "ws", "quic"} {
		t.Run(carrier, func(t *testing.T) {
			f := d11OrbitStart(t, d11OrbitNewIdentity(t), carrier)
			c, _, err := f.client(t)
			if err != nil {
				t.Fatal(err)
			}
			for _, network := range []xnet.Network{xnet.Network_TCP, xnet.Network_UDP} {
				dest := xnet.Destination{Network: network, Address: xnet.ParseAddress("192.0.2.5"), Port: 9000}
				ctx, cancel := context.WithTimeout(f.context, 5*time.Second)
				ctx = xsession.ContextWithOutbounds(ctx, []*xsession.Outbound{{Target: dest}})
				input, send := pipe.New()
				receive, output := pipe.New()
				done := make(chan error, 1)
				go func() { done <- c.Process(ctx, &xtransport.Link{Reader: input, Writer: output}, new(netDialer)) }()
				payload := []byte("full outbound Process and inbound dispatch")
				packet := buf.FromBytes(append([]byte(nil), payload...))
				if network == xnet.Network_UDP {
					perPacket := xnet.UDPDestination(xnet.ParseAddress("192.0.2.6"), 9011)
					packet.UDP = &perPacket
					dest = perPacket
				}
				if err := send.WriteMultiBuffer(buf.MultiBuffer{packet}); err != nil {
					t.Fatal(err)
				}
				mb, err := receive.ReadMultiBufferTimeout(4 * time.Second)
				if err != nil {
					cancel()
					t.Fatal("outbound Process response:", err)
				}
				var got []byte
				for _, b := range mb {
					got = append(got, b.Bytes()...)
					if network == xnet.Network_UDP && (b.UDP == nil || *b.UDP != dest) {
						t.Fatal("per-packet destination was lost in outbound Process")
					}
				}
				buf.ReleaseMulti(mb)
				if !bytes.Equal(got, payload) {
					t.Fatal("outbound Process changed payload")
				}
				cancel()
				input.Interrupt()
				_ = send.Close()
				receive.Interrupt()
				_ = output.Close()
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					t.Fatal("outbound Process ignored cancellation")
				}
			}
		})
	}
}

func TestD11OrbitNativeConcurrentFlowsKeepMetadata(t *testing.T) {
	for _, carrier := range []string{"tcp", "quic"} {
		t.Run(carrier, func(t *testing.T) { d11OrbitConcurrentFlows(t, carrier) })
	}
}

func d11OrbitConcurrentFlows(t *testing.T, carrier string) {
	f := d11OrbitStart(t, d11OrbitNewIdentity(t), carrier)
	f.dispatcher.mu.Lock()
	f.dispatcher.mutate = true
	f.dispatcher.mu.Unlock()
	_, g, err := f.client(t)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(f.context, 5*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	failures := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			stream, err := g.peer.Open(ctx, "route-"+strconv.Itoa(i)+".invalid", 443)
			if err != nil {
				failures <- err
				return
			}
			defer stream.Close()
			_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
			message := []byte{byte(i), 0, 255}
			if _, err := stream.Write(message); err != nil {
				failures <- err
				return
			}
			got := make([]byte, len(message))
			if _, err := io.ReadFull(stream, got); err != nil {
				failures <- err
				return
			}
			if !bytes.Equal(got, message) {
				failures <- fmt.Errorf("flow %d payload mismatch", i)
			}
		}(i)
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	records := f.dispatcher.snapshot()
	if len(records) != 8 {
		t.Fatalf("got %d dispatched concurrent flows", len(records))
	}
	seen := make(map[*xsession.Inbound]bool)
	seenOut := make(map[*xsession.Outbound]bool)
	seenContent := make(map[*xsession.Content]bool)
	for _, record := range records {
		if record.inbound == nil || seen[record.inbound] {
			t.Fatal("concurrent flows reused mutable inbound metadata")
		}
		seen[record.inbound] = true
		if record.outbound == nil || seenOut[record.outbound] || record.content == nil || seenContent[record.content] {
			t.Fatal("concurrent flows reused mutable outbound or sniffing content metadata")
		}
		seenOut[record.outbound], seenContent[record.content] = true, true
		marker := record.destination.Address.String()
		if record.outbound.Target != record.destination || record.outbound.Name != marker || record.content.Protocol != marker ||
			record.content.Attribute("flow") != marker || record.content.SniffingRequest.ExcludeForDomain[0] != marker ||
			record.content.SniffingRequest.OverrideDestinationForProtocol[0] != marker {
			t.Fatal("a concurrent dispatcher overwrote another flow's routing/sniffing data")
		}
		if record.email != "orbit-test@example.invalid" || record.level != 7 {
			t.Fatal("concurrent flow lost authenticated user")
		}
	}
}

func TestD11OrbitNativeQUICIncompleteStreamDoesNotBlockFlow(t *testing.T) {
	f := d11OrbitStart(t, d11OrbitNewIdentity(t), "quic", func(c *ServerConfig) { c.MaxFlows = 2 })
	_, g, err := f.client(t)
	if err != nil {
		t.Fatal(err)
	}
	q, ok := g.peer.(quicPeer)
	if !ok {
		t.Fatal("fixture did not negotiate native QUIC")
	}
	ctx, cancel := context.WithTimeout(f.context, 2*time.Second)
	defer cancel()
	pending, err := q.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer pending.Close()
	// Lower stream IDs are accepted first. This deliberately incomplete frame
	// occupies one parser slot until the server handshake deadline, while a
	// subsequent complete stream must still be admitted without waiting for it.
	if _, err := pending.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := q.Probe(ctx); err != nil {
		t.Fatal("control channel stalled behind incomplete stream:", err)
	}
	flow, err := q.Open(ctx, "complete.invalid", 443)
	if err != nil {
		t.Fatal("incomplete QUIC stream consumed all logical parser slots:", err)
	}
	defer flow.Close()
	_ = flow.SetDeadline(time.Now().Add(time.Second))
	if _, err := flow.Write([]byte("complete")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("complete"))
	if _, err := io.ReadFull(flow, got); err != nil || string(got) != "complete" {
		t.Fatal("independent complete QUIC flow failed", err)
	}
	if len(f.dispatcher.snapshot()) != 1 {
		t.Fatal("incomplete unauthenticated stream reached dispatch")
	}
}

func TestD11OrbitNativeRuntimeUsersAndExpiry(t *testing.T) {
	id := d11OrbitNewIdentity(t)
	f := d11OrbitStart(t, id, "tcp", func(c *ServerConfig) { c.Users = nil })
	if f.server.GetUsersCount(f.context) != 0 || f.server.GetUser(f.context, "orbit-test@example.invalid") != nil {
		t.Fatal("empty inbound started with an account")
	}
	u := &xprotocol.User{Email: "orbit-test@example.invalid", Level: 7, Account: serial.ToTypedMessage(&Account{Key: id.key, ExpiresAt: time.Now().Add(3 * time.Second).Unix()})}
	user, err := u.ToMemoryUser()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.server.AddUser(f.context, user); err != nil {
		t.Fatal(err)
	}
	if f.server.GetUsersCount(f.context) != 1 || len(f.server.GetUsers(f.context)) != 1 {
		t.Fatal("runtime user was not registered")
	}
	copy := f.server.GetUser(f.context, user.Email)
	if copy == nil {
		t.Fatal("runtime user not retrievable by email")
	}
	copy.Email = "mutated@example.invalid"
	if got := f.server.GetUser(f.context, user.Email); got == nil || got.Email != user.Email {
		t.Fatal("GetUser exposed mutable user metadata")
	}
	if err := f.server.AddUser(f.context, user); err == nil {
		t.Fatal("duplicate runtime user accepted")
	}
	_, g, err := f.client(t)
	if err != nil {
		t.Fatal("runtime-added account could not authenticate:", err)
	}
	select {
	case <-g.peer.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("expired account retained its active session")
	}
	if _, _, err := f.client(t); err == nil {
		t.Fatal("expired account authenticated again")
	}
	if err := f.server.RemoveUser(f.context, user.Email); err != nil {
		t.Fatal(err)
	}
	if f.server.GetUsersCount(f.context) != 0 {
		t.Fatal("runtime account removal was lost")
	}
}

func TestD11OrbitNativeSessionLimitIsReleased(t *testing.T) {
	f := d11OrbitStart(t, d11OrbitNewIdentity(t), "tcp", func(c *ServerConfig) { c.MaxSessions = 1 })
	first, _, err := f.client(t)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.client(t); err == nil {
		t.Fatal("session admission limit was ignored")
	}
	_ = first.Close()
	deadline := time.Now().Add(2 * time.Second)
	for {
		f.server.mu.Lock()
		active := len(f.server.active)
		f.server.mu.Unlock()
		if active == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("closed session did not release admission slot")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, _, err := f.client(t); err != nil {
		t.Fatal("released session slot could not be reused:", err)
	}
}

func TestD11OrbitNativeCloseInterruptsBlockedUDPDispatch(t *testing.T) {
	f := d11OrbitStart(t, d11OrbitNewIdentity(t), "tcp")
	f.dispatcher.mu.Lock()
	f.dispatcher.blockWrites = true
	f.dispatcher.writeEntered = make(chan struct{}, 1)
	entered := f.dispatcher.writeEntered
	f.dispatcher.mu.Unlock()
	_, g, err := f.client(t)
	if err != nil {
		t.Fatal(err)
	}
	association, err := g.udp.Open(netip.AddrPort{}, protocol.UDPKindData)
	if err != nil {
		t.Fatal(err)
	}
	defer association.Close()
	if err := association.Send(f.context, netip.MustParseAddrPort("192.0.2.1:9000"), []byte("blocked outbound")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("UDP packet did not reach blocking Xray writer")
	}
	done := make(chan error, 1)
	go func() { done <- f.server.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		// Unblock the fixture before failing so the test reports the lifecycle
		// defect without hanging the entire package until its global timeout.
		_ = f.dispatcher.Close()
		t.Fatal("server Close did not interrupt a blocked UDP routed write")
	}
}

func TestD11OrbitNativeUDPMappingSurvivesPeerRotation(t *testing.T) {
	f := d11OrbitStart(t, d11OrbitNewIdentity(t), "tcp")
	first, one, err := f.client(t)
	if err != nil {
		t.Fatal(err)
	}
	_, two, err := f.client(t, func(p *dialPlan) { p.channelID = first.plan.channelID })
	if err != nil {
		t.Fatal(err)
	}
	source := netip.MustParseAddrPort("26.26.26.2:42424")
	a, err := one.udp.Open(source, protocol.UDPKindData)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := two.udp.Open(source, protocol.UDPKindData)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	to := netip.MustParseAddrPort("192.0.2.1:9000")
	ctx, cancel := context.WithTimeout(f.context, 5*time.Second)
	defer cancel()
	if err := a.Send(ctx, to, []byte("first peer")); err != nil {
		t.Fatal(err)
	}
	if packet, err := a.Receive(ctx); err != nil || string(packet.Data) != "first peer" {
		t.Fatal("first peer UDP failed", err)
	}
	if err := b.Send(ctx, to, []byte("second peer")); err != nil {
		t.Fatal(err)
	}
	if packet, err := b.Receive(ctx); err != nil || string(packet.Data) != "second peer" {
		t.Fatal("rotated peer UDP failed", err)
	}
	_ = first.Close()
	if err := b.Send(ctx, to, []byte("surviving peer")); err != nil {
		t.Fatal(err)
	}
	if packet, err := b.Receive(ctx); err != nil || string(packet.Data) != "surviving peer" {
		t.Fatal("UDP mapping died with the first physical connection", err)
	}
	if n := len(f.dispatcher.snapshot()); n != 1 {
		t.Fatalf("one authenticated channel UDP mapping dispatched %d times", n)
	}
}

func TestD11OrbitNativeTrustedTransportMatrix(t *testing.T) {
	for _, mode := range []string{"wss", "reality"} {
		t.Run(mode, func(t *testing.T) {
			id := d11OrbitNewIdentity(t)
			dir := t.TempDir()
			certFile, keyFile := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "key.pem")
			if err := os.WriteFile(certFile, []byte(id.certificate), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(keyFile, []byte(id.privateKey), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestD11OrbitTrustedTransportChild$", "-test.v", "-test.timeout=25s")
			cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+certFile, "SSL_CERT_DIR="+dir, "ORBIT_D11_TRUSTED_MODE="+mode, "ORBIT_D11_CERT="+certFile, "ORBIT_D11_KEY="+keyFile)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("trusted %s subprocess failed: %v\n%s", mode, err, out)
			}
			t.Logf("%s", out)
		})
	}
}

func TestD11OrbitTrustedTransportChild(t *testing.T) {
	mode := os.Getenv("ORBIT_D11_TRUSTED_MODE")
	if mode == "" {
		t.Skip("only invoked by the local trust subprocess fixture")
	}
	if mode != "wss" && mode != "reality" {
		t.Fatal("invalid test fixture mode")
	}
	cert, err := os.ReadFile(os.Getenv("ORBIT_D11_CERT"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(os.Getenv("ORBIT_D11_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(cert)
	id := d11OrbitIdentity{certificate: string(cert), privateKey: string(key), pair: pair}
	if block == nil {
		t.Fatal("missing fixture certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	id.pin = sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	id.key, _, err = connectionkey.Generate(id.pin)
	if err != nil {
		t.Fatal(err)
	}
	f := d11OrbitStart(t, id, mode)
	_, g, err := f.client(t)
	if err != nil {
		t.Fatal("current client trusted transport handshake:", err)
	}
	d11OrbitRoundTrip(t, f, g)
	if mode == "wss" {
		other := d11OrbitNewIdentity(t)
		untrusted := d11OrbitStart(t, id, mode, func(c *ServerConfig) {
			c.OuterTls = &Certificate{Certificate: []string{other.certificate}, Key: []string{other.privateKey}}
		})
		if _, _, err := untrusted.client(t); err == nil {
			t.Fatal("inner SPKI pin incorrectly trusted an unrelated outer WSS certificate")
		}
		if len(untrusted.dispatcher.snapshot()) != 0 {
			t.Fatal("untrusted outer WSS reached dispatcher")
		}
	} else {
		before := len(f.dispatcher.snapshot())
		for _, field := range []string{"public-key", "short-id", "server-name", "account"} {
			t.Run(field, func(t *testing.T) {
				if _, _, err := f.client(t, func(p *dialPlan) {
					switch field {
					case "public-key":
						private, e := ecdh.X25519().GenerateKey(rand.Reader)
						if e != nil {
							t.Fatal(e)
						}
						p.settings.Reality.PublicKey = base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())
					case "short-id":
						p.settings.Reality.ShortID = "ffffffffffffffff"
					case "server-name":
						p.settings.Reality.ServerName = "different.test"
					case "account":
						p.user.Token = strings.Repeat("0", 32)
					}
				}); err == nil {
					t.Fatal("invalid REALITY or native account authenticated")
				}
			})
		}
		if len(f.dispatcher.snapshot()) != before {
			t.Fatal("invalid REALITY/native identity reached dispatcher")
		}
	}
}
