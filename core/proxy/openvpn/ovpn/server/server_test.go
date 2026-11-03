package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/client"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/clientproof"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/ctlwrap"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/handshake"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/options"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/wire"
)

type testPacketConn struct {
	net.Conn
	tcp bool
	fr  *wire.FrameReader
}

func (c *testPacketConn) ReadPacket(b []byte) (int, error) {
	if c.tcp {
		return c.fr.ReadPacket(b)
	}
	return c.Read(b)
}
func (c *testPacketConn) WritePacket(b []byte) error {
	if c.tcp {
		var err error
		b, err = wire.AppendFrame(nil, b)
		if err != nil {
			return err
		}
	}
	for len(b) > 0 {
		n, err := c.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

// Single-peer UDP is enough for this per-session engine; Xray owns association
// dispatch. Clone packet bytes before handing them to the engine.
type testUDP struct {
	*net.UDPConn
	mu   sync.Mutex
	peer *net.UDPAddr
}

func (c *testUDP) ReadPacket(b []byte) (int, error) {
	for {
		n, p, e := c.ReadFromUDP(b)
		if e != nil {
			return n, e
		}
		c.mu.Lock()
		if c.peer == nil {
			c.peer = p
		}
		ok := p.String() == c.peer.String()
		c.mu.Unlock()
		if ok {
			return n, nil
		}
	}
}
func (c *testUDP) WritePacket(b []byte) error {
	c.mu.Lock()
	p := c.peer
	c.mu.Unlock()
	if p == nil {
		return errors.New("missing peer")
	}
	_, e := c.WriteToUDP(b, p)
	return e
}

type harness struct {
	address string
	tcp     bool
	result  chan *Session
	errors  chan error
	ctx     context.Context
	cancel  context.CancelFunc
	cfg     Config
}

func startHarness(t *testing.T, cfg Config) *harness { return startHarnessTransform(t, cfg, nil) }
func startHarnessTransform(t *testing.T, cfg Config, transform func([]byte) []byte) *harness {
	return startHarnessTransport(t, cfg, transform, nil)
}
func startHarnessTransport(t *testing.T, cfg Config, transform func([]byte) []byte, wrap func(PacketConn) PacketConn) *harness {
	t.Helper()
	p := getPKI(t)
	if cfg.TLSConfig == nil {
		cfg.TLSConfig = &tls.Config{Certificates: []tls.Certificate{p.serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: p.pool, MinVersion: tls.VersionTLS12}
	}
	if cfg.Authenticate == nil {
		cfg.Authenticate = func(context.Context, *handshake.ClientMessage, tls.ConnectionState) (Admission, error) {
			return Admission{Identity: "client", Push: []string{"topology subnet", "ifconfig 10.8.0.2 255.255.255.0", "route-gateway 10.8.0.1"}}, nil
		}
	}
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = 3 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := &harness{tcp: cfg.TCP, result: make(chan *Session, 1), errors: make(chan error, 1), ctx: ctx, cancel: cancel, cfg: cfg}
	t.Cleanup(cancel)
	run := func(pc PacketConn) {
		if wrap != nil {
			pc = wrap(pc)
		}
		s, err := Serve(ctx, pc, cfg)
		if err != nil {
			h.errors <- err
			return
		}
		h.result <- s
		defer s.Close()
		b := make([]byte, 65536)
		for {
			n, e := s.ReadPacket(b)
			if e != nil {
				return
			}
			packet := b[:n]
			if transform != nil {
				packet = transform(packet)
			}
			if len(packet) == 0 {
				continue
			}
			if e = s.WritePacket(packet); e != nil {
				return
			}
		}
	}
	if cfg.TCP {
		l, e := net.Listen("tcp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		h.address = l.Addr().String()
		t.Cleanup(func() { l.Close() })
		go func() {
			c, e := l.Accept()
			if e != nil {
				return
			}
			run(&testPacketConn{Conn: c, tcp: true, fr: wire.NewFrameReader(c)})
		}()
	} else {
		u, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if e != nil {
			t.Fatal(e)
		}
		h.address = u.LocalAddr().String()
		t.Cleanup(func() { u.Close() })
		go run(&testUDP{UDPConn: u})
	}
	return h
}
func (h *harness) text(t *testing.T, extra string) string {
	p := getPKI(t)
	host, port, _ := net.SplitHostPort(h.address)
	proto := "udp"
	if h.tcp {
		proto = "tcp-client"
	}
	return fmt.Sprintf("client\ndev tun\nnobind\nremote-cert-tls server\nremote %s %s %s\nauth SHA256\ndata-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305\n%s\n<ca>\n%s</ca>\n<cert>\n%s</cert>\n<key>\n%s</key>\n", host, port, proto, extra, p.caPEM, p.clientCertPEM, p.clientKeyPEM)
}
func dialHarness(t *testing.T, h *harness, extra string, mutate func(*client.Config)) (*client.Client, error) {
	t.Helper()
	o, e := options.Parse(h.text(t, extra))
	if e != nil {
		t.Fatal(e)
	}
	cfg := client.Config{Options: o, Dial: func(ctx context.Context, n, a string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, n, a)
	}, HandshakeTimeout: 4 * time.Second}
	if mutate != nil {
		mutate(&cfg)
	}
	return client.Dial(h.ctx, cfg)
}
func echoPacket(t *testing.T, c *client.Client, n int) {
	t.Helper()
	p := make([]byte, n)
	p[0] = 0x45
	rand.Read(p[20:])
	if err := c.WritePacket(p); err != nil {
		t.Fatal(err)
	}
	got := make(chan []byte, 1)
	go func() {
		b := make([]byte, 65536)
		n, e := c.ReadPacket(b)
		if e == nil {
			got <- b[:n]
		}
	}()
	select {
	case b := <-got:
		if !bytes.Equal(p, b) {
			t.Fatal("packet mismatch")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("packet timeout")
	}
}

func TestNativeClientMatrix(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		for _, cipher := range []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305", "AES-256-CBC"} {
			for _, prf := range []bool{false, true} {
				t.Run(fmt.Sprintf("tcp=%v/cipher=%s/prf=%v", tcp, cipher, prf), func(t *testing.T) {
					h := startHarness(t, Config{TCP: tcp, Ciphers: []string{cipher}})
					extra := ""
					if strings.Contains(cipher, "CBC") {
						extra = "data-ciphers AES-256-CBC\ncipher AES-256-CBC"
					}
					c, e := dialHarness(t, h, extra, func(c *client.Config) { c.DisableEKM = prf; c.DisableDataV2 = prf })
					if e != nil {
						t.Fatal(e)
					}
					defer c.Close()
					if c.Info().Cipher != cipher {
						t.Fatal("cipher mismatch")
					}
					echoPacket(t, c, 100)
					echoPacket(t, c, 1400)
				})
			}
		}
	}
}
func TestNativeWrappers(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		for _, mode := range []string{"tls-auth", "tls-crypt", "tls-crypt-v2"} {
			t.Run(fmt.Sprintf("%s/tcp=%v", mode, tcp), func(t *testing.T) {
				key := newStaticKey(t)
				cfg := Config{TCP: tcp, Wrapper: mode, StaticKey: key, KeyDirection: ctlwrap.Normal}
				extra := ""
				if mode == "tls-auth" {
					extra = "key-direction 1\n<tls-auth>\n" + staticKeyText(key) + "</tls-auth>"
				} else if mode == "tls-crypt" {
					extra = "<tls-crypt>\n" + staticKeyText(key) + "</tls-crypt>"
				} else {
					if _, e := os.Stat("/usr/sbin/openvpn"); e != nil {
						t.Skip("stock key generator missing")
					}
					dir := t.TempDir()
					srv := filepath.Join(dir, "s.key")
					cli := filepath.Join(dir, "c.key")
					for _, args := range [][]string{{"--genkey", "tls-crypt-v2-server", srv}, {"--tls-crypt-v2", srv, "--genkey", "tls-crypt-v2-client", cli}} {
						if out, e := exec.Command("/usr/sbin/openvpn", args...).CombinedOutput(); e != nil {
							t.Fatalf("genkey: %v (%d output bytes)", e, len(out))
						}
					}
					b, _ := os.ReadFile(srv)
					cfg.TLSCryptV2Key, _ = ctlwrap.ParseTLSCryptV2ServerKey(b)
					b, _ = os.ReadFile(cli)
					extra = "<tls-crypt-v2>\n" + string(b) + "</tls-crypt-v2>"
				}
				h := startHarness(t, cfg)
				c, e := dialHarness(t, h, extra, nil)
				if e != nil {
					t.Fatal(e)
				}
				defer c.Close()
				echoPacket(t, c, 1400)
			})
		}
	}
}
func proofPolicy(t *testing.T, required bool, calls *atomic.Int32) (func(context.Context, *handshake.ClientMessage, tls.ConnectionState) (Admission, error), *clientproof.Key) {
	t.Helper()
	key, e := clientproof.New("test", bytes.Repeat([]byte{0x43}, 32))
	if e != nil {
		t.Fatal(e)
	}
	auth := func(ctx context.Context, cm *handshake.ClientMessage, cs tls.ConnectionState) (Admission, error) {
		calls.Add(1)
		if len(cs.VerifiedChains) == 0 {
			return Admission{}, ErrAuthentication
		}
		if required {
			fields, e := peerFields(cm.PeerInfo)
			if e != nil {
				return Admission{}, e
			}
			ekm, e := cs.ExportKeyingMaterial(clientproof.ExporterLabel, nil, 32)
			if e != nil {
				return Admission{}, e
			}
			if e = clientproof.Verify(fields[clientproof.PeerInfoKey], ekm, bytes.Repeat([]byte{0x43}, 32)); e != nil {
				return Admission{}, e
			}
		}
		return Admission{Identity: cs.PeerCertificates[0].Subject.CommonName, Push: []string{"topology subnet", "ifconfig 10.8.0.2 255.255.255.0"}}, nil
	}
	return auth, key
}
func TestAdmissionRekeyAndProof(t *testing.T) {
	for _, required := range []bool{false, true} {
		t.Run(fmt.Sprintf("proof=%v", required), func(t *testing.T) {
			var calls atomic.Int32
			auth, key := proofPolicy(t, required, &calls)
			h := startHarness(t, Config{Authenticate: auth, Renegotiate: 250 * time.Millisecond})
			c, e := dialHarness(t, h, "", func(c *client.Config) {
				if required {
					c.ClientProof = key
				}
			})
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			until := time.Now().Add(1100 * time.Millisecond)
			for time.Now().Before(until) {
				echoPacket(t, c, 1400)
				time.Sleep(30 * time.Millisecond)
			}
			if calls.Load() < 3 {
				t.Fatalf("only %d admissions", calls.Load())
			}
		})
	}
	for _, which := range []string{"missing", "wrong-key", "reject-rekey"} {
		t.Run(which, func(t *testing.T) {
			var calls atomic.Int32
			policy, key := proofPolicy(t, true, &calls)
			if which == "wrong-key" {
				key, _ = clientproof.New("test", bytes.Repeat([]byte{0x44}, 32))
			}
			auth := func(ctx context.Context, m *handshake.ClientMessage, cs tls.ConnectionState) (Admission, error) {
				if which == "reject-rekey" && calls.Load() > 0 {
					return Admission{}, ErrAuthentication
				}
				return policy(ctx, m, cs)
			}
			h := startHarness(t, Config{TCP: true, Authenticate: auth, Renegotiate: 200 * time.Millisecond})
			c, e := dialHarness(t, h, "", func(c *client.Config) {
				if which != "missing" {
					c.ClientProof = key
				}
			})
			if which != "reject-rekey" {
				if e == nil {
					c.Close()
					t.Fatal("unauthorized client admitted")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			select {
			case <-c.Done():
			case <-time.After(2 * time.Second):
				t.Fatal("rejected rekey remained active")
			}
		})
	}
}

// Stock OpenVPN is an independent interoperability oracle. The null device
// prevents any host routing changes; it still performs real TLS, key-method2,
// push negotiation and encrypted keepalive exchanges against the native server.
func TestStockOpenVPNClient(t *testing.T) {
	if testing.Short() {
		t.Skip("stock process integration")
	}
	if _, e := os.Stat("/usr/sbin/openvpn"); e != nil {
		t.Skip("stock OpenVPN not installed")
	}
	for _, tcp := range []bool{false, true} {
		for _, mode := range []string{"", "tls-auth", "tls-crypt", "tls-crypt-v2"} {
			t.Run(fmt.Sprintf("tcp=%v/%s", tcp, mode), func(t *testing.T) {
				cfg := Config{TCP: tcp, Wrapper: mode}
				extra := ""
				if mode == "tls-auth" || mode == "tls-crypt" {
					cfg.StaticKey = newStaticKey(t)
					extra = "<" + mode + ">\n" + staticKeyText(cfg.StaticKey) + "</" + mode + ">"
					if mode == "tls-auth" {
						extra += "\nkey-direction 1"
					}
				}
				if mode == "tls-crypt-v2" {
					d := t.TempDir()
					sp := filepath.Join(d, "s")
					cp := filepath.Join(d, "c")
					for _, a := range [][]string{{"--genkey", "tls-crypt-v2-server", sp}, {"--tls-crypt-v2", sp, "--genkey", "tls-crypt-v2-client", cp}} {
						if b, e := exec.Command("/usr/sbin/openvpn", a...).CombinedOutput(); e != nil {
							t.Fatalf("genkey %v (%d)", e, len(b))
						}
					}
					b, _ := os.ReadFile(sp)
					cfg.TLSCryptV2Key, _ = ctlwrap.ParseTLSCryptV2ServerKey(b)
					b, _ = os.ReadFile(cp)
					extra = "<tls-crypt-v2>\n" + string(b) + "</tls-crypt-v2>"
				}
				h := startHarness(t, cfg)
				text := strings.Replace(h.text(t, extra), "dev tun", "dev null\ndev-type tun\nifconfig-noexec\nroute-noexec\n", 1)
				p := filepath.Join(t.TempDir(), "client.ovpn")
				os.WriteFile(p, []byte(text), 0600)
				ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, "/usr/sbin/openvpn", "--config", p, "--verb", "3", "--connect-retry-max", "1")
				out, e := cmd.StdoutPipe()
				if e != nil {
					t.Fatal(e)
				}
				cmd.Stderr = cmd.Stdout
				if e = cmd.Start(); e != nil {
					t.Fatal(e)
				}
				defer func() { cancel(); cmd.Wait() }()
				ready := make(chan bool, 1)
				go func() {
					b := make([]byte, 4096)
					var log bytes.Buffer
					for {
						n, e := out.Read(b)
						log.Write(b[:n])
						if bytes.Contains(log.Bytes(), []byte("Initialization Sequence Completed")) {
							ready <- true
							return
						}
						if e != nil {
							ready <- false
							return
						}
					}
				}()
				select {
				case ok := <-ready:
					if !ok {
						t.Fatal("stock initialization failed")
					}
				case <-ctx.Done():
					t.Fatal("stock initialization timed out")
				}
				select {
				case s := <-h.result:
					if s.Identity() != "client" {
						t.Fatal("identity")
					}
				case e := <-h.errors:
					t.Fatal(e)
				case <-ctx.Done():
					t.Fatal("missing native admission")
				}
			})
		}
	}
}

func TestConfigAndBounds(t *testing.T) {
	p := getPKI(t)
	base := Config{TLSConfig: &tls.Config{Certificates: []tls.Certificate{p.serverCert}}, Authenticate: func(context.Context, *handshake.ClientMessage, tls.ConnectionState) (Admission, error) {
		return Admission{}, ErrAuthentication
	}}
	for _, mut := range []func(*Config){func(c *Config) { c.TLSConfig = nil }, func(c *Config) { c.Authenticate = nil }, func(c *Config) { c.Ciphers = []string{"invalid"} }, func(c *Config) { c.HandshakeTimeout = -1 }} {
		c := base
		mut(&c)
		if validate(&c) == nil {
			t.Fatal("bad config accepted")
		}
	}
	for _, push := range [][]string{{"cipher AES-256-GCM"}, {"ifconfig x,y"}, {"ping 1\n"}, {strings.Repeat("x", 1025)}} {
		if validatePush(push) == nil {
			t.Fatal("bad push accepted")
		}
	}
	if _, e := peerFields("IV_PROTO=2\nIV_PROTO=8\n"); e == nil {
		t.Fatal("duplicate capability accepted")
	}
	a := newTLSAdapter(1000, nil, nil, nil)
	defer a.Close()
	if _, e := a.Write(make([]byte, maxAdapterBuffer+1)); !errors.Is(e, errAdapterOverflow) {
		t.Fatal("write queue unbounded")
	}
}
