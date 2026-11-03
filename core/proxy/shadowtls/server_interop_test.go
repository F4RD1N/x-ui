package shadowtls

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
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

	"github.com/xtls/xray-core/transport/internet/stat"
)

const nativeServerTestPassword = "native-server-interop-password"

// managedTestListener owns every accepted socket, including ones stalled during
// a TLS handshake. Its cleanup waits for handlers, so tests do not silently pass
// with server goroutines surviving the end of a test case.
type managedTestListener struct {
	listener net.Listener
	mu       sync.Mutex
	active   map[net.Conn]struct{}
	workers  sync.WaitGroup
	done     chan struct{}
	ctx      context.Context
	cancel   context.CancelFunc
}

func newManagedTestListener(t *testing.T, handler func(context.Context, net.Conn)) *managedTestListener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &managedTestListener{listener: l, active: make(map[net.Conn]struct{}), done: make(chan struct{}), ctx: ctx, cancel: cancel}
	go func() {
		defer close(s.done)
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.active[conn] = struct{}{}
			s.workers.Add(1)
			s.mu.Unlock()
			go func() {
				defer s.workers.Done()
				defer func() {
					conn.Close()
					s.mu.Lock()
					delete(s.active, conn)
					s.mu.Unlock()
				}()
				_ = conn.SetDeadline(time.Now().Add(12 * time.Second))
				handler(ctx, conn)
			}()
		}
	}()
	t.Cleanup(func() {
		cancel()
		l.Close()
		<-s.done
		s.mu.Lock()
		for conn := range s.active {
			conn.Close()
		}
		s.mu.Unlock()
		done := make(chan struct{})
		go func() { s.workers.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("server connection handlers did not terminate on cleanup")
		}
	})
	return s
}

func (s *managedTestListener) address() string { return s.listener.Addr().String() }

func (s *managedTestListener) waitIdle(t *testing.T) {
	t.Helper()
	end := time.Now().Add(2 * time.Second)
	for {
		s.mu.Lock()
		n := len(s.active)
		s.mu.Unlock()
		if n == 0 {
			return
		}
		if time.Now().After(end) {
			t.Fatalf("%d connection handlers remain after clients closed", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The target is a real local TLS web server. Authenticated carrier traffic leaves
// it after the TLS handshake; ordinary browsers can fetch its small HTTP reply.
func nativeCamouflage(t *testing.T, minVersion, maxVersion uint16, tickets bool) (*managedTestListener, string) {
	t.Helper()
	certificate := testCert(t)
	caFile := filepath.Join(t.TempDir(), "test-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: minVersion, MaxVersion: maxVersion, SessionTicketsDisabled: !tickets}
	s := newManagedTestListener(t, func(ctx context.Context, raw net.Conn) {
		conn := tls.Server(raw, cfg)
		if err := conn.HandshakeContext(ctx); err != nil {
			return
		}
		r := bufio.NewReader(conn)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				_, _ = io.WriteString(conn, "HTTP/1.0 200 OK\r\nContent-Length: 10\r\n\r\ncamouflage")
				return
			}
		}
	})
	return s, caFile
}

func nativeEchoCarrier(t *testing.T, peer string, cfg *ServerConfig) (*managedTestListener, *atomic.Int64) {
	t.Helper()
	accepted := new(atomic.Int64)
	s := newManagedTestListener(t, func(ctx context.Context, raw net.Conn) {
		dialer := net.Dialer{Timeout: 3 * time.Second}
		hs, err := dialer.DialContext(ctx, "tcp", peer)
		if err != nil {
			return
		}
		_ = hs.SetDeadline(time.Now().Add(12 * time.Second))
		conn, _, err := ServerHandshake(ctx, raw, hs, cfg)
		if err != nil {
			return
		}
		accepted.Add(1)
		_, _ = io.Copy(conn, conn)
	})
	return s, accepted
}

func nativeServerConfig(version uint32, strict bool) *ServerConfig {
	return &ServerConfig{Version: version, Strict: strict, Password: nativeServerTestPassword,
		Clients: []*ServerUser{{Email: "test@example.invalid", Password: nativeServerTestPassword}}}
}

func nativeEchoRoundTrip(addr string, cfg *Config, delay time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	conn, err := Handshake(ctx, raw, cfg)
	if err != nil {
		return fmt.Errorf("client handshake: %w", err)
	}
	if delay > 0 {
		time.Sleep(delay)
	}
	for _, size := range []int{33, 65537, 1} {
		want := bytes.Repeat([]byte{byte(size % 251)}, size)
		n, err := conn.Write(want)
		if err != nil || n != len(want) {
			return fmt.Errorf("write %d bytes: n=%d err=%v", size, n, err)
		}
		got := make([]byte, size)
		if _, err = io.ReadFull(conn, got); err != nil {
			return fmt.Errorf("read %d bytes: %w", size, err)
		}
		if !bytes.Equal(want, got) {
			return fmt.Errorf("%d-byte echo mismatch", size)
		}
	}
	return nil
}

func TestNativeServerProtocolMatrix(t *testing.T) {
	for _, tc := range []struct {
		name       string
		version    uint32
		strict     bool
		tlsVersion uint16
		tickets    bool
		delay      time.Duration
		failure    bool
	}{
		{"v1-tls12", 1, false, tls.VersionTLS12, false, 0, false},
		{"v1-tls13-capable", 1, false, tls.VersionTLS13, true, 0, false},
		{"v2-tls12", 2, false, tls.VersionTLS12, false, 0, false},
		{"v2-tls13-tickets", 2, false, tls.VersionTLS13, true, 0, false},
		{"v2-tls13-delayed-write", 2, false, tls.VersionTLS13, true, 150 * time.Millisecond, false},
		{"v3-strict-tls13", 3, true, tls.VersionTLS13, true, 0, false},
		{"v3-nonstrict-tls13", 3, false, tls.VersionTLS13, true, 0, false},
		{"v3-nonstrict-tls12", 3, false, tls.VersionTLS12, false, 0, false},
		{"v3-strict-refuses-tls12", 3, true, tls.VersionTLS12, false, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peer, _ := nativeCamouflage(t, tls.VersionTLS12, tc.tlsVersion, tc.tickets)
			server, accepted := nativeEchoCarrier(t, peer.address(), nativeServerConfig(tc.version, tc.strict))
			cfg := &Config{Version: tc.version, Strict: tc.strict, Password: nativeServerTestPassword, ServerName: "x", AllowInsecure: true}
			err := nativeEchoRoundTrip(server.address(), cfg, tc.delay)
			if (err != nil) != tc.failure {
				t.Fatalf("want failure=%v, got %v", tc.failure, err)
			}
			server.waitIdle(t)
			peer.waitIdle(t)
			if !tc.failure && accepted.Load() != 1 {
				t.Fatalf("authenticated connections = %d", accepted.Load())
			}
			if tc.failure && accepted.Load() != 0 {
				t.Fatal("rejected handshake reached the inner handler")
			}
		})
	}
}

func TestNativeServerAuthentication(t *testing.T) {
	const id = "00112233-4455-6677-8899-aabbccddeeff"
	for _, tc := range []struct {
		name          string
		version       uint32
		serverPass    string
		clientPass    string
		requireUUID   bool
		clientUUID    bool
		wantConnected bool
	}{
		{"v2-wrong-password", 2, nativeServerTestPassword, "incorrect", false, false, false},
		{"v3-wrong-password", 3, nativeServerTestPassword, "incorrect", false, false, false},
		{"v3-standard-uuid-password", 3, id, id, false, false, true},
		{"v3-uuid-accepted-by-default", 3, id, id, false, true, true},
		{"v3-required-uuid-present", 3, id, id, true, true, true},
		{"v3-required-uuid-absent", 3, id, id, true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peer, _ := nativeCamouflage(t, tls.VersionTLS13, tls.VersionTLS13, true)
			scfg := nativeServerConfig(tc.version, true)
			scfg.Password = tc.serverPass
			scfg.Clients[0].Password = tc.serverPass
			scfg.Clients[0].RequireUuidSessionId = tc.requireUUID
			server, accepted := nativeEchoCarrier(t, peer.address(), scfg)
			err := nativeEchoRoundTrip(server.address(), &Config{Version: tc.version, Strict: true, Password: tc.clientPass, ServerName: "x", AllowInsecure: true, UuidSessionId: tc.clientUUID}, 0)
			if (err == nil) != tc.wantConnected {
				t.Fatalf("want connected=%v, got %v", tc.wantConnected, err)
			}
			server.waitIdle(t)
			if !tc.wantConnected && accepted.Load() != 0 {
				t.Fatal("unauthenticated client reached inner handler")
			}
		})
	}
}

func TestNativeServerBrowserCamouflage(t *testing.T) {
	for _, version := range []uint32{2, 3} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			peer, _ := nativeCamouflage(t, tls.VersionTLS13, tls.VersionTLS13, true)
			server, accepted := nativeEchoCarrier(t, peer.address(), nativeServerConfig(version, true))
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", server.address(), &tls.Config{ServerName: "x", InsecureSkipVerify: true})
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			_, err = io.WriteString(conn, "GET / HTTP/1.0\r\nHost: x\r\n\r\n")
			if err != nil {
				conn.Close()
				t.Fatal(err)
			}
			response, err := io.ReadAll(conn)
			conn.Close()
			if err != nil || !strings.HasSuffix(string(response), "\r\n\r\ncamouflage") {
				t.Fatalf("camouflage response=%q err=%v", response, err)
			}
			server.waitIdle(t)
			peer.waitIdle(t)
			if accepted.Load() != 0 {
				t.Fatal("ordinary browser entered authenticated inner handler")
			}
		})
	}
}

func TestNativeServerConcurrentConnections(t *testing.T) {
	peer, _ := nativeCamouflage(t, tls.VersionTLS13, tls.VersionTLS13, true)
	server, accepted := nativeEchoCarrier(t, peer.address(), nativeServerConfig(3, true))
	const count = 12
	results := make(chan error, count)
	for i := 0; i < count; i++ {
		go func() {
			results <- nativeEchoRoundTrip(server.address(), &Config{Version: 3, Strict: true, Password: nativeServerTestPassword, ServerName: "x", AllowInsecure: true}, 0)
		}()
	}
	for i := 0; i < count; i++ {
		if err := <-results; err != nil {
			t.Error(err)
		}
	}
	server.waitIdle(t)
	peer.waitIdle(t)
	if accepted.Load() != count {
		t.Fatalf("accepted=%d, expected %d", accepted.Load(), count)
	}
}

func TestNativeServerHandshakeCancellation(t *testing.T) {
	for _, version := range []uint32{1, 2, 3} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			client, raw := net.Pipe()
			peer, hs := net.Pipe()
			defer client.Close()
			defer raw.Close()
			defer peer.Close()
			defer hs.Close()
			_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
			_ = hs.SetDeadline(time.Now().Add(3 * time.Second))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, _, err := ServerHandshake(ctx, raw, hs, nativeServerConfig(version, true))
				done <- err
			}()
			cancel()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("canceled handshake succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("pending handshake ignored context cancellation")
			}
		})
	}
}

func TestNativeServerHelloValidation(t *testing.T) {
	const password = "00112233-4455-6677-8899-aabbccddeeff"
	hello := make([]byte, 71)
	hello[0], hello[3], hello[38] = 1, 67, 32
	if _, err := SessionID(hello, password, true); err != nil {
		t.Fatal(err)
	}
	user := &ServerUser{Email: "user@example.invalid", Password: password, RequireUuidSessionId: true}
	if got := authenticatedHello(hello, []*ServerUser{nil, user}); got != user {
		t.Fatal("valid custom ClientHello was not authenticated")
	}
	frames := append(record(22, [2]byte{3, 1}, hello[:20]), record(22, [2]byte{3, 1}, hello[20:])...)
	parsed, original, err := readHello(bytes.NewReader(frames), 1)
	if err != nil || !bytes.Equal(parsed, hello) || !bytes.Equal(original, frames) {
		t.Fatalf("fragmented ClientHello was not preserved: %v", err)
	}
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"truncated", frames[:len(frames)-1]},
		{"wrong-record-type", record(23, [2]byte{3, 3}, hello)},
		{"oversized-record", []byte{22, 3, 1, 255, 255}},
		{"oversized-hello", record(22, [2]byte{3, 1}, []byte{1, 255, 255, 255})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := readHello(bytes.NewReader(tc.data), 1); err == nil {
				t.Fatal("malformed ClientHello accepted")
			}
		})
	}
	for i := range hello {
		tampered := append([]byte(nil), hello...)
		tampered[i] ^= 1
		if authenticatedHello(tampered, []*ServerUser{user}) != nil {
			t.Fatalf("modified authenticated ClientHello byte %d accepted", i)
		}
	}
}

func TestNativeServerStrictPolicyIndependentOfClient(t *testing.T) {
	peer, _ := nativeCamouflage(t, tls.VersionTLS12, tls.VersionTLS12, false)
	server, accepted := nativeEchoCarrier(t, peer.address(), nativeServerConfig(3, true))
	err := nativeEchoRoundTrip(server.address(), &Config{Version: 3, Strict: false, Password: nativeServerTestPassword, ServerName: "x", AllowInsecure: true}, 0)
	if err == nil {
		t.Fatal("strict server accepted a non-strict client through TLS 1.2")
	}
	server.waitIdle(t)
	if accepted.Load() != 0 {
		t.Fatal("server-side strict policy was bypassed")
	}
}

type tamperOnceConn struct {
	net.Conn
	tamper atomic.Bool
}

func (c *tamperOnceConn) Write(p []byte) (int, error) {
	if c.tamper.Swap(false) && len(p) > 0 {
		p = append([]byte(nil), p...)
		p[len(p)-1] ^= 1
	}
	return c.Conn.Write(p)
}

type fragmentReadConn struct {
	net.Conn
	limit int
}

func (c *fragmentReadConn) Read(p []byte) (int, error) {
	if len(p) > c.limit {
		p = p[:c.limit]
	}
	return c.Conn.Read(p)
}

func TestNativeServerFragmentedReads(t *testing.T) {
	for _, version := range []uint32{1, 2, 3} {
		for _, limit := range []int{1, 7, 13} {
			t.Run(fmt.Sprintf("v%d-read%d", version, limit), func(t *testing.T) {
				peer, _ := nativeCamouflage(t, tls.VersionTLS12, tls.VersionTLS13, true)
				server, _ := nativeEchoCarrier(t, peer.address(), nativeServerConfig(version, true))
				raw, err := net.DialTimeout("tcp", server.address(), 3*time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer raw.Close()
				_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
				conn, err := Handshake(context.Background(), &fragmentReadConn{Conn: raw, limit: limit}, &Config{Version: version, Strict: true, Password: nativeServerTestPassword, ServerName: "x", AllowInsecure: true})
				if err != nil {
					t.Fatal(err)
				}
				want := bytes.Repeat([]byte("fragmented"), 73)
				if _, err = conn.Write(want); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, len(want))
				if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(want, got) {
					t.Fatalf("fragmented stream echo: %v", err)
				}
				raw.Close()
				server.waitIdle(t)
				peer.waitIdle(t)
			})
		}
	}
}

func TestNativeServerHalfClose(t *testing.T) {
	for _, version := range []uint32{1, 2, 3} {
		for _, withStats := range []bool{false, true} {
			t.Run(fmt.Sprintf("v%d-stats%v", version, withStats), func(t *testing.T) {
				peer, _ := nativeCamouflage(t, tls.VersionTLS12, tls.VersionTLS13, true)
				result := make(chan error, 1)
				server := newManagedTestListener(t, func(ctx context.Context, raw net.Conn) {
					hs, err := (&net.Dialer{}).DialContext(ctx, "tcp", peer.address())
					if err != nil {
						result <- err
						return
					}
					conn, _, err := ServerHandshake(ctx, raw, hs, nativeServerConfig(version, true))
					if err != nil {
						result <- err
						return
					}
					// This service does not respond until it receives the client's
					// request EOF. A full close would prevent delivery of the reply.
					request, err := io.ReadAll(io.LimitReader(conn, 1<<20))
					if err == nil {
						_, err = conn.Write(append([]byte("ack:"), request...))
					}
					result <- err
				})
				raw, err := net.DialTimeout("tcp", server.address(), 3*time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer raw.Close()
				_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
				var carrier net.Conn = raw
				if withStats {
					carrier = &stat.CounterConnection{Connection: raw}
				}
				conn, err := Handshake(context.Background(), carrier, &Config{Version: version, Strict: true, Password: nativeServerTestPassword, ServerName: "x", AllowInsecure: true})
				if err != nil {
					t.Fatal(err)
				}
				request := bytes.Repeat([]byte("client-fin"), 4096)
				if _, err := conn.Write(request); err != nil {
					t.Fatal(err)
				}
				if err := conn.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				response, err := io.ReadAll(conn)
				if err != nil || !bytes.Equal(response, append([]byte("ack:"), request...)) {
					t.Fatalf("half-close lost response: bytes=%d err=%v", len(response), err)
				}
				select {
				case err := <-result:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("server request handler did not complete")
				}
				raw.Close()
				server.waitIdle(t)
				peer.waitIdle(t)
			})
		}
	}
}

func TestNativeServerRejectsTamperedData(t *testing.T) {
	for _, damage := range []string{"bad-mac", "oversized-record"} {
		t.Run(damage, func(t *testing.T) {
			peer, _ := nativeCamouflage(t, tls.VersionTLS13, tls.VersionTLS13, true)
			server, accepted := nativeEchoCarrier(t, peer.address(), nativeServerConfig(3, true))
			raw, err := net.DialTimeout("tcp", server.address(), 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			_ = raw.SetDeadline(time.Now().Add(4 * time.Second))
			wrapped := &tamperOnceConn{Conn: raw}
			conn, err := Handshake(context.Background(), wrapped, &Config{Version: 3, Strict: true, Password: nativeServerTestPassword, ServerName: "x", AllowInsecure: true})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Write([]byte("authorized")); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len("authorized"))
			if _, err := io.ReadFull(conn, got); err != nil || string(got) != "authorized" {
				t.Fatalf("initial authenticated echo: %q %v", got, err)
			}
			if accepted.Load() != 1 {
				t.Fatal("initial request did not reach authenticated handler")
			}
			if damage == "bad-mac" {
				wrapped.tamper.Store(true)
				_, err = conn.Write([]byte("modified"))
			} else {
				_, err = raw.Write([]byte{23, 3, 3, 255, 255})
			}
			if err != nil {
				t.Fatal(err)
			}
			var b [1]byte
			_, err = conn.Read(b[:])
			if err == nil {
				t.Fatal("malformed authenticated record was accepted")
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatalf("malformed record was not rejected promptly: %v", err)
			}
			raw.Close()
			server.waitIdle(t)
			peer.waitIdle(t)
		})
	}
}

// This optional independent reference is deliberately an external executable.
// Its GPL reference sources/dependencies do not enter the core's module graph.
func TestNativeServerIndependentClient(t *testing.T) {
	bin := os.Getenv("SHADOWTLS_REFERENCE_CLIENT")
	if bin == "" {
		t.Skip("SHADOWTLS_REFERENCE_CLIENT is not set")
	}
	for _, version := range []uint32{1, 2, 3} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			peer, ca := nativeCamouflage(t, tls.VersionTLS12, tls.VersionTLS13, false)
			server, accepted := nativeEchoCarrier(t, peer.address(), nativeServerConfig(version, true))
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bin, "-server", server.address(), "-version", strconv.Itoa(int(version)), "-password", nativeServerTestPassword, "-strict=true", "-ca", ca)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("independent client: %v\n%s", err, output)
			}
			if !strings.Contains(string(output), "PASS independent-client echo") || accepted.Load() != 1 {
				t.Fatalf("missing independent echo confirmation: %q; accepted=%d", output, accepted.Load())
			}
			server.waitIdle(t)
			peer.waitIdle(t)
		})
	}
}

func FuzzNativeServerHello(f *testing.F) {
	hello := make([]byte, 71)
	hello[0], hello[3], hello[38] = 1, 67, 32
	f.Add(record(22, [2]byte{3, 1}, hello))
	f.Add([]byte{22, 3, 3, 255, 255})
	f.Fuzz(func(t *testing.T, data []byte) {
		parsed, _, err := readHello(bytes.NewReader(data), 1)
		if err == nil {
			if len(parsed) > 65536 {
				t.Fatal("ClientHello parser exceeded its bound")
			}
			_ = authenticatedHello(parsed, []*ServerUser{{Password: "00112233-4455-6677-8899-aabbccddeeff", RequireUuidSessionId: true}})
		}
		_ = serverHelloTLS13(data)
	})
}
