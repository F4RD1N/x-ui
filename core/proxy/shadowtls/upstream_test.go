package shadowtls

// Interop against the official shadow-tls servers. Skipped unless
// NATIVE_SERVER_DIR names the directory holding shadow-tls (0.2.25) and
// shadow-tls-v1 (0.1.4); run it under the interop lock.

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol/tls/cert"
)

const upstreamPassword = "interop-password-123"

func serverDir(t *testing.T) string {
	d := os.Getenv("NATIVE_SERVER_DIR")
	if d == "" {
		t.Skip("NATIVE_SERVER_DIR not set")
	}
	return d
}

func freePort(t *testing.T) int {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func echoServer(t *testing.T) string {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); c.Close() }()
		}
	}()
	return l.Addr().String()
}

func spawn(t *testing.T, name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	time.Sleep(500 * time.Millisecond)
}

func opensslServer(t *testing.T, flags ...string) string {
	dir := t.TempDir()
	generated, _ := cert.MustGenerate(nil, cert.DNSNames("x"))
	c, k := generated.ToPEM()
	_ = os.WriteFile(filepath.Join(dir, "c.pem"), c, 0o600)
	_ = os.WriteFile(filepath.Join(dir, "k.pem"), k, 0o600)
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	spawn(t, "openssl", append([]string{"s_server", "-accept", addr, "-cert", filepath.Join(dir, "c.pem"), "-key", filepath.Join(dir, "k.pem"), "-www", "-quiet"}, flags...)...)
	return addr
}

func upstreamServer(t *testing.T, version int, strict bool, data, hs string) string {
	dir := serverDir(t)
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	if version == 1 {
		spawn(t, filepath.Join(dir, "shadow-tls-v1"), "server", addr, data, hs)
		return addr
	}
	var args []string
	if version == 3 {
		args = append(args, "--v3")
		if strict {
			args = append(args, "--strict")
		}
	}
	args = append(args, "server", "--listen", addr, "--server", data, "--tls", hs, "--password", upstreamPassword)
	spawn(t, filepath.Join(dir, "shadow-tls"), args...)
	return addr
}

func roundTrip(t *testing.T, addr string, cfg *Config, delay time.Duration) error {
	raw, e := net.Dial("tcp", addr)
	if e != nil {
		t.Fatal(e)
	}
	defer raw.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cfg.Password, cfg.ServerName, cfg.AllowInsecure = upstreamPassword, "x", true
	conn, e := Handshake(ctx, raw, cfg)
	if e != nil {
		return fmt.Errorf("handshake: %w", e)
	}
	time.Sleep(delay)
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	for i, n := range []int{33, 40000, 1} {
		msg := bytes.Repeat([]byte{byte('a' + i)}, n)
		if _, e = conn.Write(msg); e != nil {
			return fmt.Errorf("write %d (%d bytes): %w", i, n, e)
		}
		got := make([]byte, n)
		if _, e = io.ReadFull(conn, got); e != nil {
			return fmt.Errorf("read %d (%d bytes): %w", i, n, e)
		}
		if !bytes.Equal(got, msg) {
			return fmt.Errorf("echo mismatch: %q", got[:min(n, 40)])
		}
	}
	return nil
}

func goHandshakeServer(t *testing.T, max uint16) string {
	return tlsServer(t, &gotls.Config{MaxVersion: max}, func(c *gotls.Conn) { _, _ = io.Copy(io.Discard, c) })
}

func TestUpstreamShadowTLS(t *testing.T) {
	serverDir(t)
	for _, tc := range []struct {
		name    string
		version int
		strict  bool
		hs      func(t *testing.T) string
		delay   time.Duration
		fails   bool
	}{
		// v2: TLS 1.3 handshake servers send tickets the client must drop.
		{"v2-go-tls13", 2, false, func(t *testing.T) string { return goHandshakeServer(t, gotls.VersionTLS13) }, 0, false},
		{"v2-openssl-tls13-delayed-write", 2, false, func(t *testing.T) string { return opensslServer(t, "-tls1_3") }, 300 * time.Millisecond, false},
		{"v2-openssl-tls13", 2, false, func(t *testing.T) string { return opensslServer(t, "-tls1_3") }, 0, false},
		{"v2-go-tls12", 2, false, func(t *testing.T) string { return goHandshakeServer(t, gotls.VersionTLS12) }, 0, false},
		// v1 must negotiate TLS 1.2 also with TLS 1.3-capable servers.
		{"v1-go-tls13-capable", 1, false, func(t *testing.T) string { return goHandshakeServer(t, gotls.VersionTLS13) }, 0, false},
		{"v1-openssl-any", 1, false, func(t *testing.T) string { return opensslServer(t) }, 0, false},
		{"v1-go-tls12", 1, false, func(t *testing.T) string { return goHandshakeServer(t, gotls.VersionTLS12) }, 0, false},
		// v3: non-strict allows TLS 1.2 handshake servers, strict does not.
		{"v3-nonstrict-go-tls12", 3, false, func(t *testing.T) string { return goHandshakeServer(t, gotls.VersionTLS12) }, 0, false},
		{"v3-nonstrict-go-tls13", 3, false, func(t *testing.T) string { return goHandshakeServer(t, gotls.VersionTLS13) }, 0, false},
		{"v3-strict-go-tls13", 3, true, func(t *testing.T) string { return goHandshakeServer(t, gotls.VersionTLS13) }, 0, false},
		{"v3-strict-go-tls12", 3, true, func(t *testing.T) string { return goHandshakeServer(t, gotls.VersionTLS12) }, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := upstreamServer(t, tc.version, tc.strict, echoServer(t), tc.hs(t))
			e := roundTrip(t, addr, &Config{Version: uint32(tc.version), Strict: tc.strict}, tc.delay)
			if tc.fails != (e != nil) {
				t.Fatalf("want failure=%v, got %v", tc.fails, e)
			}
		})
	}
}
