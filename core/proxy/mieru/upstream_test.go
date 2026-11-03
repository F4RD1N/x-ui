package mieru

// Interop against official mita servers. Skipped unless NATIVE_MITA lists
// mita executables (comma-separated, e.g. 3.38.1 and 3.34.1); run it under
// the interop lock.

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet"
)

func mitaServers(t *testing.T) []string {
	v := os.Getenv("NATIVE_MITA")
	if v == "" {
		t.Skip("NATIVE_MITA not set")
	}
	return strings.Split(v, ",")
}

func freeUDPPort(t *testing.T, network string) int {
	if network == "udp" {
		c, e := net.ListenPacket("udp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		return c.LocalAddr().(*net.UDPAddr).Port
	}
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func startMita(t *testing.T, bin, network string) string {
	dir := t.TempDir()
	port := freeUDPPort(t, network)
	cfg, _ := json.Marshal(map[string]any{
		"portBindings": []any{map[string]any{"port": port, "protocol": strings.ToUpper(network)}},
		"users":        []any{map[string]any{"name": "user", "password": "pass", "allowLoopbackIP": true}},
		"loggingLevel": "INFO", "mtu": 1400,
	})
	file := filepath.Join(dir, "mita.json")
	_ = os.WriteFile(file, cfg, 0o600)
	cmd := exec.Command(bin, "run")
	cmd.Env = append(os.Environ(), "MITA_CONFIG_JSON_FILE="+file, "MITA_INSECURE_UDS=1", "MITA_UDS_PATH="+filepath.Join(dir, "mita.sock"))
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	time.Sleep(3 * time.Second)
	return fmt.Sprintf("127.0.0.1:%d", port)
}

func dialMita(t *testing.T, network, addr string, dest net.Addr) *Conn {
	var raw net.Conn
	if network == "udp" {
		pc, e := net.ListenPacket("udp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		ua, _ := net.ResolveUDPAddr("udp", addr)
		raw = &internet.PacketConnWrapper{PacketConn: pc, Dest: ua}
	} else {
		var e error
		if raw, e = net.Dial("tcp", addr); e != nil {
			t.Fatal(e)
		}
	}
	t.Cleanup(func() { raw.Close() })
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	w, _ := newWire(raw, "user", "pass", network == "udp", false)
	c, e := Open(w)
	if e != nil {
		t.Fatal(e)
	}
	p := dest.(*net.TCPAddr).Port
	if e = socksRequest(c, 1, []byte{1, 127, 0, 0, 1, byte(p >> 8), byte(p)}); e != nil {
		t.Fatal(e)
	}
	_ = raw.SetDeadline(time.Time{})
	return c
}

func TestUpstreamMita(t *testing.T) {
	for _, bin := range mitaServers(t) {
		for _, network := range []string{"udp", "tcp"} {
			t.Run(filepath.Base(filepath.Dir(bin))+"-"+network, func(t *testing.T) {
				addr := startMita(t, bin, network)
				dst, e := net.Listen("tcp", "127.0.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				defer dst.Close()
				accepted := make(chan net.Conn, 4)
				go func() {
					for {
						c, e := dst.Accept()
						if e != nil {
							return
						}
						accepted <- c
					}
				}()

				// Close reaches the destination promptly (UDP: closeRequest).
				c := dialMita(t, network, addr, dst.Addr())
				_, _ = c.Write([]byte("hi"))
				d := <-accepted
				c.Close()
				_ = d.SetReadDeadline(time.Now().Add(5 * time.Second))
				start := time.Now()
				b, e := io.ReadAll(d)
				d.Close()
				if e != nil || string(b) != "hi" || time.Since(start) > 2*time.Second {
					t.Fatalf("destination saw %q, %v after %v of client close", b, e, time.Since(start))
				}

				// Upload: 1 MiB, checked by its hash.
				c = dialMita(t, network, addr, dst.Addr())
				data := randomBytes(1 << 20)
				d = <-accepted
				sum := make(chan [32]byte, 1)
				go func() {
					h := sha256.New()
					_, _ = io.CopyN(h, d, int64(len(data)))
					var s [32]byte
					copy(s[:], h.Sum(nil))
					sum <- s
				}()
				start = time.Now()
				if _, e = c.Write(data); e != nil {
					t.Fatal(e)
				}
				select {
				case s := <-sum:
					if s != sha256.Sum256(data) {
						t.Fatal("upload corrupted")
					}
				case <-time.After(30 * time.Second):
					t.Fatal("upload incomplete")
				}
				t.Logf("1 MiB upload: %v", time.Since(start))

				// Download 4 MiB with a reader that stalls for 2 s while the
				// client keeps writing: acknowledgements must keep flowing.
				down := randomBytes(4 << 20)
				go func() { _, _ = d.Write(down) }()
				time.Sleep(2 * time.Second)
				for i := 0; i < 3; i++ {
					if _, e = c.Write([]byte("ping")); e != nil {
						t.Fatalf("write during stalled download: %v", e)
					}
				}
				got := make([]byte, len(down))
				_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
				start = time.Now()
				if _, e = io.ReadFull(c, got); e != nil {
					t.Fatalf("download: %v", e)
				}
				if !bytes.Equal(got, down) {
					t.Fatal("download corrupted")
				}
				t.Logf("4 MiB download after a 2 s stall: %v", time.Since(start))
				c.Close()
				d.Close()
			})
		}
	}
}
