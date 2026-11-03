package shadowtls

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	gotls "crypto/tls"
	"encoding/hex"
	"hash"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol/tls/cert"
)

func testCert(t *testing.T) gotls.Certificate {
	generated, _ := cert.MustGenerate(nil, cert.DNSNames("x"))
	kp, e := gotls.X509KeyPair(generated.ToPEM())
	if e != nil {
		t.Fatal(e)
	}
	return kp
}

// tlsServer is a Go crypto/tls handshake server. handle runs on each
// completed connection.
func tlsServer(t *testing.T, cfg *gotls.Config, handle func(*gotls.Conn)) string {
	cfg.Certificates = []gotls.Certificate{testCert(t)}
	l, e := gotls.Listen("tcp", "127.0.0.1:0", cfg)
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
			go func() {
				defer c.Close()
				tc := c.(*gotls.Conn)
				if tc.Handshake() == nil && handle != nil {
					handle(tc)
				} else {
					_, _ = io.Copy(io.Discard, c)
				}
			}()
		}
	}()
	return l.Addr().String()
}

func handshake(t *testing.T, addr string, cfg *Config) (*Conn, error) {
	raw, e := net.Dial("tcp", addr)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { raw.Close() })
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cfg.ServerName, cfg.AllowInsecure = "x", true
	if cfg.Password == "" {
		cfg.Password = "test-password"
	}
	return Handshake(ctx, raw, cfg)
}

func offered(versions []uint16) (has12, has13, hasOld bool) {
	for _, v := range versions {
		switch {
		case v&0x0f0f == 0x0a0a:
		case v == gotls.VersionTLS13:
			has13 = true
		case v == gotls.VersionTLS12:
			has12 = true
		default:
			hasOld = true
		}
	}
	return
}

// The version caps reach the ClientHello although utls presets replace
// Config.Min/MaxVersion: v1 offers TLS 1.2 at most and then negotiates 1.2
// with a TLS 1.3 server; strict v3 offers only TLS 1.3.
func TestClientHelloVersionPolicy(t *testing.T) {
	for _, tc := range []struct {
		name       string
		cfg        *Config
		want12     bool
		want13     bool
		handshakes bool
	}{
		{"v1", &Config{Version: 1}, true, false, true},
		{"v1-firefox", &Config{Version: 1, Fingerprint: "firefox"}, true, false, true},
		{"v3-strict", &Config{Version: 3, Strict: true}, false, true, false},
		{"v3-strict-safari", &Config{Version: 3, Strict: true, Fingerprint: "safari"}, false, true, false},
		{"v3-nonstrict", &Config{Version: 3}, true, true, true},
		{"v2", &Config{Version: 2}, true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var seen []uint16
			addr := tlsServer(t, &gotls.Config{GetConfigForClient: func(chi *gotls.ClientHelloInfo) (*gotls.Config, error) {
				mu.Lock()
				seen = append([]uint16(nil), chi.SupportedVersions...)
				mu.Unlock()
				return nil, nil
			}}, nil)
			_, e := handshake(t, addr, tc.cfg)
			if tc.handshakes && e != nil {
				t.Fatalf("handshake: %v", e)
			}
			mu.Lock()
			has12, has13, _ := offered(seen)
			mu.Unlock()
			if has12 != tc.want12 || has13 != tc.want13 {
				t.Fatalf("offered %x: TLS1.2=%v TLS1.3=%v", seen, has12, has13)
			}
		})
	}
}

// Strict v3 refuses a TLS 1.2 handshake server; non-strict v3 accepts one
// (the spec allows TLS 1.2 in non-strict mode) and only needs ServerRandom.
func TestV3TLS12OnlyInNonStrictMode(t *testing.T) {
	addr := tlsServer(t, &gotls.Config{MaxVersion: gotls.VersionTLS12}, nil)
	if _, e := handshake(t, addr, &Config{Version: 3, Strict: true}); e == nil {
		t.Fatal("strict v3 accepted a TLS 1.2 handshake server")
	}
	c, e := handshake(t, addr, &Config{Version: 3})
	if e != nil {
		t.Fatalf("non-strict v3 rejected a TLS 1.2 handshake server: %v", e)
	}
	if c.handshakeHash == nil || c.rhash == nil || c.whash == nil {
		t.Fatal("non-strict v3 connection lacks its MACs")
	}
}

// When the server fails authentication, strict v3 finishes like a browser:
// an HTTP request with a random-length path over the finished TLS session.
func TestV3DecoyRequestOnHijack(t *testing.T) {
	got := make(chan string, 1)
	addr := tlsServer(t, &gotls.Config{MinVersion: gotls.VersionTLS13}, func(c *gotls.Conn) {
		r := bufio.NewReader(c)
		var req strings.Builder
		for {
			line, e := r.ReadString('\n')
			req.WriteString(line)
			if e != nil || line == "\r\n" {
				break
			}
		}
		got <- req.String()
		_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"))
	})
	_, e := handshake(t, addr, &Config{Version: 3, Strict: true})
	if e == nil || e.Error() != "ShadowTLS server authentication failed" {
		t.Fatalf("hijacked handshake: %v", e)
	}
	select {
	case req := <-got:
		if !strings.HasPrefix(req, "GET /") || !strings.Contains(req, "\r\nHost: x\r\n") || len(strings.SplitN(req, " ", 3)[1]) < 9 {
			t.Fatalf("decoy request: %q", req)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no decoy request reached the server")
	}
}

// fakeV2Server relays to a TLS 1.3 handshake server that sends its session
// tickets with Finished, switches to an echo data server on the client's
// HMAC-tagged first record, as ShadowTLS v2 servers do.
func fakeV2Server(t *testing.T, hs, password string) string {
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
			go func() {
				defer c.Close()
				h, e := net.Dial("tcp", hs)
				if e != nil {
					return
				}
				defer h.Close()
				var mu sync.Mutex
				switched := false
				mac := hmac.New(sha1.New, []byte(password))
				tags := map[string]bool{}
				go func() {
					for {
						rt, rv, b, e := readRecord(h)
						if e != nil {
							return
						}
						mu.Lock()
						if switched {
							mu.Unlock()
							return
						}
						mac.Write(record(rt, rv, b))
						tags[string(mac.Sum(nil)[:8])] = true
						_, _ = c.Write(record(rt, rv, b))
						mu.Unlock()
					}
				}()
				for {
					rt, rv, b, e := readRecord(c)
					if e != nil {
						return
					}
					mu.Lock()
					if rt == 23 && len(b) >= 8 && tags[string(b[:8])] {
						switched = true
						_, _ = c.Write(record(23, [2]byte{3, 3}, b[8:]))
						mu.Unlock()
						break
					}
					mu.Unlock()
					_, _ = h.Write(record(rt, rv, b))
				}
				for {
					_, _, b, e := readRecord(c)
					if e != nil {
						return
					}
					_, _ = c.Write(record(23, [2]byte{3, 3}, b))
				}
			}()
		}
	}()
	return l.Addr().String()
}

func TestV2DropsHandshakeServerTickets(t *testing.T) {
	for _, fp := range []string{"", "firefox"} {
		hs := tlsServer(t, &gotls.Config{MinVersion: gotls.VersionTLS13}, func(c *gotls.Conn) { _, _ = io.Copy(io.Discard, c) })
		addr := fakeV2Server(t, hs, "test-password")
		c, e := handshake(t, addr, &Config{Version: 2, Fingerprint: fp})
		if e != nil {
			t.Fatal(e)
		}
		for i := 0; i < 3; i++ {
			msg := bytes.Repeat([]byte{byte('a' + i)}, 40+i*1000)
			if _, e = c.Write(msg); e != nil {
				t.Fatal(e)
			}
			got := make([]byte, len(msg))
			if _, e = io.ReadFull(c, got); e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(got, msg) {
				t.Fatalf("round %d: echo mismatch (handshake server records leaked): %q", i, got[:min(len(got), 40)])
			}
		}
	}
}

func TestExpandLabelVector(t *testing.T) {
	// RFC 8448 section 3: server handshake traffic key and iv.
	secret := mustHex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
	if k := expandLabel(sha256New, secret, "key", 16); !bytes.Equal(k, mustHex("3fce516009c21727d0f2e4e86ee403bc")) {
		t.Fatalf("key %x", k)
	}
	if iv := expandLabel(sha256New, secret, "iv", 12); !bytes.Equal(iv, mustHex("5d313eb2671276ee13000b30")) {
		t.Fatalf("iv %x", iv)
	}
}

func sha256New() hash.Hash { return sha256.New() }

func mustHex(s string) []byte {
	b, e := hex.DecodeString(s)
	if e != nil {
		panic(e)
	}
	return b
}
