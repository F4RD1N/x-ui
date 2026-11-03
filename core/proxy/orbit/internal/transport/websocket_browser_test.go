package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func TestBrowserDefaultsActualWSAndWSS(t *testing.T) {
	for _, secure := range []bool{false, true} {
		for _, mode := range []string{"", "on", "off"} {
			t.Run(strings.Join([]string{map[bool]string{false: "ws", true: "wss"}[secure], mode}, "/"), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				server, tc, _ := fingerprintEchoServer(t, secure, nil)
				baseHandler := server.Config.Handler
				seen := make(chan http.Header, 1)
				// Install before the only connection; no serving handler is active.
				server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					seen <- r.Header.Clone()
					baseHandler.ServeHTTP(w, r)
				})
				var wire *recordedHelloConn
				dialer := new(net.Dialer)
				dial := func(ctx context.Context, network, address string) (net.Conn, error) {
					c, err := dialer.DialContext(ctx, network, address)
					if err != nil {
						return nil, err
					}
					wire = &recordedHelloConn{Conn: c}
					return wire, nil
				}
				c, err := DialWebSocket(ctx, WebSocketDialOptions{Address: server.Listener.Addr().String(), Host: "owned.test", Path: "/core", Secure: secure, Browser: mode, TLSConfig: tc, DialContext: dial})
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				want := []byte("browser-compatible binary echo")
				if _, err = c.Write(want); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, len(want))
				if _, err = io.ReadFull(c, got); err != nil || !bytes.Equal(got, want) {
					t.Fatal("echo failed", err)
				}
				h := <-seen
				if mode == "off" {
					if h.Get("Origin") != "" || h.Get("Cache-Control") != "" || h.Get("Accept-Language") != "" || h.Get("User-Agent") != "Go-http-client/1.1" {
						t.Fatal("legacy HTTP behavior changed", h)
					}
				} else {
					scheme := "http"
					if secure {
						scheme = "https"
					}
					if h.Get("Origin") != scheme+"://owned.test" || !strings.Contains(h.Get("User-Agent"), "Chrome/"+utls.HelloChrome_Auto.Version+".") || h.Get("Cache-Control") != "no-cache" || h.Get("Pragma") != "no-cache" || h.Get("Accept-Language") != "en-US,en;q=0.9" {
						t.Fatal("browser defaults absent or use dial address", h)
					}
					if secure {
						hello := parseHelloWire(t, wire.snapshot())
						if len(hello.ciphers) == 0 || hello.ciphers[0]&0x0f0f != 0x0a0a || !slices.Contains(hello.extensions, 27) || !slices.Contains(hello.extensions, 43) {
							t.Fatal("default WSS did not use Chrome ClientHello")
						}
					}
				}
				if h.Get("Sec-WebSocket-Extensions") != "" {
					t.Fatal("unsupported compression advertised")
				}
			})
		}
	}
}

func TestBrowserHTTPOverridesAndPresetConsistency(t *testing.T) {
	for _, secure := range []bool{false, true} {
		for _, mode := range []string{"", "on", "off"} {
			input := map[string]string{"accept-language": "fa-IR", "Cache-Control": "", "Pragma": "custom", "X-Route": "keep"}
			before := map[string]string{"accept-language": "fa-IR", "Cache-Control": "", "Pragma": "custom", "X-Route": "keep"}
			h, err := webSocketHeaders(WebSocketDialOptions{Host: "owned.test", Browser: mode, Secure: secure, UserAgent: "Explicit/1.0", Headers: input})
			if err != nil {
				t.Fatal(err)
			}
			if h.Get("User-Agent") != "Explicit/1.0" || h.Get("Accept-Language") != "fa-IR" || h.Get("Pragma") != "custom" || h.Get("X-Route") != "keep" || !reflect.DeepEqual(h["Cache-Control"], []string{""}) || !reflect.DeepEqual(before, input) {
				t.Fatal("caller overrides changed", h)
			}
		}
	}
	for _, fp := range []string{"", "chrome", "firefox", "safari", "ios", "edge", "android", "360", "qq", "random", "randomized", "randomizednoalpn", "unsafe"} {
		h, err := webSocketHeaders(WebSocketDialOptions{Host: "owned.test", Secure: true, Fingerprint: fp})
		if err != nil || h.Get("User-Agent") == "" || strings.Contains(h.Get("User-Agent"), "Go-http-client") {
			t.Fatal(fp, h, err)
		}
		if fp == "random" {
			id, err := randomBrowser()
			if err != nil {
				t.Fatal(err)
			}
			if id.Client == utls.HelloFirefox_Auto.Client && !strings.Contains(h.Get("User-Agent"), "Firefox/"+id.Version) {
				t.Fatal("random HTTP/TLS browser mismatch")
			}
		}
	}
}

func TestBrowserModeAndVerificationFailClosed(t *testing.T) {
	dials := 0
	dial := func(context.Context, string, string) (net.Conn, error) {
		dials++
		t.Fatal("invalid options attempted dial")
		return nil, nil
	}
	for _, o := range []WebSocketDialOptions{
		{Browser: "invalid"}, {TLSConfig: &tls.Config{InsecureSkipVerify: true}},
		{Headers: map[string]string{"Origin": "https://evil.test"}},
	} {
		o.Address, o.Host, o.Path, o.Secure, o.DialContext = "127.0.0.1:1", "owned.test", "/core", true, dial
		if _, err := DialWebSocket(context.Background(), o); err == nil {
			t.Fatal("invalid options accepted")
		}
	}
	if dials != 0 {
		t.Fatal("unexpected network")
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted server reached HTTP") }))
	defer server.Close()
	d := new(net.Dialer)
	if c, err := DialWebSocket(context.Background(), WebSocketDialOptions{Address: server.Listener.Addr().String(), Host: "owned.test", Path: "/core", Secure: true, DialContext: d.DialContext}); err == nil {
		c.Close()
		t.Fatal("default Chrome accepted untrusted certificate")
	}
}
