package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

type recordedHelloConn struct {
	net.Conn
	mu   sync.Mutex
	wire []byte
}

func (c *recordedHelloConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if len(c.wire) < 32768 {
		c.wire = append(c.wire, p[:min(len(p), 32768-len(c.wire))]...)
	}
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func (c *recordedHelloConn) snapshot() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.wire)
}

type helloWire struct {
	ciphers    []uint16
	extensions []uint16
	data       map[uint16][]byte
}

// Parse the actual emitted TLS records, independent of the preset builder.
func parseHelloWire(t *testing.T, wire []byte) helloWire {
	t.Helper()
	var handshake []byte
	for len(wire) >= 5 {
		size := int(binary.BigEndian.Uint16(wire[3:5]))
		if len(wire) < 5+size {
			t.Fatal("truncated captured TLS record")
		}
		if wire[0] == 22 {
			handshake = append(handshake, wire[5:5+size]...)
		}
		wire = wire[5+size:]
		if len(handshake) >= 4 {
			length := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
			if len(handshake) >= 4+length {
				break
			}
		}
	}
	if len(handshake) < 38 || handshake[0] != 1 {
		t.Fatal("no actual ClientHello on wire")
	}
	p := handshake[38:]
	take := func(n int) []byte {
		if n > len(p) {
			t.Fatal("invalid captured ClientHello length")
		}
		v := p[:n]
		p = p[n:]
		return v
	}
	take(int(take(1)[0]))
	ciphers := take(int(binary.BigEndian.Uint16(take(2))))
	result := helloWire{data: make(map[uint16][]byte)}
	for len(ciphers) > 0 {
		result.ciphers = append(result.ciphers, binary.BigEndian.Uint16(ciphers[:2]))
		ciphers = ciphers[2:]
	}
	take(int(take(1)[0]))
	p = take(int(binary.BigEndian.Uint16(take(2))))
	for len(p) != 0 {
		id := binary.BigEndian.Uint16(take(2))
		body := take(int(binary.BigEndian.Uint16(take(2))))
		result.extensions = append(result.extensions, id)
		result.data[id] = bytes.Clone(body)
	}
	return result
}

type wsHandshakeObservation struct {
	host, agent, custom, sni, alpn string
	version                        uint16
}

func fingerprintEchoServer(t *testing.T, secure bool, mutate func(*tls.Config)) (*httptest.Server, *tls.Config, <-chan wsHandshakeObservation) {
	t.Helper()
	observed := make(chan wsHandshakeObservation, 32)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o := wsHandshakeObservation{host: r.Host, agent: r.UserAgent(), custom: r.Header.Get("X-Core-Test")}
		if r.TLS != nil {
			o.sni = r.TLS.ServerName
			o.alpn = r.TLS.NegotiatedProtocol
			o.version = r.TLS.Version
		}
		observed <- o
		conn, err := AcceptWebSocket(ctx, w, r)
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	var tc *tls.Config
	if secure {
		bundle := testBundle(t, []string{"owned.test"})
		pair, err := tls.X509KeyPair(bundle.Certificate, bundle.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
		if mutate != nil {
			mutate(server.TLS)
		}
		roots := x509.NewCertPool()
		roots.AppendCertsFromPEM(bundle.Certificate)
		tc = &tls.Config{RootCAs: roots}
		server.StartTLS()
	} else {
		server.Start()
	}
	t.Cleanup(server.Close)
	return server, tc, observed
}

func TestWebSocketFingerprintsActualWireAndHeaders(t *testing.T) {
	server, tc, observed := fingerprintEchoServer(t, true, nil)
	results := make(map[string]helloWire)
	for _, fp := range []string{"", "unsafe", "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized", "randomizednoalpn"} {
		t.Run("preset_"+fp, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			var recorded *recordedHelloConn
			var dials atomic.Int64
			dialer := new(net.Dialer)
			dial := func(ctx context.Context, network, address string) (net.Conn, error) {
				if network != "tcp" || address != server.Listener.Addr().String() {
					return nil, errors.New("wrong dial endpoint")
				}
				dials.Add(1)
				raw, err := dialer.DialContext(ctx, network, address)
				if err != nil {
					return nil, err
				}
				recorded = &recordedHelloConn{Conn: raw}
				return recorded, nil
			}
			conn, err := DialWebSocket(ctx, WebSocketDialOptions{Address: server.Listener.Addr().String(), Host: "owned.test", Path: "/core", Secure: true, Timeout: 2 * time.Second, DialContext: dial, TLSConfig: tc, Fingerprint: fp, Browser: "off", UserAgent: "Core Wire Test/1.0", Headers: map[string]string{"x-core-test": "wire-value"}})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			payload := []byte("actual websocket binary echo")
			if _, err = conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(payload))
			if _, err = io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
				t.Fatal("echo", err)
			}
			o := <-observed
			if o.host != "owned.test" || o.sni != "owned.test" || o.agent != "Core Wire Test/1.0" || o.custom != "wire-value" || o.version < tls.VersionTLS12 || dials.Load() != 1 {
				t.Fatalf("incorrect wire handshake: %+v", o)
			}
			// net/http's Go TLS path deliberately omits ALPN for an Upgrade.
			if o.alpn != "http/1.1" && !((fp == "randomizednoalpn" || fp == "" || fp == "unsafe") && o.alpn == "") {
				t.Fatal("invalid websocket ALPN", o.alpn)
			}
			wire := parseHelloWire(t, recorded.snapshot())
			results[fp] = wire
			if slices.Contains(wire.extensions, 17513) || slices.Contains(wire.extensions, 17613) {
				t.Fatal("H2 ALPS leaked into HTTP1 upgrade")
			}
			if fp == "randomizednoalpn" && slices.Contains(wire.extensions, 16) {
				t.Fatal("noALPN preset advertised ALPN")
			}
			if fp == "android" && (o.version != tls.VersionTLS12 || slices.Contains(wire.extensions, 43) || slices.Contains(wire.ciphers, tls.TLS_AES_128_GCM_SHA256)) {
				t.Fatal("Android OkHttp TLS12 fingerprint was rewritten as TLS13")
			}
		})
	}
	if !reflect.DeepEqual(results[""].ciphers, results["unsafe"].ciphers) || !reflect.DeepEqual(results[""].extensions, results["unsafe"].extensions) {
		t.Fatal("unsafe changed the ordinary Go TLS fingerprint")
	}
	if reflect.DeepEqual(results["chrome"].ciphers, results["android"].ciphers) {
		t.Fatal("different browser choices emitted identical suites")
	}
	chrome := results["chrome"]
	if !slices.Contains(chrome.extensions, 43) || !slices.Contains(chrome.extensions, 27) {
		t.Fatal("Chrome browser ClientHello extensions missing")
	}
	if len(chrome.ciphers) == 0 || chrome.ciphers[0]&0x0f0f != 0x0a0a {
		t.Fatal("Chrome GREASE cipher missing")
	}
}

func TestWebSocketHeadersPlainWSAndReservedFields(t *testing.T) {
	server, _, observed := fingerprintEchoServer(t, false, nil)
	dialer := new(net.Dialer)
	opts := WebSocketDialOptions{Address: server.Listener.Addr().String(), Host: "owned.test", Path: "/core", DialContext: dialer.DialContext, UserAgent: "Plain WS/1", Headers: map[string]string{"x-core-test": "plain"}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := DialWebSocket(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if o := <-observed; o.agent != "Plain WS/1" || o.custom != "plain" || o.host != "owned.test" || o.version != 0 {
		t.Fatal("plain WS custom headers missing")
	}
	var dials atomic.Int64
	opts.DialContext = func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("unexpected dial")
	}
	for _, name := range []string{"Host", "uSeR-aGeNt", "Connection", "Upgrade", "Origin", "Sec-WebSocket-Key", "Proxy-Authorization", "Content-Length", "Transfer-Encoding", "TE", "Trailer"} {
		opts.Headers = map[string]string{name: "private-marker"}
		_, err = DialWebSocket(ctx, opts)
		if err == nil || strings.Contains(err.Error(), "private-marker") {
			t.Fatal("invalid header accepted or leaked")
		}
	}
	opts.Headers = nil
	opts.Fingerprint = "chrome"
	if _, err = DialWebSocket(ctx, opts); err == nil || dials.Load() != 0 {
		t.Fatal("invalid options reached network")
	}
}

func TestWebSocketFingerprintPreservesVerificationAndLimits(t *testing.T) {
	server, tc, _ := fingerprintEchoServer(t, true, nil)
	dialer := new(net.Dialer)
	for _, fp := range []string{"unsafe", "chrome", "android"} {
		for _, bad := range []string{"untrusted", "hostname", "expired", "peer-check", "connection-check", "insecure", "client-cert-option", "tls-version"} {
			t.Run(fp+"/"+bad, func(t *testing.T) {
				x := tc.Clone()
				host := "owned.test"
				sentinel := errors.New("additional certificate check")
				switch bad {
				case "untrusted":
					x.RootCAs = x509.NewCertPool()
				case "hostname":
					host = "different.test"
				case "expired":
					x.Time = func() time.Time { return time.Now().Add(24 * time.Hour) }
				case "peer-check":
					x.VerifyPeerCertificate = func(_ [][]byte, verified [][]*x509.Certificate) error {
						if len(verified) == 0 {
							t.Error("no verified chain")
						}
						return sentinel
					}
				case "connection-check":
					x.VerifyConnection = func(s tls.ConnectionState) error {
						if len(s.VerifiedChains) == 0 || s.ServerName != host {
							t.Error("lost verified state")
						}
						return sentinel
					}
				case "insecure":
					x.InsecureSkipVerify = true
				case "client-cert-option":
					if fp == "unsafe" {
						return
					}
					x.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return nil, sentinel }
				case "tls-version":
					x.MaxVersion = tls.VersionTLS11
				}
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				conn, err := DialWebSocket(ctx, WebSocketDialOptions{Address: server.Listener.Addr().String(), Host: host, Path: "/core", Secure: true, DialContext: dialer.DialContext, TLSConfig: x, Fingerprint: fp})
				if err == nil {
					conn.Close()
					t.Fatal("certificate restriction was bypassed")
				}
				if (bad == "peer-check" || bad == "connection-check") && !errors.Is(err, sentinel) {
					t.Fatal("additional verifier not preserved", err)
				}
			})
		}
	}
}

func TestWebSocketFingerprintHandshakeCancellation(t *testing.T) {
	for _, fp := range []string{"unsafe", "chrome", "android"} {
		t.Run(fp, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			raw, peer := net.Pipe()
			defer peer.Close()
			dialed := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				_, err := DialWebSocket(ctx, WebSocketDialOptions{Address: "127.0.0.1:443", Host: "owned.test", Path: "/core", Secure: true, Fingerprint: fp, DialContext: func(context.Context, string, string) (net.Conn, error) { close(dialed); return raw, nil }})
				done <- err
			}()
			<-dialed
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatal("cancellation lost", err)
				}
			case <-time.After(time.Second):
				t.Fatal("canceled fingerprint handshake leaked")
			}
			peer.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := io.Copy(io.Discard, peer); err != nil {
				t.Fatal("raw socket was not closed after cancellation", err)
			}
		})
	}
}

func TestWebSocketFingerprintHandshakeTimeoutClosesSocket(t *testing.T) {
	for _, fp := range []string{"unsafe", "chrome", "android"} {
		t.Run(fp, func(t *testing.T) {
			raw, peer := net.Pipe()
			defer peer.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			started := time.Now()
			_, err := DialWebSocket(ctx, WebSocketDialOptions{
				Address: "127.0.0.1:443", Host: "owned.test", Path: "/core", Secure: true,
				Fingerprint: fp, Timeout: 50 * time.Millisecond,
				DialContext: func(context.Context, string, string) (net.Conn, error) { return raw, nil },
			})
			if err == nil || time.Since(started) > time.Second || ctx.Err() != nil {
				t.Fatal("handshake timeout ignored or lifetime context canceled", err)
			}
			peer.SetReadDeadline(time.Now().Add(time.Second))
			if _, err = io.Copy(io.Discard, peer); err != nil {
				t.Fatal("timed out fingerprint handshake leaked raw socket", err)
			}
		})
	}
}

func TestWebSocketFingerprintHonorsTLSVersionBounds(t *testing.T) {
	server, tc, observed := fingerprintEchoServer(t, true, func(c *tls.Config) {
		c.MaxVersion = tls.VersionTLS12
	})
	dialer := new(net.Dialer)
	for _, fp := range []string{"chrome", "firefox", "safari", "android"} {
		t.Run(fp, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			tc := tc.Clone()
			tc.MaxVersion = tls.VersionTLS12
			opts := WebSocketDialOptions{Address: server.Listener.Addr().String(), Host: "owned.test", Path: "/core", Secure: true, Fingerprint: fp, TLSConfig: tc, DialContext: dialer.DialContext}
			conn, err := DialWebSocket(ctx, opts)
			if err != nil {
				t.Fatal("TLS12 browser compatibility", err)
			}
			conn.Close()
			if (<-observed).version != tls.VersionTLS12 {
				t.Fatal("preset overrode caller's maximum TLS version")
			}
			tc.MinVersion, tc.MaxVersion = tls.VersionTLS13, 0
			conn, err = DialWebSocket(ctx, opts)
			if err == nil {
				conn.Close()
				t.Fatal("preset lowered caller's minimum TLS version")
			}
		})
	}
}

func TestWebSocketFingerprintConcurrentHandshakes(t *testing.T) {
	server, tc, _ := fingerprintEchoServer(t, true, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dialer := new(net.Dialer)
	var wg sync.WaitGroup
	for range 3 {
		for _, fp := range []string{"chrome", "android", "random", "randomized", "randomizednoalpn"} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				conn, err := DialWebSocket(ctx, WebSocketDialOptions{Address: server.Listener.Addr().String(), Host: "owned.test", Path: "/core", Secure: true, Fingerprint: fp, TLSConfig: tc, DialContext: dialer.DialContext})
				if err != nil {
					t.Error("concurrent fingerprint", fp, err)
					return
				}
				conn.Close()
			}()
		}
	}
	wg.Wait()
}

func TestWebSocketRandomizedHybridSharesDeterministicRegression(t *testing.T) {
	// In the pinned uTLS version randomized seed1 (noALPN seed20) advertises
	// ML-KEM but sends no share; seed10 sends its share without advertising the
	// group. Either breaks TLS13
	// against a standards-conforming server. Force hybrid negotiation so a
	// fallback to a classical group cannot accidentally make this test pass.
	server, tc, _ := fingerprintEchoServer(t, true, func(c *tls.Config) {
		c.MinVersion = tls.VersionTLS13
		c.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
	})
	for _, test := range []struct {
		name string
		seed byte
	}{
		{"randomized", 1}, {"randomized", 10}, {"randomizednoalpn", 20}, {"randomizednoalpn", 10},
	} {
		name, value := test.name, test.seed
		t.Run(fmt.Sprintf("%s/seed%d", name, value), func(t *testing.T) {
			var seed utls.PRNGSeed
			seed[0] = value
			id := utls.HelloRandomized
			if name == "randomizednoalpn" {
				id = utls.HelloRandomizedNoALPN
			}
			id.Seed = &seed
			spec, err := fingerprintSpec(id, name, &tls.Config{MinVersion: tls.VersionTLS12})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			raw, err := new(net.Dialer).DialContext(ctx, "tcp", server.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			recorded := &recordedHelloConn{Conn: raw}
			client := utls.UClient(recorded, &utls.Config{RootCAs: tc.RootCAs, ServerName: "owned.test"}, utls.HelloCustom)
			if err = client.ApplyPreset(&spec); err != nil {
				t.Fatal(err)
			}
			if err = client.HandshakeContext(ctx); err != nil {
				t.Fatal("deterministic randomized hybrid handshake", err)
			}
			if client.ConnectionState().Version != tls.VersionTLS13 {
				t.Fatal("hybrid regression negotiated old TLS")
			}
			wire := parseHelloWire(t, recorded.snapshot())
			groups, shares := wire.data[10], wire.data[51]
			if len(groups) < 4 || len(shares) < 6 {
				t.Fatal("hybrid extensions missing")
			}
			foundGroup, foundShare := false, false
			for p := groups[2:]; len(p) >= 2; p = p[2:] {
				foundGroup = foundGroup || binary.BigEndian.Uint16(p[:2]) == uint16(utls.X25519MLKEM768)
			}
			for p := shares[2:]; len(p) >= 4; {
				group := utls.CurveID(binary.BigEndian.Uint16(p[:2]))
				size := int(binary.BigEndian.Uint16(p[2:4]))
				if size > len(p)-4 {
					t.Fatal("invalid wire share")
				}
				foundShare = foundShare || binary.BigEndian.Uint16(p[:2]) == uint16(utls.X25519MLKEM768)
				switch group {
				case utls.CurveP256, utls.CurveP384, utls.CurveP521:
					t.Fatal("pinned randomized defaults must retain X25519 alongside hybrid share")
				}
				p = p[4+size:]
			}
			if !foundGroup || !foundShare {
				t.Fatal("wire group and key share disagree")
			}
		})
	}
}

func TestWebSocketRandomizedClassicalHandshakeMatrix(t *testing.T) {
	// Seed0 emits two initial classical shares without our normalization. The
	// P256-only server must now use a classical HRR, instead of selecting a
	// second share whose private key uTLS has discarded. Exercise the other
	// advertised classical groups and multiple deterministic specs as well.
	for _, curve := range []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521} {
		t.Run(curve.String(), func(t *testing.T) {
			server, tc, _ := fingerprintEchoServer(t, true, func(c *tls.Config) {
				c.MinVersion = tls.VersionTLS13
				c.CurvePreferences = []tls.CurveID{curve}
			})
			tested := 0
			for _, name := range []string{"randomized", "randomizednoalpn"} {
				for _, value := range []byte{0, 1, 2, 10, 20} {
					var seed utls.PRNGSeed
					seed[0] = value
					id := utls.HelloRandomized
					if name == "randomizednoalpn" {
						id = utls.HelloRandomizedNoALPN
					}
					id.Seed = &seed
					spec, err := fingerprintSpec(id, name, &tls.Config{MinVersion: tls.VersionTLS12})
					if err != nil {
						t.Fatal(err)
					}
					advertised := false
					for _, extension := range spec.Extensions {
						if groups, ok := extension.(*utls.SupportedCurvesExtension); ok {
							advertised = slices.Contains(groups.Curves, utls.CurveID(curve))
						}
					}
					if spec.TLSVersMax < tls.VersionTLS13 || !advertised {
						continue
					}
					tested++
					t.Run(fmt.Sprintf("%s/seed%d", name, value), func(t *testing.T) {
						ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
						defer cancel()
						raw, err := new(net.Dialer).DialContext(ctx, "tcp", server.Listener.Addr().String())
						if err != nil {
							t.Fatal(err)
						}
						defer raw.Close()
						recorded := &recordedHelloConn{Conn: raw}
						client := utls.UClient(recorded, &utls.Config{RootCAs: tc.RootCAs, ServerName: "owned.test"}, utls.HelloCustom)
						if err = client.ApplyPreset(&spec); err != nil {
							t.Fatal(err)
						}
						if err = client.HandshakeContext(ctx); err != nil {
							t.Fatal("classical group/HRR compatibility", err)
						}
						if client.ConnectionState().Version != tls.VersionTLS13 {
							t.Fatal("HRR regression negotiated old TLS")
						}
						wire := parseHelloWire(t, recorded.snapshot())
						shares := wire.data[51]
						if len(shares) < 2 {
							t.Fatal("missing initial key shares")
						}
						classical := 0
						for p := shares[2:]; len(p) >= 4; {
							group := binary.BigEndian.Uint16(p[:2])
							size := int(binary.BigEndian.Uint16(p[2:4]))
							if size > len(p)-4 {
								t.Fatal("invalid wire share")
							}
							switch utls.CurveID(group) {
							case utls.X25519, utls.CurveP256, utls.CurveP384, utls.CurveP521:
								classical++
							}
							p = p[4+size:]
						}
						if classical != 1 {
							t.Fatal("randomized initial hello has incompatible classical shares")
						}
					})
				}
			}
			if tested == 0 {
				t.Fatal("matrix omitted classical group")
			}
		})
	}
}
