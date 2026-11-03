package transport

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/reality"
)

type realityCover struct {
	address string
	roots   *tls.Config
	opened  atomic.Int64
	data    atomic.Int64
}

func newRealityCover(t *testing.T) *realityCover {
	t.Helper()
	serverTLS, clientTLS := testTLS(t)
	serverTLS.MinVersion = tls.VersionTLS13
	serverTLS.MaxVersion = tls.VersionTLS13
	serverTLS.NextProtos = []string{"h2", "http/1.1"}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cover := &realityCover{address: listener.Addr().String(), roots: clientTLS}
	var workers sync.WaitGroup
	var mu sync.Mutex
	active := make(map[net.Conn]bool)
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			cover.opened.Add(1)
			mu.Lock()
			active[raw] = true
			mu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer raw.Close()
				defer func() {
					mu.Lock()
					delete(active, raw)
					mu.Unlock()
				}()
				raw.SetDeadline(time.Now().Add(5 * time.Second))
				conn := tls.Server(raw, serverTLS)
				if conn.Handshake() != nil {
					return
				}
				buffer := make([]byte, 4096)
				for {
					n, err := conn.Read(buffer)
					cover.data.Add(int64(n))
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		mu.Lock()
		for conn := range active {
			conn.Close()
		}
		mu.Unlock()
		workers.Wait()
	})
	return cover
}

func realityTestOptions(t *testing.T, cover *realityCover) (RealityClientOptions, RealityServerOptions) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return RealityClientOptions{
		ServerName: "vpn.test", PublicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), ShortID: "1032547698badcfe",
	}, RealityServerOptions{
		PrivateKey: base64.RawURLEncoding.EncodeToString(key.Bytes()), ShortIDs: []string{"1032547698badcfe", ""},
		ServerNames: []string{"vpn.test"}, Target: cover.address, CoverRootCAs: cover.roots.RootCAs,
	}
}

func realityTestServer(t *testing.T, options RealityServerOptions) *RealityServer {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server, err := NewRealityServer(ctx, options)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

type realityWireCapture struct {
	net.Conn
	mu      sync.Mutex
	written bytes.Buffer
}

func (c *realityWireCapture) Write(data []byte) (int, error) {
	n, err := c.Conn.Write(data)
	c.mu.Lock()
	c.written.Write(data[:n])
	c.mu.Unlock()
	return n, err
}

func (c *realityWireCapture) snapshot() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.written.Bytes())
}

func TestRealityOfficialServerCarriesNativeHTTP(t *testing.T) {
	cover := newRealityCover(t)
	clientOptions, serverOptions := realityTestOptions(t, cover)
	server := realityTestServer(t, serverOptions)
	for _, fingerprint := range []string{"", "chrome", "firefox", "safari"} {
		t.Run("fingerprint="+fingerprint, func(t *testing.T) {
			options := clientOptions
			options.Fingerprint = fingerprint
			if fingerprint == "safari" {
				options.ShortID = "" // Explicitly configured empty short IDs remain interoperable.
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				raw, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				outer, err := server.Accept(ctx, raw)
				if err != nil {
					done <- err
					return
				}
				if !IsRealityConnection(outer) {
					outer.Close()
					done <- errors.New("accepted connection lost REALITY authentication marker")
					return
				}
				conn, proxy, err := HTTPServer(ctx, outer, HTTPServerOptions{})
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				if !bytes.Equal(proxy, []byte("owned-native-route\x00metadata")) {
					done <- errors.New("REALITY changed the native proxy envelope")
					return
				}
				_, err = io.Copy(conn, conn)
				done <- err
			}()
			raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			wire := &realityWireCapture{Conn: raw}
			outer, err := DialReality(ctx, wire, options)
			if err != nil {
				t.Fatal(err)
			}
			defer outer.Close()
			if !IsRealityConnection(outer) || IsRealityConnection(raw) {
				t.Fatal("REALITY marker does not distinguish authenticated connections")
			}
			conn, err := HTTPClient(ctx, outer, HTTPOptions{
				Options: Options{ProxyBuffer: []byte("owned-native-route\x00metadata")},
				Type:    2, Header: HTTPHeader{CheaterID: 2, Domain: "vpn.test"}, Path: "/owned", Reality: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			payload := bytes.Repeat([]byte("owned native TLS2 framed payload\x00\xff"), 2200)
			writeDone := make(chan error, 1)
			go func() { _, err := conn.Write(payload); writeDone <- err }()
			received := make([]byte, len(payload))
			if _, err = io.ReadFull(conn, received); err != nil {
				t.Fatal(err)
			}
			if err = <-writeDone; err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(payload, received) {
				t.Fatal("REALITY changed native framed data")
			}
			if captured := wire.snapshot(); bytes.Contains(captured, []byte("GET /owned")) || bytes.Contains(captured, payload[:128]) {
				t.Fatal("native HTTP or framed payload leaked on the raw TCP connection")
			}
			if err = conn.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if err = <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
	if cover.data.Load() != 0 {
		t.Fatal("native data or HTTP spider request reached the cover")
	}
}

func TestRealityRejectsAuthenticationFailures(t *testing.T) {
	cover := newRealityCover(t)
	clientOptions, serverOptions := realityTestOptions(t, cover)
	server := realityTestServer(t, serverOptions)
	for _, test := range []string{"wrong-public-key", "wrong-short-id", "wrong-server-name", "expired-client-time"} {
		t.Run(test, func(t *testing.T) {
			options := clientOptions
			selectedServer := server
			switch test {
			case "wrong-public-key":
				other, _ := realityTestOptions(t, cover)
				options.PublicKey = other.PublicKey
			case "wrong-short-id":
				options.ShortID = "abcd"
			case "wrong-server-name":
				options.ServerName = "other.test"
			case "expired-client-time":
				config := server.config.Clone()
				config.MaxTimeDiff = time.Nanosecond
				selectedServer = &RealityServer{config: config}
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				raw, err := listener.Accept()
				if err == nil {
					var conn net.Conn
					conn, err = selectedServer.Accept(ctx, raw)
					if conn != nil {
						conn.Close()
					}
				}
				done <- err
			}()
			raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			conn, err := DialReality(ctx, raw, options)
			if conn != nil || !errors.Is(err, ErrRealityAuthentication) {
				t.Fatalf("unauthenticated cover accepted or wrong error: conn=%T, err=%v", conn, err)
			}
			if err = <-done; err == nil {
				t.Fatal("official server returned a native stream for an invalid client")
			}
		})
	}
	if cover.data.Load() != 0 {
		t.Fatal("an authentication failure sent application data to the cover")
	}
}

func TestRealityRejectsNormalTrustedCoverCertificate(t *testing.T) {
	cover := newRealityCover(t)
	options, _ := realityTestOptions(t, cover)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// Prove this cover's certificate is trusted by ordinary TLS first.
	trusted, err := (&tls.Dialer{Config: cover.roots}).DialContext(ctx, "tcp", cover.address)
	if err != nil {
		t.Fatal(err)
	}
	trusted.Close()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", cover.address)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := DialReality(ctx, raw, options)
	if conn != nil || !errors.Is(err, ErrRealityAuthentication) {
		t.Fatalf("normal CA certificate accepted as REALITY: conn=%T, err=%v", conn, err)
	}
	if cover.data.Load() != 0 {
		t.Fatal("failed verification started a cover HTTP request")
	}
}

func TestRealityCancellationInterruptsServerHandshake(t *testing.T) {
	cover := newRealityCover(t)
	_, options := realityTestOptions(t, cover)
	server := realityTestServer(t, options)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	raw, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	if conn, err := server.Accept(ctx, raw); conn != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stalled handshake cancellation: conn=%T, err=%v", conn, err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("server handshake ignored context cancellation")
	}
}

func TestRealityCancellationClosesClientConnection(t *testing.T) {
	cover := newRealityCover(t)
	options, _ := realityTestOptions(t, cover)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	raw, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	peer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, peer)
		done <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	if conn, err := DialReality(ctx, raw, options); conn != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stalled client handshake cancellation: conn=%T err=%v", conn, err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("client handshake ignored context cancellation")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("failed client handshake retained its raw connection")
	}
}

func TestRealityRejectsLegacyFingerprintBeforeWriting(t *testing.T) {
	cover := newRealityCover(t)
	options, _ := realityTestOptions(t, cover)
	for _, fingerprint := range []string{"ios", "android", "edge", "random", "randomized", "unknown"} {
		t.Run(fingerprint, func(t *testing.T) {
			a, b := net.Pipe()
			defer b.Close()
			options.Fingerprint = fingerprint
			if conn, err := DialReality(context.Background(), a, options); conn != nil || err == nil {
				t.Fatal("unsupported REALITY fingerprint was accepted")
			}
			buffer := make([]byte, 1)
			if n, err := b.Read(buffer); n != 0 || !errors.Is(err, io.EOF) {
				t.Fatalf("invalid fingerprint wrote data or failed to close: n=%d err=%v", n, err)
			}
		})
	}
}

func TestRealityCoverProbeRespectsContext(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			io.Copy(io.Discard, conn)
		}
	}()
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	server, err := NewRealityServer(ctx, RealityServerOptions{
		PrivateKey: base64.RawURLEncoding.EncodeToString(private.Bytes()), ShortIDs: []string{""},
		ServerNames: []string{"vpn.test"}, Target: listener.Addr().String(),
	})
	if server != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stalled cover probe returned server=%T err=%v", server, err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("startup cover probe ignored its context")
	}
	<-done
}

func TestRealityFailedInitializationPreservesCoverMeasurements(t *testing.T) {
	cover := newRealityCover(t)
	_, options := realityTestOptions(t, cover)
	key := realityCoverKey(cover.address, "vpn.test", 2)
	reality.GlobalPostHandshakeRecordsLens.Store(key, []int{12345})
	t.Cleanup(func() { reality.GlobalPostHandshakeRecordsLens.Delete(key) })
	// The first name probes successfully. The second is absent from the
	// trusted cover certificate, so the complete constructor must fail.
	options.ServerNames = []string{"vpn.test", "other.test"}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if server, err := NewRealityServer(ctx, options); server != nil || err == nil {
		t.Fatal("a cover with the wrong hostname was accepted")
	}
	value, ok := reality.GlobalPostHandshakeRecordsLens.Load(key)
	lengths, typed := value.([]int)
	if !ok || !typed || len(lengths) != 1 || lengths[0] != 12345 {
		t.Fatal("a failed constructor replaced a working listener's cover measurements")
	}
}

func TestRealityCoverCollectorRejectsMalformedAndOversizedRecords(t *testing.T) {
	validRecord := append([]byte{23, 3, 3, 0, 17}, make([]byte, 17)...)
	for _, test := range []struct {
		name string
		data []byte
	}{
		{"unbounded-response", bytes.Repeat(validRecord, 4000)},
		{"too-many-records", bytes.Repeat(validRecord, 33)},
		{"truncated-record", []byte{23, 3, 3, 0, 17, 1}},
		{"invalid-record-type", append([]byte{22}, validRecord[1:]...)},
	} {
		t.Run(test.name, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer b.Close()
				_, _ = b.Write(test.data)
			}()
			collector := &realityCoverCollector{Conn: a, afterCCS: true}
			if n, err := collector.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) || collector.err == nil {
				t.Fatalf("malformed cover response accepted: n=%d, err=%v, collector=%v", n, err, collector.err)
			}
			a.Close()
			<-done
		})
	}
}

func TestRealityCancellationInterruptsCoverDial(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	peer, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	raw, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	server := &RealityServer{config: &reality.Config{
		Type: "tcp", Dest: "127.0.0.1:1",
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	if conn, err := server.Accept(ctx, raw); conn != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cover dial cancellation: conn=%T err=%v", conn, err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("cover dial escaped the enclosing Accept context")
	}
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := peer.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("cover dial cancellation retained incoming connection: n=%d err=%v", n, err)
	}
}
