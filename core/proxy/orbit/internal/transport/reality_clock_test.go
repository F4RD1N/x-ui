package transport

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/xtls/reality"
)

// The official server accepts a client only when the time sealed in its
// session ID is within MaxTimeDiff (one minute by default, as VPN-Core's
// vpn-server runs it). A client clock two minutes off either way is refused
// like any other unauthenticated client: it gets the cover, and the client
// fails the REALITY proof without sending the native protocol. A clock
// twenty seconds off is inside the window and works.
func TestRealityClientClockWindow(t *testing.T) {
	cover := newRealityCover(t)
	clientOptions, serverOptions := realityTestOptions(t, cover)
	server := realityTestServer(t, serverOptions)
	for _, test := range []struct {
		name string
		skew time.Duration
		ok   bool
	}{
		{"behind-2m", -2 * time.Minute, false},
		{"ahead-2m", 2 * time.Minute, false},
		{"ahead-20s", 20 * time.Second, true},
		{"behind-20s", -20 * time.Second, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			accepted := make(chan error, 1)
			go func() {
				raw, err := listener.Accept()
				if err == nil {
					var conn net.Conn
					if conn, err = server.Accept(ctx, raw); conn != nil {
						conn.Close()
					}
				}
				accepted <- err
			}()
			raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			options := clientOptions
			skew := test.skew
			options.now = func() time.Time { return time.Now().Add(skew) }
			conn, err := DialReality(ctx, raw, options)
			if test.ok {
				if err != nil {
					t.Fatalf("clock %v inside the window refused: %v", skew, err)
				}
				conn.Close()
				if err = <-accepted; err != nil {
					t.Fatalf("server refused a clock inside the window: %v", err)
				}
				return
			}
			if conn != nil || !errors.Is(err, ErrRealityAuthentication) {
				t.Fatalf("clock %v outside the window: conn=%T err=%v", skew, conn, err)
			}
			if err = <-accepted; err == nil {
				t.Fatal("the server returned a native stream for a client clock outside the window")
			}
		})
	}
	if cover.data.Load() != 0 {
		t.Fatal("a refused clock sent application data to the cover")
	}
}

// The session ID carries VPN-Core's own client version (0.12.0), so the
// server sees the same bytes from orbit as from VPN-Core's client; nothing of
// Xray's version leaks into it.
func TestRealityClientVersionBytes(t *testing.T) {
	cover := newRealityCover(t)
	clientOptions, serverOptions := realityTestOptions(t, cover)
	server := realityTestServer(t, serverOptions)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	version := make(chan []byte, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			version <- nil
			return
		}
		conn, err := server.Accept(ctx, raw)
		if err != nil {
			version <- nil
			return
		}
		defer conn.Close()
		// The official server records the decrypted client version.
		c, ok := conn.(*authenticatedRealityConn).Conn.(*reality.Conn)
		if !ok {
			version <- nil
			return
		}
		version <- append([]byte(nil), c.ClientVer[:]...)
	}()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := DialReality(ctx, raw, clientOptions)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	v := <-version
	if v == nil {
		t.Fatal("server did not accept")
	}
	if len(v) != 3 || v[0] != 0 || v[1] != 12 || v[2] != 0 {
		t.Fatalf("client version %v, want VPN-Core's 0.12.0", v)
	}
}

// The temporary certificate's HMAC proof is what authenticates the server:
// the official server here accepts the client (right pbk, sid, sni and
// clock) and sends a genuine ed25519 REALITY certificate, but the client
// checks it against a different key. That must fail as an authentication
// error with nothing sent; without the HMAC comparison it would pass, since
// every other check sees a real REALITY certificate.
func TestRealityClientChecksTheCertificateProof(t *testing.T) {
	cover := newRealityCover(t)
	clientOptions, serverOptions := realityTestOptions(t, cover)
	server := realityTestServer(t, serverOptions)
	for _, tamper := range []bool{false, true} {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		accepted := make(chan net.Conn, 1)
		go func() {
			raw, err := listener.Accept()
			if err != nil {
				accepted <- nil
				return
			}
			conn, _ := server.Accept(ctx, raw)
			accepted <- conn
		}()
		raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		options := clientOptions
		if tamper {
			options.proofKey = func(key []byte) { key[0] ^= 0x80 }
		}
		conn, err := DialReality(ctx, raw, options)
		if !tamper {
			if err != nil {
				t.Fatalf("untampered proof refused: %v", err)
			}
			conn.Close()
		} else if conn != nil || !errors.Is(err, ErrRealityAuthentication) {
			t.Fatalf("a certificate proof made with another key was accepted: conn=%T err=%v", conn, err)
		}
		if c := <-accepted; c != nil {
			c.Close()
		}
		cancel()
		listener.Close()
	}
	if cover.data.Load() != 0 {
		t.Fatal("a failed proof sent application data to the cover")
	}
}
