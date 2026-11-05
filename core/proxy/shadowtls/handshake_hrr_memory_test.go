package shadowtls

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type hrrProbeTrace struct {
	net.Conn
	mu     sync.Mutex
	writes []byte
}

func (c *hrrProbeTrace) Write(p []byte) (int, error) {
	n, e := c.Conn.Write(p)
	c.mu.Lock()
	c.writes = append(c.writes, p[:n]...)
	c.mu.Unlock()
	return n, e
}
func (c *hrrProbeTrace) helloCounts() (retry, final, encryptedHelloLike int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := c.writes
	afterCCS := false
	for len(b) >= 5 {
		n := int(binary.BigEndian.Uint16(b[3:5]))
		if len(b) < 5+n {
			break
		}
		body := b[5 : 5+n]
		if b[0] == 20 {
			afterCCS = true
		}
		if b[0] == 22 && len(body) >= 38 && body[0] == 2 {
			messageSize := 4 + (int(body[1]) << 16) + (int(body[2]) << 8) + int(body[3])
			if messageSize > len(body) {
				if afterCCS {
					encryptedHelloLike++
				}
			} else if bytes.Equal(body[6:38], helloRetryRequestRandom[:]) {
				retry++
			} else {
				final++
			}
		}
		b = b[5+n:]
	}
	return
}
func hrrProbePair() (net.Conn, net.Conn, func()) {
	a, ar := net.Pipe()
	b, br := net.Pipe()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(ar, br); done <- struct{}{} }()
	go func() { _, _ = io.Copy(br, ar); done <- struct{}{} }()
	return a, b, func() {
		a.Close()
		b.Close()
		ar.Close()
		br.Close()
		<-done
		<-done
	}
}

type fixedTLSRandom byte

func (b fixedTLSRandom) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(b)
	}
	return len(p), nil
}

func TestShadowTLSFullWireHRRMemory(t *testing.T) {
	for _, tc := range []struct {
		name        string
		curve       tls.CurveID
		wantRetry   bool
		version     uint16
		fingerprint string
		fixedCBCIV  bool
	}{
		{name: "x25519-control", curve: tls.X25519, version: tls.VersionTLS13, fingerprint: "chrome"},
		{name: "p256-forced-retry", curve: tls.CurveP256, wantRetry: true, version: tls.VersionTLS13, fingerprint: "chrome"},
		{name: "tls12-cbc-finished-starts-with-02", curve: tls.CurveP256, version: tls.VersionTLS12, fingerprint: "360", fixedCBCIV: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			certificate := testCert(t)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			clientRaw, serverRaw, closeCarrier := hrrProbePair()
			defer closeCarrier()
			serverHS, coverConn, closeCover := hrrProbePair()
			defer closeCover()
			deadline, _ := ctx.Deadline()
			for _, c := range []net.Conn{clientRaw, serverRaw, serverHS, coverConn} {
				c.SetDeadline(deadline)
			}
			coverRaw := &hrrProbeTrace{Conn: coverConn}
			coverResult := make(chan error, 1)
			serverResult := make(chan error, 1)
			go func() {
				config := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tc.version, MaxVersion: tc.version, CurvePreferences: []tls.CurveID{tc.curve}, SessionTicketsDisabled: true}
				if tc.fixedCBCIV {
					// Only this fixture uses deterministic randomness. It forces the
					// encrypted Finished's explicit CBC IV to begin with 0x02.
					config.Rand = fixedTLSRandom(2)
					config.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA}
				}
				cover := tls.Server(coverRaw, config)
				err := cover.HandshakeContext(ctx)
				if err == nil {
					var b [1]byte
					_, err = cover.Read(b[:])
				}
				coverResult <- err
			}()
			go func() {
				tunnel, _, err := ServerHandshake(ctx, serverRaw, serverHS, nativeServerConfig(3, tc.version == tls.VersionTLS13))
				if err == nil {
					payload := make([]byte, 8)
					_, err = io.ReadFull(tunnel, payload)
					if err == nil {
						_, err = tunnel.Write(payload)
					}
				}
				serverResult <- err
			}()
			tunnel, clientErr := Handshake(ctx, clientRaw, &Config{Version: 3, Strict: tc.version == tls.VersionTLS13, Password: nativeServerTestPassword, ServerName: "x", AllowInsecure: true, Fingerprint: tc.fingerprint})
			if clientErr == nil {
				want := []byte("hrrprobe")
				_, clientErr = tunnel.Write(want)
				if clientErr == nil {
					got := make([]byte, len(want))
					_, clientErr = io.ReadFull(tunnel, got)
					if clientErr == nil && !bytes.Equal(got, want) {
						clientErr = fmt.Errorf("echo mismatch")
					}
				}
			}
			cancel()
			clientRaw.Close()
			serverRaw.Close()
			serverHS.Close()
			coverConn.Close()
			serverErr := <-serverResult
			coverErr := <-coverResult
			retries, finals, ciphertext := coverRaw.helloCounts()
			t.Logf("cover HRR=%d finalServerHello=%d hello-like-ciphertext=%d client=%v server=%v cover=%v", retries, finals, ciphertext, clientErr, serverErr, coverErr)
			if tc.wantRetry && retries != 1 {
				t.Fatalf("fixture did not force HRR: %d", retries)
			}
			if !tc.wantRetry && retries != 0 {
				t.Fatalf("control unexpectedly forced HRR: %d", retries)
			}
			if finals != 1 || (tc.fixedCBCIV && ciphertext != 1) {
				t.Fatalf("expected handshake/ciphertext fixture was not observed: final=%d ciphertext=%d", finals, ciphertext)
			}
			if clientErr != nil || serverErr != nil {
				t.Fatalf("full ShadowTLS carrier failed: client=%v server=%v", clientErr, serverErr)
			}
		})
	}
}
