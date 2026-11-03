package client

import (
	"crypto/tls"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/handshake"
)

// TestDataCipherChoice: the data cipher is limited to what the client
// offers (data-ciphers plus the fallback), as in OpenVPN 2.6: a pushed
// cipher outside it is refused; without a pushed cipher the server's
// options string names it; there is no implicit BF-CBC.
func TestDataCipherChoice(t *testing.T) {
	for _, tc := range []struct {
		name    string
		srv     srvConfig
		ovpn    string
		cipher  string // want Info().Cipher; "" wants an error
		errHas  []string
		datPkts bool
	}{
		{name: "pushed-bf-outside-data-ciphers", srv: srvConfig{cipher: "BF-CBC", auth: "MD5", pushAuth: "MD5"},
			errHas: []string{"BF-CBC", "data-ciphers"}},
		{name: "pushed-aes128cbc-outside-data-ciphers", srv: srvConfig{cipher: "AES-128-CBC", auth: "MD5", pushAuth: "MD5"},
			errHas: []string{"AES-128-CBC", "data-ciphers"}},
		{name: "pushed-in-data-ciphers", srv: srvConfig{cipher: "AES-128-CBC"}, ovpn: "data-ciphers AES-256-GCM:AES-128-CBC\n", cipher: "AES-128-CBC"},
		{name: "pushed-equals-deprecated-cipher-option", srv: srvConfig{cipher: "AES-256-CBC"}, ovpn: "cipher AES-256-CBC\n", cipher: "AES-256-CBC"},
		{name: "none-pushed-server-options-cipher-allowed", srv: srvConfig{occCipher: "AES-256-CBC"}, ovpn: "data-ciphers AES-256-GCM:AES-256-CBC\n", cipher: "AES-256-CBC"},
		{name: "none-pushed-server-options-cipher-not-allowed", srv: srvConfig{occCipher: "AES-256-CBC"},
			errHas: []string{"AES-256-CBC", "data-ciphers-fallback"}},
		{name: "none-pushed-bf-not-allowed", srv: srvConfig{occCipher: "BF-CBC"},
			errHas: []string{"BF-CBC", "data-ciphers-fallback"}},
		{name: "none-pushed-bf-fallback", srv: srvConfig{occCipher: "BF-CBC"}, ovpn: "data-ciphers-fallback BF-CBC\n", cipher: "BF-CBC"},
		{name: "none-pushed-fallback-wins-over-unknown", srv: srvConfig{occCipher: "AES-128-CBC"}, ovpn: "data-ciphers-fallback AES-128-CBC\n", cipher: "AES-128-CBC"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := startServer(t, tc.srv)
			c, err := dialServer(t, srv, sessionOpts{ovpn: tc.ovpn})
			if tc.cipher == "" {
				if err == nil {
					in := packetReader(c)
					got := 0
					for i := 0; i < 3; i++ {
						if c.WritePacket(testPacket(uint32(i), 80)) == nil {
							select {
							case <-in:
								got++
							case <-time.After(300 * time.Millisecond):
							}
						}
					}
					t.Fatalf("tunnel up with cipher %q (%d of 3 packets echoed), want an error", c.Info().Cipher, got)
				}
				for _, sub := range tc.errHas {
					if !strings.Contains(err.Error(), sub) {
						t.Errorf("error %q does not mention %q", err, sub)
					}
				}
				if st := srv.snapshot(); st.echoed != 0 {
					t.Errorf("the server echoed %d data packets", st.echoed)
				}
				return
			}
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			if got := c.Info().Cipher; got != tc.cipher {
				t.Errorf("cipher %q, want %q", got, tc.cipher)
			}
			echo(t, c, packetReader(c), 3, 200)
		})
	}
}

// TestOptionsStringWithoutCipher: with no data-ciphers-fallback or --cipher
// the client's options string names no cipher, as OpenVPN 2.6's does.
func TestOptionsStringWithoutCipher(t *testing.T) {
	srv := startServer(t, srvConfig{cipher: "AES-256-GCM"})
	mustDial(t, srv, sessionOpts{})
	if st := srv.snapshot(); strings.Contains(st.options, "cipher") {
		t.Errorf("options string %q names a cipher", st.options)
	}
}

// TestPushedAuthIgnored: "auth" is not a push option (OpenVPN rejects it
// there and the server keeps its own --auth), so the data digest comes
// from the profile only.
func TestPushedAuthIgnored(t *testing.T) {
	for _, tc := range []struct {
		name, auth, push, ovpn string
	}{
		{"push-sha256-server-sha1", "SHA1", "SHA256", ""},
		{"push-md5-server-sha1", "SHA1", "MD5", ""},
		{"push-sha1-server-sha512", "SHA512", "SHA1", "auth SHA512\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := startServer(t, srvConfig{cipher: "AES-256-CBC", auth: tc.auth, pushAuth: tc.push})
			c := mustDial(t, srv, sessionOpts{ovpn: "data-ciphers AES-256-GCM:AES-256-CBC\n" + tc.ovpn})
			if c.Info().Cipher != "AES-256-CBC" {
				t.Fatalf("cipher %q", c.Info().Cipher)
			}
			echo(t, c, packetReader(c), 3, 200)
			if st := srv.snapshot(); st.badData != 0 {
				t.Errorf("the server dropped %d data packets that failed authentication", st.badData)
			}
		})
	}
}

// TestAuthPendingTimeout: AUTH_PENDING with a timeout keyword extends the
// handshake window; plain AUTH_PENDING does not; the client announces that
// it understands the keyword.
func TestAuthPendingTimeout(t *testing.T) {
	t.Run("timeout-extends", func(t *testing.T) {
		srv := startServer(t, srvConfig{cipher: "AES-256-GCM", authPending: 2 * time.Second, authPendingMsg: "AUTH_PENDING,timeout 5"})
		start := time.Now()
		_, err := dialServer(t, srv, sessionOpts{cfg: func(c *Config) { c.HandshakeTimeout = time.Second }})
		if err != nil {
			t.Fatalf("Dial with AUTH_PENDING,timeout 5 and approval after 2s: %v (after %v)", err, time.Since(start).Round(time.Millisecond))
		}
		if st := srv.snapshot(); st.ivProto&handshake.IVProtoAuthPendingKW == 0 {
			t.Errorf("IV_PROTO %#x does not announce AUTH_PENDING keywords", st.ivProto)
		}
	})
	t.Run("plain-does-not", func(t *testing.T) {
		srv := startServer(t, srvConfig{cipher: "AES-256-GCM", authPending: 2 * time.Second})
		start := time.Now()
		_, err := dialServer(t, srv, sessionOpts{cfg: func(c *Config) { c.HandshakeTimeout = time.Second }})
		if !errors.Is(err, ErrHandshakeTimeout) || !strings.Contains(err.Error(), "authentication still pending") {
			t.Fatalf("err = %v, want a handshake timeout while authentication is pending", err)
		}
		if d := time.Since(start); d > 1800*time.Millisecond {
			t.Errorf("failed after %v, want about 1s", d)
		}
	})
	t.Run("timeout-capped", func(t *testing.T) {
		c := fuzzClient(t, fuzzDialer(t), false)
		defer stopFuzzClient(c)
		now := time.Now()
		if err := c.handleControlMessage("AUTH_PENDING,timeout 4000000000", now); err != nil {
			t.Fatal(err)
		}
		if d := c.loop.hsDeadline.Sub(now); d < 9*time.Minute || d > 31*time.Minute {
			t.Errorf("AUTH_PENDING,timeout 4000000000 moved the handshake deadline %v ahead, want it capped", d)
		}
		before := c.loop.hsDeadline
		for _, msg := range []string{"AUTH_PENDING,timeout x", "AUTH_PENDING,timeout -5", "AUTH_PENDING,timeout 1", "AUTH_PENDING,foo 9"} {
			if err := c.handleControlMessage(msg, now); err != nil {
				t.Fatal(err)
			}
		}
		if !c.loop.hsDeadline.Equal(before) {
			t.Errorf("a bad, shorter or unknown keyword moved the deadline")
		}
	})
}

// TestTLS10Server: crypto/tls splits every TLS 1.0 CBC record (1/n-1), and
// OpenVPN rejects the 1-byte key-method 2 read, so a session on TLS 1.0
// can never work: fail at once and say why. (The Go fake server reassembles
// the split records, so the test checks the client's own diagnosis.)
func TestTLS10Server(t *testing.T) {
	t.Run("tls-1.0", func(t *testing.T) {
		srv := startServer(t, srvConfig{cipher: "AES-256-GCM", tlsMin: tls.VersionTLS10, tlsMax: tls.VersionTLS10})
		start := time.Now()
		c, err := dialServer(t, srv, sessionOpts{cfg: func(c *Config) { c.HandshakeTimeout = 5 * time.Second }})
		if err == nil {
			t.Fatalf("Dial succeeded on %s", c.Info().TLSVersion)
		}
		if errors.Is(err, ErrHandshakeTimeout) || !strings.Contains(err.Error(), "TLS 1.0") {
			t.Errorf("err = %v, want one that names TLS 1.0", err)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("failed after %v", d)
		}
		if st := srv.snapshot(); st.exchanges != 0 {
			t.Errorf("the key-method 2 message was sent over TLS 1.0")
		}
	})
	t.Run("tls-1.1", func(t *testing.T) {
		srv := startServer(t, srvConfig{cipher: "AES-256-GCM", tlsMin: tls.VersionTLS11, tlsMax: tls.VersionTLS11})
		c := mustDial(t, srv, sessionOpts{})
		if v := c.Info().TLSVersion; v != "TLS 1.1" {
			t.Errorf("TLS version %q", v)
		}
		echo(t, c, packetReader(c), 2, 100)
	})
}

// TestHandshakeFailureHints: a TLS handshake the server never answers
// (no common TLS version or cipher suite: DHE-only servers) is told apart
// from a key exchange that did not finish.
func TestHandshakeFailureHints(t *testing.T) {
	for _, tc := range []struct {
		name   string
		srv    srvConfig
		want   string
		reject string
	}{
		{"udp-no-tls-reply", srvConfig{cipher: "AES-256-GCM", noTLSReply: true}, "no TLS reply", ""},
		{"tcp-no-tls-reply", srvConfig{tcp: true, cipher: "AES-256-GCM", noTLSReply: true}, "no TLS reply", ""},
		{"udp-no-key-method", srvConfig{cipher: "AES-256-GCM", noKeyMethod: true}, "key exchange did not finish", "TLS handshake or"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := startServer(t, tc.srv)
			_, err := dialServer(t, srv, sessionOpts{cfg: func(c *Config) { c.HandshakeTimeout = time.Second }})
			if err == nil {
				t.Fatal("Dial succeeded")
			}
			if !strings.Contains(err.Error(), tc.want) || (tc.reject != "" && strings.Contains(err.Error(), tc.reject)) {
				t.Errorf("err = %v, want it to say %q", err, tc.want)
			}
		})
	}
}
