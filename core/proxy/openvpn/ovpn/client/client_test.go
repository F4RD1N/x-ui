package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand/v2"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/handshake"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/options"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/reliable"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/wire"
)

// session starts a server with scfg, dials it with the config built from
// extra ovpn lines and returns the connected client.
type sessionOpts struct {
	ovpn    string        // extra client config lines
	cfg     func(*Config) // adjusts the client Config
	opts    func(*options.Options)
	timeout time.Duration
}

func parseOpts(t testing.TB, text string) *options.Options {
	t.Helper()
	o, err := options.Parse(text)
	if err != nil {
		t.Fatalf("options.Parse: %v\n%s", err, text)
	}
	return o
}

func dialServer(t testing.TB, srv *fakeServer, so sessionOpts) (*Client, error) {
	t.Helper()
	o := parseOpts(t, ovpnText(t, srv.remoteLine()+wrapLines(srv.cfg)+so.ovpn))
	if so.opts != nil {
		so.opts(o)
	}
	cfg := Config{Options: o, Dial: netDial, Logger: newTestLogger(t), HandshakeTimeout: 10 * time.Second}
	if so.cfg != nil {
		so.cfg(&cfg)
	}
	timeout := so.timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c, err := Dial(ctx, cfg)
	if c != nil {
		t.Cleanup(func() { c.Close() })
	}
	return c, err
}

func mustDial(t testing.TB, srv *fakeServer, so sessionOpts) *Client {
	t.Helper()
	c, err := dialServer(t, srv, so)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	return c
}

// echoCase is one connect-and-echo scenario.
type echoCase struct {
	name     string
	srv      srvConfig
	so       sessionOpts
	cipher   string // want Info().Cipher
	kd       string // want Info().KeyDerivation
	tlsVer   string // want Info().TLSVersion; "" means TLS 1.3
	dataOp   wire.Opcode
	size     int // echoed packet size; 0 means 100
	checkSrv func(t *testing.T, st srvStats)
}

func TestConnectEcho(t *testing.T) {
	cases := []echoCase{
		{name: "udp-plain-gcm-ekm", srv: srvConfig{cipher: "AES-256-GCM", ekm: true}, cipher: "AES-256-GCM", kd: "tls-ekm", dataOp: wire.DataV2},
		{name: "udp-tlsauth-aes128gcm", srv: srvConfig{wrap: "tls-auth", cipher: "AES-128-GCM", ekm: true}, cipher: "AES-128-GCM", kd: "tls-ekm", dataOp: wire.DataV2},
		{name: "udp-tlscrypt-chacha", srv: srvConfig{wrap: "tls-crypt", cipher: "CHACHA20-POLY1305", ekm: true}, cipher: "CHACHA20-POLY1305", kd: "tls-ekm", dataOp: wire.DataV2},
		{name: "tcp-plain-gcm", srv: srvConfig{tcp: true, cipher: "AES-256-GCM", ekm: true}, cipher: "AES-256-GCM", kd: "tls-ekm", dataOp: wire.DataV2, size: 1400},
		{name: "tcp-tlsauth-cbc-sha256", srv: srvConfig{tcp: true, wrap: "tls-auth", cipher: "AES-256-CBC", auth: "SHA256", ekm: true}, so: sessionOpts{ovpn: "data-ciphers AES-256-GCM:AES-256-CBC\nauth SHA256\n"}, cipher: "AES-256-CBC", kd: "tls-ekm", dataOp: wire.DataV2},
		{name: "tcp-tlscrypt-prf", srv: srvConfig{tcp: true, wrap: "tls-crypt", cipher: "AES-256-GCM", ekm: true}, so: sessionOpts{cfg: func(c *Config) { c.DisableEKM = true }}, cipher: "AES-256-GCM", kd: "prf", dataOp: wire.DataV2},
		{name: "udp-cbc-sha512-prf", srv: srvConfig{cipher: "AES-128-CBC", auth: "SHA512"}, so: sessionOpts{ovpn: "data-ciphers AES-256-GCM:AES-128-CBC\nauth SHA512\n"}, cipher: "AES-128-CBC", kd: "prf", dataOp: wire.DataV2, size: 1300},
		{name: "udp-data-v1-no-peer-id", srv: srvConfig{cipher: "AES-256-GCM", ekm: true, noPeerID: true}, cipher: "AES-256-GCM", kd: "tls-ekm", dataOp: wire.DataV1},
		{name: "udp-disable-datav2", srv: srvConfig{cipher: "AES-256-GCM", ekm: true}, so: sessionOpts{cfg: func(c *Config) { c.DisableDataV2 = true }}, cipher: "AES-256-GCM", kd: "tls-ekm", dataOp: wire.DataV1,
			checkSrv: func(t *testing.T, st srvStats) {
				if st.ivProto&handshake.IVProtoDataV2 != 0 {
					t.Errorf("IV_PROTO %#x announces DATA_V2", st.ivProto)
				}
			}},
		{name: "udp-tls12-ekm", srv: srvConfig{cipher: "AES-256-GCM", ekm: true, tlsMax: 0x0303}, cipher: "AES-256-GCM", kd: "tls-ekm", tlsVer: "TLS 1.2", dataOp: wire.DataV2},
		{name: "udp-fallback-cipher", srv: srvConfig{occCipher: "AES-128-CBC"}, so: sessionOpts{ovpn: "data-ciphers-fallback AES-128-CBC\n"}, cipher: "AES-128-CBC", kd: "prf", dataOp: wire.DataV2},
		{name: "udp-push-continuation-early", srv: srvConfig{cipher: "AES-256-GCM", ekm: true, split: true, pushEarly: true}, cipher: "AES-256-GCM", kd: "tls-ekm", dataOp: wire.DataV2},
		{name: "udp-compress-stub-v2", srv: srvConfig{cipher: "AES-256-GCM", compress: "stub-v2"}, cipher: "AES-256-GCM", kd: "prf", dataOp: wire.DataV2},
		{name: "udp-comp-lzo-no", srv: srvConfig{cipher: "AES-256-GCM", compress: "lzo-no"}, cipher: "AES-256-GCM", kd: "prf", dataOp: wire.DataV2},
		{name: "udp-tlscrypt-big-chain-chunked", srv: srvConfig{wrap: "tls-crypt", cipher: "AES-256-GCM", ekm: true},
			so:     sessionOpts{ovpn: bigChain(), cfg: func(c *Config) { c.Rand = mathrand.NewChaCha8([32]byte{1, 2, 3}) }},
			cipher: "AES-256-GCM", kd: "tls-ekm", dataOp: wire.DataV2,
			checkSrv: func(t *testing.T, st srvStats) {
				if st.maxCtl > maxControlPacket || st.maxCtl < 1150 {
					t.Errorf("largest control packet %d bytes, want close to but not over %d", st.maxCtl, maxControlPacket)
				}
			}},
		{name: "tcp-tlsauth-big-chain-chunked", srv: srvConfig{tcp: true, wrap: "tls-auth", cipher: "AES-256-GCM", ekm: true},
			so:     sessionOpts{ovpn: bigChain()},
			cipher: "AES-256-GCM", kd: "tls-ekm", dataOp: wire.DataV2,
			checkSrv: func(t *testing.T, st srvStats) {
				if st.maxCtl > maxControlPacket || st.maxCtl < 1150 {
					t.Errorf("largest control packet %d bytes, want close to but not over %d", st.maxCtl, maxControlPacket)
				}
			}},
		{name: "udp-auth-pending-userpass", srv: srvConfig{cipher: "AES-256-GCM", authPending: 300 * time.Millisecond},
			so:     sessionOpts{ovpn: "auth-user-pass\n", cfg: func(c *Config) { c.Username, c.Password = "alice", "s3cret" }},
			cipher: "AES-256-GCM", kd: "prf", dataOp: wire.DataV2,
			checkSrv: func(t *testing.T, st srvStats) {
				if len(st.usernames) != 1 || st.usernames[0] != "alice" || st.passwords[0] != "s3cret" {
					t.Errorf("server saw credentials %q/%q", st.usernames, st.passwords)
				}
			}},
	}
	v2check := func(t *testing.T, st srvStats) {
		if st.v3Resets == 0 {
			t.Errorf("no P_CONTROL_HARD_RESET_CLIENT_V3 with WKc arrived")
		}
	}
	cases = append(cases,
		echoCase{name: "udp-tlscrypt-v2", srv: newV2Config(t, srvConfig{cipher: "AES-256-GCM", ekm: true}), cipher: "AES-256-GCM", kd: "tls-ekm", dataOp: wire.DataV2, checkSrv: v2check},
		echoCase{name: "tcp-tlscrypt-v2-big-chain", srv: newV2Config(t, srvConfig{tcp: true, cipher: "AES-256-GCM", ekm: true}), so: sessionOpts{ovpn: bigChain()},
			cipher: "AES-256-GCM", kd: "tls-ekm", dataOp: wire.DataV2, checkSrv: func(t *testing.T, st srvStats) {
				v2check(t, st)
				if st.maxCtl > maxControlPacket+len(newV2Config(t, srvConfig{}).wkc) {
					t.Errorf("largest control packet %d bytes", st.maxCtl)
				}
			}},
	)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.srv.wrap != "" && tc.srv.key == nil {
				tc.srv.key = newStaticKey(t)
			}
			srv := startServer(t, tc.srv)
			c := mustDial(t, srv, tc.so)
			info := c.Info()
			if info.Cipher != tc.cipher {
				t.Errorf("cipher %q, want %q", info.Cipher, tc.cipher)
			}
			if info.KeyDerivation != tc.kd {
				t.Errorf("key derivation %q, want %q", info.KeyDerivation, tc.kd)
			}
			wantTLS := tc.tlsVer
			if wantTLS == "" {
				wantTLS = "TLS 1.3"
			}
			if info.TLSVersion != wantTLS {
				t.Errorf("TLS version %q, want %q", info.TLSVersion, wantTLS)
			}
			if info.IPv4 != netip.MustParsePrefix("10.8.0.2/24") || info.IPv6 != netip.MustParsePrefix("fd00::2/64") {
				t.Errorf("addresses %v %v", info.IPv4, info.IPv6)
			}
			if len(info.DNS) != 1 || info.DNS[0] != netip.MustParseAddr("10.8.0.1") {
				t.Errorf("DNS %v", info.DNS)
			}
			if info.MTU != 1500 {
				t.Errorf("MTU %d", info.MTU)
			}
			in := packetReader(c)
			size := tc.size
			if size == 0 {
				size = 100
			}
			echo(t, c, in, 20, size)
			// Payloads that start like the compression framing bytes.
			for _, first := range []byte{0x50, 0xfa, 0xfb, 0x66, 0x69} {
				p := testPacket(uint32(first), 60)
				p[0] = first
				expectEcho(t, c, in, p)
			}
			st := srv.snapshot()
			if st.dataOps[tc.dataOp] == 0 {
				t.Errorf("server saw data opcodes %v, want %v", st.dataOps, tc.dataOp)
			}
			if st.sessions != 1 || st.exchanges != 1 {
				t.Errorf("server saw %d sessions, %d key exchanges", st.sessions, st.exchanges)
			}
			if !strings.Contains(st.peerInfo, "IV_VER=2.6.12") || !strings.Contains(st.peerInfo, "IV_PLAT=linux") {
				t.Errorf("peer info:\n%s", st.peerInfo)
			}
			var probe Config
			if tc.so.cfg != nil {
				tc.so.cfg(&probe)
			}
			// Go's TLS can always export here (TLS 1.3, or 1.2 with EMS).
			if (st.ivProto&handshake.IVProtoTLSKeyExport != 0) == probe.DisableEKM {
				t.Errorf("IV_PROTO %#x: TLS key export bit wrong", st.ivProto)
			}
			if tc.checkSrv != nil {
				tc.checkSrv(t, st)
			}
			if err := c.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
			if !errors.Is(c.Err(), ErrClosed) {
				t.Errorf("Err after Close: %v", c.Err())
			}
		})
	}
}

// bigChain adds the CA four times as extra-certs, so the client's TLS
// flight needs several control packets.
func bigChain() string {
	return "<extra-certs>\n" + strings.Repeat(string(getPKIQuiet().caPEM), 4) + "</extra-certs>\n"
}

func getPKIQuiet() *testPKI {
	pkiOnce.Do(func() { pkiVal, pkiErr = makePKI() })
	if pkiErr != nil {
		panic(pkiErr)
	}
	return pkiVal
}

// expectEcho sends p and waits for it to come back.
func expectEcho(t testing.TB, c *Client, in <-chan []byte, p []byte) {
	t.Helper()
	if err := c.WritePacket(p); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	timeout := time.After(2 * time.Second)
	for {
		select {
		case got, ok := <-in:
			if !ok {
				t.Fatalf("session ended: %v", c.Err())
			}
			if bytes.Equal(got, p) {
				return
			}
		case <-timeout:
			t.Fatalf("packet starting %#x not echoed", p[0])
		}
	}
}

func TestPeerInfoAndOptionsString(t *testing.T) {
	srv := startServer(t, srvConfig{cipher: "AES-256-GCM", ekm: true})
	mustDial(t, srv, sessionOpts{
		ovpn: "data-ciphers AES-256-GCM:bogus-cipher:aes-128-gcm\ndata-ciphers-fallback AES-256-CBC\n",
		cfg:  func(c *Config) { c.Platform = "android" },
	})
	st := srv.snapshot()
	for _, want := range []string{"IV_PLAT=android", "IV_CIPHERS=AES-256-GCM:AES-128-GCM:AES-256-CBC", "IV_MTU=1600"} {
		if !strings.Contains(st.peerInfo, want) {
			t.Errorf("peer info lacks %q:\n%s", want, st.peerInfo)
		}
	}
	wantBits := uint32(handshake.IVProtoDataV2 | handshake.IVProtoRequestPush | handshake.IVProtoTLSKeyExport | handshake.IVProtoCCExitNotify | handshake.IVProtoDNSOption | handshake.IVProtoAuthPendingKW)
	if st.ivProto != wantBits {
		t.Errorf("IV_PROTO %d, want %d", st.ivProto, wantBits)
	}
	if !strings.HasPrefix(st.options, "V4,") || !strings.Contains(st.options, "cipher AES-256-CBC") || !strings.Contains(st.options, "tls-client") {
		t.Errorf("options string %q", st.options)
	}
}

func TestLossyHandshake(t *testing.T) {
	var lost int64
	for _, tc := range []struct {
		name string
		wrap string
		seed uint64
	}{
		{"plain", "", 1},
		{"plain", "", 2},
		{"tls-crypt", "tls-crypt", 7},
		{"tls-crypt", "tls-crypt", 8},
		{"tls-crypt", "tls-crypt", 9},
		{"tls-auth", "tls-auth", 12345},
		{"tls-auth", "tls-auth", 4242},
		{"tls-crypt-v2", "tls-crypt-v2", 99},
		{"tls-crypt-v2", "tls-crypt-v2", 100},
	} {
		t.Run(fmt.Sprintf("%s-%d", tc.name, tc.seed), func(t *testing.T) {
			rel := reliable.Options{InitialTimeout: 100 * time.Millisecond, MaxTimeout: 400 * time.Millisecond}
			scfg := srvConfig{wrap: tc.wrap, cipher: "AES-256-GCM", ekm: true, reliable: rel}
			switch tc.wrap {
			case "":
			case "tls-crypt-v2":
				scfg = newV2Config(t, scfg)
			default:
				scfg.key = newStaticKey(t)
			}
			srv := startServer(t, scfg)
			relay := startRelay(t, srv, tc.seed)
			relay.loss.Store(20)
			relay.jitter.Store(int64(15 * time.Millisecond))
			o := parseOpts(t, ovpnText(t, fmt.Sprintf("remote 127.0.0.1 %d udp\n", relay.port())+wrapLines(scfg)))
			cfg := Config{Options: o, Dial: netDial, Logger: newTestLogger(t), HandshakeTimeout: 20 * time.Second,
				hooks: &testHooks{reliable: rel, pushInterval: 300 * time.Millisecond}}
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			start := time.Now()
			c, err := Dial(ctx, cfg)
			if err != nil {
				t.Fatalf("Dial through a lossy link: %v", err)
			}
			defer c.Close()
			t.Logf("handshake took %v, relay dropped %d packets", time.Since(start), relay.lost.Load())
			lost += relay.lost.Load()
			relay.loss.Store(0)
			relay.jitter.Store(0)
			echo(t, c, packetReader(c), 10, 200)
		})
	}
	if lost < 10 {
		t.Errorf("the relay dropped only %d packets in all handshakes", lost)
	}
}

func TestAuthFailed(t *testing.T) {
	for _, tc := range []struct {
		name string
		bad  srvConfig
	}{
		{"udp", srvConfig{cipher: "AES-256-GCM", authFail: "bad username or password"}},
		{"tcp", srvConfig{tcp: true, cipher: "AES-256-GCM", authFail: "bad username or password"}},
		{"tcp-hang-up", srvConfig{tcp: true, cipher: "AES-256-GCM", authFail: "bad username or password", hangUp: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := startServer(t, tc.bad)
			good := startServer(t, srvConfig{cipher: "AES-256-GCM"})
			before := runtime.NumGoroutine()
			o := parseOpts(t, ovpnText(t, bad.remoteLine()+good.remoteLine()+"auth-user-pass\n"))
			cfg := Config{Options: o, Dial: netDial, Logger: newTestLogger(t), Username: "bob", Password: "wrong", HandshakeTimeout: 10 * time.Second}
			start := time.Now()
			c, err := Dial(context.Background(), cfg)
			if err == nil {
				c.Close()
				t.Fatal("Dial succeeded")
			}
			if !errors.Is(err, ErrAuthFailed) || !strings.Contains(err.Error(), "bad username or password") {
				t.Fatalf("err = %v, want ErrAuthFailed with the reason", err)
			}
			if d := time.Since(start); d > 5*time.Second {
				t.Errorf("AUTH_FAILED took %v", d)
			}
			if st := good.snapshot(); st.sessions != 0 {
				t.Errorf("the next remote was tried after AUTH_FAILED")
			}
			bad.Close() // its session's TLS goroutine started after the baseline
			checkGoroutines(t, before)
		})
	}
}

// checkGoroutines waits for the goroutine count to fall back to before.
func checkGoroutines(t testing.TB, before int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > before {
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<20)
			n := runtime.Stack(buf, true)
			t.Fatalf("%d goroutines before, %d after:\n%s", before, runtime.NumGoroutine(), buf[:n])
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestControlMessagesAfterUp(t *testing.T) {
	for _, tc := range []struct {
		msg  string
		want error
	}{
		{"RESTART", ErrServerRestart},
		{"RESTART,server going down", ErrServerRestart},
		{"HALT", ErrServerHalt},
		{"EXIT", ErrServerRestart},
		{"AUTH_FAILED,session expired", ErrAuthFailed},
	} {
		t.Run(tc.msg, func(t *testing.T) {
			srv := startServer(t, srvConfig{cipher: "AES-256-GCM"})
			c := mustDial(t, srv, sessionOpts{})
			srv.sendControl("INFO,hello there")
			srv.sendControl("PUSH_REPLY,ping 1") // a late reply is ignored
			srv.sendControl(tc.msg)
			select {
			case <-c.Done():
			case <-time.After(3 * time.Second):
				t.Fatal("session did not end")
			}
			if !errors.Is(c.Err(), tc.want) {
				t.Fatalf("Err = %v, want %v", c.Err(), tc.want)
			}
			if _, err := c.ReadPacket(make([]byte, 100)); !errors.Is(err, tc.want) {
				t.Errorf("ReadPacket err = %v", err)
			}
			if err := c.WritePacket(testPacket(1, 40)); !errors.Is(err, tc.want) {
				t.Errorf("WritePacket err = %v", err)
			}
		})
	}
}

func TestPingRestart(t *testing.T) {
	srv := startServer(t, srvConfig{cipher: "AES-256-GCM"})
	// Ignore the pushed ping 10 / ping-restart 60 so the configured short
	// values apply.
	c := mustDial(t, srv, sessionOpts{
		ovpn: "pull-filter ignore \"ping\"\n",
		opts: func(o *options.Options) {
			o.Ping = 100 * time.Millisecond
			o.PingRestart = 600 * time.Millisecond
		},
	})
	time.Sleep(450 * time.Millisecond)
	if st := srv.snapshot(); st.pings < 2 {
		t.Errorf("server got %d pings in 450ms with ping 100ms", st.pings)
	}
	if c.Err() != nil {
		t.Fatalf("session ended although the server answers pings: %v", c.Err())
	}
	srv.silent.Store(true)
	start := time.Now()
	select {
	case <-c.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("ping-restart did not end the session")
	}
	if !errors.Is(c.Err(), ErrPingTimeout) {
		t.Fatalf("Err = %v, want ErrPingTimeout", c.Err())
	}
	if d := time.Since(start); d < 400*time.Millisecond || d > 2*time.Second {
		t.Errorf("ping-restart fired %v after the server went silent, want about 600ms", d)
	}
}

func TestServerRenegotiation(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		t.Run(fmt.Sprintf("tcp=%v", tcp), func(t *testing.T) {
			srv := startServer(t, srvConfig{tcp: tcp, wrap: "tls-crypt", key: newStaticKey(t), cipher: "AES-256-GCM", ekm: true, renegAfter: 250 * time.Millisecond})
			c := mustDial(t, srv, sessionOpts{})
			traffic(t, c, func() bool {
				st := srv.snapshot()
				return st.serverResets >= 3 && st.exchanges >= 4 && st.dataKeys[3] > 20
			})
			st := srv.snapshot()
			if st.clientResets != 0 {
				t.Errorf("client started %d renegotiations of its own", st.clientResets)
			}
			for id := uint8(0); id <= 3; id++ {
				if st.dataKeys[id] == 0 {
					t.Errorf("no data packets with key %d (%v)", id, st.dataKeys)
				}
			}
		})
	}
}

func TestClientRenegotiation(t *testing.T) {
	srv := startServer(t, srvConfig{cipher: "AES-128-GCM", authToken: "TOKEN-123"})
	c := mustDial(t, srv, sessionOpts{
		ovpn: "auth-user-pass\n",
		cfg:  func(c *Config) { c.Username, c.Password = "carol", "pw" },
		opts: func(o *options.Options) { o.RenegSec = 120 * time.Millisecond },
	})
	// Eight renegotiations wrap the key id around (1..7, then 1).
	traffic(t, c, func() bool {
		st := srv.snapshot()
		return st.clientResets >= 8 && st.exchanges >= 9
	})
	st := srv.snapshot()
	if st.serverResets != 0 {
		t.Errorf("server renegotiated")
	}
	if st.passwords[0] != "pw" {
		t.Errorf("first key exchange password %q", st.passwords[0])
	}
	for i := 1; i < len(st.passwords); i++ {
		if st.passwords[i] != "TOKEN-123" || st.usernames[i] != "carol" {
			t.Errorf("key exchange %d sent %q/%q, want the auth-token", i, st.usernames[i], st.passwords[i])
		}
	}
	for id := uint8(1); id <= 7; id++ {
		if st.dataKeys[id] == 0 {
			t.Errorf("no data packets with key %d (%v)", id, st.dataKeys)
		}
	}
}

// An AUTH_FAILED that answers a renegotiation which logged in with the
// pushed auth-token ends the session with ErrAuthFailed and
// ErrAuthTokenRejected: the server refused the token, and the caller may log
// in again with the username and password, as OpenVPN 2.x does. Without a
// token the renegotiation sent the password, and the AUTH_FAILED stays a
// plain one.
func TestRenegotiationAuthFailed(t *testing.T) {
	for _, tc := range []struct {
		name, token, wantPass string
		tokenRejected         bool
	}{
		{"auth-token", "TOKEN-123", "TOKEN-123", true},
		{"password", "", "pw", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := startServer(t, srvConfig{cipher: "AES-128-GCM", authToken: tc.token, renegAuthFail: "SESSION:token expired"})
			c := mustDial(t, srv, sessionOpts{
				ovpn: "auth-user-pass\n",
				cfg:  func(c *Config) { c.Username, c.Password = "carol", "pw" },
				opts: func(o *options.Options) { o.RenegSec = 200 * time.Millisecond },
			})
			defer c.Close()
			select {
			case <-c.Done():
			case <-time.After(10 * time.Second):
				t.Fatal("the session outlived the AUTH_FAILED on its renegotiation")
			}
			err := c.Err()
			if !errors.Is(err, ErrAuthFailed) || !strings.Contains(err.Error(), "SESSION:token expired") {
				t.Fatalf("err = %v, want ErrAuthFailed with the reason", err)
			}
			if got := errors.Is(err, ErrAuthTokenRejected); got != tc.tokenRejected {
				t.Fatalf("err = %v: ErrAuthTokenRejected %v, want %v", err, got, tc.tokenRejected)
			}
			st := srv.snapshot()
			if len(st.passwords) < 2 || st.passwords[0] != "pw" || st.passwords[1] != tc.wantPass {
				t.Fatalf("key exchanges sent passwords %q, want pw then %q", st.passwords, tc.wantPass)
			}
		})
	}
}

// traffic keeps packets flowing until done reports true, then checks that
// echoes still come back.
func traffic(t *testing.T, c *Client, done func() bool) {
	t.Helper()
	in := packetReader(c)
	var (
		mu       sync.Mutex
		received int
	)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			select {
			case _, ok := <-in:
				if !ok {
					return
				}
				mu.Lock()
				received++
				mu.Unlock()
			case <-stop:
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for seq := uint32(0); ; seq++ {
			select {
			case <-stop:
				return
			case <-time.After(3 * time.Millisecond):
			}
			if c.WritePacket(testPacket(seq, 120)) != nil {
				return
			}
		}
	}()
	deadline := time.Now().Add(15 * time.Second)
	for !done() {
		if c.Err() != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("session ended: %v", c.Err())
		}
		if time.Now().After(deadline) {
			close(stop)
			wg.Wait()
			t.Fatalf("timed out waiting for the renegotiations")
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	before := received
	mu.Unlock()
	time.Sleep(150 * time.Millisecond)
	mu.Lock()
	after := received
	mu.Unlock()
	close(stop)
	wg.Wait()
	if after-before < 10 {
		t.Errorf("only %d echoes in the 150ms after renegotiation (total %d)", after-before, after)
	}
	if c.Err() != nil {
		t.Fatalf("session ended: %v", c.Err())
	}
}

func TestRemoteFallback(t *testing.T) {
	// A TCP port nobody listens on, then a working UDP server.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadPort := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	srv := startServer(t, srvConfig{cipher: "AES-256-GCM"})
	o := parseOpts(t, ovpnText(t, fmt.Sprintf("remote 127.0.0.1 %d tcp\n", deadPort)+srv.remoteLine()))
	c, err := Dial(context.Background(), Config{Options: o, Dial: netDial, Logger: newTestLogger(t), HandshakeTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()
	if r := c.Info().Remote; r.Port != uint16(srv.port) || r.IsTCP() {
		t.Errorf("connected to %+v", r)
	}

	// With only the dead remote, the error is the dial's, not a timeout.
	o2 := parseOpts(t, ovpnText(t, fmt.Sprintf("remote 127.0.0.1 %d tcp\n", deadPort)))
	_, err = Dial(context.Background(), Config{Options: o2, Dial: netDial, HandshakeTimeout: 5 * time.Second})
	if err == nil || errors.Is(err, ErrHandshakeTimeout) || !strings.Contains(err.Error(), "refused") {
		t.Errorf("dead remote: err = %v", err)
	}
}

func TestHandshakeTimeout(t *testing.T) {
	hole, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer hole.Close()
	port := hole.LocalAddr().(*net.UDPAddr).Port
	o := parseOpts(t, ovpnText(t, fmt.Sprintf("remote 127.0.0.1 %d udp\nremote 127.0.0.1 %d udp\n", port, port)))
	before := runtime.NumGoroutine()
	defer checkGoroutines(t, before)
	start := time.Now()
	_, err = Dial(context.Background(), Config{Options: o, Dial: netDial, Logger: newTestLogger(t), HandshakeTimeout: 300 * time.Millisecond})
	if !errors.Is(err, ErrHandshakeTimeout) {
		t.Fatalf("err = %v, want ErrHandshakeTimeout", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("two 300ms attempts took %v", d)
	}

	// ctx ends the whole Dial.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start = time.Now()
	_, err = Dial(ctx, Config{Options: o, Dial: netDial, HandshakeTimeout: 10 * time.Second})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the context's error", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("ctx deadline 200ms, Dial took %v", d)
	}
}

func TestCloseNoLeak(t *testing.T) {
	before := runtime.NumGoroutine()
	for _, tc := range []struct {
		name string
		srv  srvConfig
		ovpn string
		exit func(st srvStats) bool
	}{
		{"udp-cc-exit", srvConfig{cipher: "AES-256-GCM", ccExit: true}, "", func(st srvStats) bool { return st.exitMsgs == 1 && st.occExits == 0 }},
		{"tcp-cc-exit", srvConfig{tcp: true, cipher: "AES-256-GCM", ccExit: true}, "", func(st srvStats) bool { return st.exitMsgs == 1 }},
		{"udp-explicit-exit-notify", srvConfig{cipher: "AES-256-GCM"}, "explicit-exit-notify 3\n", func(st srvStats) bool { return st.occExits == 3 && st.exitMsgs == 0 }},
		{"tcp-explicit-exit-notify", srvConfig{tcp: true, cipher: "AES-256-GCM"}, "explicit-exit-notify 3\n", func(st srvStats) bool { return st.occExits == 0 && st.exitMsgs == 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := startServer(t, tc.srv)
			c := mustDial(t, srv, sessionOpts{ovpn: tc.ovpn})
			echo(t, c, packetReader(c), 3, 64)
			start := time.Now()
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			if d := time.Since(start); d > 600*time.Millisecond {
				t.Errorf("Close took %v", d)
			}
			if err := c.Close(); err != nil {
				t.Errorf("second Close: %v", err)
			}
			if !errors.Is(c.Err(), ErrClosed) {
				t.Errorf("Err = %v", c.Err())
			}
			if err := c.WritePacket(testPacket(1, 40)); err == nil {
				t.Errorf("WritePacket after Close succeeded")
			}
			time.Sleep(100 * time.Millisecond)
			if st := srv.snapshot(); !tc.exit(st) {
				t.Errorf("server saw %d EXIT messages and %d OCC exits", st.exitMsgs, st.occExits)
			}
			srv.Close()
		})
	}
	checkGoroutines(t, before)
}

func TestReadPacketShortBuffer(t *testing.T) {
	srv := startServer(t, srvConfig{cipher: "AES-256-GCM"})
	c := mustDial(t, srv, sessionOpts{})
	want := testPacket(9, 200)
	if err := c.WritePacket(want); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 50)
	n, err := c.ReadPacket(buf)
	if n != 50 || !errors.Is(err, io.ErrShortBuffer) || !bytes.Equal(buf, want[:50]) {
		t.Fatalf("ReadPacket = %d, %v", n, err)
	}
}

func TestDialValidation(t *testing.T) {
	o := parseOpts(t, ovpnText(t, "remote 127.0.0.1 1194 udp\n"))
	if _, err := Dial(context.Background(), Config{Options: o}); err == nil {
		t.Error("Dial without Dial func succeeded")
	}
	if _, err := Dial(context.Background(), Config{Dial: netDial}); err == nil {
		t.Error("Dial without options succeeded")
	}
	o2 := *o
	o2.Remotes = nil
	if _, err := Dial(context.Background(), Config{Options: &o2, Dial: netDial}); err == nil {
		t.Error("Dial without remotes succeeded")
	}
}

func TestShuffleRemotes(t *testing.T) {
	rs := make([]options.Remote, 6)
	for i := range rs {
		rs[i].Port = uint16(i)
	}
	if err := shuffleRemotes(rs, bytes.NewReader(bytes.Repeat([]byte{0x5a, 0x13, 0x77}, 40))); err != nil {
		t.Fatal(err)
	}
	seen := map[uint16]bool{}
	for _, r := range rs {
		seen[r.Port] = true
	}
	if len(seen) != 6 {
		t.Errorf("shuffle lost remotes: %v", rs)
	}
	if err := shuffleRemotes(rs, bytes.NewReader(nil)); err == nil {
		t.Error("shuffle with an empty random source succeeded")
	}
}

func TestNextKeyID(t *testing.T) {
	want := []uint8{1, 2, 3, 4, 5, 6, 7, 1}
	id := uint8(0)
	for i, w := range want {
		id = nextKeyID(id)
		if id != w {
			t.Fatalf("step %d: %d, want %d", i, id, w)
		}
	}
}

func TestSplitControlMessages(t *testing.T) {
	msgs, rest := splitControlMessages([]byte("PUSH_REPLY,a\x00\x00INFO,x\x00AUTH_"))
	if fmt.Sprint(msgs) != "[PUSH_REPLY,a INFO,x]" || string(rest) != "AUTH_" {
		t.Errorf("got %q, %q", msgs, rest)
	}
	msgs, rest = splitControlMessages([]byte("EXIT\x00"))
	if len(msgs) != 1 || rest != nil {
		t.Errorf("got %q, %q", msgs, rest)
	}
}

func TestRedactPush(t *testing.T) {
	got := redactPush("PUSH_REPLY,ping 10,auth-token SECRET,auth-token-user Ym9i,peer-id 1")
	if strings.Contains(got, "SECRET") || strings.Contains(got, "Ym9i") || !strings.Contains(got, "peer-id 1") {
		t.Errorf("redactPush = %q", got)
	}
}
