package interop_test

// Acceptance tests for the OpenVPN client against the harness's stock
// OpenVPN 2.6 servers. They run only with OVPN_INTEROP=1 as root:
//
//	OVPN_INTEROP=1 ovpn-gorun go test -count=1 -timeout 900s -v ./proxy/openvpn/ovpn/interop/
//
// Each case: client.Dial with the case's .ovpn (sockets made in the client
// namespace by interop.Dial), a gVisor userspace stack on the pushed
// addresses (MTU 1400) and two goroutines moving packets between the stack
// and the session; then HTTP and UDP through the tunnel to the test server.
// TestLoopbackPlumbing runs the same checks against an in-process test
// server over a second gVisor stack, so the plumbing here is known good
// whatever the client does.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/client"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/interop"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/options"
	"github.com/xtls/xray-core/proxy/openvpn/netstack"
)

const (
	stackMTU    = 1400
	blobSize    = 4_000_000
	blobSeed    = 7
	textSize    = 2_000_000
	echoSize    = 256 << 10
	caseTimeout = 3 * time.Minute
)

var (
	blobSum = sync.OnceValue(func() [32]byte { return interop.BlobSHA256(blobSize, blobSeed) })
	textSum = sync.OnceValue(func() [32]byte { return interop.TextSHA256(textSize) })
)

// ---------------------------------------------------------------- session

// testLogger sends the client's log to t until the test ends.
type testLogger struct {
	mu    sync.Mutex
	t     testing.TB
	done  bool
	debug bool
}

func newTestLogger(t testing.TB) *testLogger {
	l := &testLogger{t: t, debug: os.Getenv("OVPN_INTEROP_DEBUG") == "1"}
	t.Cleanup(func() {
		l.mu.Lock()
		l.done = true
		l.mu.Unlock()
	})
	return l
}

func (l *testLogger) logf(level, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.done {
		l.t.Logf("client %s: %s", level, fmt.Sprintf(format, args...))
	}
}

func (l *testLogger) Debugf(format string, args ...any) {
	if l.debug {
		l.logf("debug", format, args...)
	}
}
func (l *testLogger) Infof(format string, args ...any) { l.logf("info", format, args...) }
func (l *testLogger) Warnf(format string, args ...any) { l.logf("warn", format, args...) }

func mustCase(t *testing.T, name string) interop.Case {
	t.Helper()
	c, ok := interop.Lookup(name)
	if !ok {
		t.Fatalf("no interop case %q in %s/cases.json", name, interop.Dir())
	}
	return c
}

// parseOVPN is options.Parse with a panic turned into an error.
func parseOVPN(text string) (opts *options.Options, err error) {
	defer func() {
		if p := recover(); p != nil {
			opts, err = nil, fmt.Errorf("panicked: %v", p)
		}
	}()
	return options.Parse(text)
}

// dialCase parses the case's .ovpn and dials it; mod adjusts the config
// (cfg.Options included) first. A panic in the client is a test failure, not
// a crash of the whole suite.
func dialCase(ctx context.Context, t *testing.T, c interop.Case, mod func(*client.Config)) (cl *client.Client, took time.Duration, err error) {
	t.Helper()
	text, err := c.ReadOVPN()
	if err != nil {
		t.Fatal(err)
	}
	opts, err := parseOVPN(text)
	if err != nil {
		t.Fatalf("%s: options.Parse(%s): %v", c, c.OVPN, err)
	}
	if c.Username != "" && (opts.Username != c.Username || opts.Password != c.Password || !opts.AuthUserPass) {
		t.Errorf("%s: inline <auth-user-pass> parsed as auth-user-pass=%v user %q (password %d bytes), want %q",
			c, opts.AuthUserPass, opts.Username, len(opts.Password), c.Username)
	}
	cfg := client.Config{
		Options:          opts,
		Username:         c.Username,
		Password:         c.Password,
		Dial:             interop.Dial,
		Logger:           newTestLogger(t),
		HandshakeTimeout: 30 * time.Second,
	}
	if mod != nil {
		mod(&cfg)
	}
	start := time.Now()
	defer func() {
		took = time.Since(start)
		if p := recover(); p != nil {
			cl, err = nil, fmt.Errorf("client.Dial panicked: %v", p)
		}
	}()
	cl, err = client.Dial(ctx, cfg)
	return cl, 0, err // took is set by the deferred function
}

// linkStats counts the bytes the session reads from its transport socket:
// what actually crossed the link, before decryption and decompression.
type linkStats struct{ rx atomic.Int64 }

// wrap returns a DialFunc whose connections count into s.
func (s *linkStats) wrap(dial client.DialFunc) client.DialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		c, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &countingConn{Conn: c, s: s}, nil
	}
}

type countingConn struct {
	net.Conn
	s *linkStats
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.s.rx.Add(int64(n))
	return n, err
}

// waitServerLog returns what the server logged since off once every want is
// in it, or after timeout. OpenVPN prints some per-client lines (the
// "Data Channel: cipher ..." summary among them) from its once-a-second
// timer, up to about 1.5 s after the PUSH_REPLY, and a TCP client instance
// that is gone by then never prints them: wait while the session is up.
func waitServerLog(c interop.Case, off int64, timeout time.Duration, wants ...string) (string, error) {
	deadline := time.Now().Add(timeout)
	for {
		slog, err := c.ServerLogSince(off)
		if err != nil {
			return "", err
		}
		all := true
		for _, w := range wants {
			if !strings.Contains(slog, w) {
				all = false
				break
			}
		}
		if all || time.Now().After(deadline) {
			return slog, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// ---------------------------------------------------------------- tunnel

// packetIO is the packet side of a session (*client.Client has it).
type packetIO interface {
	ReadPacket(p []byte) (int, error)
	WritePacket(p []byte) error
}

// tunnel is a gVisor stack whose packets are pumped to and from a packetIO.
type tunnel struct {
	dev     tun.Device
	net     *gvisortun.Net
	st      *stack.Stack
	inDone  chan struct{} // session -> stack pump ended
	outDone chan struct{} // stack -> session pump ended
	panicV  atomic.Value
	once    sync.Once
}

func newTunnel(t testing.TB, pio packetIO, addrs []netip.Addr) *tunnel {
	t.Helper()
	dev, tnet, st, err := gvisortun.CreateNetTUN(addrs, stackMTU, false)
	if err != nil {
		t.Fatalf("gvisortun.CreateNetTUN(%v): %v", addrs, err)
	}
	tn := &tunnel{dev: dev, net: tnet, st: st, inDone: make(chan struct{}), outDone: make(chan struct{})}
	go func() { // stack -> session
		defer close(tn.outDone)
		defer tn.recoverPanic("stack->session")
		bufs := [][]byte{make([]byte, 65536)}
		sizes := []int{0}
		for {
			n, err := dev.Read(bufs, sizes, 0)
			if err != nil {
				return
			}
			for i := 0; i < n; i++ {
				// Errors after the session ended are expected; keep draining
				// so the stack never blocks on its outbound channel.
				pio.WritePacket(bufs[i][:sizes[i]]) //nolint:errcheck
			}
		}
	}()
	go func() { // session -> stack
		defer close(tn.inDone)
		defer tn.recoverPanic("session->stack")
		buf := make([]byte, 65536)
		for {
			n, err := pio.ReadPacket(buf)
			if err != nil {
				if errors.Is(err, io.ErrShortBuffer) {
					continue
				}
				return
			}
			if n > 0 {
				dev.Write([][]byte{buf[:n]}, 0) //nolint:errcheck // a non-IP packet is dropped
			}
		}
	}()
	return tn
}

func (tn *tunnel) recoverPanic(where string) {
	if p := recover(); p != nil {
		tn.panicV.CompareAndSwap(nil, fmt.Sprintf("%s: %v", where, p))
	}
}

// close stops the session (stopIO), then the stack, then the device, in the
// order that keeps gvisortun from writing to a closed channel: nothing is
// injected into the stack once it is being destroyed, and the stack's
// outbound packets are drained until the device closes.
func (tn *tunnel) close(t testing.TB, stopIO func()) {
	tn.once.Do(func() {
		stopIO()
		select {
		case <-tn.inDone:
		case <-time.After(10 * time.Second):
			t.Errorf("ReadPacket did not return within 10 s of the session closing; leaking the stack")
			return
		}
		tn.st.Destroy()
		tn.dev.Close()
		select {
		case <-tn.outDone:
		case <-time.After(10 * time.Second):
			t.Errorf("WritePacket blocked for 10 s after the session closed")
		}
		if p := tn.panicV.Load(); p != nil {
			t.Errorf("packet pump panicked: %v", p)
		}
	})
}

func (tn *tunnel) httpClient() *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			ap, err := netip.ParseAddrPort(addr)
			if err != nil {
				return nil, err
			}
			return tn.net.DialContextTCPAddrPort(ctx, ap)
		},
		DisableCompression:    true,
		MaxIdleConnsPerHost:   2,
		ResponseHeaderTimeout: 30 * time.Second,
	}}
}

// ---------------------------------------------------------------- checks

// fetch GETs url (or POSTs body when not nil) and returns the body's SHA-256
// and length, or its bytes when keep is set.
func fetch(ctx context.Context, hc *http.Client, method, url string, body []byte, timeout time.Duration, keep bool) (sum [32]byte, n int64, kept []byte, err error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rd)
	if err != nil {
		return sum, 0, nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return sum, 0, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return sum, 0, nil, fmt.Errorf("%s %s: %s", method, url, resp.Status)
	}
	h := sha256.New()
	var w io.Writer = h
	var buf strings.Builder
	if keep {
		w = io.MultiWriter(h, &buf)
	}
	n, err = io.Copy(w, resp.Body)
	h.Sum(sum[:0])
	return sum, n, []byte(buf.String()), err
}

// runChecks talks to the test server at server through tn: /hello, /ip,
// /blob, /text, POST /echo and UDP echo.
func runChecks(ctx context.Context, t *testing.T, tn *tunnel, server, self netip.Addr, label string) {
	t.Helper()
	hc := tn.httpClient()
	defer hc.CloseIdleConnections()
	base := "http://" + netip.AddrPortFrom(server, interop.HTTPPort).String()

	_, _, body, err := fetch(ctx, hc, "GET", base+"/hello", nil, 30*time.Second, true)
	if err != nil {
		t.Fatalf("%s GET /hello: %v", label, err)
	}
	if string(body) != interop.HelloBody {
		t.Errorf("%s GET /hello = %q, want %q", label, body, interop.HelloBody)
	}

	if _, _, body, err = fetch(ctx, hc, "GET", base+"/ip", nil, 30*time.Second, true); err != nil {
		t.Errorf("%s GET /ip: %v", label, err)
	} else if got := strings.TrimSpace(string(body)); got != self.String() {
		t.Errorf("%s GET /ip = %q, want the tunnel address %s", label, got, self)
	}

	start := time.Now()
	sum, n, _, err := fetch(ctx, hc, "GET", fmt.Sprintf("%s/blob?size=%d&seed=%d", base, blobSize, blobSeed), nil, 2*time.Minute, false)
	took := time.Since(start)
	switch {
	case err != nil:
		t.Errorf("%s GET /blob: %v after %d bytes", label, err, n)
	case n != blobSize || sum != blobSum():
		t.Errorf("%s GET /blob: %d bytes, sha256 %x, want %d bytes, %x", label, n, sum, blobSize, blobSum())
	default:
		t.Logf("%s: /blob %d bytes in %v: %.1f Mbit/s", label, n, took.Round(time.Millisecond), float64(n)*8/took.Seconds()/1e6)
	}

	start = time.Now()
	sum, n, _, err = fetch(ctx, hc, "GET", fmt.Sprintf("%s/text?size=%d", base, textSize), nil, 2*time.Minute, false)
	took = time.Since(start)
	switch {
	case err != nil:
		t.Errorf("%s GET /text: %v after %d bytes", label, err, n)
	case n != textSize || sum != textSum():
		t.Errorf("%s GET /text: %d bytes, sha256 %x, want %d bytes, %x", label, n, sum, textSize, textSum())
	default:
		t.Logf("%s: /text %d bytes in %v: %.1f Mbit/s", label, n, took.Round(time.Millisecond), float64(n)*8/took.Seconds()/1e6)
	}

	payload, _ := io.ReadAll(interop.NewBlobReader(echoSize, 42))
	sum, n, _, err = fetch(ctx, hc, "POST", base+"/echo", payload, time.Minute, false)
	if err != nil {
		t.Errorf("%s POST /echo: %v", label, err)
	} else if n != echoSize || sum != sha256.Sum256(payload) {
		t.Errorf("%s POST /echo: %d bytes back, want the %d sent", label, n, echoSize)
	}

	checkUDPEcho(t, tn, server, label)
}

// checkUDPEcho sends three datagrams (small, medium, near the MTU) to the
// echo port, each up to three times, and wants each back unchanged.
func checkUDPEcho(t *testing.T, tn *tunnel, server netip.Addr, label string) {
	t.Helper()
	conn, err := tn.net.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(server, interop.UDPEchoPort))
	if err != nil {
		t.Errorf("%s UDP: %v", label, err)
		return
	}
	defer conn.Close()
	maxPayload := stackMTU - 28
	if server.Is6() {
		maxPayload = stackMTU - 48
	}
	for i, size := range []int{24, 512, maxPayload - 20} {
		msg := make([]byte, size)
		copy(msg, fmt.Sprintf("%s datagram %d %d ", label, i, time.Now().UnixNano()))
		for j := 40; j < size; j++ {
			msg[j] = byte(j)
		}
		ok := false
		for try := 0; try < 3 && !ok; try++ {
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := conn.Write(msg); err != nil {
				t.Errorf("%s UDP write: %v", label, err)
				return
			}
			buf := make([]byte, 2048)
			for {
				n, err := conn.Read(buf)
				if err != nil {
					break // timed out: send again
				}
				if string(buf[:n]) == string(msg) {
					ok = true
					break
				}
			}
		}
		if !ok {
			t.Errorf("%s UDP echo of a %d-byte datagram: no reply after 3 tries", label, size)
		}
	}
}

// ---------------------------------------------------------------- cases

type variant struct {
	mod    func(*client.Config)
	wantKD string // key derivation, default "tls-ekm"
	dataV1 bool   // the client announced no DATA_V2: no peer-id pushed
}

func TestInterop(t *testing.T) {
	interop.Require(t)
	cases := interop.Cases()
	if len(cases) == 0 {
		t.Fatal("no interop cases")
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) { runCase(t, c, variant{}) })
	}
	c := mustCase(t, "udp-gcm-tlscrypt")
	t.Run(c.Name+"+prf", func(t *testing.T) {
		runCase(t, c, variant{mod: func(cfg *client.Config) { cfg.DisableEKM = true }, wantKD: "prf"})
	})
	t.Run(c.Name+"+data-v1", func(t *testing.T) {
		runCase(t, c, variant{mod: func(cfg *client.Config) { cfg.DisableDataV2 = true }, dataV1: true})
	})
}

// sessionUp dials c, checks what was negotiated and builds the tunnel; a
// test cleanup tears both down. The returned linkStats counts the session's
// link bytes.
func sessionUp(ctx context.Context, t *testing.T, c interop.Case, v variant) (*client.Client, *tunnel, *linkStats) {
	t.Helper()
	ls := &linkStats{}
	cl, took, err := dialCase(ctx, t, c, func(cfg *client.Config) {
		if v.mod != nil {
			v.mod(cfg)
		}
		cfg.Dial = ls.wrap(cfg.Dial)
	})
	if err != nil {
		t.Fatalf("%s: client.Dial after %v: %v", c, took.Round(time.Millisecond), err)
	}
	info := cl.Info()
	t.Logf("%s: handshake %v: %s, cipher %s, key derivation %s, IPv4 %v, IPv6 %v, MTU %d, remote %s:%d",
		c, took.Round(time.Millisecond), info.TLSVersion, info.Cipher, info.KeyDerivation, info.IPv4, info.IPv6, info.MTU,
		info.Remote.Host, info.Remote.Port)
	if !strings.EqualFold(info.Cipher, c.Cipher) {
		t.Errorf("%s: cipher %q, want %q", c, info.Cipher, c.Cipher)
	}
	if c.TLSVersion != "" && info.TLSVersion != c.TLSVersion {
		t.Errorf("%s: TLS version %q, want %q", c, info.TLSVersion, c.TLSVersion)
	}
	wantKD := v.wantKD
	if wantKD == "" {
		wantKD = "tls-ekm"
	}
	if info.KeyDerivation != wantKD {
		t.Errorf("%s: key derivation %q, want %q", c, info.KeyDerivation, wantKD)
	}
	if !info.IPv4.IsValid() {
		cl.Close()
		t.Fatalf("%s: no IPv4 address pushed", c)
	}
	addrs := []netip.Addr{info.IPv4.Addr()}
	if info.IPv6.IsValid() {
		addrs = append(addrs, info.IPv6.Addr())
	}
	tn := newTunnel(t, cl, addrs)
	t.Cleanup(func() { tn.close(t, func() { cl.Close() }) })
	return cl, tn, ls
}

func runCase(t *testing.T, c interop.Case, v variant) {
	ctx, cancel := context.WithTimeout(context.Background(), caseTimeout)
	defer cancel()
	off := c.ServerLogSize()
	cl, tn, ls := sessionUp(ctx, t, c, v)
	info := cl.Info()

	runChecks(ctx, t, tn, c.TestServer(false), info.IPv4.Addr(), "IPv4")
	if c.TunnelServerIPv6 != "" {
		if !info.IPv6.IsValid() {
			t.Errorf("%s: the server pushes IPv6 (ifconfig-ipv6) but the session has no IPv6 address", c)
		} else {
			runChecks(ctx, t, tn, c.TestServer(true), info.IPv6.Addr(), "IPv6")
		}
	}
	checkCompressionRatio(ctx, t, c, tn, ls)
	if err := cl.Err(); err != nil {
		t.Errorf("%s: session ended during the checks: %v", c, err)
	}

	// What the server says about this session (the session is still up).
	wantCipher := "Data Channel: cipher '" + c.Cipher + "'"
	wantComp := ""
	if w := map[string]string{"lz4-v2": "lz4v2", "lzo": "lzo", "stub": "stub"}[c.Compression]; w != "" {
		wantComp = "compression: '" + w + "'"
	}
	slog, err := waitServerLog(c, off, 5*time.Second, wantCipher, wantComp)
	if err != nil {
		t.Fatalf("server log: %v", err)
	}
	if !strings.Contains(slog, wantCipher) {
		t.Errorf("%s: server log does not show data cipher %s", c, c.Cipher)
	}
	if wantComp != "" && !strings.Contains(slog, wantComp) {
		t.Errorf("%s: server log does not show %s", c, wantComp)
	}
	if push := lastPushReply(slog); push == "" {
		t.Errorf("%s: no PUSH_REPLY in the server log", c)
	} else if hasPeerID := strings.Contains(push, ",peer-id "); hasPeerID == v.dataV1 {
		t.Errorf("%s: PUSH_REPLY %s peer-id with DisableDataV2=%v: %s", c, map[bool]string{true: "has", false: "lacks"}[hasPeerID], v.dataV1, push)
	}
}

// checkCompressionRatio downloads the compressible /text once more and
// compares the bytes that crossed the link with the body size: a server
// that pushes lz4-v2 or comp-lzo yes must really compress (the real client
// saw about 2.08 MB arrive as 330-360 KB), and without compression the
// link carries at least the body.
func checkCompressionRatio(ctx context.Context, t *testing.T, c interop.Case, tn *tunnel, ls *linkStats) {
	t.Helper()
	hc := tn.httpClient()
	defer hc.CloseIdleConnections()
	url := fmt.Sprintf("http://%s/text?size=%d", netip.AddrPortFrom(c.TestServer(false), interop.HTTPPort), textSize)
	before := ls.rx.Load()
	sum, n, _, err := fetch(ctx, hc, "GET", url, nil, 2*time.Minute, false)
	link := ls.rx.Load() - before
	if err != nil || n != textSize || sum != textSum() {
		t.Errorf("%s: GET /text for the compression check: %d bytes, %v", c, n, err)
		return
	}
	ratio := float64(link) / float64(textSize)
	t.Logf("%s: /text %d bytes arrived as %d link bytes (%.2f)", c, n, link, ratio)
	switch c.Compression {
	case "lz4-v2", "lzo":
		if ratio > 0.5 {
			t.Errorf("%s: compression %s pushed but %d body bytes took %d link bytes: the server did not compress", c, c.Compression, n, link)
		}
	default:
		if ratio < 0.9 {
			t.Errorf("%s: no compression but %d body bytes took only %d link bytes: link counter broken?", c, n, link)
		}
	}
}

// lastPushReply finds the last PUSH_REPLY the server logged sending.
func lastPushReply(log string) string {
	i := strings.LastIndex(log, "'PUSH_REPLY,")
	if i < 0 {
		return ""
	}
	s := log[i+1:]
	if j := strings.IndexByte(s, '\''); j >= 0 {
		s = s[:j]
	}
	return s
}

// TestInteropRenegotiation downloads slowly for about 40 s from the server
// that renegotiates every 15 s: the transfer must survive at least two soft
// resets.
func TestInteropRenegotiation(t *testing.T) {
	interop.Require(t)
	c := mustCase(t, "udp-reneg")
	ctx, cancel := context.WithTimeout(context.Background(), caseTimeout)
	defer cancel()
	off := c.ServerLogSize()
	cl, tn, _ := sessionUp(ctx, t, c, variant{})
	hc := tn.httpClient()
	defer hc.CloseIdleConnections()
	base := "http://" + netip.AddrPortFrom(c.TestServer(false), interop.HTTPPort).String()

	const size, rate = 4_000_000, 100_000 // 40 s
	start := time.Now()
	sum, n, _, err := fetch(ctx, hc, "GET", fmt.Sprintf("%s/blob?size=%d&seed=11&rate=%d", base, size, rate), nil, 2*time.Minute, false)
	took := time.Since(start)
	if err != nil {
		t.Fatalf("slow download: %v after %d bytes, %v (session: %v)", err, n, took, cl.Err())
	}
	if n != size || sum != interop.BlobSHA256(size, 11) {
		t.Errorf("slow download: %d bytes, sha256 %x, want %d bytes, %x", n, sum, size, interop.BlobSHA256(size, 11))
	}
	if took < 35*time.Second {
		t.Errorf("slow download took %v; too short to span two renegotiations", took)
	}
	slog, err := c.ServerLogSince(off)
	if err != nil {
		t.Fatal(err)
	}
	resets := strings.Count(slog, "TLS: soft reset")
	handshakes := strings.Count(slog, "Control Channel: TLS")
	t.Logf("%s: %d bytes in %v, %d soft resets, %d TLS handshakes", c, n, took.Round(time.Millisecond), resets, handshakes)
	if resets < 2 || handshakes < 3 {
		t.Errorf("%s: %d soft resets and %d TLS handshakes in the server log, want at least 2 and 3", c, resets, handshakes)
	}
	// Still carrying traffic on the newest key.
	if _, _, body, err := fetch(ctx, hc, "GET", base+"/hello", nil, 30*time.Second, true); err != nil || string(body) != interop.HelloBody {
		t.Errorf("GET /hello after renegotiation: %q, %v", body, err)
	}
	checkUDPEcho(t, tn, c.TestServer(false), "after renegotiation")
	if err := cl.Err(); err != nil {
		t.Errorf("session ended: %v", err)
	}
}

// ---------------------------------------------------------------- failures

func TestInteropFailures(t *testing.T) {
	interop.Require(t)

	for _, name := range []string{"udp-chacha-userpass", "udp-certpass"} {
		t.Run("wrong-password/"+name, func(t *testing.T) {
			c := mustCase(t, name)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			cl, took, err := dialCase(ctx, t, c, func(cfg *client.Config) { cfg.Password = "not-the-password" })
			if err == nil {
				cl.Close()
				t.Fatalf("%s: dial with a wrong password succeeded", c)
			}
			t.Logf("%s: failed after %v: %v", c, took.Round(time.Millisecond), err)
			if !errors.Is(err, client.ErrAuthFailed) {
				t.Errorf("%s: error %v, want ErrAuthFailed", c, err)
			}
		})
	}

	t.Run("wrong-ca", func(t *testing.T) {
		c := mustCase(t, "udp-gcm-tlscrypt")
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		ca := selfSignedCA(t)
		cl, took, err := dialCase(ctx, t, c, func(cfg *client.Config) { cfg.Options.CA = ca })
		if err == nil {
			cl.Close()
			t.Fatalf("%s: dial with the wrong CA succeeded", c)
		}
		t.Logf("%s: failed after %v: %v", c, took.Round(time.Millisecond), err)
		var unknown x509.UnknownAuthorityError
		var verr *tls.CertificateVerificationError
		switch {
		case errors.Is(err, client.ErrAuthFailed):
			t.Errorf("%s: error %v is ErrAuthFailed, want a certificate verification error", c, err)
		case errors.As(err, &unknown), errors.As(err, &verr):
		case strings.Contains(err.Error(), "certificate") || strings.Contains(err.Error(), "x509"):
			t.Logf("%s: verification error is not wrapped as x509.UnknownAuthorityError / tls.CertificateVerificationError", c)
		default:
			t.Errorf("%s: error %v, want a certificate verification error", c, err)
		}
		if took > 30*time.Second {
			t.Errorf("%s: took %v to reject the server certificate", c, took)
		}
	})

	t.Run("wrong-tls-auth", func(t *testing.T) {
		c := mustCase(t, "udp-cbc-sha1-net30")
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		const hs = 5 * time.Second
		cl, took, err := dialCase(ctx, t, c, func(cfg *client.Config) {
			cfg.Options.TLSAuth = randomStaticKey(t)
			cfg.HandshakeTimeout = hs
		})
		if err == nil {
			cl.Close()
			t.Fatalf("%s: dial with the wrong tls-auth key succeeded", c)
		}
		t.Logf("%s: failed after %v: %v", c, took.Round(time.Millisecond), err)
		if !errors.Is(err, client.ErrHandshakeTimeout) {
			t.Errorf("%s: error %v, want ErrHandshakeTimeout (the server drops packets with a bad HMAC)", c, err)
		}
		if took > hs+10*time.Second {
			t.Errorf("%s: took %v with HandshakeTimeout %v", c, took, hs)
		}
	})
}

func selfSignedCA(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ovpntest wrong CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// randomStaticKey is a fresh 2048-bit key in OpenVPN static key format.
func randomStaticKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 256)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString("-----BEGIN OpenVPN Static key V1-----\n")
	for i := 0; i < len(key); i += 16 {
		b.WriteString(hex.EncodeToString(key[i : i+16]))
		b.WriteByte('\n')
	}
	b.WriteString("-----END OpenVPN Static key V1-----\n")
	return []byte(b.String())
}

// ---------------------------------------------------------------- loopback

// devIO exposes a gvisortun device as a packetIO: the far side of a loopback
// tunnel. Writes go through a queue and their own goroutine, like a link:
// a stack may answer a packet synchronously inside Write, and two pumps
// blocked on each other's stack would deadlock.
type devIO struct {
	dev     tun.Device
	queue   chan []byte
	done    chan struct{}
	stopped chan struct{}
}

func newDevIO(dev tun.Device) *devIO {
	d := &devIO{dev: dev, queue: make(chan []byte, 4096), done: make(chan struct{}), stopped: make(chan struct{})}
	go func() {
		defer close(d.stopped)
		for {
			select {
			case p := <-d.queue:
				d.dev.Write([][]byte{p}, 0) //nolint:errcheck
			case <-d.done:
				return
			}
		}
	}()
	return d
}

func (d *devIO) ReadPacket(p []byte) (int, error) {
	sizes := []int{0}
	n, err := d.dev.Read([][]byte{p}, sizes, 0)
	if err != nil || n == 0 {
		return 0, err
	}
	return sizes[0], nil
}

func (d *devIO) WritePacket(p []byte) error {
	select {
	case <-d.done:
		return net.ErrClosed
	case d.queue <- append([]byte(nil), p...):
	default: // full: dropped, as a link would
	}
	return nil
}

// stop ends the writer; nothing reaches the device afterwards.
func (d *devIO) stop() {
	close(d.done)
	<-d.stopped
}

// TestLoopbackPlumbing runs runChecks through two gVisor stacks wired back to
// back, the far one serving interop.NewTestHandler and ServeUDPEcho: the
// tunnel, pumps, HTTP/UDP checks and teardown, without OpenVPN.
func TestLoopbackPlumbing(t *testing.T) {
	srv4, srv6 := netip.MustParseAddr("10.81.0.1"), netip.MustParseAddr("fd81::1")
	cli4, cli6 := netip.MustParseAddr("10.81.0.2"), netip.MustParseAddr("fd81::1000")
	sdev, _, sst, err := gvisortun.CreateNetTUN([]netip.Addr{srv4, srv6}, stackMTU, false)
	if err != nil {
		t.Fatal(err)
	}
	far := newDevIO(sdev)
	var servers []*http.Server
	var pcs []net.PacketConn
	for _, a := range []netip.Addr{srv4, srv6} {
		proto := ipv4.ProtocolNumber
		if a.Is6() {
			proto = ipv6.ProtocolNumber
		}
		ln, err := gonet.ListenTCP(sst, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(a.AsSlice()), Port: interop.HTTPPort}, proto)
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: interop.NewTestHandler(), ReadHeaderTimeout: 10 * time.Second}
		go srv.Serve(ln) //nolint:errcheck
		servers = append(servers, srv)
		pc, err := gonet.DialUDP(sst, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(a.AsSlice()), Port: interop.UDPEchoPort}, nil, proto)
		if err != nil {
			t.Fatal(err)
		}
		go interop.ServeUDPEcho(pc) //nolint:errcheck
		pcs = append(pcs, pc)
	}
	tn := newTunnel(t, far, []netip.Addr{cli4, cli6})
	defer tn.close(t, func() {
		for _, s := range servers {
			s.Close()
		}
		for _, pc := range pcs {
			pc.Close()
		}
		far.stop()
		sst.Destroy()
		sdev.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	runChecks(ctx, t, tn, srv4, cli4, "IPv4")
	runChecks(ctx, t, tn, srv6, cli6, "IPv6")
}
