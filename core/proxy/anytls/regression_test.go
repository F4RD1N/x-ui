package anytls

import (
	"context"
	gotls "crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/pipe"
)

// fakeServer speaks the server side of AnyTLS on conn. After the client's
// settings it can push a padding scheme update or an alert.
func fakeServer(conn net.Conn, schemeUpdate, alert string, echo bool) {
	defer conn.Close()
	var a [34]byte
	if _, e := io.ReadFull(conn, a[:]); e != nil {
		return
	}
	if _, e := io.CopyN(io.Discard, conn, int64(binary.BigEndian.Uint16(a[32:]))); e != nil {
		return
	}
	seen := map[uint32]bool{}
	for {
		var h [7]byte
		if _, e := io.ReadFull(conn, h[:]); e != nil {
			return
		}
		id := binary.BigEndian.Uint32(h[1:5])
		p := make([]byte, binary.BigEndian.Uint16(h[5:]))
		if _, e := io.ReadFull(conn, p); e != nil {
			return
		}
		switch h[0] {
		case cmdSettings:
			conn.Write(frame(cmdServerSettings, 0, []byte("v=2")))
			if schemeUpdate != "" {
				conn.Write(frame(cmdPadding, 0, []byte(schemeUpdate)))
			}
			if alert != "" {
				conn.Write(frame(cmdAlert, 0, []byte(alert)))
			}
		case cmdSYN:
			conn.Write(frame(cmdSYNACK, id, nil))
		case cmdHeartRequest:
			conn.Write(frame(cmdHeartResponse, id, nil))
		case cmdPSH:
			if !seen[id] {
				seen[id] = true // the destination address
				continue
			}
			if echo {
				conn.Write(frame(cmdPSH, id, p))
			}
		}
	}
}

func TestPaddingParserIsLenient(t *testing.T) {
	for _, tc := range []struct {
		scheme string
		packet int
		want   []padRange
		stop   int
	}{
		{"stop=8\n0=30-30\n1=400-100", 1, []padRange{{low: 100, high: 400}}, 8},
		{"stop=8\n1=100-400,", 1, []padRange{{low: 100, high: 400}}, 8},
		{"stop=8\nnote=custom\n1=100-400", 1, []padRange{{low: 100, high: 400}}, 8},
		{"stop=8\n2=400-500, c, 500-1000", 2, []padRange{{low: 400, high: 500}, {check: true}, {low: 500, high: 1000}}, 8},
		{"stop=8\n2=x, 1-2-3, 7-9", 2, []padRange{{low: 7, high: 9}}, 8},
		{"stop=2000\n1=0-999999", 1, []padRange{{low: 0, high: 65535}}, 1024},
		{" stop = 3 \n 0 = 5-6 ", 0, []padRange{{low: 5, high: 6}}, 3},
	} {
		p, e := parsePadding(tc.scheme)
		if e != nil {
			t.Fatalf("%q rejected: %v", tc.scheme, e)
		}
		if p.stop != tc.stop || p.raw != tc.scheme {
			t.Fatalf("%q: stop %d raw %q", tc.scheme, p.stop, p.raw)
		}
		got := p.rules[tc.packet]
		if len(got) != len(tc.want) {
			t.Fatalf("%q: rules %v, want %v", tc.scheme, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("%q: rules %v, want %v", tc.scheme, got, tc.want)
			}
		}
	}
	many := "stop=8\n0=" + strings.Repeat("1-1,", 200)
	if p, e := parsePadding(many); e != nil || len(p.rules[0]) != maxPaddingFragments {
		t.Fatalf("fragment cap: %v", e)
	}
	// Only a missing or invalid stop (as upstream) and an oversized scheme are errors.
	for _, s := range []string{"", "0=1-2", "stop=x\n0=1-2", "stop=-1", strings.Repeat("a", 65536)} {
		if _, e := parsePadding(s); e == nil {
			t.Fatalf("accepted %q", s)
		}
	}
}

func TestPaddingUpdateNeverClosesSession(t *testing.T) {
	for _, tc := range []struct {
		scheme  string
		applied bool
	}{
		{"stop=8\n0=30-30\n1=100-400", true},
		{"stop=8\n0=30-30\n1=400-100\n2=400-500,c,500-1000", true},
		{"stop=8\n0=30-30\n1=100-400,\n2=400-500", true},
		{"stop=8\n0=30-30\n1=100-400\nnote=custom\n2=400-500", true},
		{"stop=8\n0=30-30\n1=100-400\n2=400-500, c, 500-1000", true},
		{"stop=2000\n0=30-30", true},
		{"0=30-30\n1=100-400", false}, // no stop: ignored, old scheme kept
	} {
		def, _ := parsePadding(defaultPadding)
		c := &Client{config: &Config{Password: "p"}, padding: def, done: make(chan struct{})}
		a, b := net.Pipe()
		go fakeServer(b, tc.scheme, "", false)
		s, e := newSession(a, c, def, nil)
		if e != nil {
			t.Fatal(e)
		}
		if _, e := s.open(context.Background(), []byte{1, 1, 2, 3, 4, 0, 80}); e != nil {
			t.Fatalf("%q: stream open failed: %v", tc.scheme, e)
		}
		select {
		case <-s.done:
			t.Fatalf("%q: session closed: %v", tc.scheme, s.failure())
		case <-time.After(300 * time.Millisecond):
		}
		c.mu.Lock()
		applied := c.padding.raw == tc.scheme
		kept := c.padding == def
		c.mu.Unlock()
		if applied != tc.applied || (!tc.applied && !kept) {
			t.Fatalf("%q: applied=%v", tc.scheme, applied)
		}
		s.fail(net.ErrClosed)
	}
}

type captureLog struct {
	mu   sync.Mutex
	msgs []string
}

func (l *captureLog) Handle(m log.Message) {
	l.mu.Lock()
	l.msgs = append(l.msgs, m.String())
	l.mu.Unlock()
}
func (l *captureLog) has(s string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, m := range l.msgs {
		if strings.Contains(m, s) {
			return true
		}
	}
	return false
}

func TestServerAlertIsLoggedAndReported(t *testing.T) {
	logs := &captureLog{}
	log.RegisterHandler(logs)
	def, _ := parsePadding(defaultPadding)
	c := &Client{config: &Config{Password: "p"}, padding: def, done: make(chan struct{})}
	a, b := net.Pipe()
	go fakeServer(b, "", "client version too old", false)
	s, e := newSession(a, c, def, nil)
	if e != nil {
		t.Fatal(e)
	}
	_, _ = s.open(context.Background(), []byte{1, 1, 2, 3, 4, 0, 80})
	select {
	case <-s.done:
	case <-time.After(2 * time.Second):
		t.Fatal("alert did not close the session")
	}
	if !logs.has("AnyTLS server alert: client version too old") {
		t.Fatalf("alert not logged: %v", logs.msgs)
	}
	if e := withSessionFailure(io.ErrClosedPipe, s); !strings.Contains(e.Error(), "client version too old") || !errors.Is(e, io.ErrClosedPipe) {
		t.Fatalf("request error lacks the alert: %v", e)
	}
	logs.mu.Lock()
	logs.msgs = nil
	logs.mu.Unlock()
	// An update without stop is rejected: logged, session kept.
	a2, b2 := net.Pipe()
	go fakeServer(b2, "0=1-2", "", false)
	s2, _ := newSession(a2, c, def, nil)
	_, _ = s2.open(context.Background(), []byte{1, 1, 2, 3, 4, 0, 80})
	deadline := time.Now().Add(2 * time.Second)
	for !logs.has("ignoring padding scheme update") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !logs.has("ignoring padding scheme update") {
		t.Fatal("rejected padding update not logged")
	}
	s2.fail(net.ErrClosed)
}

// MinIdleSession keeps the newest idle sessions on every tick.
func TestReapKeepsNewestIdleSessions(t *testing.T) {
	def, _ := parsePadding(defaultPadding)
	c := &Client{config: &Config{Password: "p", IdleSessionCheckInterval: 1, IdleSessionTimeout: 1, MinIdleSession: 1}, padding: def, done: make(chan struct{})}
	idleAt := time.Now()
	for i := 1; i <= 3; i++ {
		a, b := net.Pipe()
		go io.Copy(io.Discard, b)
		c.sessions = append(c.sessions, &muxSession{conn: a, owner: c, sequence: uint64(i), idleAt: idleAt, streams: map[uint32]*stream{}, done: make(chan struct{}), heartbeat: make(chan struct{}, 1)})
	}
	defer c.Close()
	c.reapOnce(idleAt.Add(500 * time.Millisecond)) // nothing expired
	c.mu.Lock()
	order := [3]uint64{c.sessions[0].sequence, c.sessions[1].sequence, c.sessions[2].sequence}
	c.mu.Unlock()
	if order != [3]uint64{1, 2, 3} {
		t.Fatalf("pool order after a tick %v, want ascending", order)
	}
	c.reapOnce(idleAt.Add(3 * time.Second))
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.sessions) != 1 || c.sessions[0].sequence != 3 {
		var kept []uint64
		for _, s := range c.sessions {
			kept = append(kept, s.sequence)
		}
		t.Fatalf("kept %v, want the newest [3]", kept)
	}
}

// ctxBoundDialer closes its connection when the Dial ctx ends, as Handler.Dial
// does on the proxySettings path (go handler.Dispatch(ctx, ...)).
type ctxBoundDialer struct {
	addr  string
	dials *atomic.Int32
}

func (ctxBoundDialer) DestIpAddress() xnet.IP { return nil }
func (ctxBoundDialer) Address() xnet.Address  { return xnet.LocalHostIP }
func (d ctxBoundDialer) Dial(ctx context.Context, _ xnet.Destination) (stat.Connection, error) {
	d.dials.Add(1)
	c, e := net.Dial("tcp", d.addr)
	if e != nil {
		return nil, e
	}
	context.AfterFunc(ctx, func() { c.Close() })
	return c, nil
}

type tlsFake struct {
	l       net.Listener
	accepts atomic.Int32
	port    uint32
}

func newTLSFake(t *testing.T) *tlsFake {
	crt, _ := cert.MustGenerate(nil, cert.DNSNames("x"))
	kp, e := gotls.X509KeyPair(crt.ToPEM())
	if e != nil {
		t.Fatal(e)
	}
	l, e := gotls.Listen("tcp", "127.0.0.1:0", &gotls.Config{Certificates: []gotls.Certificate{kp}})
	if e != nil {
		t.Fatal(e)
	}
	f := &tlsFake{l: l, port: uint32(l.Addr().(*net.TCPAddr).Port)}
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			f.accepts.Add(1)
			go fakeServer(c, "", "", true)
		}
	}()
	t.Cleanup(func() { l.Close() })
	return f
}

func (f *tlsFake) client() *Client {
	def, _ := parsePadding(defaultPadding)
	return &Client{config: &Config{Address: "127.0.0.1", Port: f.port, Password: "p", Tls: &xtls.Config{AllowInsecure: true, ServerName: "x"}}, policy: policy.DefaultManager{}, padding: def, done: make(chan struct{})}
}

func echoRequest(t *testing.T, c *Client, ctx context.Context, d ctxBoundDialer) error {
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: xnet.TCPDestination(xnet.ParseAddress("1.2.3.4"), 80)}})
	ur, uw := pipe.New()
	dr, dw := pipe.New()
	done := make(chan error, 1)
	go func() { done <- c.Process(ctx, &transport.Link{Reader: ur, Writer: dw}, d) }()
	b := buf.New()
	b.WriteString("hello")
	uw.WriteMultiBuffer(buf.MultiBuffer{b})
	mb, e := dr.ReadMultiBuffer()
	if e != nil {
		return e
	}
	buf.ReleaseMulti(mb)
	uw.Close()
	// The relay ends through its inactivity timer, which reports a cancel.
	if e = <-done; errors.Is(e, context.Canceled) {
		return nil
	}
	return e
}

func TestPooledSessionOutlivesFirstRequestCtx(t *testing.T) {
	f := newTLSFake(t)
	c := f.client()
	defer c.Close()
	d := ctxBoundDialer{addr: f.l.Addr().String(), dials: new(atomic.Int32)}
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		if e := echoRequest(t, c, ctx, d); e != nil {
			t.Fatalf("request %d: %v", i, e)
		}
		time.Sleep(50 * time.Millisecond)
		cancel() // the inbound finishes after its outbound returned
		time.Sleep(100 * time.Millisecond)
	}
	if n := f.accepts.Load(); n != 1 {
		t.Fatalf("%d TLS sessions for 2 sequential requests, want 1 reused", n)
	}
}

func reapGoroutines() int {
	b := make([]byte, 1<<20)
	n := runtime.Stack(b, true)
	return strings.Count(string(b[:n]), "anytls.(*Client).reap(")
}

func countReapers(c *Client) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reaping
}

func TestReaperStartsWithFirstSessionAndStopsOnClose(t *testing.T) {
	f := newTLSFake(t)
	c := f.client()
	if countReapers(c) {
		t.Fatal("reaper running before any session")
	}
	d := ctxBoundDialer{addr: f.l.Addr().String(), dials: new(atomic.Int32)}
	if e := echoRequest(t, c, context.Background(), d); e != nil {
		t.Fatal(e)
	}
	if !countReapers(c) {
		t.Fatal("reaper not started by the first session")
	}
	before := reapGoroutines()
	c.Close()
	deadline := time.Now().Add(2 * time.Second)
	for reapGoroutines() >= before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if reapGoroutines() >= before {
		t.Fatal("reaper did not exit on Close")
	}
}

type errDialer struct{ dials *atomic.Int32 }

func (errDialer) DestIpAddress() xnet.IP { return nil }
func (errDialer) Address() xnet.Address  { return xnet.LocalHostIP }
func (d errDialer) Dial(context.Context, xnet.Destination) (stat.Connection, error) {
	d.dials.Add(1)
	return nil, errors.New("dial refused")
}

// A panic in one request fails at most that request's session; the client and
// its other pooled sessions keep working.
func TestPanicConfinedToItsSession(t *testing.T) {
	f := newTLSFake(t)
	c := f.client()
	defer c.Close()
	d := ctxBoundDialer{addr: f.l.Addr().String(), dials: new(atomic.Int32)}
	if e := echoRequest(t, c, context.Background(), d); e != nil {
		t.Fatal(e)
	}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: xnet.TCPDestination(xnet.LocalHostIP, 80)}})
	// The pooled session is busy in another request, so this one dials and panics.
	c.mu.Lock()
	pooled := c.sessions[0]
	c.mu.Unlock()
	pooled.mu.Lock()
	pooled.busy = true
	pooled.mu.Unlock()
	if e := c.Process(ctx, &transport.Link{}, panicDialer{}); e == nil || e.Error() != "native outbound internal failure" {
		t.Fatalf("panic not contained: %v", e)
	}
	pooled.mu.Lock()
	pooled.busy = false
	closed := pooled.closed
	pooled.mu.Unlock()
	if c.closed || closed {
		t.Fatalf("panic closed the client (%v) or another request's session (%v)", c.closed, closed)
	}
	if e := echoRequest(t, c, context.Background(), d); e != nil {
		t.Fatalf("pooled session unusable after a panic elsewhere: %v", e)
	}
	if f.accepts.Load() != 1 {
		t.Fatalf("pooled session not reused after the panic: %d sessions", f.accepts.Load())
	}
}
