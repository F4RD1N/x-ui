package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

type limitPacket struct {
	b []byte
	a net.Addr
}
type limitPacketConn struct{ queue []limitPacket }

func (p *limitPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if len(p.queue) == 0 {
		return 0, nil, io.EOF
	}
	q := p.queue[0]
	p.queue = p.queue[1:]
	return copy(b, q.b), q.a, nil
}
func (*limitPacketConn) WriteTo([]byte, net.Addr) (int, error) { return 0, io.ErrClosedPipe }
func (*limitPacketConn) Close() error                          { return nil }
func (*limitPacketConn) LocalAddr() net.Addr                   { return &net.UDPAddr{} }
func (*limitPacketConn) SetDeadline(time.Time) error           { return nil }
func (*limitPacketConn) SetReadDeadline(time.Time) error       { return nil }
func (*limitPacketConn) SetWriteDeadline(time.Time) error      { return nil }

func TestQUICInitialAdmissionLimitsAndExpiry(t *testing.T) {
	wire := unhex(t, fixtures(t).QUIC[0].FormattedHex)
	a := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1234}
	b := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 1234}
	raw := &limitPacketConn{}
	p := &initialPacketConn{PacketConn: raw, verify: func(QUICMetadata, net.Addr) error { return nil }, entries: make(map[string]*initialAdmission), options: QUICServerOptions{MaxSessions: 2, MaxHandshakes: 1, HandshakeTimeout: time.Second}}
	buf := make([]byte, 65535)
	raw.queue = []limitPacket{{wire, a}, {wire, b}, {[]byte{0x40}, b}}
	if _, _, e := p.ReadFrom(buf); e != nil {
		t.Fatal(e)
	}
	if n, _, e := p.ReadFrom(buf); e != nil || n != 1 {
		t.Fatal("pending cap did not drop second initial", n, e)
	}
	if len(p.entries) != 1 || p.entries[b.String()] != nil {
		t.Fatal("pending admission cap exceeded")
	}
	p.entries[a.String()].expires = time.Now().Add(-time.Second)
	raw.queue = []limitPacket{{wire, b}}
	if _, _, e := p.ReadFrom(buf); e != nil {
		t.Fatal(e)
	}
	if len(p.entries) != 1 || p.entries[b.String()] == nil {
		t.Fatal("expired pending admission retained")
	}
	p.entries[b.String()].active = true
	p.entries[b.String()].complete = true
	p.options.MaxSessions = 1
	raw.queue = []limitPacket{{wire, a}, {[]byte{0x40}, a}}
	if n, _, e := p.ReadFrom(buf); e != nil || n != 1 {
		t.Fatal("session cap did not drop new initial", n, e)
	}
	p.options.MaxSessions = 2
	raw.queue = []limitPacket{{wire, a}}
	if _, _, e := p.ReadFrom(buf); e != nil {
		t.Fatal(e)
	}
	if len(p.entries) != 2 {
		t.Fatal("completed handshake still occupied pending budget")
	}
}

func TestQUICServerLimitsValidate(t *testing.T) {
	st, _ := testTLS(t)
	for _, o := range []QUICServerOptions{{MaxFlows: -1}, {MaxFlows: 65537}, {MaxSessions: -1}, {MaxHandshakes: 4097}, {HandshakeTimeout: -time.Second}, {HandshakeTimeout: time.Nanosecond}, {HandshakeTimeout: 91 * time.Second}} {
		if _, e := ListenQUICWithOptions(nil, st, testVerify, o); e == nil {
			t.Fatal("invalid options accepted", o)
		}
	}
	if _, e := ListenQUICWithOptions(nil, st, testVerify, QUICServerOptions{}); e == nil {
		t.Fatal("nil socket accepted")
	}
}

func TestQUICFlowLimitAndRelease(t *testing.T) {
	st, ct := testTLS(t)
	raw, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	l, e := ListenQUICWithOptions(raw, st, testVerify, QUICServerOptions{MaxFlows: 1, MaxHandshakes: 1, HandshakeTimeout: time.Second})
	if e != nil {
		raw.Close()
		t.Fatal(e)
	}
	defer l.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, e := DialQUIC(ctx, l.Addr().String(), ct, testInitial())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	s, e := l.Accept(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	type result struct {
		st *QUICStream
		e  error
	}
	open := func() chan result {
		ch := make(chan result, 1)
		go func() { f, e := c.Open(ctx, "owned.test", 443); ch <- result{f, e} }()
		return ch
	}
	ch := open()
	one, e := s.Accept(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = one.Accept(); e != nil {
		t.Fatal(e)
	}
	first := <-ch
	if first.e != nil {
		t.Fatal(first.e)
	}
	short, stop := context.WithTimeout(ctx, 60*time.Millisecond)
	_, e = c.Open(short, "owned.test", 443)
	stop()
	if !errors.Is(e, context.DeadlineExceeded) {
		t.Fatalf("full flow limit: %v", e)
	}
	one.Close()
	first.st.Close()
	s.logical.mu.Lock()
	n := len(s.logical.ids)
	s.logical.mu.Unlock()
	if n != 0 {
		t.Fatal("closed flow retained slot", n)
	}
	ch = open()
	two, e := s.Accept(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = two.Accept(); e != nil {
		t.Fatal(e)
	}
	second := <-ch
	if second.e != nil {
		t.Fatal(second.e)
	}
	two.Reset()
	second.st.Close()
	s.logical.mu.Lock()
	n = len(s.logical.ids)
	s.logical.mu.Unlock()
	if n != 0 {
		t.Fatal("reset flow retained slot", n)
	}
}

func TestQUICSocketHandshakeTimeout(t *testing.T) {
	st, ct := testTLS(t)
	raw, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	l, e := ListenQUICWithOptions(raw, st, testVerify, QUICServerOptions{MaxHandshakes: 2, HandshakeTimeout: 60 * time.Millisecond})
	if e != nil {
		raw.Close()
		t.Fatal(e)
	}
	defer l.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	c, e := DialQUIC(ctx, l.Addr().String(), ct, testInitial())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	s, e := l.Accept(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = c.waitReady(ctx); e != nil {
		t.Fatal(e)
	}
	f, e := c.OpenStream(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if _, e = f.Write([]byte{8}); e != nil {
		t.Fatal(e)
	}
	_ = f.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, e = f.Read(b[:]); e == nil {
		t.Fatal("incomplete handshake not reset")
	}
}
