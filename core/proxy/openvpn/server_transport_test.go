package openvpn

import (
	"bytes"
	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/wire"
	"github.com/xtls/xray-core/transport/internet/stat"
	"io"
	"net"
	"testing"
	"time"
)

func TestChainedPacketTransportNestedCounters(t *testing.T) {
	mk := func(s string) *buf.Buffer { b := buf.New(); _, _ = b.WriteString(s); return b }
	raw := &nativeDatagramConn{packets: buf.MultiBuffer{mk("one"), mk("second"), mk("pending")}}
	inner, outer := new(appstats.Counter), new(appstats.Counter)
	c := preserveTransportPackets(&stat.CounterConnection{
		Connection: &stat.CounterConnection{Connection: raw, ReadCounter: inner}, ReadCounter: outer,
	})
	var b [128]byte
	for _, want := range []string{"one", "second"} {
		n, err := c.Read(b[:])
		if err != nil || string(b[:n]) != want {
			t.Fatalf("read %q: %q, %v", want, b[:n], err)
		}
	}
	if inner.Value() != 9 || outer.Value() != 9 {
		t.Fatalf("counters %d, %d", inner.Value(), outer.Value())
	}
	if err := c.Close(); err != nil || !raw.closed {
		t.Fatalf("close: %v", err)
	}
	if n, err := c.Read(b[:]); n != 0 || err != io.EOF {
		t.Fatalf("read after close: %d, %v", n, err)
	}
	if inner.Value() != 9 || outer.Value() != 9 {
		t.Fatal("discarded pending packet counted")
	}
}

type nativeDatagramConn struct {
	net.Conn
	packets buf.MultiBuffer
	closed  bool
}

func (c *nativeDatagramConn) Read([]byte) (int, error) { panic("UDP io.Reader must not be used") }
func (c *nativeDatagramConn) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb := c.packets
	c.packets = nil
	return mb, io.EOF
}
func (c *nativeDatagramConn) Close() error {
	c.closed = true
	buf.ReleaseMulti(c.packets)
	c.packets = nil
	return nil
}
func TestNativeServerPacketTransport(t *testing.T) {
	mk := func(s string) *buf.Buffer { b := buf.New(); _, _ = b.WriteString(s); return b }
	u := &nativeDatagramConn{packets: buf.MultiBuffer{mk("one"), mk("two")}}
	p := newServerPacketConn(u, false)
	b := make([]byte, 100)
	for _, want := range []string{"one", "two"} {
		n, e := p.ReadPacket(b)
		if e != nil || string(b[:n]) != want {
			t.Fatalf("datagram %q: %v", want, e)
		}
	}
	p.Close()
	if !u.closed {
		t.Fatal("transport not closed")
	}
	left, right := net.Pipe()
	defer right.Close()
	p = newServerPacketConn(left, true)
	defer p.Close()
	right.SetDeadline(time.Now().Add(time.Second))
	done := make(chan error, 1)
	go func() { done <- p.WritePacket([]byte("framed")) }()
	r := wire.NewFrameReader(right)
	n, e := r.ReadPacket(b)
	if e != nil || !bytes.Equal(b[:n], []byte("framed")) {
		t.Fatalf("TCP framing: %v", e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	go func() { _, e := p.ReadPacket(b); done <- e }()
	p.Close()
	select {
	case e = <-done:
		if e == nil {
			t.Fatal("read succeeded after close")
		}
	case <-time.After(time.Second):
		t.Fatal("close did not interrupt read")
	}
}

func TestNativeServerActiveWriteKeepsReadAlive(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	c := &serverIdleConn{Conn: left, idle: 80 * time.Millisecond}
	readDone := make(chan error, 1)
	go func() { var b [1]byte; _, e := c.Read(b[:]); readDone <- e }()
	go func() { _, _ = io.Copy(io.Discard, right) }()
	for i := 0; i < 6; i++ {
		time.Sleep(30 * time.Millisecond)
		if _, e := c.Write([]byte("x")); e != nil {
			t.Fatal(e)
		}
		select {
		case e := <-readDone:
			t.Fatalf("active flow read expired: %v", e)
		default:
		}
	}
	select {
	case e := <-readDone:
		if e == nil {
			t.Fatal("idle read unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("idle flow deadline missing")
	}
}
