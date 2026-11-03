package tunneldns

import (
	"context"
	"encoding/binary"
	"errors"
	"github.com/xtls/xray-core/proxy/orbit/internal/datagram"
	"github.com/xtls/xray-core/proxy/orbit/internal/protocol"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

type fakeChannel struct {
	packets chan protocol.UDPEnvelope
	respond func(dnsmessage.Message) dnsmessage.Message
}

func (f *fakeChannel) SendUDP(ctx context.Context, u protocol.UDPEnvelope) error {
	var q dnsmessage.Message
	if e := q.Unpack(u.Data); e != nil {
		return e
	}
	r := f.respond(q)
	b, e := r.Pack()
	if e != nil {
		return e
	}
	select {
	case f.packets <- protocol.UDPEnvelope{Kind: u.Kind, Source: u.Destination, Destination: u.Source, Data: b}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (f *fakeChannel) ReceiveUDP(ctx context.Context) (protocol.UDPEnvelope, error) {
	select {
	case u := <-f.packets:
		return u, nil
	case <-ctx.Done():
		return protocol.UDPEnvelope{}, ctx.Err()
	}
}
func answer(q dnsmessage.Message) dnsmessage.Message {
	q.Response = true
	q.RecursionAvailable = true
	q.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 10}}}}
	return q
}
func newResolver(t *testing.T, fn func(dnsmessage.Message) dnsmessage.Message) *Resolver {
	t.Helper()
	f := &fakeChannel{packets: make(chan protocol.UDPEnvelope, 4), respond: fn}
	h := datagram.New(context.Background(), f, 8)
	t.Cleanup(func() { h.Close() })
	return &Resolver{UDP: h, Server: netip.MustParseAddrPort("192.0.2.53:53"), Timeout: time.Second}
}
func TestLookupIPv4AndAliases(t *testing.T) {
	r := newResolver(t, answer)
	for _, h := range []string{"test.example", "test.example."} {
		ips, e := r.LookupIP(context.Background(), h)
		if e != nil || len(ips) != 1 || ips[0].String() != "192.0.2.10" {
			t.Fatal(ips, e)
		}
	}
	ips, e := r.LookupIP(context.Background(), "1.2.3.4")
	if e != nil || ips[0].String() != "1.2.3.4" {
		t.Fatal(ips, e)
	}
	r = newResolver(t, func(q dnsmessage.Message) dnsmessage.Message {
		v := answer(q)
		alias, _ := dnsmessage.NewName("actual.example.")
		v.Answers[0].Header.Name = alias
		v.Answers = append(v.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET}, Body: &dnsmessage.CNAMEResource{CNAME: alias}})
		return v
	})
	if _, e = r.LookupIP(context.Background(), "alias.example"); e != nil {
		t.Fatal(e)
	}
}
func TestErrorsAndCancellation(t *testing.T) {
	for _, change := range []func(dnsmessage.Message) dnsmessage.Message{func(q dnsmessage.Message) dnsmessage.Message {
		q.Response = true
		q.RCode = dnsmessage.RCodeNameError
		return q
	}, func(q dnsmessage.Message) dnsmessage.Message { q.Response = true; return q }, func(q dnsmessage.Message) dnsmessage.Message {
		v := answer(q)
		v.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET}, Body: &dnsmessage.CNAMEResource{CNAME: q.Questions[0].Name}}}
		return v
	}} {
		r := newResolver(t, change)
		if _, e := r.LookupIP(context.Background(), "test.example"); e == nil {
			t.Fatal("invalid DNS accepted")
		}
	}
	r := newResolver(t, answer)
	for _, h := range []string{"", "bad/name", "::1", "with space"} {
		if _, e := r.LookupIP(context.Background(), h); e == nil {
			t.Fatalf("accepted %q", h)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := r.LookupIP(ctx, "test.example"); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	r = newResolver(t, func(q dnsmessage.Message) dnsmessage.Message { v := answer(q); v.ID++; return v })
	r.Timeout = 20 * time.Millisecond
	if _, e := r.LookupIP(context.Background(), "test.example"); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal(e)
	}
}
func TestTCPFallback(t *testing.T) {
	r := newResolver(t, func(q dnsmessage.Message) dnsmessage.Message { v := answer(q); v.Truncated = true; return v })
	r.OpenTCP = func(ctx context.Context, host string, port uint16) (net.Conn, error) {
		if host != "192.0.2.53" || port != 53 {
			t.Error(host, port)
		}
		a, b := net.Pipe()
		go func() {
			defer b.Close()
			var h [2]byte
			io.ReadFull(b, h[:])
			wire := make([]byte, binary.BigEndian.Uint16(h[:]))
			io.ReadFull(b, wire)
			var q dnsmessage.Message
			q.Unpack(wire)
			v := answer(q)
			encoded, _ := v.Pack()
			b.Write(binary.BigEndian.AppendUint16(nil, uint16(len(encoded))))
			b.Write(encoded)
		}()
		return a, nil
	}
	if ips, e := r.LookupIP(context.Background(), "large.example"); e != nil || len(ips) != 1 {
		t.Fatal(ips, e)
	}
	r.OpenTCP = nil
	if _, e := r.LookupIP(context.Background(), "large.example"); e == nil {
		t.Fatal("truncated UDP accepted")
	}
}
