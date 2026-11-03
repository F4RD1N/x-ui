package datagram

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/orbit/internal/protocol"
)

type fakeChannel struct{ sent, received chan protocol.UDPEnvelope }

func (f *fakeChannel) SendUDP(ctx context.Context, u protocol.UDPEnvelope) error {
	select {
	case f.sent <- u:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (f *fakeChannel) ReceiveUDP(ctx context.Context) (protocol.UDPEnvelope, error) {
	select {
	case u := <-f.received:
		return u, nil
	case <-ctx.Done():
		return protocol.UDPEnvelope{}, ctx.Err()
	}
}
func newTestHub(t *testing.T, limit int) (*Hub, *fakeChannel) {
	t.Helper()
	f := &fakeChannel{make(chan protocol.UDPEnvelope, 256), make(chan protocol.UDPEnvelope, 256)}
	h := New(context.Background(), f, limit)
	t.Cleanup(func() { h.Close() })
	return h, f
}

func TestDispatchByBothEndpoints(t *testing.T) {
	h, f := newTestHub(t, 4)
	source := netip.MustParseAddrPort("26.26.26.2:12345")
	a, _ := h.Open(source, protocol.UDPKindData)
	defer a.Close()
	b, _ := h.Open(source, protocol.UDPKindData)
	defer b.Close()
	one, two := netip.MustParseAddrPort("192.0.2.1:80"), netip.MustParseAddrPort("192.0.2.2:80")
	if err := a.Send(context.Background(), one, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := b.Send(context.Background(), two, []byte("two")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		u := <-f.sent
		u.Source, u.Destination = u.Destination, u.Source
		f.received <- u
	}
	for _, tc := range []struct {
		a    *Association
		body string
	}{{a, "one"}, {b, "two"}} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		u, err := tc.a.Receive(ctx)
		cancel()
		if err != nil || string(u.Data) != tc.body {
			t.Fatal(u, err)
		}
	}
	if err := b.Send(context.Background(), one, nil); err == nil {
		t.Fatal("ambiguous tuple accepted")
	}
}

func TestLimitsCloseCancellationAndValidation(t *testing.T) {
	h, _ := newTestHub(t, 1)
	a, err := h.Open(netip.AddrPort{}, protocol.UDPKindDNS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.Open(netip.AddrPort{}, protocol.UDPKindData); err == nil {
		t.Fatal("limit ignored")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = a.Receive(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err = a.Send(context.Background(), netip.MustParseAddrPort("[::1]:53"), nil); err == nil {
		t.Fatal("IPv6 UDP accepted")
	}
	if err = a.Send(context.Background(), netip.MustParseAddrPort("1.1.1.1:53"), make([]byte, 1471)); err == nil {
		t.Fatal("oversize accepted")
	}
	a.Close()
	a.Close()
	if _, err = a.Receive(context.Background()); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	if err = a.Send(context.Background(), netip.MustParseAddrPort("1.1.1.1:53"), nil); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	b, err := h.Open(netip.AddrPort{}, protocol.UDPKindData)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if a.Source() == b.Source() {
		t.Fatal("source port immediately reused")
	}
}

func TestUnsolicitedAndOverloadDrops(t *testing.T) {
	h, f := newTestHub(t, 1)
	a, _ := h.Open(netip.AddrPort{}, protocol.UDPKindData)
	defer a.Close()
	remote := netip.MustParseAddrPort("192.0.2.1:53")
	f.received <- protocol.UDPEnvelope{Kind: protocol.UDPKindData, Source: remote, Destination: a.Source()}
	deadline := time.Now().Add(time.Second)
	for h.Drops() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if h.Drops() != 1 {
		t.Fatal("unsolicited packet not dropped")
	}
	if err := a.Send(context.Background(), remote, nil); err != nil {
		t.Fatal(err)
	}
	<-f.sent
	for i := 0; i < 64; i++ {
		f.received <- protocol.UDPEnvelope{Kind: protocol.UDPKindData, Source: remote, Destination: a.Source()}
	}
	deadline = time.Now().Add(time.Second)
	for h.Drops() < 33 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if h.Drops() != 33 {
		t.Fatal("bounded receive queue not enforced", h.Drops())
	}
}
