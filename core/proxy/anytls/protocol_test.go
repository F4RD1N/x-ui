package anytls

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func TestAuthModes(t *testing.T) {
	password := "00112233-4455-6677-8899-aabbccddeeff"
	for _, tc := range []struct {
		custom bool
		want   string
	}{{false, "e34f7b59834d35a6dcb646f99b7d856df3ffbc955cece7c90714d13705703680"}, {true, "e34f7b59834d35a600112233445566778899aabbccddeeff0714d13705703680"}} {
		v := Auth(password, tc.custom)
		if hex.EncodeToString(v[:]) != tc.want {
			t.Fatalf("custom=%v wrong authentication vector", tc.custom)
		}
	}
	if Auth("ordinary-password", false) != Auth("ordinary-password", true) {
		t.Fatal("non-UUID password was changed")
	}
}
func TestPaddingValidation(t *testing.T) {
	p, e := parsePadding(defaultPadding)
	if e != nil || p.stop != 8 {
		t.Fatalf("default padding: %v", e)
	}
	// Only a missing or invalid stop makes a scheme invalid (lenient like
	// the reference client); see TestPaddingParserIsLenient.
	for _, s := range []string{"stop=-1", "stop=x", "0=5-2", "1=0-999999", "0=abc"} {
		if _, e = parsePadding(s); e == nil {
			t.Fatalf("accepted invalid padding %q", s)
		}
	}
}

type panicDialer struct{}

func (panicDialer) DestIpAddress() xnet.IP { return nil }
func (panicDialer) Address() xnet.Address  { return xnet.LocalHostIP }

func (panicDialer) Dial(context.Context, xnet.Destination) (stat.Connection, error) {
	panic("test credential must never escape")
}
func TestPanicContainedToAnyTLS(t *testing.T) {
	p, _ := parsePadding(defaultPadding)
	c := &Client{config: &Config{Address: "127.0.0.1", Port: 1, Password: "test"}, padding: p, done: make(chan struct{})}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: xnet.TCPDestination(xnet.LocalHostIP, 80)}})
	e := c.Process(ctx, &transport.Link{}, panicDialer{})
	if e == nil || e.Error() != "native outbound internal failure" {
		t.Fatalf("panic not contained: %v", e)
	}
	if c.closed {
		t.Fatal("one failed request closed the whole client")
	}
	dials := new(atomic.Int32)
	if e = c.Process(ctx, &transport.Link{}, errDialer{dials}); e == nil || errors.Is(e, net.ErrClosed) || dials.Load() != 1 {
		t.Fatalf("next request did not reach the dialer: %v", e)
	}
	if errors.Is(e, context.Canceled) {
		t.Fatal("panic misreported")
	}
}
func FuzzPadding(f *testing.F) {
	f.Add(defaultPadding)
	f.Add("stop=8\n0=0-1")
	f.Fuzz(func(t *testing.T, s string) { _, _ = parsePadding(s) })
}

func TestConstructorPanicIsContained(t *testing.T) {
	if _, e := common.CreateObject(context.Background(), (*Config)(nil)); e == nil || e.Error() != "native outbound internal failure" {
		t.Fatalf("constructor panic escaped: %v", e)
	}
}
