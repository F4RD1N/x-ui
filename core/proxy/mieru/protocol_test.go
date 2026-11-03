package mieru

import (
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func TestUUIDTrailerVector(t *testing.T) {
	e := make([]byte, 64)
	for i := range e {
		e[i] = byte(i)
	}
	v, err := UUIDTrailer("00112233-4455-6677-8899-aabbccddeeff", e)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(v[:]) != "00102030405060708090a0b0c0d0e0f0" {
		t.Fatal("wrong metadata trailer")
	}
}
func TestKeyWindowAndIdentity(t *testing.T) {
	tm := time.Unix(120000, 0)
	a := Key("u", "p", tm)
	if !bytes.Equal(a, Key("u", "p", tm.Add(10*time.Second))) {
		t.Fatal("key changed within one time window")
	}
	if bytes.Equal(a, Key("u2", "p", tm)) || bytes.Equal(a, Key("u", "p2", tm)) {
		t.Fatal("credentials ignored")
	}
}
func TestStatefulFramesAcrossNonceTransitions(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_ = a.SetDeadline(time.Now().Add(5 * time.Second))
	_ = b.SetDeadline(time.Now().Add(5 * time.Second))
	w, _ := newWire(a, "user", "password", false, false)
	r, _ := newWire(b, "user", "password", false, false)
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 300; i++ {
			if e := w.write(segment{kind: dataClient, session: 1, seq: uint32(i), payload: []byte{byte(i), 42}}); e != nil {
				done <- e
				return
			}
		}
		done <- nil
	}()
	for i := 0; i < 300; i++ {
		s, e := r.read()
		if e != nil {
			t.Fatalf("frame %d: %v", i, e)
		}
		if s.seq != uint32(i) || !bytes.Equal(s.payload, []byte{byte(i), 42}) {
			t.Fatalf("frame %d corrupted", i)
		}
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}

type panicDialer struct{}

func (panicDialer) DestIpAddress() xnet.IP                                { return nil }
func (panicDialer) SetOutboundGateway(context.Context, *session.Outbound) {}
func (panicDialer) Address() xnet.Address                                 { return xnet.LocalHostIP }

func (panicDialer) Dial(context.Context, xnet.Destination) (stat.Connection, error) {
	panic("private panic")
}
func TestPanicContainedToMieru(t *testing.T) {
	c := &Client{config: &Config{Address: "127.0.0.1", Port: 1, Transport: "tcp"}}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: xnet.TCPDestination(xnet.LocalHostIP, 80)}})
	if e := c.Process(ctx, &transport.Link{}, panicDialer{}); e == nil || e.Error() != "native outbound internal failure" {
		t.Fatalf("panic escaped: %v", e)
	}
}
func FuzzMetadata(f *testing.F) {
	f.Add(make([]byte, 32))
	f.Add(metadata(segment{kind: dataServer, session: 1, payload: []byte("hi")}))
	f.Fuzz(func(t *testing.T, m []byte) { _, _, _, _ = parseMetadata(m) })
}

func TestConstructorPanicIsContained(t *testing.T) {
	if _, e := common.CreateObject(context.Background(), (*Config)(nil)); e == nil || e.Error() != "native outbound internal failure" {
		t.Fatalf("constructor panic escaped: %v", e)
	}
}
