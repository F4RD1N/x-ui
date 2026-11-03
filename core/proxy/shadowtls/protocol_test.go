package shadowtls

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"testing"

	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func TestUUIDSessionIDAndMAC(t *testing.T) {
	b := make([]byte, 100)
	b[0] = 1
	b[38] = 32
	p := "00112233-4455-6677-8899-aabbccddeeff"
	s, e := SessionID(b, p, true)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(s[12:28], []byte{0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255}) {
		t.Fatal("UUID not embedded at the required offset")
	}
	clear(b[67:71])
	h := hmac.New(sha1.New, []byte(p))
	h.Write(b)
	if !hmac.Equal(h.Sum(nil)[:4], s[28:]) {
		t.Fatal("ClientHello MAC does not cover UUID")
	}
	if _, e = SessionID(b, "not-a-uuid", true); e == nil {
		t.Fatal("invalid UUID accepted")
	}
}
func TestReadRecordRejectsOversize(t *testing.T) {
	if _, _, _, e := readRecord(bytes.NewReader([]byte{23, 3, 3, 255, 255})); e == nil {
		t.Fatal("oversized record accepted")
	}
}

type panicDialer struct{}

func (panicDialer) DestIpAddress() xnet.IP                                { return nil }
func (panicDialer) Address() xnet.Address                                 { return xnet.LocalHostIP }
func (panicDialer) SetOutboundGateway(context.Context, *session.Outbound) {}

func (panicDialer) Dial(context.Context, xnet.Destination) (stat.Connection, error) {
	panic("private panic value")
}
func TestPanicContainedToShadowTLS(t *testing.T) {
	c := &Client{config: &Config{Address: "127.0.0.1", Port: 1}}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: xnet.TCPDestination(xnet.LocalHostIP, 80)}})
	if e := c.Process(ctx, &transport.Link{}, panicDialer{}); e == nil || e.Error() != "native outbound internal failure" {
		t.Fatalf("panic escaped: %v", e)
	}
}
func FuzzTLSRecord(f *testing.F) {
	f.Add([]byte{23, 3, 3, 0, 0})
	f.Fuzz(func(t *testing.T, p []byte) { _, _, _, _ = readRecord(bytes.NewReader(p)) })
}

func TestConstructorPanicIsContained(t *testing.T) {
	if _, e := common.CreateObject(context.Background(), (*Config)(nil)); e == nil || e.Error() != "native outbound internal failure" {
		t.Fatalf("constructor panic escaped: %v", e)
	}
}
