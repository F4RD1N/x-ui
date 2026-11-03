package openvpn

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	proxyoutbound "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	_ "github.com/xtls/xray-core/transport/internet/tcp" // the default stream settings
)

// burstOutbound answers a link with datagrams written back to back, the way
// a server's multi-packet TLS flight arrives through a chained outbound.
type burstOutbound struct {
	tag   string
	burst []string
	wrote chan struct{}
}

func (o *burstOutbound) Tag() string  { return o.tag }
func (o *burstOutbound) Start() error { return nil }
func (o *burstOutbound) Close() error { return nil }

func (o *burstOutbound) Dispatch(ctx context.Context, link *transport.Link) {
	var mb buf.MultiBuffer
	for _, d := range o.burst {
		b := buf.New()
		b.WriteString(d)
		mb = append(mb, b)
	}
	_ = link.Writer.WriteMultiBuffer(mb)
	close(o.wrote)
	_ = buf.Copy(link.Reader, buf.Discard)
}

// A UDP transport chained with "proxySettings": {"tag": ...} reads one
// datagram per Read, as the session's UDP transport requires (one Read, one
// OpenVPN packet), also when several are waiting.
func TestProxySettingsUDPTransportKeepsDatagrams(t *testing.T) {
	v, err := core.New(&core.Config{})
	if err != nil {
		t.Fatal(err)
	}
	ohm, err := proxyoutbound.New(context.Background(), &proxyman.OutboundConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.AddFeature(ohm); err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), core.XrayKey(1), v)
	stub := &burstOutbound{tag: "chain", burst: []string{"datagram one", "datagram two", "datagram three"}, wrote: make(chan struct{})}
	if err := ohm.AddHandler(ctx, stub); err != nil {
		t.Fatal(err)
	}
	oh, err := proxyoutbound.NewHandler(ctx, &core.OutboundHandlerConfig{
		Tag:            "vpn",
		SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{ProxySettings: &internet.ProxyConfig{Tag: "chain"}}),
		ProxySettings:  serial.ToTypedMessage(&Config{Ovpn: testOVPN}),
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := oh.(*proxyoutbound.Handler)
	vpn, ok := handler.GetOutbound().(*Handler)
	if !ok {
		t.Fatalf("outbound is %T", handler.GetOutbound())
	}

	// The transport is dialled as a session does: through the handler.
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Tag: "vpn"}})
	dctx, cancel := context.WithTimeout(ctx, waitLong)
	defer cancel()
	conn, err := vpn.dialFunc(ctx, handler)(dctx, "udp", "192.0.2.10:1194")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	select {
	case <-stub.wrote:
	case <-time.After(waitLong):
		t.Fatal("the chained outbound was not dispatched")
	}
	for i, want := range stub.burst {
		p := make([]byte, 2048)
		n, err := conn.Read(p)
		if err != nil {
			t.Fatalf("Read %d: %v", i, err)
		}
		if string(p[:n]) != want {
			t.Fatalf("Read %d returned %q, want the single datagram %q", i, p[:n], want)
		}
	}
}
