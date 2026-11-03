package openvpn

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	policyapp "github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	proxyoutbound "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	vlessin "github.com/xtls/xray-core/proxy/vless/inbound"
)

const muxTestUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

// muxServer is a server-style Xray instance: a VLESS inbound (user level 8:
// connIdle 12 s, uplinkOnly and downlinkOnly 1 s) routed to the OpenVPN
// outbound on the fixture's fake session, which is up. It returns the
// inbound's port.
func muxServer(t *testing.T, f *fixture) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	sec := func(v uint32) *policyapp.Second { return &policyapp.Second{Value: v} }
	v, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&policyapp.Config{Level: map[uint32]*policyapp.Policy{
				8: {Timeout: &policyapp.Policy_Timeout{Handshake: sec(4), ConnectionIdle: sec(12), UplinkOnly: sec(1), DownlinkOnly: sec(1)}},
			}}),
		},
		Inbound: []*core.InboundHandlerConfig{{
			Tag: "vless",
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(xnet.Port(port))}},
				Listen:   xnet.NewIPOrDomain(xnet.LocalHostIP),
			}),
			ProxySettings: serial.ToTypedMessage(&vlessin.Config{
				Clients:    []*protocol.User{{Level: 8, Email: "mux@test", Account: serial.ToTypedMessage(&vless.Account{Id: muxTestUUID})}},
				Decryption: "none",
			}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{
			Tag:           "proxy",
			ProxySettings: serial.ToTypedMessage(&Config{Ovpn: testOVPN}),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Close() })
	vpn := v.GetFeature(outbound.ManagerType()).(outbound.Manager).GetHandler("proxy").(*proxyoutbound.Handler).GetOutbound().(*Handler)
	if _, err := vpn.getTunnel(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	return port
}

// muxStream opens a VLESS mux connection, as a VLESS client with mux on
// sends it, and on it one TCP stream to the silent server carrying
// "request". It returns once the destination has accepted the stream.
func muxStream(t *testing.T, f *fixture, port int) (*net.TCPConn, *mux.Writer) {
	t.Helper()
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), waitLong)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	acc, err := (&vless.Account{Id: muxTestUUID}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	req := &protocol.RequestHeader{
		Version: encoding.Version,
		User:    &protocol.MemoryUser{Account: acc},
		Command: protocol.RequestCommandMux,
		Address: xnet.DomainAddress("v1.mux.cool"),
	}
	if err := encoding.EncodeRequestHeader(c, req, &encoding.Addons{}); err != nil {
		t.Fatal(err)
	}
	w := mux.NewWriter(1, tcpDest(srvV4, hcSilentPort), buf.NewWriter(c), protocol.TransferTypeStream, [8]byte{}, nil)
	if err := w.WriteMultiBuffer(buf.MergeBytes(nil, []byte("request"))); err != nil {
		t.Fatal(err)
	}
	st := f.session(0).srv.stack
	deadline := time.Now().Add(waitLong)
	for st.Stats().TCP.CurrentEstablished.Value() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the stream did not reach the destination")
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	return c.(*net.TCPConn), w
}

// expectNoRelay fails t unless the OpenVPN relay is gone within d.
func expectNoRelay(t *testing.T, d time.Duration, what string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		n, stacks := relayGoroutines()
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %d OpenVPN relay goroutines still running after %v\n%s", what, n, d, stacks)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A mux stream has no half-close (a mux End, or the end of the mux
// connection, closes both directions of the stream), and the inbound's
// timer is the whole mux connection's. So the end of a mux stream's request
// is not a FIN that waits up to the connection-idle timeout for a reply, and
// it does not touch the mux connection's timer: the client ending the whole
// mux connection while a stream to a silent destination is open ends it
// after the inbound's DownlinkOnly (1 s), not after its connection-idle
// timeout (12 s), and a mux End frees the stream after DownlinkOnly too.
func TestMuxStreamHasNoHalfClose(t *testing.T) {
	t.Run("the client ends the mux connection", func(t *testing.T) {
		f := newFixture(t, nil)
		port := muxServer(t, f)
		f.serveHalfClose(t, 0, srvV4, 0)
		c, _ := muxStream(t, f, port)
		if err := c.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		_ = c.SetReadDeadline(start.Add(4 * time.Second))
		if _, err := io.Copy(io.Discard, c); err != nil {
			t.Fatalf("the mux connection was still open %v after the client ended it: %v", time.Since(start).Round(time.Millisecond), err)
		}
		if el := time.Since(start); el > 3*time.Second {
			t.Fatalf("the mux connection ended %v after the client ended it", el.Round(time.Millisecond))
		}
		expectNoRelay(t, 3*time.Second, "after the mux connection ended")
	})
	t.Run("mux End", func(t *testing.T) {
		f := newFixture(t, nil)
		port := muxServer(t, f)
		f.serveHalfClose(t, 0, srvV4, 0)
		_, w := muxStream(t, f, port)
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		expectNoRelay(t, 2500*time.Millisecond, "after the mux End")
	})
}
