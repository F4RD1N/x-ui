package openvpn

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/client"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/options"
)

// A stack carried over a TCP transport uses reno; over UDP it keeps
// gvisortun's cubic.
func TestTunnelCongestionControl(t *testing.T) {
	for network, want := range map[string]string{
		"udp": "cubic", "udp4": "cubic", "udp6": "cubic",
		"tcp": tcpTransportCongestionControl, "tcp4": tcpTransportCongestionControl, "tcp6": tcpTransportCongestionControl,
	} {
		ctx, cancel := context.WithCancel(context.Background())
		s := newFakeSession(client.TunnelInfo{IPv4: cliV4, Remote: options.Remote{Host: "192.0.2.1", Port: 1194, Network: network}}, nil)
		tun, err := newTunnel(ctx, cancel, s, 0)
		if err != nil {
			t.Fatal(err)
		}
		tun.start()
		var cc tcpip.CongestionControlOption
		if err := tun.stack.TransportProtocolOption(tcp.ProtocolNumber, &cc); err != nil {
			t.Fatalf("%s: %v", network, err)
		}
		if string(cc) != want {
			t.Errorf("%s transport: congestion control %q, want %q", network, cc, want)
		}
		tun.close()
	}
}

// recordWriter records every Write.
type recordWriter struct {
	writes [][]byte
	err    error
}

func (w *recordWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	w.writes = append(w.writes, append([]byte(nil), p...))
	return len(p), nil
}

func multiBuffer(sizes ...int) (buf.MultiBuffer, []byte) {
	var mb buf.MultiBuffer
	var all []byte
	for i, n := range sizes {
		b := buf.New()
		p := bytes.Repeat([]byte{byte('a' + i%26)}, n)
		b.Write(p)
		mb = append(mb, b)
		all = append(all, p...)
	}
	return mb, all
}

// stackWriter writes a MultiBuffer with as few Writes as coalesceSize
// allows, keeps the bytes in order and skips empty buffers.
func TestStackWriterCoalesces(t *testing.T) {
	cases := []struct {
		name   string
		sizes  []int
		writes int
	}{
		{"one buffer", []int{buf.Size}, 1},
		{"three buffers", []int{buf.Size, buf.Size, 100}, 1},
		{"empty buffers", []int{0, buf.Size, 0, 5, 0}, 1},
		{"a full scratch", []int{buf.Size, buf.Size, buf.Size, buf.Size, buf.Size, buf.Size, buf.Size, buf.Size}, 1},
		{"more than a scratch", []int{buf.Size, buf.Size, buf.Size, buf.Size, buf.Size, buf.Size, buf.Size, buf.Size, buf.Size, 1}, 2},
		{"sixteen buffers", []int{buf.Size, buf.Size, buf.Size, buf.Size, buf.Size, buf.Size, buf.Size, buf.Size, buf.Size, buf.Size, buf.Size, buf.Size, buf.Size, buf.Size, buf.Size, buf.Size}, 2},
	}
	for _, tc := range cases {
		w := &recordWriter{}
		mb, want := multiBuffer(tc.sizes...)
		if err := newStackWriter(w).WriteMultiBuffer(mb); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if len(w.writes) != tc.writes {
			t.Errorf("%s: %d writes, want %d", tc.name, len(w.writes), tc.writes)
		}
		var got []byte
		for _, p := range w.writes {
			if len(p) == 0 || len(p) > coalesceSize {
				t.Errorf("%s: a write of %d bytes", tc.name, len(p))
			}
			got = append(got, p...)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: wrote %d bytes, not the %d given in order", tc.name, len(got), len(want))
		}
	}
}

func TestStackWriterError(t *testing.T) {
	boom := errors.New("boom")
	for _, sizes := range [][]int{{10}, {10, 20}} {
		mb, _ := multiBuffer(sizes...)
		if err := newStackWriter(&recordWriter{err: boom}).WriteMultiBuffer(mb); !errors.Is(err, boom) {
			t.Errorf("%d buffers: error %v, want %v", len(sizes), err, boom)
		}
	}
}
