package openvpn

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/client"
)

// gatedDevice holds the first Write -- the downlink injecting a packet into
// the stack -- until release is closed, and records a Close that comes
// meanwhile.
type gatedDevice struct {
	tun.Device
	entered, release, closed chan struct{}
	enterOnce, closeOnce     sync.Once
	writing                  atomic.Bool
	closedWhileWriting       atomic.Bool
}

func newGatedDevice(d tun.Device) *gatedDevice {
	return &gatedDevice{Device: d, entered: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
}

func (d *gatedDevice) Write(bufs [][]byte, offset int) (int, error) {
	d.writing.Store(true)
	defer d.writing.Store(false)
	d.enterOnce.Do(func() {
		close(d.entered)
		<-d.release
	})
	return d.Device.Write(bufs, offset)
}

func (d *gatedDevice) Close() error {
	if d.writing.Load() {
		d.closedWhileWriting.Store(true)
	}
	d.closeOnce.Do(func() { close(d.closed) })
	return d.Device.Close()
}

// onePacketSession delivers pkt once, then behaves as its fakeSession.
type onePacketSession struct {
	*fakeSession
	pkt  []byte
	once sync.Once
}

func (s *onePacketSession) ReadPacket(p []byte) (int, error) {
	first := false
	s.once.Do(func() { first = true })
	if first {
		return copy(p, s.pkt), nil
	}
	return s.fakeSession.ReadPacket(p)
}

// strayPacket is an IPv4 packet for an address the tunnel does not have
// (the stack drops it without an answer).
func strayPacket() []byte {
	b := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize)
	ip := header.IPv4(b)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(b)),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4(srvV4.As4()),
		DstAddr:     tcpip.AddrFrom4([4]byte{10, 9, 0, 77}),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	return b
}

// When the session ends while the downlink is still injecting a packet, the
// teardown waits for the downlink before it destroys the stack and closes
// the device: a reply the stack makes to that packet must not be written to
// a device that is gone.
func TestTeardownWaitsForDownlink(t *testing.T) {
	sess := &onePacketSession{
		fakeSession: newFakeSession(client.TunnelInfo{IPv4: cliV4, MTU: 1500}, nil),
		pkt:         strayPacket(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	tn, err := newTunnel(ctx, cancel, sess, 0)
	if err != nil {
		t.Fatal(err)
	}
	gd := newGatedDevice(tn.dev)
	tn.dev = gd
	tn.start()
	select {
	case <-gd.entered:
	case <-time.After(waitLong):
		t.Fatal("the downlink did not write the packet")
	}

	sess.fail(client.ErrPingTimeout)
	select {
	case <-gd.closed:
		close(gd.release)
		t.Fatal("the device was closed while the downlink was still injecting a packet into the stack")
	case <-time.After(300 * time.Millisecond):
	}
	close(gd.release)
	select {
	case <-tn.finished:
	case <-time.After(waitLong):
		t.Fatal("the tunnel was not released after the downlink finished")
	}
	if gd.closedWhileWriting.Load() {
		t.Fatal("the device was closed during a downlink write")
	}
	if ctx.Err() == nil {
		t.Fatal("the session context outlived the tunnel")
	}
}
