package openvpn

import (
	"context"
	goerrors "errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/client"
	"github.com/xtls/xray-core/proxy/openvpn/netstack"
)

// vpnSession is what a tunnel needs of an ovpn/client session.
type vpnSession interface {
	Info() client.TunnelInfo
	ReadPacket(p []byte) (int, error)
	WritePacket(p []byte) error
	Done() <-chan struct{}
	Err() error
	Close() error
}

// dialSession opens a session; tests replace it.
var dialSession = func(ctx context.Context, cfg client.Config) (vpnSession, error) {
	c, err := client.Dial(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return c, nil
}

const (
	// tcpTransportCongestionControl is the stack's TCP congestion control
	// when the OpenVPN transport is TCP (gvisortun's default, cubic, stays
	// for UDP). Over a TCP transport the stack's connections see no loss,
	// only the delay of the outer connection's queue. gVisor's cubic leaves
	// slow start at the first rise of that delay (HyStart) and then grows
	// along the cubic curve from that point, a fraction of a packet per
	// round trip for seconds: an upload stayed at a window of about 300
	// packets and 36-38 Mbit/s. Reno stays in slow start until the window
	// covers the path (153-162 Mbit/s on the same server).
	//
	// Seeing no loss, reno also never stops growing: up to the stack's
	// send-buffer limit (4 MiB) per connection. It relies on the bound on
	// the transport socket's unsent data (transportNotSentLowat), which
	// keeps that excess in each connection's own queue in the stack. Without
	// it the excess waited in the socket in front of every other connection
	// in the tunnel: at 20 Mbit/s every request alongside an upload waited
	// 0.6-1.2 s, for no gain in speed.
	tcpTransportCongestionControl = "reno"

	// packetBufferSize holds any IP packet, whatever MTU the stack or the
	// server uses.
	packetBufferSize = 64 << 10
	// teardownWait bounds how long Close waits for a tunnel to wind down.
	teardownWait = 5 * time.Second
)

// tunnel is one OpenVPN session bound to one gVisor stack. Two goroutines
// move packets between them; a third tears both down when the session ends
// or stop is called.
type tunnel struct {
	sess    vpnSession
	dev     tun.Device
	net     *gvisortun.Net
	stack   *stack.Stack
	hasIPv4 bool
	hasIPv6 bool
	mtu     int

	// ctx is the session's context (logs; the transport was dialled with
	// it); cancel ends it once the tunnel is down.
	ctx    context.Context
	cancel context.CancelFunc

	dead         chan struct{} // closed when the tunnel stops taking requests
	finished     chan struct{} // closed when everything is released
	downlinkDone chan struct{} // closed when downlink returns
	stopOnce     sync.Once
	pumps        sync.WaitGroup // uplink
}

// newTunnel builds the userspace stack for sess on the addresses the server
// assigned. mtu 0 means min(the session's MTU, defaultMTU). It does not start
// the tunnel and does not close sess on failure.
func newTunnel(ctx context.Context, cancel context.CancelFunc, sess vpnSession, mtu int) (*tunnel, error) {
	info := sess.Info()
	var addrs []netip.Addr
	if info.IPv4.IsValid() {
		addrs = append(addrs, info.IPv4.Addr())
	}
	if info.IPv6.IsValid() {
		addrs = append(addrs, info.IPv6.Addr())
	}
	if len(addrs) == 0 {
		return nil, errors.New("the server assigned no tunnel address (no ifconfig or ifconfig-ipv6 in its push)")
	}
	if mtu <= 0 {
		mtu = defaultMTU
		if info.MTU > 0 && info.MTU < mtu {
			mtu = info.MTU
		}
	}
	dev, n, s, err := gvisortun.CreateNetTUN(addrs, mtu, false)
	if err != nil {
		if s != nil {
			s.Destroy()
		}
		return nil, errors.New("failed to create the userspace network stack").Base(err)
	}
	if overTCP(info.Remote.Network) {
		cc := tcpip.CongestionControlOption(tcpTransportCongestionControl)
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &cc); err != nil {
			s.Destroy()
			_ = dev.Close()
			return nil, errors.New("failed to set the stack's congestion control: ", err)
		}
	}
	return &tunnel{
		sess:         sess,
		dev:          dev,
		net:          n,
		stack:        s,
		hasIPv4:      info.IPv4.IsValid(),
		hasIPv6:      info.IPv6.IsValid(),
		mtu:          mtu,
		ctx:          ctx,
		cancel:       cancel,
		dead:         make(chan struct{}),
		finished:     make(chan struct{}),
		downlinkDone: make(chan struct{}),
	}, nil
}

func (t *tunnel) start() {
	t.pumps.Add(1)
	go t.uplink()
	go t.downlink()
	go t.watch()
}

// alive reports whether the tunnel still takes requests.
func (t *tunnel) alive() bool {
	select {
	case <-t.dead:
		return false
	default:
		return true
	}
}

// stop makes the tunnel stop taking requests and starts its teardown.
func (t *tunnel) stop() { t.stopOnce.Do(func() { close(t.dead) }) }

// close stops the tunnel and waits (bounded) until it is released.
func (t *tunnel) close() {
	t.stop()
	timer := time.NewTimer(teardownWait)
	defer timer.Stop()
	select {
	case <-t.finished:
	case <-timer.C:
		errors.LogWarning(t.ctx, "the OpenVPN tunnel is taking long to shut down; not waiting for it")
	}
}

// uplink moves the packets the stack sends into the session. It keeps
// reading until the device is closed, also after the session ended: the
// stack's writers block until their packet is read, and the device must not
// be closed under a blocked writer.
func (t *tunnel) uplink() {
	defer t.pumps.Done()
	bufs := [][]byte{make([]byte, packetBufferSize)}
	sizes := []int{0}
	for {
		n, err := t.dev.Read(bufs, sizes, 0)
		if err != nil {
			if goerrors.Is(err, os.ErrClosed) {
				return
			}
			continue // one unreadable packet
		}
		if n < 1 || sizes[0] <= 0 || !t.alive() {
			continue
		}
		// A packet the session cannot take now (no data key yet, a key
		// being replaced) is lost like any dropped packet; a session that
		// is over is noticed by watch.
		_ = t.sess.WritePacket(bufs[0][:sizes[0]])
	}
}

// downlink moves the session's packets into the stack until the session is
// over.
func (t *tunnel) downlink() {
	defer close(t.downlinkDone)
	buf := make([]byte, packetBufferSize)
	bufs := [][]byte{nil}
	for {
		n, err := t.sess.ReadPacket(buf)
		if err != nil {
			if goerrors.Is(err, io.ErrShortBuffer) {
				continue // cannot happen with a 64 KiB buffer; drop it
			}
			return
		}
		if n <= 0 {
			select {
			case <-t.sess.Done():
				return
			default:
				continue
			}
		}
		bufs[0] = buf[:n]
		// The stack copies the packet; a packet that is not IPv4 or IPv6
		// is refused and dropped.
		_, _ = t.dev.Write(bufs, 0)
	}
}

// watch tears the tunnel down when the session ends or stop is called:
// session, then (once downlink is out of the stack) every connection in the
// stack (so requests in flight fail at once instead of idling out), then the
// device, then the context the transport was dialled with.
func (t *tunnel) watch() {
	select {
	case <-t.sess.Done():
		if err := t.sess.Err(); err != nil && !goerrors.Is(err, client.ErrClosed) {
			errors.LogWarningInner(t.ctx, err, "the OpenVPN session ended")
		} else {
			errors.LogInfo(t.ctx, "the OpenVPN session ended")
		}
	case <-t.dead:
	}
	t.stop()
	_ = t.sess.Close()
	// downlink returns now that the session is closed. It may still be
	// injecting a packet, and the stack answers some packets in the
	// injecting goroutine (an echo reply, a reset to a connection that is
	// going away): the stack and the device must outlive that. uplink keeps
	// draining the device meanwhile, so the injector never blocks on it.
	timer := time.NewTimer(teardownWait)
	select {
	case <-t.downlinkDone:
	case <-timer.C:
		errors.LogWarning(t.ctx, "the OpenVPN tunnel's downlink is taking long to stop; tearing the stack down anyway")
	}
	timer.Stop()
	t.stack.Destroy()
	_ = t.dev.Close()
	t.pumps.Wait()
	t.cancel()
	close(t.finished)
}

// overTCP reports whether an ovpn transport network (options.Remote.Network:
// "udp", "udp4", "tcp6", ...) is TCP.
func overTCP(network string) bool { return strings.HasPrefix(network, "tcp") }

// sessionLogger sends the session's log lines to Xray's log. The client
// package keeps secrets out of its lines.
type sessionLogger struct{ ctx context.Context }

func (l sessionLogger) line(format string, args []any) string {
	return strings.TrimPrefix(fmt.Sprintf(format, args...), "openvpn: ")
}

func (l sessionLogger) Debugf(format string, args ...any) {
	errors.LogDebug(l.ctx, l.line(format, args))
}

func (l sessionLogger) Infof(format string, args ...any) {
	errors.LogInfo(l.ctx, l.line(format, args))
}

func (l sessionLogger) Warnf(format string, args ...any) {
	errors.LogWarning(l.ctx, l.line(format, args))
}

// platform is the IV_PLAT value OpenVPN uses for this system.
func platform() string {
	switch runtime.GOOS {
	case "darwin":
		return "mac"
	case "windows":
		return "win"
	case "android", "ios", "freebsd", "openbsd", "netbsd", "solaris":
		return runtime.GOOS
	}
	return "linux"
}
