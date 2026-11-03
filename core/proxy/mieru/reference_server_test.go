package mieru

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

// A peer of the test UDP listener models Xray's worker contract. Multiple
// queued datagrams are intentionally returned together to verify that the
// production adapter preserves their individual boundaries.
type referenceServerUDPPeer struct {
	pc      net.PacketConn
	peer    net.Addr
	packets chan []byte
	done    chan struct{}
	once    sync.Once
}

func (*referenceServerUDPPeer) Read([]byte) (int, error) { panic("worker uses ReadMultiBuffer") }
func (p *referenceServerUDPPeer) ReadMultiBuffer() (buf.MultiBuffer, error) {
	select {
	case <-p.done:
		return nil, net.ErrClosed
	case data := <-p.packets:
		mb := buf.MultiBuffer{buf.FromBytes(data)}
		for len(mb) < 8 {
			select {
			case data := <-p.packets:
				mb = append(mb, buf.FromBytes(data))
			default:
				return mb, nil
			}
		}
		return mb, nil
	}
}
func (p *referenceServerUDPPeer) Write(b []byte) (int, error) {
	select {
	case <-p.done:
		return 0, net.ErrClosed
	default:
		return p.pc.WriteTo(b, p.peer)
	}
}
func (p *referenceServerUDPPeer) Close() error                   { p.once.Do(func() { close(p.done) }); return nil }
func (p *referenceServerUDPPeer) LocalAddr() net.Addr            { return p.pc.LocalAddr() }
func (p *referenceServerUDPPeer) RemoteAddr() net.Addr           { return p.peer }
func (*referenceServerUDPPeer) SetDeadline(time.Time) error      { return nil }
func (*referenceServerUDPPeer) SetReadDeadline(time.Time) error  { return nil }
func (*referenceServerUDPPeer) SetWriteDeadline(time.Time) error { return nil }

func nativeReferenceListener(t *testing.T, s *Server, network string, d *nativeEchoDispatcher) (string, *atomic.Int64) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	accepted := new(atomic.Int64)
	start := func(c net.Conn) {
		accepted.Add(1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer c.Close()
			cctx := session.ContextWithInbound(ctx, &session.Inbound{Tag: "reference-in", Source: xnet.DestinationFromAddr(c.RemoteAddr()), Gateway: xnet.DestinationFromAddr(c.LocalAddr())})
			n := xnet.Network_TCP
			if network == "udp" {
				n = xnet.Network_UDP
			}
			if err := s.Process(cctx, n, c, d); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && ctx.Err() == nil {
				t.Logf("reference %s underlay ended: %v", network, err)
			}
		}()
	}
	loopDone := make(chan struct{})
	var address string
	var closeListener func() error
	if network == "tcp" {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address = ln.Addr().String()
		closeListener = ln.Close
		go func() {
			defer close(loopDone)
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				start(c)
			}
		}()
	} else {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address = pc.LocalAddr().String()
		closeListener = pc.Close
		go func() {
			defer close(loopDone)
			peers := map[string]*referenceServerUDPPeer{}
			defer func() {
				for _, p := range peers {
					p.Close()
				}
			}()
			for {
				b := make([]byte, 65535)
				n, addr, err := pc.ReadFrom(b)
				if err != nil {
					return
				}
				p := peers[addr.String()]
				if p != nil {
					select {
					case <-p.done:
						p = nil
					default:
					}
				}
				if p == nil {
					p = &referenceServerUDPPeer{pc: pc, peer: addr, packets: make(chan []byte, 256), done: make(chan struct{})}
					peers[addr.String()] = p
					start(p)
				}
				select {
				case p.packets <- b[:n]:
				case <-p.done:
				default:
				}
			}
		}()
	}
	t.Cleanup(func() {
		cancel()
		_ = closeListener()
		_ = s.Close()
		<-loopDone
		finished := make(chan struct{})
		go func() { wg.Wait(); close(finished) }()
		select {
		case <-finished:
		case <-time.After(3 * time.Second):
			t.Error("reference listener left live server handlers")
		}
	})
	return address, accepted
}

func TestNativeServerOfficialClientInterop(t *testing.T) {
	binary := os.Getenv("NATIVE_MIERU_CLIENT")
	if binary == "" {
		t.Skip("set NATIVE_MIERU_CLIENT to separately-built testdata/upstream-client driver")
	}
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			s := nativeTestServer(t, network, nativeTestUser("synthetic-user", "synthetic-password", "reference@test", false))
			d := &nativeEchoDispatcher{}
			address, accepted := nativeReferenceListener(t, s, network, d)
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			output, err := exec.CommandContext(ctx, binary, network, address).CombinedOutput()
			if err != nil {
				t.Fatalf("official client failed: %v\n%s", err, output)
			}
			if !strings.Contains(string(output), "PASS:") {
				t.Fatalf("missing reference success: %s", output)
			}
			records := d.snapshot()
			if len(records) != 11 {
				t.Fatalf("got %d dispatches, want 8 TCP + 3 UDP", len(records))
			}
			for _, r := range records {
				if r.email != "reference@test" {
					t.Fatalf("reference request has no authenticated user: %+v", r)
				}
			}
			if got := accepted.Load(); got >= 9 {
				t.Fatalf("reference did not reuse an underlay: %d accepted for 9 sessions", got)
			}
			t.Logf("%s: %s; %d underlying connections", network, strings.TrimSpace(string(output)), accepted.Load())
		})
	}
}
