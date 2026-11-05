package anytls

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// These lifecycle tests use only in-memory pipes, without socket listeners.
type anyTLSLifecycleUDPReader struct {
	*pipe.Reader
	interrupted chan struct{}
	once        sync.Once
}

func (r *anyTLSLifecycleUDPReader) Interrupt() {
	r.Reader.Interrupt()
	r.once.Do(func() { close(r.interrupted) })
}

type anyTLSLifecycleUDPFlow struct {
	target xnet.Destination
	ctx    context.Context
	reader *anyTLSLifecycleUDPReader
	writer *pipe.Writer
}

type anyTLSLifecycleUDPDispatcher struct{ calls chan *anyTLSLifecycleUDPFlow }

func (d *anyTLSLifecycleUDPDispatcher) Type() interface{} { return routing.DispatcherType() }
func (d *anyTLSLifecycleUDPDispatcher) Start() error      { return nil }
func (d *anyTLSLifecycleUDPDispatcher) Close() error      { return nil }
func (d *anyTLSLifecycleUDPDispatcher) DispatchLink(context.Context, xnet.Destination, *transport.Link) error {
	return errors.New("not used")
}
func (d *anyTLSLifecycleUDPDispatcher) Dispatch(ctx context.Context, target xnet.Destination) (*transport.Link, error) {
	if target.Address.String() == "denied.example" {
		return nil, errors.New("destination route denied")
	}
	r, w := pipe.New(pipe.WithSizeLimit(1024 * 1024))
	reader := &anyTLSLifecycleUDPReader{Reader: r, interrupted: make(chan struct{})}
	d.calls <- &anyTLSLifecycleUDPFlow{target: target, ctx: ctx, reader: reader, writer: w}
	if target.Address.String() == "write-failed.example" {
		return &transport.Link{Reader: reader, Writer: anyTLSLifecycleFailedUDPWriter{}}, nil
	}
	return &transport.Link{Reader: reader, Writer: w}, nil
}

type anyTLSLifecycleFailedUDPWriter struct{}

func (anyTLSLifecycleFailedUDPWriter) WriteMultiBuffer(b buf.MultiBuffer) error {
	buf.ReleaseMulti(b)
	return errors.New("destination write failed")
}

func anyTLSLifecycleUDPPeer(t *testing.T, connected bool) (net.Conn, *anyTLSLifecycleUDPDispatcher) {
	t.Helper()
	s, _ := anyTLSNewTestServer(t, "p", false)
	d := &anyTLSLifecycleUDPDispatcher{calls: make(chan *anyTLSLifecycleUDPFlow, 128)}
	c, server := net.Pipe()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	done := make(chan error, 1)
	go func() { done <- s.Process(context.Background(), xnet.Network_TCP, server, d) }()
	t.Cleanup(func() {
		c.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("UDP session did not close")
		}
	})
	anyTLSLogin(t, c, "p", false)
	anyTLSWrite(t, c, anyTLSWireFrame(1, 1, nil))
	request := anyTLSAddress("sp.v2.udp-over-tcp.arpa", 0)
	mode := byte(0)
	if connected {
		mode = 1
	}
	request = append(request, mode)
	request = append(request, anyTLSAddress("first.example", 53)...)
	anyTLSWrite(t, c, anyTLSWireFrame(2, 1, request))
	cmd, id, p := anyTLSRead(t, c)
	if cmd != 7 || id != 1 || len(p) != 0 {
		t.Fatal("UDP stream did not open")
	}
	return c, d
}

func anyTLSLifecycleUDPEcho(t *testing.T, c net.Conn, host, payload string, connected bool) {
	t.Helper()
	var wire []byte
	if !connected {
		wire = anyTLSAddress(host, 53)
		wire[0] = 2
	}
	wire = binary.BigEndian.AppendUint16(wire, uint16(len(payload)))
	wire = append(wire, payload...)
	anyTLSWrite(t, c, anyTLSWireFrame(2, 1, wire))
	cmd, id, response := anyTLSRead(t, c)
	if cmd != 2 || id != 1 || !bytes.Equal(wire, response) {
		t.Fatalf("UDP destination %s lost stream: command=%d id=%d response=%x", host, cmd, id, response)
	}
}

func anyTLSLifecycleUDPWait(t *testing.T, ch <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal(description)
	}
}

func TestAnyTLSUDPIndependentDestinationLifecycleMatrix(t *testing.T) {
	c, d := anyTLSLifecycleUDPPeer(t, false)
	anyTLSLifecycleUDPEcho(t, c, "first.example", "first", false)
	first := <-d.calls
	anyTLSLifecycleUDPEcho(t, c, "second.example", "second", false)
	second := <-d.calls
	if first.target == second.target {
		t.Fatal("destinations shared a route")
	}
	first.writer.Close()
	anyTLSLifecycleUDPWait(t, first.reader.interrupted, "ended destination was not cleaned up")
	anyTLSLifecycleUDPEcho(t, c, "second.example", "still-active", false)
	if second.ctx.Err() != nil {
		t.Fatal("another destination canceled active route context")
	}
	anyTLSLifecycleUDPEcho(t, c, "first.example", "fresh-route", false)
	replacement := <-d.calls
	if replacement == first || replacement.target != first.target {
		t.Fatal("ended destination did not get a fresh route")
	}
	// More than the maximum active destinations must be usable over time.
	// Each old route context is canceled independently when its worker exits.
	for i := 0; i < 70; i++ {
		replacement.writer.Close()
		anyTLSLifecycleUDPWait(t, replacement.reader.interrupted, "replaced destination was not cleaned up")
		anyTLSLifecycleUDPWait(t, replacement.ctx.Done(), "ended destination retained its route context")
		anyTLSLifecycleUDPEcho(t, c, "first.example", "reused-route", false)
		replacement = <-d.calls
	}
	anyTLSLifecycleUDPEcho(t, c, "second.example", "survived-replacements", false)
}

func TestAnyTLSUDPConnectedDestinationEndMatrix(t *testing.T) {
	c, d := anyTLSLifecycleUDPPeer(t, true)
	anyTLSLifecycleUDPEcho(t, c, "first.example", "connected", true)
	flow := <-d.calls
	flow.writer.Close()
	cmd, id, _ := anyTLSRead(t, c)
	if cmd != 3 || id != 1 {
		t.Fatalf("connected destination EOF must close its logical stream: %d/%d", cmd, id)
	}
	anyTLSWrite(t, c, anyTLSWireFrame(8, 0, nil))
	cmd, id, _ = anyTLSRead(t, c)
	if cmd != 9 || id != 0 {
		t.Fatal("connected stream EOF closed unrelated carrier")
	}
}

func TestAnyTLSUDPDestinationFailureIsolationMatrix(t *testing.T) {
	c, d := anyTLSLifecycleUDPPeer(t, false)
	anyTLSLifecycleUDPEcho(t, c, "healthy.example", "before-errors", false)
	healthy := <-d.calls
	for _, host := range []string{"denied.example", "write-failed.example"} {
		wire := anyTLSAddress(host, 53)
		wire[0] = 2
		wire = binary.BigEndian.AppendUint16(wire, 1)
		wire = append(wire, 'x')
		anyTLSWrite(t, c, anyTLSWireFrame(2, 1, wire))
		if host == "write-failed.example" {
			failed := <-d.calls
			anyTLSLifecycleUDPWait(t, failed.reader.interrupted, "failed writer retained destination")
			anyTLSLifecycleUDPWait(t, failed.ctx.Done(), "failed writer retained route context")
		}
		anyTLSLifecycleUDPEcho(t, c, "healthy.example", "after-error", false)
		if healthy.ctx.Err() != nil {
			t.Fatal("destination failure canceled healthy route")
		}
	}
}

func TestAnyTLSUDPActiveDestinationLimitMatrix(t *testing.T) {
	c, d := anyTLSLifecycleUDPPeer(t, false)
	flows := make([]*anyTLSLifecycleUDPFlow, 0, 64)
	for i := 0; i < 64; i++ {
		anyTLSLifecycleUDPEcho(t, c, fmt.Sprintf("destination-%d.example", i), "bounded", false)
		flows = append(flows, <-d.calls)
	}
	wire := anyTLSAddress("destination-over-limit.example", 53)
	wire[0] = 2
	wire = binary.BigEndian.AppendUint16(wire, 1)
	wire = append(wire, 'x')
	anyTLSWrite(t, c, anyTLSWireFrame(2, 1, wire))
	cmd, id, _ := anyTLSRead(t, c)
	if cmd != 3 || id != 1 {
		t.Fatal("65 active destinations bypassed the logical stream limit")
	}
	for _, flow := range flows {
		anyTLSLifecycleUDPWait(t, flow.ctx.Done(), "bounded stream left route context active")
		anyTLSLifecycleUDPWait(t, flow.reader.interrupted, "bounded stream left reader active")
	}
	select {
	case <-d.calls:
		t.Fatal("excess destination reached dispatcher")
	default:
	}
	anyTLSWrite(t, c, anyTLSWireFrame(8, 0, nil))
	cmd, _, _ = anyTLSRead(t, c)
	if cmd != 9 {
		t.Fatal("UDP destination limit broke carrier")
	}
}
