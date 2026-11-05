package anytls

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport"
)

// Real dispatchers can take time to return after interruption. Holding that
// return makes FIN followed by immediate carrier reuse deterministic.
type anyTLSDelayedCleanupReader struct {
	entered, interrupted, release chan struct{}
	enterOnce, interruptOnce      sync.Once
}

func (r *anyTLSDelayedCleanupReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	r.enterOnce.Do(func() { close(r.entered) })
	<-r.interrupted
	<-r.release
	return nil, errors.New("reader interrupted")
}
func (r *anyTLSDelayedCleanupReader) Interrupt() {
	r.interruptOnce.Do(func() { close(r.interrupted) })
}

type anyTLSDiscardWriter struct{}

func (anyTLSDiscardWriter) WriteMultiBuffer(b buf.MultiBuffer) error {
	buf.ReleaseMulti(b)
	return nil
}

type anyTLSDelayedCleanupDispatcher struct {
	*anyTLSEchoDispatcher
	reader *anyTLSDelayedCleanupReader
}

func (d *anyTLSDelayedCleanupDispatcher) Dispatch(ctx context.Context, target xnet.Destination) (*transport.Link, error) {
	if target.Address.String() == "slow-cleanup.example" {
		return &transport.Link{Reader: d.reader, Writer: anyTLSDiscardWriter{}}, nil
	}
	return d.anyTLSEchoDispatcher.Dispatch(ctx, target)
}

func TestAnyTLSNativeInboundSerialReuseDuringWorkerCleanup(t *testing.T) {
	s, base := anyTLSNewTestServer(t, "p", false)
	s.maxStreams = 1
	r := &anyTLSDelayedCleanupReader{entered: make(chan struct{}), interrupted: make(chan struct{}), release: make(chan struct{})}
	d := &anyTLSDelayedCleanupDispatcher{anyTLSEchoDispatcher: base, reader: r}
	client, server := net.Pipe()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	done := make(chan error, 1)
	go func() { done <- s.Process(context.Background(), xnet.Network_TCP, server, d) }()
	defer func() {
		close(r.release)
		client.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("carrier did not clean up")
		}
	}()
	anyTLSLogin(t, client, "p", false)
	anyTLSOpen(t, client, 1, anyTLSAddress("slow-cleanup.example", 443))
	select {
	case <-r.entered:
	case <-time.After(time.Second):
		t.Fatal("copy worker never entered")
	}
	finThenSyn := append(anyTLSWireFrame(cmdFIN, 1, nil), anyTLSWireFrame(cmdSYN, 2, nil)...)
	anyTLSWrite(t, client, finThenSyn)
	anyTLSWrite(t, client, anyTLSWireFrame(cmdPSH, 2, anyTLSAddress("echo.example", 443)))
	command, id, p := anyTLSRead(t, client)
	if command != cmdSYNACK || id != 2 || len(p) != 0 {
		t.Fatalf("replacement stream not admitted: %d/%d/%q", command, id, p)
	}
	if len(s.streamSlots) != 2 {
		t.Fatal("finishing worker lost global admission")
	}
	anyTLSWrite(t, client, anyTLSWireFrame(cmdPSH, 2, []byte("replacement-payload")))
	command, id, p = anyTLSRead(t, client)
	if command != cmdPSH || id != 2 || string(p) != "replacement-payload" {
		t.Fatalf("replacement stream payload failed: %d/%d/%q", command, id, p)
	}
	anyTLSWrite(t, client, anyTLSWireFrame(cmdHeartRequest, 0, nil))
	command, _, _ = anyTLSRead(t, client)
	if command != cmdHeartResponse {
		t.Fatal("healthy carrier was not reusable")
	}
}
