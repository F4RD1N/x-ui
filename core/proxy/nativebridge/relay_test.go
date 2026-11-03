package nativebridge

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
)

type panicReader struct{}

func (panicReader) ReadMultiBuffer() (buf.MultiBuffer, error) { panic("private payload") }

func TestRelayTaskPanicReturnsAnError(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := Relay(ctx, &transport.Link{Reader: panicReader{}, Writer: buf.NewWriter(io.Discard)}, a, nil,
		xnet.TCPDestination(xnet.LocalHostIP, 80), policy.Session{Timeouts: policy.Timeout{ConnectionIdle: time.Second}})
	if err == nil {
		t.Fatal("task panic was swallowed without reporting failure")
	}
}
