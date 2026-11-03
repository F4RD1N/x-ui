package shadowtls

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/uot"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

func TestShadowTLSUOTShutdownAdmission(t *testing.T) {
	target := xnet.TCPDestination(xnet.DomainAddress(uot.MagicAddress), 0)
	for round := 0; round < 20; round++ {
		d := new(carrierDispatcher)
		var callers sync.WaitGroup
		for i := 0; i < 10; i++ {
			callers.Add(1)
			go func() {
				defer callers.Done()
				_, err := d.Dispatch(context.Background(), target)
				if err != nil && !errors.Is(err, net.ErrClosed) {
					t.Errorf("unexpected admission error: %v", err)
				}
			}()
		}
		d.interrupt()
		done := make(chan struct{})
		go func() { d.workers.Wait(); close(done) }()
		callers.Wait()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("UoT worker survived carrier shutdown")
		}
		if _, err := d.Dispatch(context.Background(), target); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("closed carrier admitted a worker: %v", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := new(carrierDispatcher).Dispatch(ctx, target); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("cancelled flow admitted a worker: %v", err)
	}
}

func TestShadowTLSUOTRoutingContextIsolation(t *testing.T) {
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: "carrier", Name: "shadowtls"})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Tag: "original"}})
	ctx = session.ContextWithContent(ctx, &session.Content{Protocol: "original", Attributes: map[string]string{"host": "original"}})
	one, two := shadowTLSFlowContext(ctx), shadowTLSFlowContext(ctx)
	session.InboundFromContext(one).Name = "modified"
	session.OutboundsFromContext(one)[0].Tag = "modified"
	session.ContentFromContext(one).Protocol = "modified"
	session.ContentFromContext(one).Attributes["host"] = "modified"
	for _, unaffected := range []context.Context{ctx, two} {
		if session.InboundFromContext(unaffected).Name != "shadowtls" || session.OutboundsFromContext(unaffected)[0].Tag != "original" || session.ContentFromContext(unaffected).Protocol != "original" || session.ContentFromContext(unaffected).Attributes["host"] != "original" {
			t.Fatal("UDP targets share mutable routing state")
		}
	}
}
