package orbit

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	xprotocol "github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/nativebridge"
	"github.com/xtls/xray-core/proxy/orbit/internal/protocol"
	"github.com/xtls/xray-core/proxy/orbit/internal/router"
	"github.com/xtls/xray-core/transport"
)

func terminalMetadata(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	p, e := router.ParseProxyPath(b)
	return e == nil && (len(p.Nodes) != 1 || p.Nodes[0].Field0 == 4)
}

func (s *Server) servePeer(ctx context.Context, p serverPeer, run *serverRun, authenticated *xprotocol.MemoryUser, d routing.Dispatcher) error {
	u, err := s.admit(run, p.User(), authenticated)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx = inboundContext(ctx, u)
	c := s.attachPeer(ctx, p, u)
	defer s.detachPeer(c, p)
	stop := context.AfterFunc(ctx, func() { _ = p.Close() })
	defer stop()
	var wg sync.WaitGroup
	worker := func(fn func()) {
		wg.Add(1)
		go func() { defer wg.Done(); defer nativebridge.RecoverWorker(func(error) { cancel() }); fn() }()
	}
	worker(func() { s.serveApp(ctx, p); cancel() })
	worker(func() { s.serveUDP(ctx, p, c, d); cancel() })
	worker(func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-p.Done():
				cancel()
				return
			case <-ticker.C:
				if current, e := s.authorize(p.User()); e != nil || current != authenticated {
					cancel()
					return
				}
			}
		}
	})
	defer func() { cancel(); _ = p.Close(); wg.Wait() }()
	for {
		flow, e := p.Accept(ctx)
		if e != nil {
			return e
		}
		select {
		case c.tcpSlots <- struct{}{}:
			worker(func() { defer func() { <-c.tcpSlots }(); defer flow.Close(); s.serveStream(ctx, flow, u, d) })
		default:
			_ = flow.Reject()
			_ = flow.Close()
		}
	}
}

func (s *Server) serveApp(ctx context.Context, p serverPeer) {
	for {
		m, e := p.ReceiveApp(ctx)
		if e != nil {
			return
		}
		reply := protocol.AppMessage{RequestID: m.RequestID}
		switch m.Type {
		case 1:
			reply.Type = 2
		case 3:
			reply.Type = 4
			reply.Data, e = router.MarshalPathStat(router.PathStat{})
			if e != nil {
				return
			}
		case 5:
			reply.Type = 6
		default:
			continue
		}
		if e = p.SendApp(ctx, reply); e != nil {
			return
		}
	}
}

func (s *Server) serveStream(parent context.Context, flow incomingFlow, user *xprotocol.MemoryUser, dispatcher routing.Dispatcher) {
	a := flow.Destination()
	host, err := a.Host()
	if err != nil || a.Port == 0 {
		_ = flow.Reject()
		return
	}
	dest := xnet.TCPDestination(xnet.ParseAddress(host), xnet.Port(a.Port))
	if !dest.IsValid() {
		_ = flow.Reject()
		return
	}
	p := policy.SessionDefault()
	if s.policy != nil {
		p = s.policy.ForLevel(user.Level)
	}
	ctx, cancel := context.WithCancel(inboundContext(parent, user))
	defer cancel()
	ctx = policy.ContextWithBufferPolicy(ctx, p.Buffer)
	link, err := orbitDispatch(dispatcher, ctx, dest)
	if err != nil {
		_ = flow.Reject()
		return
	}
	if link == nil || link.Reader == nil || link.Writer == nil {
		_ = flow.Reject()
		return
	}
	stop := context.AfterFunc(ctx, func() { common.Interrupt(link.Reader); common.Interrupt(link.Writer); _ = flow.Close() })
	defer stop()
	defer common.Interrupt(link.Reader)
	defer common.Interrupt(link.Writer)
	if err = flow.Accept(); err != nil {
		return
	}
	timer := signal.CancelAfterInactivity(ctx, cancel, p.Timeouts.ConnectionIdle)
	defer timer.SetTimeout(0)
	done := make(chan error, 2)
	go func() {
		defer nativebridge.RecoverWorker(func(e error) { done <- e })
		e := buf.Copy(buf.NewReader(flow), link.Writer, buf.UpdateActivity(timer))
		if e == nil {
			_ = common.Close(link.Writer)
		}
		timer.SetTimeout(p.Timeouts.DownlinkOnly)
		done <- e
	}()
	go func() {
		defer nativebridge.RecoverWorker(func(e error) { done <- e })
		e := buf.Copy(link.Reader, buf.NewWriter(flow), buf.UpdateActivity(timer))
		if w, ok := flow.(interface{ CloseWrite() error }); ok {
			_ = w.CloseWrite()
		}
		timer.SetTimeout(p.Timeouts.UplinkOnly)
		done <- e
	}()
	for n := 0; n < 2; n++ {
		select {
		case e := <-done:
			if e != nil && !errors.Is(e, io.EOF) {
				cancel()
			}
		case <-ctx.Done():
			cancel()
			common.Interrupt(link.Reader)
			common.Interrupt(link.Writer)
			_ = flow.Close()
			for ; n < 2; n++ {
				<-done
			}
			return
		}
	}
}

// Contain a failing dispatcher at the native protocol boundary without leaving
// pending channel flow bookkeeping behind.
func orbitDispatch(dispatcher routing.Dispatcher, ctx context.Context, dest xnet.Destination) (link *transport.Link, err error) {
	defer nativebridge.Recover(&err, nil)
	return dispatcher.Dispatch(ctx, dest)
}
