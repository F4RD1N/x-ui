package orbit

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	xprotocol "github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/nativebridge"
	"github.com/xtls/xray-core/proxy/orbit/internal/protocol"
	"github.com/xtls/xray-core/transport"
)

type channelKey struct {
	uid  string
	id   [16]byte
	user *xprotocol.MemoryUser
}
type serverUDPKey struct {
	source, dest netip.AddrPort
	kind         byte
}
type serverUDPFlow struct {
	ctx       context.Context
	cancel    context.CancelFunc
	ready     chan struct{}
	link      *transport.Link
	timer     *signal.ActivityTimer
	preferred serverPeer
	writeSlot chan struct{}
}
type serverChannel struct {
	key      channelKey
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	peers    map[serverPeer]struct{}
	flows    map[serverUDPKey]*serverUDPFlow
	tcpSlots chan struct{}
	wg       sync.WaitGroup
	closed   bool
	user     *xprotocol.MemoryUser
}

func (s *Server) attachPeer(ctx context.Context, p serverPeer, u *xprotocol.MemoryUser) *serverChannel {
	key := channelKey{uid: p.User().UID, id: p.ChannelID(), user: u}
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.channels[key]
	if c == nil {
		base, cancel := context.WithCancel(context.WithoutCancel(ctx))
		c = &serverChannel{key: key, ctx: base, cancel: cancel, peers: make(map[serverPeer]struct{}), flows: make(map[serverUDPKey]*serverUDPFlow), tcpSlots: make(chan struct{}, s.cfg.MaxFlows), user: u}
		s.channels[key] = c
	}
	c.mu.Lock()
	c.peers[p] = struct{}{}
	c.mu.Unlock()
	return c
}
func (s *Server) detachPeer(c *serverChannel, p serverPeer) {
	s.mu.Lock()
	c.mu.Lock()
	delete(c.peers, p)
	last := len(c.peers) == 0
	if last {
		c.closed = true
		delete(s.channels, c.key)
		c.cancel()
	}
	c.mu.Unlock()
	s.mu.Unlock()
	if last {
		c.wg.Wait()
	}
}

func (s *Server) serveUDP(ctx context.Context, p serverPeer, c *serverChannel, d routing.Dispatcher) {
	for {
		u, e := p.ReceiveUDP(ctx)
		if e != nil {
			return
		}
		if u.Source.Port() == 0 || u.Destination.Port() == 0 || !u.Source.Addr().Is4() || !u.Destination.Addr().Is4() || len(u.Data) > protocol.MaxUDPDataSize {
			continue
		}
		key := serverUDPKey{u.Source, u.Destination, u.Kind}
		f := s.udpFlow(ctx, p, c, key, d)
		if f == nil {
			continue
		}
		select {
		case f.writeSlot <- struct{}{}:
		case <-ctx.Done():
			return
		case <-f.ctx.Done():
			continue
		}
		// A disconnected physical peer must not remain blocked behind another
		// peer or a congested outbound. Retire this mapping if its current send
		// is interrupted; other channel mappings remain available.
		stopSend := context.AfterFunc(ctx, f.cancel)
		b := buf.New()
		_, _ = b.Write(u.Data)
		dest := xnet.UDPDestination(xnet.IPAddress(u.Destination.Addr().AsSlice()), xnet.Port(u.Destination.Port()))
		b.UDP = &dest
		e = f.link.Writer.WriteMultiBuffer(buf.MultiBuffer{b})
		if e == nil {
			f.timer.Update()
		}
		stopSend()
		<-f.writeSlot
		if e != nil {
			f.cancel()
		}
	}
}

func (s *Server) udpFlow(ctx context.Context, p serverPeer, c *serverChannel, k serverUDPKey, d routing.Dispatcher) *serverUDPFlow {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	f := c.flows[k]
	if f == nil {
		if len(c.flows) >= int(s.cfg.MaxFlows) {
			c.mu.Unlock()
			return nil
		}
		// A channel can span physical connections. New mappings inherit the
		// creating peer's source/sniffing metadata, while their lifetime remains
		// the shared channel's lifetime after that peer disconnects.
		base, cancel := context.WithCancel(inboundContext(context.WithoutCancel(ctx), c.user))
		stopChannel := context.AfterFunc(c.ctx, cancel)
		f = &serverUDPFlow{ctx: base, cancel: cancel, ready: make(chan struct{}), preferred: p, writeSlot: make(chan struct{}, 1)}
		c.flows[k] = f
		c.wg.Add(1)
		c.mu.Unlock()
		dest := xnet.UDPDestination(xnet.IPAddress(k.dest.Addr().AsSlice()), xnet.Port(k.dest.Port()))
		stopInit := context.AfterFunc(ctx, cancel)
		link, err := orbitDispatch(d, base, dest)
		stopInit()
		if err != nil || link == nil || link.Reader == nil || link.Writer == nil {
			stopChannel()
			cancel()
			close(f.ready)
			c.mu.Lock()
			if c.flows[k] == f {
				delete(c.flows, k)
			}
			c.mu.Unlock()
			c.wg.Done()
			return nil
		}
		f.link = link
		f.timer = signal.CancelAfterInactivity(base, cancel, time.Duration(s.cfg.UdpIdleTimeout)*time.Second)
		close(f.ready)
		go func() {
			defer c.wg.Done()
			defer stopChannel()
			defer nativebridge.RecoverWorker(func(error) { cancel() })
			defer cancel()
			defer f.timer.SetTimeout(0)
			defer common.Interrupt(link.Reader)
			defer common.Interrupt(link.Writer)
			stop := context.AfterFunc(base, func() { common.Interrupt(link.Reader); common.Interrupt(link.Writer) })
			defer stop()
			defer func() {
				c.mu.Lock()
				if c.flows[k] == f {
					delete(c.flows, k)
				}
				c.mu.Unlock()
			}()
			s.readUDPReplies(c, k, f)
		}()
	} else {
		f.preferred = p
		c.mu.Unlock()
		select {
		case <-f.ready:
		case <-ctx.Done():
			return nil
		case <-f.ctx.Done():
			return nil
		}
	}
	if f.ctx.Err() != nil || f.link == nil {
		return nil
	}
	return f
}
func (s *Server) readUDPReplies(c *serverChannel, k serverUDPKey, f *serverUDPFlow) {
	for {
		mb, err := f.link.Reader.ReadMultiBuffer()
		for _, b := range mb {
			if b.Len() > protocol.MaxUDPDataSize {
				continue
			}
			source := k.dest
			if b.UDP != nil && b.UDP.Address.Family().IsIP() {
				if ip, ok := netip.AddrFromSlice(b.UDP.Address.IP()); ok && ip.Unmap().Is4() {
					source = netip.AddrPortFrom(ip.Unmap(), b.UDP.Port.Value())
				}
			}
			u := protocol.UDPEnvelope{Kind: k.kind, Source: source, Destination: k.source, Data: b.Bytes()}
			c.mu.Lock()
			p := f.preferred
			alive := func(peer serverPeer) bool {
				if peer == nil {
					return false
				}
				if _, ok := c.peers[peer]; !ok {
					return false
				}
				select {
				case <-peer.Done():
					return false
				default:
					return true
				}
			}
			if !alive(p) {
				p = nil
				for candidate := range c.peers {
					if alive(candidate) {
						p = candidate
						break
					}
				}
			}
			c.mu.Unlock()
			if p != nil {
				sendCtx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
				e := p.SendUDP(sendCtx, u)
				cancel()
				if e == nil {
					f.timer.Update()
				}
			}
		}
		buf.ReleaseMulti(mb)
		if err != nil {
			return
		}
	}
}
