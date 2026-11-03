package shadowtls

// UoT is handled only inside this authenticated native carrier. Existing
// Shadowsocks handlers remain unchanged and all decoded UDP destinations are
// dispatched through Xray routing independently.

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	B "github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/uot"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/singbridge"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func shadowTLSUOTVersion(target xnet.Destination) int {
	if target.Network != xnet.Network_TCP || target.Address == nil || target.Address.Family() != xnet.AddressFamilyDomain {
		return 0
	}
	switch target.Address.Domain() {
	case uot.MagicAddress:
		return 2
	case uot.LegacyMagicAddress:
		return 1
	}
	return 0
}

func shadowTLSUOTLink(ctx context.Context, dispatcher routing.Dispatcher, version int, workers *sync.WaitGroup) *transport.Link {
	upReader, upWriter := pipe.New(pipe.WithSizeLimit(64 << 10))
	downReader, downWriter := pipe.New(pipe.WithSizeLimit(64 << 10))
	stream := cnc.NewConnection(cnc.ConnectionInputMulti(downWriter), cnc.ConnectionOutputMulti(upReader))
	workers.Add(1)
	go func() { defer workers.Done(); _ = serveShadowTLSUOT(ctx, stream, dispatcher, version) }()
	return &transport.Link{Reader: downReader, Writer: upWriter}
}

type shadowTLSUDPFlow struct {
	link        *transport.Link
	destination xnet.Destination
}

// Each UDP target has its own routing/sniffing state. The dispatcher updates
// these records asynchronously; sharing them across targets could misroute a
// later packet or race sniffing metadata.
func shadowTLSFlowContext(ctx context.Context) context.Context {
	if old := session.InboundFromContext(ctx); old != nil {
		copied := *old
		ctx = session.ContextWithInbound(ctx, &copied)
	}
	old := session.OutboundsFromContext(ctx)
	outbounds := make([]*session.Outbound, len(old))
	for i, entry := range old {
		if entry != nil {
			copied := *entry
			outbounds[i] = &copied
		} else {
			outbounds[i] = new(session.Outbound)
		}
	}
	ctx = session.ContextWithOutbounds(ctx, outbounds)
	if old := session.ContentFromContext(ctx); old != nil {
		copied := *old
		if old.Attributes != nil {
			copied.Attributes = make(map[string]string, len(old.Attributes))
			for k, v := range old.Attributes {
				copied.Attributes[k] = v
			}
		}
		ctx = session.ContextWithContent(ctx, &copied)
	}
	return ctx
}

func serveShadowTLSUOT(parent context.Context, stream net.Conn, dispatcher routing.Dispatcher, version int) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	defer stream.Close()
	stop := context.AfterFunc(ctx, func() { _ = stream.Close() })
	defer stop()
	idle := time.AfterFunc(60*time.Second, cancel)
	defer idle.Stop()
	request := uot.Request{}
	if version == 2 {
		r, err := uot.ReadRequest(stream)
		if err != nil {
			return err
		}
		request = *r
	}
	packets := uot.NewConn(stream, request)
	flows := make(map[string]*shadowTLSUDPFlow)
	var workers sync.WaitGroup
	var writeMu sync.Mutex
	defer func() {
		cancel()
		for _, flow := range flows {
			_ = common.Interrupt(flow.link.Reader)
			_ = common.Interrupt(flow.link.Writer)
		}
		workers.Wait()
	}()
	packet := B.NewSize(65535)
	defer packet.Release()
	for {
		packet.Reset()
		destination, err := packets.ReadPacket(packet)
		if err != nil {
			return err
		}
		if packet.Len() > buf.Size {
			return errors.New("ShadowTLS UoT datagram exceeds Xray packet buffer size")
		}
		if !destination.IsValid() || destination.Port == 0 {
			return errors.New("invalid ShadowTLS UoT destination")
		}
		idle.Reset(60 * time.Second)
		target := singbridge.ToDestination(destination, xnet.Network_UDP)
		key := target.String()
		flow := flows[key]
		if flow == nil {
			if len(flows) >= 64 {
				return errors.New("ShadowTLS UoT destination limit reached")
			}
			link, err := dispatcher.Dispatch(shadowTLSFlowContext(ctx), target)
			if err != nil {
				return err
			}
			flow = &shadowTLSUDPFlow{link: link, destination: target}
			flows[key] = flow
			workers.Add(1)
			go func(f *shadowTLSUDPFlow) {
				defer workers.Done()
				defer cancel()
				for {
					mb, err := f.link.Reader.ReadMultiBuffer()
					for _, b := range mb {
						response := f.destination
						if b.UDP != nil {
							response = *b.UDP
						}
						writeMu.Lock()
						writeErr := packets.WritePacket(B.As(b.Bytes()), singbridge.ToSocksaddr(response))
						writeMu.Unlock()
						if writeErr != nil {
							buf.ReleaseMulti(mb)
							return
						}
						idle.Reset(60 * time.Second)
					}
					buf.ReleaseMulti(mb)
					if err != nil {
						return
					}
				}
			}(flow)
		}
		b := buf.New()
		_, _ = b.Write(packet.Bytes())
		b.UDP = &target
		if err := flow.link.Writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
			return err
		}
	}
}
