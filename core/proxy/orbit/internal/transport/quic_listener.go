package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

type QUICListener struct {
	listener  *quic.Listener
	transport *quic.Transport
	packet    net.PacketConn
	once      sync.Once
	options   QUICServerOptions
	initial   *initialPacketConn
}

func (o QUICServerOptions) validate() error {
	if o.MaxSessions < 1 || o.MaxSessions > 100000 || o.MaxHandshakes < 1 || o.MaxHandshakes > 4096 || o.MaxFlows < 1 || o.MaxFlows > 65536 || o.HandshakeTimeout < 2*time.Nanosecond || o.HandshakeTimeout > 90*time.Second {
		return errors.New("transport: invalid QUIC server limits")
	}
	return nil
}

// ListenQUIC authenticates the recovered Initial metadata before permitting a
// handshake. verify is mandatory and must check credentials and relay policy.
// This profile admits one active QUIC connection per remote UDP source tuple.
func ListenQUIC(raw net.PacketConn, tlsConfig *tls.Config, verify func(QUICMetadata, net.Addr) error) (*QUICListener, error) {
	return ListenQUICWithOptions(raw, tlsConfig, verify, QUICServerOptions{})
}
func ListenQUICWithOptions(raw net.PacketConn, tlsConfig *tls.Config, verify func(QUICMetadata, net.Addr) error, options QUICServerOptions) (*QUICListener, error) {
	options = options.defaults()
	if err := options.validate(); err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, errors.New("transport: QUIC packet socket is required")
	}
	if verify == nil {
		return nil, errors.New("transport: QUIC Initial verifier is required")
	}
	tc, err := cloneQUICtls(tlsConfig)
	if err != nil {
		return nil, err
	}
	// quic-go can defer the missing-certificate error until the first TLS
	// handshake. Refuse an unusable listener now and release its packet adapter.
	if len(tc.Certificates) == 0 && tc.GetCertificate == nil && tc.GetConfigForClient == nil {
		_ = raw.Close()
		return nil, errors.New("transport: QUIC server certificate is required")
	}
	pc := &initialPacketConn{PacketConn: raw, verify: verify, entries: make(map[string]*initialAdmission), options: options}
	tr := &quic.Transport{Conn: pc, ConnectionIDLength: 8, DisableVersionNegotiationPackets: true}
	tr.ConnContext = func(ctx context.Context, info *quic.ClientInfo) (context.Context, error) {
		key := info.RemoteAddr.String()
		pc.mu.Lock()
		entry := pc.entries[key]
		if entry == nil || entry.active {
			pc.mu.Unlock()
			return nil, errors.New("transport: missing or conflicting Initial metadata")
		}
		entry.active = true
		meta := entry.metadata
		pc.mu.Unlock()
		context.AfterFunc(ctx, func() {
			pc.mu.Lock()
			if pc.entries[key] == entry {
				delete(pc.entries, key)
			}
			pc.mu.Unlock()
		})
		return context.WithValue(ctx, metadataContextKey{}, meta), nil
	}
	config := referenceQUICConfig()
	// quic-go bounds the overall handshake at twice its idle timeout. Keep
	// the configured deployment value as the hard bound, even for peers
	// that continue sending packets without completing their handshake.
	config.HandshakeIdleTimeout = options.HandshakeTimeout / 2
	config.MaxIncomingStreams = int64(options.MaxFlows + 1) // one reserved UDP-control stream
	l, err := tr.Listen(tc, config)
	if err != nil {
		closeQUICPacketTransport(tr, raw)
		return nil, err
	}
	return &QUICListener{listener: l, transport: tr, packet: raw, options: options, initial: pc}, nil
}
func (l *QUICListener) Addr() net.Addr { return l.listener.Addr() }
func (l *QUICListener) Accept(ctx context.Context) (*QUICSession, error) {
	c, err := l.listener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	meta, ok := c.Context().Value(metadataContextKey{}).(QUICMetadata)
	if !ok {
		_ = c.CloseWithError(1, "missing metadata")
		return nil, errors.New("transport: missing Initial metadata")
	}
	l.initial.mu.Lock()
	if entry := l.initial.entries[c.RemoteAddr().String()]; entry != nil {
		entry.complete = true
	}
	l.initial.mu.Unlock()
	s := &QUICSession{connection: c, Metadata: meta, serverOptions: l.options}
	if err = s.startLogical(true); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}
func (l *QUICListener) Close() error {
	l.once.Do(func() {
		_ = l.listener.Close()
		closeQUICPacketTransport(l.transport, l.packet)
	})
	return nil
}

func closeQUICPacketTransport(tr *quic.Transport, packet net.PacketConn) {
	// A virtual Xray packet connection may not implement read deadlines.
	// Force its Close after a short grace to unblock quic-go's read loop,
	// then join that loop before returning. This is also needed when listener
	// initialization fails after starting the packet read loop.
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = tr.Close()
	}()
	select {
	case <-done:
	case <-time.After(quicCloseGrace):
	}
	_ = packet.Close()
	<-done
}
