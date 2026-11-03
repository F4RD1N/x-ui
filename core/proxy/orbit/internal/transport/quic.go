package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/xtls/xray-core/proxy/orbit/internal/protocol"

	quic "github.com/quic-go/quic-go"
)

// QUICSession exposes the reference mapping: one bidirectional stream per TCP
// socket, a separate framed UDP-control stream, and framed QUIC datagrams.
// Callers must implement the native type8/type9 stream preface before raw data.
type QUICSession struct {
	connection       *quic.Conn
	owner            *quic.Transport
	packet           net.PacketConn
	Metadata         QUICMetadata
	closeOnce        sync.Once
	logical          *quicLogical
	user             protocol.UserInfo
	allocateSocketID func() (uint32, error)
	serverOptions    QUICServerOptions
}

func (s *QUICSession) Context() context.Context { return s.connection.Context() }
func (s *QUICSession) LocalAddr() net.Addr      { return s.connection.LocalAddr() }
func (s *QUICSession) RemoteAddr() net.Addr     { return s.connection.RemoteAddr() }
func (s *QUICSession) OpenStream(ctx context.Context) (*QUICStream, error) {
	v, e := s.connection.OpenStreamSync(ctx)
	if e != nil {
		return nil, e
	}
	return &QUICStream{stream: v, session: s}, nil
}
func (s *QUICSession) AcceptStream(ctx context.Context) (*QUICStream, error) {
	v, e := s.connection.AcceptStream(ctx)
	if e != nil {
		return nil, e
	}
	return &QUICStream{stream: v, session: s}, nil
}

// Reserve the maximum peer CID and packet number, AEAD tag, and DATAGRAM
// header. quic-go's reported MSS can grow to the full path MTU after ACKs, so
// its check alone does not prevent a subsequent silent packet-packer drop.
const maxQUICDatagramPayload = 1200 - 1 - 20 - 4 - 16 - 3

func (s *QUICSession) SendDatagram(p []byte) error {
	if len(p) > maxQUICDatagramPayload {
		return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: maxQUICDatagramPayload}
	}
	return s.connection.SendDatagram(p)
}
func (s *QUICSession) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return s.connection.ReceiveDatagram(ctx)
}

// quicCloseGrace is how long Close lets quic-go's Transport.Close stop its
// read loop by itself before closing the socket under it.
const quicCloseGrace = 200 * time.Millisecond

func (s *QUICSession) Close() error {
	s.closeOnce.Do(func() {
		_ = s.connection.CloseWithError(0, "")
		if s.owner != nil {
			// Transport.Close stops its read loop with a read deadline on a
			// socket it did not create, and waits for it. Xray's chained
			// connections (dialerProxy) ignore read deadlines, so that wait
			// would never end: past a short grace (which lets the connection
			// close leave a real UDP socket first), closing the socket ends
			// the read loop.
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() { _ = recover() }()
				_ = s.owner.Close()
			}()
			select {
			case <-done:
			case <-time.After(quicCloseGrace):
			}
			_ = s.packet.Close()
			<-done
		}
	})
	return nil
}

// QUICStream adapts a single native socket stream, not the entire QUIC session.
type QUICStream struct {
	stream      *quic.Stream
	session     *QUICSession
	destination protocol.Address
	socketID    uint32
	metadata    uint16
	decisionMu  sync.Mutex
	decided     bool
	releaseOnce sync.Once
	release     func()
}

func (s *QUICStream) Read(p []byte) (int, error)  { return s.stream.Read(p) }
func (s *QUICStream) Write(p []byte) (int, error) { return s.stream.Write(p) }
func (s *QUICStream) Close() error {
	s.stream.CancelRead(0)
	err := s.stream.Close()
	s.releaseSlot()
	return err
}
func (s *QUICStream) CloseWrite() error { return s.stream.Close() }
func (s *QUICStream) Reset()            { s.stream.CancelRead(1); s.stream.CancelWrite(1); s.releaseSlot() }
func (s *QUICStream) releaseSlot() {
	s.releaseOnce.Do(func() {
		if s.release != nil {
			s.release()
		}
	})
}
func (s *QUICStream) LocalAddr() net.Addr                { return s.session.LocalAddr() }
func (s *QUICStream) RemoteAddr() net.Addr               { return s.session.RemoteAddr() }
func (s *QUICStream) SetDeadline(t time.Time) error      { return s.stream.SetDeadline(t) }
func (s *QUICStream) SetReadDeadline(t time.Time) error  { return s.stream.SetReadDeadline(t) }
func (s *QUICStream) SetWriteDeadline(t time.Time) error { return s.stream.SetWriteDeadline(t) }
func (s *QUICStream) ID() int64                          { return int64(s.stream.StreamID()) }

type initialAdmission struct {
	metadata QUICMetadata
	expires  time.Time
	active   bool
	complete bool
}
type metadataContextKey struct{}
type initialPacketConn struct {
	net.PacketConn
	client         *QUICInitialOptions
	verify         func(QUICMetadata, net.Addr) error
	mu             sync.Mutex
	entries        map[string]*initialAdmission
	clientMetadata QUICMetadata
	options        QUICServerOptions
}

// These methods retain ordinary socket buffer configuration while deliberately
// not exposing ReadMsgUDP: that fast path would bypass Initial transformation.
func (p *initialPacketConn) SetReadBuffer(n int) error {
	if v, ok := p.PacketConn.(interface{ SetReadBuffer(int) error }); ok {
		return v.SetReadBuffer(n)
	}
	return nil
}
func (p *initialPacketConn) SetWriteBuffer(n int) error {
	if v, ok := p.PacketConn.(interface{ SetWriteBuffer(int) error }); ok {
		return v.SetWriteBuffer(n)
	}
	return nil
}

func quicInitialEnd(b []byte) (int, error) {
	if len(b) < 7 || b[0]&0xb0 != 0x80 {
		return 0, ErrQUICInitial
	}
	i := 6 + int(b[5])
	if i >= len(b) {
		return 0, ErrQUICInitial
	}
	i += 1 + int(b[i])
	if i >= len(b) {
		return 0, ErrQUICInitial
	}
	token, n, e := ParseReferenceVarint(b[i:])
	if e != nil || token != 0 {
		return 0, ErrQUICInitial
	}
	i += n
	length, n, e := ParseReferenceVarint(b[i:])
	if e != nil {
		return 0, e
	}
	i += n
	if length > len(b)-i {
		return 0, ErrQUICInitial
	}
	return i + length, nil
}

func (p *initialPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if p.client != nil && len(b) > 0 && b[0]&0xb0 == 0x80 {
		end, err := quicInitialEnd(b)
		if err != nil {
			return 0, err
		}
		out, err := FormatQUICInitial(b[:end], *p.client)
		if err != nil {
			return 0, err
		}
		out = append(out, b[end:]...)
		n, err := p.PacketConn.WriteTo(out, addr)
		if err != nil {
			return 0, err
		}
		if n != len(out) {
			return 0, io.ErrShortWrite
		}
		return len(b), nil
	}
	return p.PacketConn.WriteTo(b, addr)
}

func (p *initialPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if p.client != nil {
		return p.PacketConn.ReadFrom(b)
	}
	// The wrapped datagram can be larger than the stack's 1200-byte Initial.
	buf := make([]byte, 65535)
	for {
		n, addr, err := p.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, addr, err
		}
		packet := buf[:n]
		if n > 0 && packet[0]&0xb0 == 0x80 {
			end, err := quicInitialEnd(packet)
			if err != nil {
				continue
			}
			plain, meta, err := StripQUICInitial(packet[:end])
			if err != nil {
				continue
			}
			if err = p.verify(meta, addr); err != nil {
				continue
			}
			key := addr.String()
			now := time.Now()
			p.mu.Lock()
			for k, v := range p.entries {
				if !v.active && now.After(v.expires) {
					delete(p.entries, k)
				}
			}
			entry := p.entries[key]
			options := p.options.defaults()
			pending := 0
			for _, v := range p.entries {
				if !v.complete {
					pending++
				}
			}
			if entry == nil && len(p.entries) < options.MaxSessions && pending < options.MaxHandshakes {
				p.entries[key] = &initialAdmission{metadata: meta, expires: now.Add(options.HandshakeTimeout)}
			} else if entry == nil || entry.metadata.ChannelID != meta.ChannelID || entry.metadata.ConnectionID != meta.ConnectionID {
				p.mu.Unlock()
				continue
			}
			p.mu.Unlock()
			packet = append(plain, packet[end:]...)
		}
		if len(packet) > len(b) {
			continue
		}
		return copy(b, packet), addr, nil
	}
}

func referenceQUICConfig() *quic.Config {
	return &quic.Config{
		Versions: []quic.Version{quic.Version1}, EnableDatagrams: true, MaxIncomingStreams: 128, MaxIncomingUniStreams: -1,
		HandshakeIdleTimeout: 15 * time.Second, MaxIdleTimeout: 60 * time.Second,
		InitialPacketSize: 1200, DisablePathMTUDiscovery: true, Allow0RTT: false,
	}
}

func referenceQUICClientConfig() *quic.Config {
	c := referenceQUICConfig()
	c.MaxIdleTimeout = 20 * time.Second
	// Native XQUIC enables a separate 15s PING timer with its 20s idle limit.
	// quic-go caps keepalive to half negotiated idle (normally 10s here) and
	// applies PTO/activity rules, so its exact PING schedule remains different.
	c.KeepAlivePeriod = 15 * time.Second
	return c
}

func cloneQUICtls(config *tls.Config) (*tls.Config, error) {
	if config == nil {
		return nil, errors.New("transport: explicit QUIC TLS configuration is required")
	}
	c := config.Clone()
	c.NextProtos = []string{"transport"}
	c.MinVersion = tls.VersionTLS13
	c.MaxVersion = tls.VersionTLS13
	return c, nil
}

// DialQUIC dials an owned reference-profile peer. The injected tls.Config makes
// certificate policy explicit. Secure verification is the Go default; parity
// with every compiled native certificate policy is not claimed.
func DialQUIC(ctx context.Context, address string, tlsConfig *tls.Config, initial QUICInitialOptions) (*QUICSession, error) {
	if initial.EncodeUserInfo == nil {
		return nil, errors.New("transport: userinfo encoder is required")
	}
	tc, err := cloneQUICtls(tlsConfig)
	if err != nil {
		return nil, err
	}
	// The native client explicitly configures these groups in this order.
	// Keep a caller's explicit policy and the server's accepted groups intact;
	// this removes hybrid groups from the default supported set. crypto/tls
	// still chooses its own wire ordering and initial keyshare, unlike XQUIC.
	if len(tc.CurvePreferences) == 0 {
		tc.CurvePreferences = []tls.CurveID{tls.CurveP256, tls.X25519, tls.CurveP384, tls.CurveP521}
	}
	resolver := initial.ResolveUDP
	if resolver == nil {
		resolver = resolveUDPContext
	}
	addr, err := resolver(ctx, address)
	if err != nil {
		return nil, err
	}
	if addr == nil {
		return nil, errors.New("transport: resolver returned no UDP address")
	}
	factory := initial.PacketConnFactory
	if factory == nil {
		factory = func(ctx context.Context) (net.PacketConn, error) {
			var lc net.ListenConfig
			return lc.ListenPacket(ctx, "udp", ":0")
		}
	}
	raw, err := factory(ctx)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, errors.New("transport: packet factory returned no socket")
	}
	pc := &initialPacketConn{PacketConn: raw, client: &initial}
	encode := initial.EncodeUserInfo
	initial.EncodeUserInfo = func(r io.Reader) ([128]byte, error) {
		v, e := encode(r)
		if e == nil {
			pc.mu.Lock()
			pc.clientMetadata = QUICMetadata{UserInfo: v, ConnectionID: initial.ConnectionID, ChannelID: initial.ChannelID, ProxyBuffer: append([]byte(nil), initial.ProxyBuffer...)}
			pc.mu.Unlock()
		}
		return v, e
	}
	tr := &quic.Transport{Conn: pc, ConnectionIDLength: 8}
	conn, err := tr.Dial(ctx, addr, tc, referenceQUICClientConfig())
	if err != nil {
		_ = tr.Close()
		_ = raw.Close()
		return nil, err
	}
	pc.mu.Lock()
	meta := pc.clientMetadata
	pc.mu.Unlock()
	s := &QUICSession{connection: conn, owner: tr, packet: raw, Metadata: meta, allocateSocketID: initial.AllocateSocketID}
	if err = s.startLogical(false); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func resolveUDPContext(ctx context.Context, address string) (*net.UDPAddr, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return nil, errors.New("transport: invalid UDP endpoint port")
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, errors.New("transport: endpoint has no addresses")
	}
	return &net.UDPAddr{IP: net.IP(ips[0].AsSlice()), Port: int(port), Zone: ips[0].Zone()}, nil
}

// QUICServerOptions keeps the shared session limits the client applies to its
// own logical session (flow and handshake queues).
type QUICServerOptions struct {
	MaxSessions, MaxHandshakes, MaxFlows int
	HandshakeTimeout                     time.Duration
}

func (o QUICServerOptions) defaults() QUICServerOptions {
	if o.MaxSessions == 0 {
		o.MaxSessions = 1024
	}
	if o.MaxHandshakes == 0 {
		o.MaxHandshakes = 128
	}
	if o.MaxFlows == 0 {
		o.MaxFlows = 128
	}
	if o.HandshakeTimeout == 0 {
		o.HandshakeTimeout = 15 * time.Second
	}
	return o
}
