package transport

// The server half of VPN-Core's QUIC carrier (ListenQUICWithOptions), cut
// down for tests: it strips the recovered Initial envelope, remembers the
// metadata per source address, admits the connection with the same stream
// credit as VPN-Core's listener (MaxFlows plus the UDP-control stream) and
// starts the server side of the logical session. Every accepted flow echoes.

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/orbit/internal/protocol"

	quic "github.com/quic-go/quic-go"
)

type stripInitialConn struct {
	net.PacketConn
	mu   sync.Mutex
	meta map[string]QUICMetadata
	// drop silences the server (a dead path) when set.
	drop func() bool
}

func (p *stripInitialConn) ReadFrom(b []byte) (int, net.Addr, error) {
	buf := make([]byte, 65535)
	for {
		n, addr, err := p.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, addr, err
		}
		if p.drop != nil && p.drop() {
			continue
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
			p.mu.Lock()
			p.meta[addr.String()] = meta
			p.mu.Unlock()
			packet = append(plain, packet[end:]...)
		}
		if len(packet) > len(b) {
			continue
		}
		return copy(b, packet), addr, nil
	}
}

func (p *stripInitialConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if p.drop != nil && p.drop() {
		return len(b), nil
	}
	return p.PacketConn.WriteTo(b, addr)
}

type testQUICServer struct {
	addr     string
	conn     *stripInitialConn
	sessions chan *QUICSession
}

type testMetaKey struct{}

// listenTestQUIC starts the server. silent, when not nil, makes the server
// drop every packet while it returns true.
func listenTestQUIC(t *testing.T, serverTLS *tls.Config, options QUICServerOptions, silent func() bool) *testQUICServer {
	t.Helper()
	options = options.defaults()
	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pc := &stripInitialConn{PacketConn: raw, meta: make(map[string]QUICMetadata), drop: silent}
	tr := &quic.Transport{Conn: pc, ConnectionIDLength: 8, DisableVersionNegotiationPackets: true}
	tr.ConnContext = func(ctx context.Context, info *quic.ClientInfo) (context.Context, error) {
		pc.mu.Lock()
		meta, ok := pc.meta[info.RemoteAddr.String()]
		pc.mu.Unlock()
		if !ok {
			return nil, errors.New("no Initial metadata")
		}
		return context.WithValue(ctx, testMetaKey{}, meta), nil
	}
	tc, err := cloneQUICtls(serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	config := referenceQUICConfig()
	config.MaxIncomingStreams = int64(options.MaxFlows + 1)
	l, err := tr.Listen(tc, config)
	if err != nil {
		t.Fatal(err)
	}
	s := &testQUICServer{addr: raw.LocalAddr().String(), conn: pc, sessions: make(chan *QUICSession, 16)}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	t.Cleanup(func() { cancel(); _ = l.Close(); _ = tr.Close(); _ = raw.Close(); wg.Wait() })
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := l.Accept(ctx)
			if err != nil {
				return
			}
			meta, _ := c.Context().Value(testMetaKey{}).(QUICMetadata)
			qs := &QUICSession{connection: c, Metadata: meta, serverOptions: options}
			if err = qs.startLogical(true); err != nil {
				qs.Close()
				continue
			}
			select {
			case s.sessions <- qs:
			default:
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer qs.Close()
				go func() { <-ctx.Done(); qs.Close() }()
				for {
					st, err := qs.Accept(ctx)
					if err != nil {
						return
					}
					go func() {
						if st.Accept() != nil {
							return
						}
						_, _ = io.Copy(st, st)
						_ = st.Close()
					}()
				}
			}()
		}
	}()
	return s
}

func dialTestQUIC(t *testing.T, s *testQUICServer, client *tls.Config) *QUICSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	user := protocol.UserInfo{UID: "quic-test", Token: "token", DeviceID: "device"}
	q, err := DialQUIC(ctx, s.addr, client, QUICInitialOptions{ConnectionID: 7, ChannelID: [16]byte{1, 2, 3},
		EncodeUserInfo: func(r io.Reader) ([128]byte, error) { return protocol.EncodeUserInfo(user, r) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { q.Close() })
	if err = q.waitReady(ctx); err != nil {
		t.Fatal(err)
	}
	return q
}

func echoOnce(c io.ReadWriter, msg string) error {
	if _, err := c.Write([]byte(msg)); err != nil {
		return err
	}
	b := make([]byte, len(msg))
	if _, err := io.ReadFull(c, b); err != nil {
		return err
	}
	if string(b) != msg {
		return errors.New("echo mismatch")
	}
	return nil
}
