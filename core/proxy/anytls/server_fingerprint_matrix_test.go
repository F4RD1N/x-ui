package anytls

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

// TLS peers can simultaneously write an alert and a handshake record. A small
// bounded asynchronous buffer gives net.Pipe TCP-like write buffering without
// a listener, including on the failing HelloRetryRequest diagnostic path.
type anyTLSHandshakePipe struct {
	net.Conn
	queue chan []byte
	done  chan struct{}
	exit  chan struct{}
	once  sync.Once
}

func anyTLSBufferedHandshakePipe(c net.Conn) *anyTLSHandshakePipe {
	p := &anyTLSHandshakePipe{Conn: c, queue: make(chan []byte, 8), done: make(chan struct{}), exit: make(chan struct{})}
	go func() {
		defer close(p.exit)
		for {
			select {
			case b := <-p.queue:
				if _, err := c.Write(b); err != nil {
					p.Close()
					return
				}
			case <-p.done:
				return
			}
		}
	}()
	return p
}
func (p *anyTLSHandshakePipe) Write(b []byte) (int, error) {
	b = append([]byte(nil), b...)
	select {
	case p.queue <- b:
		return len(b), nil
	case <-p.done:
		return 0, net.ErrClosed
	}
}
func (p *anyTLSHandshakePipe) Close() error {
	p.once.Do(func() { close(p.done); p.Conn.Close() })
	return nil
}

func TestAnyTLSRandomizedFingerprintCompatibilityMatrix(t *testing.T) {
	crt, _ := cert.MustGenerate(nil, cert.DNSNames("anytls.test"))
	public, private := crt.ToPEM()
	for _, name := range []string{"randomized", "randomizednoalpn"} {
		t.Run(name, func(t *testing.T) {
			fingerprint := *xtls.GetFingerprint(name)
			seed := new(utls.PRNGSeed)
			seed[0] = 2
			fingerprint.Seed = seed
			clientConfig := (&xtls.Config{ServerName: "anytls.test", DisableSystemRoot: true, Certificate: []*xtls.Certificate{{Certificate: public, Usage: xtls.Certificate_AUTHORITY_VERIFY}}}).GetTLSConfig()
			serverConfig := (&xtls.Config{CurvePreferences: []string{"X25519", "CurveP256", "CurveP384"}, Certificate: []*xtls.Certificate{{Certificate: public, Key: private, OneTimeLoading: true}}}).GetTLSConfig()
			a, b := net.Pipe()
			left, right := anyTLSBufferedHandshakePipe(a), anyTLSBufferedHandshakePipe(b)
			t.Cleanup(func() {
				left.Close()
				right.Close()
				for _, exited := range []<-chan struct{}{left.exit, right.exit} {
					select {
					case <-exited:
					case <-time.After(time.Second):
						t.Error("handshake buffering worker leaked")
					}
				}
			})
			client := xtls.UClient(left, clientConfig, &fingerprint).(*xtls.UConn)
			if err := client.BuildHandshakeState(); err != nil {
				t.Fatal(err)
			}
			offered, shared := false, false
			for _, curve := range client.HandshakeState.Hello.SupportedCurves {
				if curve == utls.X25519MLKEM768 {
					offered = true
				}
			}
			for _, key := range client.HandshakeState.Hello.KeyShares {
				if key.Group == utls.X25519MLKEM768 {
					shared = true
				}
			}
			if !offered || shared {
				t.Fatal("diagnostic seed must advertise a hybrid group without its share")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = a.SetDeadline(time.Now().Add(3 * time.Second))
			_ = b.SetDeadline(time.Now().Add(3 * time.Second))
			server := xtls.Server(right, serverConfig).(xtls.Interface)
			serverDone := make(chan error, 1)
			go func() { serverDone <- server.HandshakeContext(ctx) }()
			if err := client.HandshakeContext(ctx); err != nil {
				t.Errorf("compatible server rejected unchanged randomized client: %v", err)
			}
			if err := <-serverDone; err != nil {
				t.Errorf("server handshake: %v", err)
			}
		})
	}
}
