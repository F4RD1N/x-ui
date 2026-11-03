package orbit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	xsession "github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/orbit/internal/connectionkey"
	xtransport "github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// These fixtures use locally generated identities and in-memory Xray routed
// links. No provider account, public server, external DNS or production key is
// contacted by the native inbound integration tests.
type d11OrbitIdentity struct {
	certificate string
	privateKey  string
	key         string
	pin         [32]byte
	pair        tls.Certificate
}

func d11OrbitNewIdentity(t *testing.T) d11OrbitIdentity {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{SerialNumber: new(big.Int).Add(serial, big.NewInt(1)), Subject: pkix.Name{CommonName: "Orbit loopback CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "orbit-owned.test"},
		DNSNames:     []string{"orbit-owned.test", "cover.test"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, root, &private.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	id := d11OrbitIdentity{
		certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})),
		privateKey:  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})),
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	id.pin = sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	id.key, _, err = connectionkey.Generate(id.pin)
	if err != nil {
		t.Fatal(err)
	}
	id.pair, err = tls.X509KeyPair([]byte(id.certificate), []byte(id.privateKey))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

type d11OrbitDispatchRecord struct {
	destination xnet.Destination
	tag         string
	name        string
	email       string
	level       uint32
	inbound     *xsession.Inbound
	outbound    *xsession.Outbound
	content     *xsession.Content
}

type d11OrbitDispatcher struct {
	mu           sync.Mutex
	records      []d11OrbitDispatchRecord
	deny         bool
	closed       bool
	mutate       bool
	blockWrites  bool
	writeEntered chan struct{}
	cleanup      []func()
}

var _ routing.Dispatcher = (*d11OrbitDispatcher)(nil)

func (*d11OrbitDispatcher) Type() interface{} { return routing.DispatcherType() }
func (*d11OrbitDispatcher) Start() error      { return nil }
func (d *d11OrbitDispatcher) Close() error {
	d.mu.Lock()
	d.closed = true
	cleanup := d.cleanup
	d.cleanup = nil
	d.mu.Unlock()
	for _, close := range cleanup {
		close()
	}
	return nil
}

func (d *d11OrbitDispatcher) snapshot() []d11OrbitDispatchRecord {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]d11OrbitDispatchRecord(nil), d.records...)
}

func (d *d11OrbitDispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*xtransport.Link, error) {
	in := xsession.InboundFromContext(ctx)
	record := d11OrbitDispatchRecord{destination: dest, inbound: in}
	obs := xsession.OutboundsFromContext(ctx)
	if len(obs) != 0 {
		record.outbound = obs[len(obs)-1]
	}
	record.content = xsession.ContentFromContext(ctx)
	d.mu.Lock()
	mutate := d.mutate
	d.mu.Unlock()
	if mutate {
		// DefaultDispatcher writes the last outbound target and sniffed content
		// concurrently for different flows. Mutate these before acquiring our
		// recording lock so -race actually checks the inbound's context clones.
		marker := dest.Address.String()
		if record.outbound != nil {
			record.outbound.Target = dest
			record.outbound.Name = marker
		}
		if record.content != nil {
			record.content.Protocol = marker
			record.content.SetAttribute("flow", marker)
			if len(record.content.SniffingRequest.ExcludeForDomain) != 0 {
				record.content.SniffingRequest.ExcludeForDomain[0] = marker
			}
			if len(record.content.SniffingRequest.OverrideDestinationForProtocol) != 0 {
				record.content.SniffingRequest.OverrideDestinationForProtocol[0] = marker
			}
		}
	}
	if in != nil {
		record.tag, record.name = in.Tag, in.Name
		if in.User != nil {
			record.email, record.level = in.User.Email, in.User.Level
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.records = append(d.records, record)
	if d.closed || d.deny {
		return nil, errors.New("fixture route denied")
	}
	if d.blockWrites {
		r, w := pipe.New()
		writer := &d11OrbitBlockingWriter{done: make(chan struct{}), entered: d.writeEntered}
		close := func() { r.Interrupt(); _ = w.Close(); writer.Interrupt() }
		stop := context.AfterFunc(ctx, close)
		d.cleanup = append(d.cleanup, func() { stop(); close() })
		return &xtransport.Link{Reader: r, Writer: writer}, nil
	}
	// The dispatcher is an echo route. The inbound's writes come back through
	// its returned Reader, retaining MultiBuffer datagram boundaries and UDP
	// metadata rather than simulating UDP with a stream socket.
	r, w := pipe.New(pipe.WithSizeLimit(1 << 20))
	close := func() { r.Interrupt(); _ = w.Close() }
	stop := context.AfterFunc(ctx, close)
	d.cleanup = append(d.cleanup, func() { stop(); close() })
	return &xtransport.Link{Reader: r, Writer: w}, nil
}

func (*d11OrbitDispatcher) DispatchLink(context.Context, xnet.Destination, *xtransport.Link) error {
	return errors.New("fixture expects packet-preserving Dispatch")
}

type d11OrbitBlockingWriter struct {
	done    chan struct{}
	entered chan struct{}
	once    sync.Once
}

func (w *d11OrbitBlockingWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	select {
	case w.entered <- struct{}{}:
	default:
	}
	<-w.done
	return net.ErrClosed
}
func (w *d11OrbitBlockingWriter) Interrupt()   { w.once.Do(func() { close(w.done) }) }
func (w *d11OrbitBlockingWriter) Close() error { w.Interrupt(); return nil }
