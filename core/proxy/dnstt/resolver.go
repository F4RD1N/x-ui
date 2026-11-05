package dnstt

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/nativebridge"
	"github.com/xtls/xray-core/transport/internet"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
	wireDNS "www.bamsoftware.com/git/dnstt.git/dns"
)

type resolverSet struct {
	members   []*dnsResolver
	scheduler *resolverScheduler
	stop      func() bool
	cancel    context.CancelFunc
	once      sync.Once
}

func newResolverSet(ctx context.Context, c *Config, d internet.Dialer) (*resolverSet, error) {
	base, cancel := context.WithCancel(ctx)
	set := &resolverSet{cancel: cancel}
	for _, config := range c.Resolvers {
		if err := ValidateResolver(config); err != nil {
			cancel()
			return nil, err
		}
		resolver := &dnsResolver{ctx: base, cfg: config, dialer: d, pending: make(map[uint16]*resolverWaiter), dialGate: make(chan struct{}, 1), writeGate: make(chan struct{}, 1), timeout: time.Duration(c.QueryTimeout) * time.Second}
		if config.Transport == "doh" {
			resolver.httpTransport = &http.Transport{Proxy: nil, ForceAttemptHTTP2: false, MaxIdleConns: 4, MaxIdleConnsPerHost: 4, MaxConnsPerHost: int(c.MaxConcurrentQueries), IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: resolver.timeout, TLSHandshakeTimeout: resolver.timeout, DisableCompression: true}
			resolver.httpTransport.DialTLSContext = func(call context.Context, _, _ string) (net.Conn, error) { return resolver.dial(call, true) }
			resolver.httpClient = &http.Client{Transport: resolver.httpTransport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		}
		set.members = append(set.members, resolver)
	}
	if len(set.members) > 1 {
		set.scheduler = newResolverScheduler(base, len(set.members), time.Duration(c.QueryTimeout)*time.Second)
	}
	set.stop = context.AfterFunc(base, func() { set.Close() })
	return set, nil
}
func (s *resolverSet) exchange(ctx context.Context, query []byte) ([]byte, error) {
	if len(s.members) == 0 {
		return nil, errors.New("dnstt: no resolver")
	}
	exchange := func(index int) ([]byte, error) {
		resolver := s.members[index]
		if resolver.cfg.Transport == "doh" {
			return resolver.exchangeHTTP(ctx, query)
		}
		return resolver.exchangeStream(ctx, query)
	}
	// Keep the established single-resolver transport and error semantics.
	if s.scheduler == nil {
		return exchange(0)
	}
	return s.scheduler.exchange(ctx, exchange)
}
func (s *resolverSet) Close() {
	s.once.Do(func() {
		s.cancel()
		for _, r := range s.members {
			r.close()
		}
	})
}

type dnsResolver struct {
	ctx           context.Context
	cfg           *Resolver
	dialer        internet.Dialer
	timeout       time.Duration
	httpTransport *http.Transport
	httpClient    *http.Client
	mu            sync.Mutex
	dialGate      chan struct{}
	writeGate     chan struct{}
	conn          net.Conn
	pending       map[uint16]*resolverWaiter
	closed        bool
	wg            sync.WaitGroup
}

func (r *dnsResolver) endpoint() (address, host string, secure bool, err error) {
	port := ""
	switch r.cfg.Transport {
	case "doh":
		var endpoint *url.URL
		endpoint, err = url.Parse(r.cfg.Address)
		if err != nil {
			return
		}
		host = endpoint.Hostname()
		port = endpoint.Port()
		if port == "" {
			port = "443"
		}
		secure = true
	case "dot":
		host, port, err = net.SplitHostPort(r.cfg.Address)
		secure = true
	default:
		host, port, err = net.SplitHostPort(r.cfg.Address)
	}
	if err != nil {
		return
	}
	dialHost := host
	if r.cfg.Bootstrap != "" {
		dialHost = r.cfg.Bootstrap
	}
	address = net.JoinHostPort(dialHost, port)
	if r.cfg.ServerName != "" {
		host = r.cfg.ServerName
	}
	return
}
func (r *dnsResolver) dial(ctx context.Context, forceTLS bool) (result net.Conn, err error) {
	address, host, secure, err := r.endpoint()
	if err != nil {
		return nil, err
	}
	h, p, _ := net.SplitHostPort(address)
	port, _ := strconv.ParseUint(p, 10, 16)
	destination := xnet.TCPDestination(xnet.ParseAddress(h), xnet.Port(port))
	if !secure && !forceTLS {
		destination.Network = xnet.Network_UDP
	}
	life, release := context.WithCancel(r.ctx)
	stopQuery := context.AfterFunc(ctx, release)
	setupTimer := time.AfterFunc(r.timeout, release)
	defer func() {
		timerStopped, queryStopped := setupTimer.Stop(), stopQuery()
		if err == nil && (!timerStopped || !queryStopped || life.Err() != nil || ctx.Err() != nil) {
			if result != nil {
				result.Close()
				result = nil
			}
			err = context.Canceled
		}
		if err != nil {
			release()
		} else {
			result = &resolverOwnedConn{Conn: result, release: release}
		}
	}()
	raw, err := r.dialer.Dial(nativebridge.DialContext(life, destination, "dnstt-resolver"), destination)
	if err != nil {
		return nil, err
	}
	if !secure && !forceTLS {
		return raw, nil
	}
	defer func() {
		if err != nil {
			raw.Close()
		}
	}()
	roots := (*x509.CertPool)(nil)
	if r.cfg.CaPem != "" {
		roots, err = x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM([]byte(r.cfg.CaPem)) {
			return nil, errors.New("dnstt: invalid resolver CA")
		}
	}
	alpn := []string{"dot"}
	if r.cfg.Transport == "doh" {
		alpn = []string{"http/1.1"}
	}
	if r.cfg.Fingerprint == "" {
		tc := tls.Client(raw, &tls.Config{ServerName: host, RootCAs: roots, MinVersion: tls.VersionTLS12, NextProtos: alpn})
		if err = tc.HandshakeContext(life); err != nil {
			return nil, err
		}
		return tc, nil
	}
	fingerprint := xtls.GetFingerprint(r.cfg.Fingerprint)
	if fingerprint == nil {
		return nil, errors.New("dnstt: unknown resolver TLS fingerprint")
	}
	tc := utls.UClient(raw, &utls.Config{ServerName: host, RootCAs: roots, MinVersion: utls.VersionTLS12, NextProtos: alpn}, *fingerprint)
	if err = tc.BuildHandshakeState(); err != nil {
		return nil, err
	}
	found := false
	for _, extension := range tc.Extensions {
		if extension, ok := extension.(*utls.ALPNExtension); ok {
			extension.AlpnProtocols = alpn
			found = true
		}
	}
	if !found {
		tc.Extensions = append(tc.Extensions, &utls.ALPNExtension{AlpnProtocols: alpn})
	}
	if err = tc.BuildHandshakeState(); err != nil {
		return nil, err
	}
	if err = tc.HandshakeContext(life); err != nil {
		return nil, err
	}
	return tc, nil
}

func (r *dnsResolver) exchangeHTTP(ctx context.Context, query []byte) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, r.cfg.Address, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/dns-message")
	request.Header.Set("Accept", "application/dns-message")
	response, err := r.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("dnstt: resolver rejected DNS-over-HTTPS request")
	}
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0]))
	if contentType != "application/dns-message" {
		return nil, errors.New("dnstt: resolver returned a non-DNS body")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil {
		return nil, err
	}
	if len(data) > 4096 {
		return nil, errors.New("dnstt: oversized resolver response")
	}
	return data, nil
}

type resolverOwnedConn struct {
	net.Conn
	release context.CancelFunc
}

func (c *resolverOwnedConn) Close() error { c.release(); return c.Conn.Close() }

type resolverWaiter struct {
	response   chan []byte
	question   string
	typ, class uint16
	originalID uint16
}

func (r *dnsResolver) ensureConn(ctx context.Context) (net.Conn, error) {
	select {
	case r.dialGate <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-r.ctx.Done():
		return nil, net.ErrClosed
	}
	defer func() { <-r.dialGate }()
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, net.ErrClosed
	}
	if r.conn != nil {
		conn := r.conn
		r.mu.Unlock()
		return conn, nil
	}
	r.mu.Unlock()
	conn, err := r.dial(ctx, false)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.ctx.Err() != nil {
		conn.Close()
		return nil, net.ErrClosed
	}
	r.conn = conn
	r.wg.Add(1)
	go r.readLoop(conn)
	return conn, nil
}
func (r *dnsResolver) exchangeStream(ctx context.Context, query []byte) ([]byte, error) {
	message, err := wireDNS.MessageFromWireFormat(query)
	if err != nil || len(message.Question) != 1 {
		return nil, errors.New("dnstt: invalid DNS query")
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	conn, err := r.ensureConn(ctx)
	if err != nil {
		return nil, err
	}
	originalID := message.ID
	id := originalID
	question := message.Question[0]
	waiter := &resolverWaiter{response: make(chan []byte, 1), question: question.Name.String(), typ: question.Type, class: question.Class, originalID: originalID}
	r.mu.Lock()
	if r.closed || r.conn != conn {
		r.mu.Unlock()
		return nil, net.ErrClosed
	}
	for r.pending[id] != nil {
		id++
	}
	r.pending[id] = waiter
	r.mu.Unlock()
	if id != originalID {
		query = bytes.Clone(query)
		binary.BigEndian.PutUint16(query, id)
	}
	defer func() {
		r.mu.Lock()
		if r.pending[id] == waiter {
			delete(r.pending, id)
		}
		r.mu.Unlock()
	}()
	select {
	case r.writeGate <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-r.ctx.Done():
		return nil, net.ErrClosed
	}
	if err = ctx.Err(); err != nil {
		<-r.writeGate
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	err = conn.SetWriteDeadline(deadline)
	if err == nil {
		if r.cfg.Transport == "dot" {
			payload := binary.BigEndian.AppendUint16(nil, uint16(len(query)))
			payload = append(payload, query...)
			err = nativebridge.WriteFull(conn, payload)
		} else {
			var n int
			n, err = conn.Write(query)
			if err == nil && n != len(query) {
				err = io.ErrShortWrite
			}
		}
	}
	<-r.writeGate
	if err != nil {
		r.drop(conn)
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-r.ctx.Done():
		return nil, net.ErrClosed
	case data, ok := <-waiter.response:
		if !ok {
			return nil, errors.New("dnstt: resolver connection closed")
		}
		return data, nil
	}
}

func (r *dnsResolver) readLoop(conn net.Conn) {
	defer r.wg.Done()
	defer r.drop(conn)
	defer nativebridge.RecoverWorker(func(error) {})
	buffer := make([]byte, 4096)
	for {
		var data []byte
		if r.cfg.Transport == "dot" {
			var prefix [2]byte
			if _, err := io.ReadFull(conn, prefix[:]); err != nil {
				return
			}
			size := int(binary.BigEndian.Uint16(prefix[:]))
			if size < 12 || size > len(buffer) {
				return
			}
			if _, err := io.ReadFull(conn, buffer[:size]); err != nil {
				return
			}
			data = bytes.Clone(buffer[:size])
		} else {
			n, err := conn.Read(buffer)
			if err != nil {
				return
			}
			if n < 12 {
				continue
			}
			data = bytes.Clone(buffer[:n])
		}
		id := binary.BigEndian.Uint16(data)
		r.mu.Lock()
		if r.conn != conn {
			r.mu.Unlock()
			return
		}
		if waiter := r.pending[id]; waiter != nil {
			message, err := wireDNS.MessageFromWireFormat(data)
			if err == nil && message.Flags&0x8000 != 0 && len(message.Question) == 1 {
				q := message.Question[0]
				if q.Type == waiter.typ && q.Class == waiter.class && strings.EqualFold(q.Name.String(), waiter.question) {
					binary.BigEndian.PutUint16(data, waiter.originalID)
					select {
					case waiter.response <- data:
					default:
					}
				}
			}
		}
		r.mu.Unlock()
	}
}
func (r *dnsResolver) drop(conn net.Conn) {
	r.mu.Lock()
	if r.conn == conn {
		r.conn = nil
		for id, waiter := range r.pending {
			close(waiter.response)
			delete(r.pending, id)
		}
	}
	r.mu.Unlock()
	conn.Close()
}
func (r *dnsResolver) close() {
	r.mu.Lock()
	r.closed = true
	conn := r.conn
	r.mu.Unlock()
	if conn != nil {
		r.drop(conn)
	}
	if r.httpTransport != nil {
		r.httpTransport.CloseIdleConnections()
	}
	r.wg.Wait()
}
