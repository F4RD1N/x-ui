// Package fixture supplies an isolated resolver for dnstt interoperability
// tests. It forwards only the explicitly configured tunnel zone and never
// performs Internet recursion.
package fixture

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const ServerName = "resolver.test"

// Resolver exposes UDP, DoT and DoH endpoints with a locally generated CA.
// Every endpoint forwards the exact DNS wire request to Authority.
type Resolver struct {
	UDP, DoT, DoH  string
	CAFile         string
	CAPEM          string
	Queries        atomic.Int64
	TLSQueries     atomic.Int64
	HTTPQueries    atomic.Int64
	TLSConnections atomic.Int64
	// DropFirst and DropEvery intentionally discard allowed DNS queries.
	// They are only fault injection for this controlled test fixture.
	DropFirst    atomic.Uint64
	DropEvery    atomic.Uint64
	Dropped      atomic.Uint64
	attempts     atomic.Uint64
	zone         string
	authority    string
	udp          *dns.Server
	dot          net.Listener
	dotConns     sync.Map
	http         *http.Server
	httpListener net.Listener
}

// Start binds only loopback ephemeral ports. The returned CA is suitable for
// normal certificate and SNI verification; insecure TLS is never required.
func Start(dir, zone, authority string) (*Resolver, error) {
	r := &Resolver{zone: strings.ToLower(dns.Fqdn(zone)), authority: authority}
	cert, ca, err := makeCertificate()
	if err != nil {
		return nil, err
	}
	r.CAFile = filepath.Join(dir, "resolver-ca.pem")
	r.CAPEM = string(ca)
	if err = os.WriteFile(r.CAFile, ca, 0600); err != nil {
		return nil, err
	}
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	r.UDP = udp.LocalAddr().String()
	r.udp = &dns.Server{PacketConn: udp, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		r.Queries.Add(1)
		r.serveDNS(w, q)
	})}
	go r.udp.ActivateAndServe()
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	dot, err := tls.Listen("tcp4", "127.0.0.1:0", tlsConfig)
	if err != nil {
		r.Close()
		return nil, err
	}
	r.DoT = dot.Addr().String()
	r.dot = dot
	go r.serveDoT()
	https, err := tls.Listen("tcp4", "127.0.0.1:0", tlsConfig.Clone())
	if err != nil {
		r.Close()
		return nil, err
	}
	r.httpListener = https
	r.DoH = "https://" + https.Addr().String() + "/dns-query"
	r.http = &http.Server{Handler: http.HandlerFunc(r.serveHTTP), ReadHeaderTimeout: 5 * time.Second}
	go r.http.Serve(https)
	return r, nil
}

func (r *Resolver) exchange(q *dns.Msg) *dns.Msg {
	answer := new(dns.Msg)
	answer.SetReply(q)
	if len(q.Question) != 1 || !dns.IsSubDomain(r.zone, strings.ToLower(q.Question[0].Name)) {
		answer.Rcode = dns.RcodeRefused
		return answer
	}
	n := r.attempts.Add(1)
	if every := r.DropEvery.Load(); n <= r.DropFirst.Load() || (every != 0 && n%every == 0) {
		r.Dropped.Add(1)
		return nil
	}
	client := &dns.Client{Net: "udp", UDPSize: 4096, Timeout: 3 * time.Second}
	response, _, err := client.Exchange(q, r.authority)
	if err != nil {
		answer.Rcode = dns.RcodeServerFailure
		return answer
	}
	return response
}

func (r *Resolver) serveDNS(w dns.ResponseWriter, q *dns.Msg) {
	if answer := r.exchange(q); answer != nil {
		_ = w.WriteMsg(answer)
	}
}

// RFC 7766 clients pipeline queries on one TLS connection. In particular,
// dnstt's empty polls may wait one second upstream, so processing requests
// serially would put later data behind every outstanding empty poll. Replies
// may arrive out of order and are paired by DNS transaction ID.
func (r *Resolver) serveDoT() {
	for {
		conn, err := r.dot.Accept()
		if err != nil {
			return
		}
		r.dotConns.Store(conn, struct{}{})
		r.TLSConnections.Add(1)
		go r.serveDoTConn(conn)
	}
}

func (r *Resolver) serveDoTConn(conn net.Conn) {
	defer conn.Close()
	defer r.dotConns.Delete(conn)
	var writeMu sync.Mutex
	workers := make(chan struct{}, 64)
	for {
		var size [2]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return
		}
		wire := make([]byte, int(binary.BigEndian.Uint16(size[:])))
		if _, err := io.ReadFull(conn, wire); err != nil {
			return
		}
		var question dns.Msg
		if question.Unpack(wire) != nil {
			return
		}
		workers <- struct{}{}
		r.TLSQueries.Add(1)
		go func(q *dns.Msg) {
			defer func() { <-workers }()
			response := r.exchange(q)
			if response == nil {
				return
			}
			answer, err := response.Pack()
			if err != nil {
				return
			}
			frame := binary.BigEndian.AppendUint16(nil, uint16(len(answer)))
			frame = append(frame, answer...)
			writeMu.Lock()
			defer writeMu.Unlock()
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, _ = conn.Write(frame)
		}(&question)
	}
}

func (r *Resolver) serveHTTP(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/dns-query" {
		http.NotFound(w, req)
		return
	}
	var wire []byte
	var err error
	switch req.Method {
	case http.MethodPost:
		if req.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "expected application/dns-message", http.StatusUnsupportedMediaType)
			return
		}
		wire, err = io.ReadAll(io.LimitReader(req.Body, 65536))
	case http.MethodGet:
		wire, err = base64.RawURLEncoding.DecodeString(req.URL.Query().Get("dns"))
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var q dns.Msg
	if err != nil || len(wire) > 65535 || q.Unpack(wire) != nil {
		http.Error(w, "bad DNS message", http.StatusBadRequest)
		return
	}
	r.HTTPQueries.Add(1)
	answer := r.exchange(&q)
	if answer == nil {
		<-req.Context().Done()
		return
	}
	response, err := answer.Pack()
	if err != nil {
		http.Error(w, "bad DNS response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	w.Write(response)
}

func (r *Resolver) Close() {
	if r.udp != nil {
		r.udp.Shutdown()
	}
	if r.dot != nil {
		r.dot.Close()
		r.DisconnectDoT()
	}
	if r.http != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		r.http.Shutdown(ctx)
		cancel()
		r.http.Close()
	}
	if r.httpListener != nil {
		r.httpListener.Close()
	}
}

// DisconnectDoT breaks current TLS underlays while preserving the listening
// endpoint and authority. It simulates resolver connection loss without
// restarting a service or replaying an authenticated inner request.
func (r *Resolver) DisconnectDoT() {
	r.dotConns.Range(func(key, _ any) bool {
		key.(net.Conn).Close()
		return true
	})
}

func makeCertificate() (tls.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: ServerName},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour),
		DNSNames: []string{ServerName}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:        true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("marshal fixture key: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	return cert, certPEM, err
}
