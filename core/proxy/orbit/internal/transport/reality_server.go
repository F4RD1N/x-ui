package transport

import (
	"context"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/reality"
)

// RealityServerOptions configures an owned REALITY listener's cover destination.
// Target is a TCP host:port, independently of the allowed ClientHello names.
type RealityServerOptions struct {
	PrivateKey  string // Unpadded base64url X25519 private key, exactly 32 bytes.
	ShortIDs    []string
	ServerNames []string
	Target      string
	MaxTimeDiff time.Duration // Zero means one minute.
	// CoverRootCAs optionally trusts an owned cover's CA. Nil uses the system
	// roots. This trust store is used only during the startup cover probes.
	CoverRootCAs *x509.CertPool
}

// RealityServer holds immutable handshake configuration shared by a listener.
// Construct it once before accepting connections.
type RealityServer struct {
	config *reality.Config
}

// NewRealityServer validates the configuration and measures the explicitly
// configured cover's post-handshake records. Probes run sequentially under ctx;
// no listener or periodic background probe is started by this constructor.
func NewRealityServer(ctx context.Context, options RealityServerOptions) (*RealityServer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rawKey, err := realityKey(options.PrivateKey)
	if err != nil {
		return nil, err
	}
	if len(options.ServerNames) == 0 || len(options.ServerNames) > 32 || len(options.ShortIDs) == 0 || len(options.ShortIDs) > 32 {
		return nil, errors.New("transport: REALITY requires one to thirty-two server names and short IDs")
	}
	if _, _, err = net.SplitHostPort(options.Target); err != nil {
		return nil, errors.New("transport: REALITY target must be a TCP host:port")
	}
	if options.MaxTimeDiff < 0 {
		return nil, errors.New("transport: REALITY maximum time difference cannot be negative")
	}
	if options.MaxTimeDiff == 0 {
		options.MaxTimeDiff = time.Minute
	}
	config := &reality.Config{
		DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		Type:        "tcp", Dest: options.Target, PrivateKey: rawKey,
		ServerNames: make(map[string]bool), ShortIds: make(map[[8]byte]bool),
		MaxTimeDiff: options.MaxTimeDiff,
		// REALITY emits its own empty records to match the cover's ticket
		// lengths. A genuine TLS resumption ticket would be rewritten by that
		// camouflage path and produce an invalid post-handshake message.
		SessionTicketsDisabled: true,
	}
	for _, name := range options.ServerNames {
		if !validRealityServerName(name) || config.ServerNames[name] {
			return nil, errors.New("transport: REALITY requires DNS server names")
		}
		config.ServerNames[name] = true
	}
	for _, encoded := range options.ShortIDs {
		id, err := realityShortID(encoded)
		if err != nil {
			return nil, err
		}
		config.ShortIds[id] = true
	}
	// The upstream server waits for these entries before releasing an accepted
	// connection. Probe into local bounded buffers first: a failed constructor
	// must not replace a working listener's process-wide cover measurements.
	startupCtx, stopStartup := context.WithTimeout(ctx, 30*time.Second)
	defer stopStartup()
	measurements := make(map[string][]int, len(options.ServerNames)*3)
	for _, name := range options.ServerNames {
		for alpn := range 3 {
			lengths, probeErr := probeRealityCover(startupCtx, config, name, alpn, options.CoverRootCAs)
			if probeErr != nil {
				return nil, fmt.Errorf("transport: REALITY cover probe: %w", probeErr)
			}
			measurements[realityCoverKey(config.Dest, name, alpn)] = lengths
		}
	}
	if err = startupCtx.Err(); err != nil {
		return nil, err
	}
	for key, lengths := range measurements {
		reality.GlobalPostHandshakeRecordsLens.Store(key, lengths)
	}
	return &RealityServer{config: config}, nil
}

func realityCoverKey(target, name string, alpn int) string {
	return target + " " + name + " " + strconv.Itoa(alpn)
}

// The collector observes only encrypted TLS record lengths after the client
// Finished. Neither cover application data nor unbounded buffers are retained.
type realityCoverCollector struct {
	net.Conn
	afterCCS bool
	lengths  []int
	err      error
}

func (c *realityCoverCollector) Write(data []byte) (int, error) {
	if len(data) >= 3 && data[0] == 20 && data[1] == 3 && data[2] == 3 {
		c.afterCCS = true
	}
	return c.Conn.Write(data)
}

func (c *realityCoverCollector) Read(data []byte) (int, error) {
	if !c.afterCCS {
		return c.Conn.Read(data)
	}
	const maximum = 64 * 1024
	buffer, readErr := io.ReadAll(io.LimitReader(c.Conn, maximum+1))
	if len(buffer) > maximum {
		c.err = errors.New("cover post-handshake response exceeds 64 KiB")
		return 0, io.EOF
	}
	if readErr != nil {
		if timeout, ok := readErr.(net.Error); !ok || !timeout.Timeout() {
			c.err = readErr
			return 0, io.EOF
		}
	}
	for len(buffer) > 0 {
		if len(buffer) < 5 || buffer[0] != 23 || buffer[1] != 3 || buffer[2] != 3 {
			c.err = errors.New("cover sent a malformed post-handshake TLS record")
			return 0, io.EOF
		}
		length := 5 + int(binary.BigEndian.Uint16(buffer[3:5]))
		if length < 22 || length > 17*1024 || length > len(buffer) || len(c.lengths) == 32 {
			c.err = errors.New("cover sent an oversized or truncated post-handshake TLS record")
			return 0, io.EOF
		}
		c.lengths = append(c.lengths, length)
		buffer = buffer[length:]
	}
	return 0, io.EOF
}

func probeRealityCover(ctx context.Context, config *reality.Config, name string, alpn int, roots *x509.CertPool) ([]int, error) {
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	raw, err := config.DialContext(probeCtx, config.Type, config.Dest)
	if err != nil {
		return nil, err
	}
	defer raw.Close()
	stop := context.AfterFunc(probeCtx, func() { raw.Close() })
	defer stop()
	deadline, _ := probeCtx.Deadline()
	if err = raw.SetDeadline(deadline); err != nil {
		return nil, err
	}
	recorder := &realityCoverCollector{Conn: raw, lengths: []int{}}
	id := utls.HelloGolang
	var next []string
	if alpn == 1 {
		next = []string{"http/1.1"}
	} else if alpn == 2 {
		next = []string{"h2", "http/1.1"}
		id = utls.HelloChrome_Auto
	}
	client := utls.UClient(recorder, &utls.Config{
		ServerName: name, RootCAs: roots, NextProtos: next,
		MinVersion: utls.VersionTLS13, MaxVersion: utls.VersionTLS13,
	}, id)
	if err = client.HandshakeContext(probeCtx); err != nil {
		if contextErr := probeCtx.Err(); contextErr != nil {
			return nil, contextErr
		}
		if !time.Now().Before(deadline) {
			return nil, context.DeadlineExceeded
		}
		return nil, err
	}
	// A cover may emit session tickets after its Finished. Collect only TLS
	// records, with no HTTP request, for a short bounded idle interval.
	if err = raw.SetReadDeadline(minTime(deadline, time.Now().Add(200*time.Millisecond))); err != nil {
		return nil, err
	}
	_, _ = io.Copy(io.Discard, client)
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if recorder.err != nil {
		return nil, recorder.err
	}
	return recorder.lengths, nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// Accept authenticates an incoming REALITY connection. Only the official
// server's accepted stream is returned; cover fallback never reaches native
// authentication. Failure and cancellation close the supplied connection.
func (s *RealityServer) Accept(ctx context.Context, raw net.Conn) (_ net.Conn, err error) {
	if raw == nil {
		return nil, errors.New("transport: REALITY requires a connection")
	}
	if s == nil || s.config == nil {
		raw.Close()
		return nil, errors.New("transport: REALITY server is uninitialized")
	}
	if _, ok := raw.(reality.CloseWriteConn); !ok {
		raw.Close()
		return nil, errors.New("transport: REALITY requires a TCP connection with half-close support")
	}
	if err = ctx.Err(); err != nil {
		raw.Close()
		return nil, err
	}
	// Embedded callers also receive a bounded handshake when they supply a
	// background context. Explicit caller deadlines remain authoritative.
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
	}
	// reality.Server uses background contexts internally once the cover has
	// connected. Closing raw and its cover on cancellation interrupts both
	// directions and prevents an unresponsive peer from retaining a handshake.
	var cover net.Conn
	var coverMu sync.Mutex
	serverCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	config := s.config.Clone()
	config.DialContext = func(_ context.Context, network, address string) (net.Conn, error) {
		conn, dialErr := s.config.DialContext(serverCtx, network, address)
		if dialErr == nil {
			coverMu.Lock()
			cover = conn
			if ctx.Err() != nil {
				conn.Close()
			}
			coverMu.Unlock()
		}
		return conn, dialErr
	}
	stop := context.AfterFunc(serverCtx, func() {
		raw.Close()
		coverMu.Lock()
		if cover != nil {
			cover.Close()
		}
		coverMu.Unlock()
	})
	defer stop()
	conn, err := reality.Server(serverCtx, raw, config)
	if err != nil {
		raw.Close()
		coverMu.Lock()
		if cover != nil {
			cover.Close()
		}
		coverMu.Unlock()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("transport: REALITY accept: %w", err)
	}
	if ctx.Err() != nil {
		conn.Close()
		return nil, ctx.Err()
	}
	return &authenticatedRealityConn{Conn: conn}, nil
}
