package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtls/xray-core/proxy/orbit/internal/wsoptions"
)

// WebSocketMessageLimit bounds a single incoming message. Writes are split into
// smaller binary messages; message boundaries have no meaning to the tunnel.
const WebSocketMessageLimit = 64 << 10
const webSocketWriteChunk = 16 << 10

type WebSocketDialOptions struct {
	Address, Host, Path string
	Secure              bool
	Timeout             time.Duration
	DialContext         func(context.Context, string, string) (net.Conn, error)
	// TLSConfig can add trust roots or stricter checks for an embedding. Normal
	// hostname verification is mandatory, with Host as SNI. This is the outer
	// HTTPS connection only; the tunnel authenticates its own pinned TLS key.
	TLSConfig *tls.Config
	// Fingerprint selects the outer WSS ClientHello only. "unsafe" retains
	// ordinary verified Go TLS. The inner key-pinned tunnel is independent.
	Fingerprint string
	UserAgent   string
	Headers     map[string]string
	// Browser is empty/on for browser-compatible defaults, or off for the
	// previous handshake. Explicit fingerprint/UA/header settings take priority.
	Browser string
}

// DialWebSocket deliberately does not use environment HTTP proxies or redirects.
// Address chooses the network endpoint; Host chooses HTTP routing and WSS SNI.
//
// VPN-Core dials with coder/websocket through net/http. This copy uses the
// gorilla/websocket client already in Xray's module graph. Both write the
// request with net/http's Request writer (sorted header names), send no
// compression extension and no proxy, and refuse redirects.
func DialWebSocket(ctx context.Context, o WebSocketDialOptions) (net.Conn, error) {
	if o.Address == "" || o.Host == "" || o.Path == "" || o.DialContext == nil {
		return nil, errors.New("incomplete WebSocket dial options")
	}
	if err := wsoptions.Validate(o.Fingerprint, o.UserAgent, o.Headers, o.Secure); err != nil {
		return nil, err
	}
	if err := wsoptions.ValidateBrowser(o.Browser); err != nil {
		return nil, err
	}
	if o.Browser != "off" && o.Secure && o.Fingerprint == "" {
		o.Fingerprint = "chrome"
	}
	headers, err := webSocketHeaders(o)
	if err != nil {
		return nil, err
	}
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}
	tc := &tls.Config{}
	if o.TLSConfig != nil {
		tc = o.TLSConfig.Clone()
	}
	if tc.InsecureSkipVerify {
		return nil, errors.New("outer WebSocket TLS requires normal certificate verification")
	}
	tc.ServerName = o.Host
	if tc.MinVersion < tls.VersionTLS12 {
		tc.MinVersion = tls.VersionTLS12
	}
	tc.NextProtos = []string{"http/1.1"}
	d := &websocket.Dialer{
		NetDialContext:   o.DialContext,
		TLSClientConfig:  tc,
		HandshakeTimeout: o.Timeout,
	}
	if o.Secure && o.Fingerprint != "" && o.Fingerprint != "unsafe" {
		dialTLS, err := fingerprintDialer(o.Fingerprint, tc, o.DialContext)
		if err != nil {
			return nil, err
		}
		d.NetDialTLSContext = dialTLS
	}
	// The Host header is applied by the dialer as the request's Host.
	headers.Set("Host", o.Host)
	scheme := "ws"
	if o.Secure {
		scheme = "wss"
	}
	u := url.URL{Scheme: scheme, Host: o.Address, Path: o.Path}
	handshake, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	ws, response, err := d.DialContext(handshake, u.String(), headers)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		if response != nil {
			return nil, errors.New("WebSocket upgrade refused with HTTP " + response.Status)
		}
		return nil, err
	}
	return newWebSocketStream(ctx, ws), nil
}

// webSocketStream is the net.Conn view of one binary-message WebSocket, as
// coder/websocket's NetConn provides in VPN-Core: reads continue across
// message boundaries, each write chunk is one binary message, a normal close
// reads as EOF and Close drops the socket without a close handshake.
type webSocketStream struct {
	ws      *websocket.Conn
	readMu  sync.Mutex
	reader  io.Reader
	writeMu sync.Mutex
	once    sync.Once
	stopMu  sync.Mutex
	stop    func() bool
}

func newWebSocketStream(ctx context.Context, ws *websocket.Conn) net.Conn {
	ws.SetReadLimit(WebSocketMessageLimit)
	c := &webSocketStream{ws: ws}
	// An idle upgraded socket must also close on cancellation. Stop the
	// callback as part of every explicit close.
	// stopMu: when ctx is already done the callback's Close can run before
	// AfterFunc has returned the stop function it reads.
	c.stopMu.Lock()
	c.stop = context.AfterFunc(ctx, func() { _ = c.Close() })
	c.stopMu.Unlock()
	return c
}

func (c *webSocketStream) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		if c.reader == nil {
			kind, r, err := c.ws.NextReader()
			if err != nil {
				return 0, webSocketError(err)
			}
			if kind != websocket.BinaryMessage {
				_ = c.Close()
				return 0, errors.New("WebSocket: unexpected text message")
			}
			c.reader = r
		}
		n, err := c.reader.Read(p)
		if err == io.EOF {
			c.reader = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		if err != nil {
			return n, webSocketError(err)
		}
		return n, nil
	}
}

func webSocketError(err error) error {
	if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
		return io.EOF
	}
	return err
}

func (c *webSocketStream) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	written := 0
	for len(p) > 0 {
		n := min(len(p), webSocketWriteChunk)
		if err := c.ws.WriteMessage(websocket.BinaryMessage, p[:n]); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

func (c *webSocketStream) Close() error {
	c.once.Do(func() {
		c.stopMu.Lock()
		stop := c.stop
		c.stopMu.Unlock()
		if stop != nil {
			stop()
		}
		// Immediate shutdown unblocks tunnel workers; no close-frame exchange
		// is needed when the authenticated stream is already closing.
		_ = c.ws.Close()
	})
	return nil
}

func (c *webSocketStream) LocalAddr() net.Addr  { return c.ws.LocalAddr() }
func (c *webSocketStream) RemoteAddr() net.Addr { return c.ws.RemoteAddr() }
func (c *webSocketStream) SetDeadline(t time.Time) error {
	if err := c.ws.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}
func (c *webSocketStream) SetReadDeadline(t time.Time) error { return c.ws.SetReadDeadline(t) }

// SetWriteDeadline takes writeMu: gorilla stores the write deadline in a
// plain field that WriteMessage reads, and the session's writer and
// tls.Conn.Close (its closeNotify) both set it, from different goroutines.
// (coder/websocket, which VPN-Core uses, is safe for this by itself.)
func (c *webSocketStream) SetWriteDeadline(t time.Time) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.ws.SetWriteDeadline(t)
}
