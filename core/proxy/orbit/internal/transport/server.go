package transport

// Native Orbit carrier server halves. These operate on connections supplied
// by the inbound; listener ownership stays with Xray.
import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gorilla/websocket"
)

// Server reads/decrypts the client's proxy buffer and sends the independently
// generated reverse header (VPN-Core transport.Server).
func Server(ctx context.Context, raw net.Conn, options Options) (*Conn, []byte, error) {
	return serverWithPrefix(ctx, raw, options, nil)
}

func serverWithPrefix(ctx context.Context, raw net.Conn, options Options, responsePrefix []byte) (result *Conn, proxy []byte, err error) {
	o, err := options.normalized()
	if err != nil {
		_ = raw.Close()
		return nil, nil, err
	}
	finish, err := handshakeLifetime(ctx, raw, o.Timeout)
	if err != nil {
		_ = raw.Close()
		return nil, nil, err
	}
	defer func() {
		if e := finish(err == nil); e != nil {
			err = e
			result = nil
			proxy = nil
		}
	}()
	return serverHandshake(raw, o, bufio.NewReaderSize(raw, 4096), responsePrefix)
}

func serverHandshake(raw net.Conn, o Options, r *bufio.Reader, responsePrefix []byte) (*Conn, []byte, error) {
	key, err := readHeader(r, o.MaxScanBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("transport client header: %w", err)
	}
	dec := ctr(key)
	var length [2]byte
	if _, err = io.ReadFull(r, length[:]); err != nil {
		return nil, nil, err
	}
	if !o.plain {
		dec.XORKeyStream(length[:], length[:])
	}
	n := int(binary.LittleEndian.Uint16(length[:]))
	if n > o.MaxProxyBytes {
		return nil, nil, ErrProxyBuffer
	}
	proxy := make([]byte, n)
	if _, err = io.ReadFull(r, proxy); err != nil {
		return nil, nil, err
	}
	if !o.plain {
		dec.XORKeyStream(proxy, proxy)
	}
	header, peerKey, err := MakeHeader(o.Random)
	if err != nil {
		return nil, nil, err
	}
	if _, err = writeFull(raw, append(responsePrefix, header...)); err != nil {
		return nil, nil, err
	}
	var enc = ctr(peerKey)
	if o.plain {
		return &Conn{Conn: raw, reader: r}, proxy, nil
	}
	return &Conn{Conn: raw, reader: r, readCipher: dec, writeCipher: enc}, proxy, nil
}

type HTTPServerOptions struct {
	Options
	TLSConfig *tls.Config
}

// HTTPServer strips only the recovered header prefix (VPN-Core HTTPServer).
func HTTPServer(ctx context.Context, raw net.Conn, options HTTPServerOptions) (result *Conn, proxy []byte, err error) {
	o, err := options.Options.normalized()
	if err != nil {
		_ = raw.Close()
		return nil, nil, err
	}
	finish, err := handshakeLifetime(ctx, raw, o.Timeout)
	if err != nil {
		_ = raw.Close()
		return nil, nil, err
	}
	defer func() {
		if e := finish(err == nil); e != nil {
			result = nil
			proxy = nil
			err = e
		}
	}()
	if options.TLSConfig != nil {
		secure := tls.Server(raw, options.TLSConfig.Clone())
		if err = secure.HandshakeContext(ctx); err != nil {
			return nil, nil, err
		}
		raw = secure
	}
	r := bufio.NewReaderSize(raw, 4096)
	header := make([]byte, 0, 1024)
	for len(header) < o.MaxScanBytes {
		b, e := r.ReadByte()
		if e != nil {
			return nil, nil, e
		}
		header = append(header, b)
		if len(header) >= 4 && string(header[len(header)-4:]) == "\r\n\r\n" {
			break
		}
	}
	if !strings.HasPrefix(string(header), "GET ") || !strings.HasSuffix(string(header), "\r\n\r\n") {
		return nil, nil, ErrHTTPProfile
	}
	h, err := parseHTTPAuthorization(string(header))
	if err != nil {
		return nil, nil, err
	}
	o.plain = h.CheaterID == 2 || h.CheaterID == 3
	prefix := []byte("HTTP/1.1 200 OK\r\n\r\n")
	if strings.Contains(string(header), "websocket") {
		prefix = []byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n\r\n")
	}
	return serverHandshake(raw, o, r, prefix)
}

func parseHTTPAuthorization(header string) (HTTPHeader, error) {
	start := strings.Index(header, "Authorization: ")
	if start < 0 {
		return HTTPHeader{}, ErrHTTPProfile
	}
	s := header[start+len("Authorization: "):]
	end := strings.Index(s, "\r\n")
	if end < 0 || end > 128 {
		return HTTPHeader{}, ErrHTTPProfile
	}
	b, e := base64.StdEncoding.DecodeString(s[:end])
	if e != nil {
		return HTTPHeader{}, ErrHTTPProfile
	}
	for i := range b {
		b[i] = ^b[i]
	}
	fields := strings.Split(string(b), "|")
	if len(fields) != 5 {
		return HTTPHeader{}, ErrHTTPProfile
	}
	if _, e = strconv.ParseInt(fields[1], 10, 32); e != nil {
		return HTTPHeader{}, ErrHTTPProfile
	}
	a, e := strconv.ParseUint(fields[2], 10, 16)
	if e != nil {
		return HTTPHeader{}, ErrHTTPProfile
	}
	c, e := strconv.ParseUint(fields[3], 10, 16)
	if e != nil {
		return HTTPHeader{}, ErrHTTPProfile
	}
	return HTTPHeader{CheaterID: uint16(a), CustomID: uint16(c)}, nil
}

// AcceptWebSocket performs only the RFC6455 upgrade and strict same-authority
// origin validation. The caller must enforce the path/Host allowlist and
// admission limits, then authenticate the inner TLS and native session.
func AcceptWebSocket(ctx context.Context, w http.ResponseWriter, r *http.Request) (net.Conn, error) {
	u := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool {
		_, valid := NormalizeWebSocketOrigin(r)
		return valid
	}}
	ws, err := u.Upgrade(w, r, nil)
	if err != nil {
		return nil, err
	}
	return newWebSocketStream(ctx, ws), nil
}

// NormalizeWebSocketOrigin accepts a missing Origin for legacy native clients
// or an HTTP(S) origin for the exact request authority. An explicit default
// port is normalized; forwarded headers are never trusted. Origin is routing
// policy, not a substitute for native authentication.
func NormalizeWebSocketOrigin(r *http.Request) (string, bool) {
	var origins []string
	present := false
	for name, values := range r.Header {
		if strings.EqualFold(name, "Origin") {
			if present || len(values) != 1 {
				return "", false
			}
			present = true
			origins = values
		}
	}
	if !present {
		return "", true
	}
	if len(origins) != 1 {
		return "", false
	}
	origin := origins[0]
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		u.User != nil || u.Opaque != "" || u.Path != "" || u.RawPath != "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		origin != u.Scheme+"://"+u.Host {
		return "", false
	}
	port := ":80"
	if u.Scheme == "https" {
		port = ":443"
	}
	if !strings.EqualFold(u.Host, r.Host) && !strings.EqualFold(u.Host, r.Host+port) {
		return "", false
	}
	return u.Scheme + "://" + r.Host, true
}
