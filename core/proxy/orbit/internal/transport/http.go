package transport

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

var ErrHTTPProfile = errors.New("transport: malformed or unsupported HTTP profile")

// HTTPHeader is the four-slot HttpCheaterHeader profile. A private orbit://
// link (VPN-Core's core:// link) always produces CheaterID 2 with the inner
// origin name as Domain; the custom/ByeDPI slots stay zero (VPN-Core
// config.ClientFromConnection).
type HTTPHeader struct {
	CheaterID, CustomID uint16
	Domain, Extra       string
}

// HTTPOptions selects the original TCP client factory types 1 (HTTP), 2 or 3
// (real TLS followed by the HTTP upgrade prefix). There are no WebSocket frames.
type HTTPOptions struct {
	Options
	Type   uint16
	Header HTTPHeader
	Path   string
	// TLSConfig is the mandatory pinned inner TLS configuration for types 2/3.
	TLSConfig *tls.Config
	// NativeTLS selects the offline-recovered ARM64 BoringSSL ClientHello for
	// direct TCP profiles2/3. WebSocket carriers leave it false.
	NativeTLS bool
	// Reality skips a second TLS handshake only after DialReality has already
	// authenticated this exact connection. A plain net.Conn cannot select it.
	Reality bool
	// ByeDPI says the connection runs through the route's ByeDPI (Xray's
	// in-process engine), which stands in for VPN-Core's local SOCKS
	// helper: a custom ID 1 route is then served directly, with no SOCKS
	// hop in between.
	ByeDPI bool
}

func safeHTTPText(s string) bool {
	for _, c := range s {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}

type httpRandom struct {
	reader io.Reader
	err    error
}

func (r *httpRandom) number(n uint32) uint32 {
	if r.err != nil {
		return 0
	}
	var p [4]byte
	_, r.err = io.ReadFull(r.reader, p[:])
	return binary.LittleEndian.Uint32(p[:]) % n
}

const httpAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890"

func (r *httpRandom) text(n int, alphabet string) string {
	p := make([]byte, n)
	for i := range p {
		p[i] = alphabet[r.number(uint32(len(alphabet)))]
	}
	return string(p)
}
func (r *httpRandom) authorization(h HTTPHeader) string {
	prefix := r.text(4+int(r.number(10)), httpAlphabet)
	suffix := r.text(5+int(r.number(10)), httpAlphabet)
	b := []byte(fmt.Sprintf("%s|0|%d|%d|%s", prefix, h.CheaterID, h.CustomID, suffix))
	for i := range b {
		b[i] = ^b[i]
	}
	return base64.StdEncoding.EncodeToString(b)
}
func (r *httpRandom) cookie() string {
	n := 1 + int(r.number(5))
	cookies := make([]string, n)
	for i := range cookies {
		name := r.text(1+int(r.number(3)), "abcdefghijklmnopqrstuvwxyz1234567890")
		value := r.text(4+int(r.number(12)), httpAlphabet)
		cookies[i] = name + "=" + value
	}
	return strings.Join(cookies, ";")
}

// MakeHTTPHeader duplicates the native order and random-word consumption. The
// Authorization value encodes profile metadata; it is not user authentication.
func MakeHTTPHeader(kind uint16, h HTTPHeader, path string, source io.Reader) ([]byte, error) {
	if kind < 1 || kind > 3 || !safeHTTPText(h.Domain) || !safeHTTPText(path) || len(path) > 1024 || len(h.Domain) > 253 || strings.Contains(path, " ") {
		return nil, ErrHTTPProfile
	}
	if source == nil {
		source = rand.Reader
	}
	r := httpRandom{reader: source}
	var out strings.Builder
	fmt.Fprintf(&out, "GET %s HTTP/1.1\r\n", path)
	if kind != 1 {
		ua := httpUserAgents[r.number(uint32(len(httpUserAgents)))]
		auth := r.authorization(h)
		fmt.Fprintf(&out, "User-Agent: %s\r\nUpgrade: websocket\r\nAuthorization: %s\r\n", ua, auth)
		if h.Domain != "" {
			fmt.Fprintf(&out, "Host: %s\r\n", h.Domain)
		}
		out.WriteString("Connection: Upgrade\r\n")
	} else {
		order := []int{3, 4, 5, 6, 7, 8, 9, 10}
		for i := len(order) - 1; i > 0; i-- {
			j := int(r.number(uint32(i + 1)))
			order[i], order[j] = order[j], order[i]
		}
		insert := func(id int) {
			i := int(r.number(3))
			order = append(order, 0)
			copy(order[i+1:], order[i:])
			order[i] = id
		}
		insert(1)
		insert(2)
		if h.Domain != "" {
			insert(0)
		}
		n := 6 + int(r.number(uint32(len(order)-6)))
		for _, id := range order[:n] {
			switch id {
			case 0:
				fmt.Fprintf(&out, "Host: %s\r\n", h.Domain)
			case 1:
				fmt.Fprintf(&out, "Authorization: %s\r\n", r.authorization(h))
			case 2:
				fmt.Fprintf(&out, "User-Agent: %s\r\n", httpUserAgents[r.number(uint32(len(httpUserAgents)))])
			case 3:
				fmt.Fprintf(&out, "Accept-Encoding: %s\r\n", httpEncodings[r.number(4)])
			case 4:
				fmt.Fprintf(&out, "Accept: %s\r\n", httpAccepts[r.number(4)])
			case 5:
				out.WriteString("Connection: keep-alive\r\n")
			case 6:
				out.WriteString("Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,de;q=0.6\r\n")
			case 7:
				fmt.Fprintf(&out, "X-Client-Data: %s\r\n", r.text(10+int(r.number(30)), httpAlphabet))
			case 8:
				fmt.Fprintf(&out, "Content-Length: %d\r\n", r.number(65536))
			case 9:
				fmt.Fprintf(&out, "Cookie: %s\r\n", r.cookie())
			case 10:
				fmt.Fprintf(&out, "Content-Type: %s\r\n", httpContentTypes[r.number(4)])
			}
		}
	}
	out.WriteString("\r\n")
	if r.err != nil {
		return nil, r.err
	}
	if out.Len() > 2079 {
		return nil, ErrHTTPProfile
	}
	return []byte(out.String()), nil
}

func HTTPClient(ctx context.Context, raw net.Conn, options HTTPOptions) (result *Conn, err error) {
	o, err := options.Options.normalized()
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	finish, err := handshakeLifetime(ctx, raw, o.Timeout)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	defer func() {
		if e := finish(err == nil); e != nil {
			result = nil
			err = e
		}
	}()
	if options.Reality && (options.Type != 2 || !IsRealityConnection(raw) || options.TLSConfig != nil || options.NativeTLS) {
		return nil, ErrHTTPProfile
	}
	if options.Type < 1 || options.Type > 3 {
		return nil, ErrHTTPProfile
	}
	h := options.Header
	if !safeHTTPText(h.Domain) || len(h.Domain) > 253 {
		return nil, ErrHTTPProfile
	}
	if options.Type == 1 && (h.CheaterID == 2 || h.CheaterID == 3) {
		return nil, ErrHTTPProfile
	}
	// Custom ID 1 routes through a local ByeDPI SOCKS helper. Inside Xray
	// that is the in-process engine on this very socket (options.ByeDPI);
	// without it the route is refused rather than sent without its desync.
	if h.CustomID == 1 && !options.ByeDPI {
		return nil, ErrHTTPProfile
	}
	if options.Reality && (h.CustomID != 0 || h.Extra != "") {
		return nil, ErrHTTPProfile
	}
	if options.Type != 1 {
		// The native empty TLS profile advertises ID0 although the client skips
		// CTR. Refuse this inconsistent profile instead of creating a dead link.
		if h.CheaterID != 2 && h.CheaterID != 3 {
			return nil, ErrHTTPProfile
		}
		// REALITY already encrypts and authenticates this stream; the inner
		// pinned TLS is not repeated inside it (VPN-Core 0.12).
		if !options.Reality {
			tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: h.Domain}
			if options.TLSConfig != nil {
				tc = options.TLSConfig.Clone()
				if tc.ServerName == "" {
					tc.ServerName = h.Domain
				}
			}
			if options.NativeTLS {
				raw, err = nativeTLSClient(ctx, raw, tc)
			} else {
				secure := tls.Client(raw, tc)
				err = secure.HandshakeContext(ctx)
				raw = secure
			}
			if err != nil {
				return nil, err
			}
		}
		o.plain = true
	}
	header, err := MakeHTTPHeader(options.Type, h, options.Path, o.Random)
	if err != nil {
		return nil, err
	}
	if _, err = writeFull(raw, header); err != nil {
		return nil, err
	}
	return clientHandshake(ctx, raw, o)
}
