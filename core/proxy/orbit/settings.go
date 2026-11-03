package orbit

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/xtls/xray-core/proxy/orbit/internal/connectionkey"
	"github.com/xtls/xray-core/proxy/orbit/internal/wsoptions"
)

// The link syntax and every rule below follow VPN-Core's config/uri.go and
// config/websocket.go (KEY-MODE.md), so a link the VPN-Core client accepts is
// accepted here with the same meaning. The differences: the errors name the
// offending field (never its value), and "auto" -- VPN-Core's pooled TCP+QUIC
// race -- is not offered; an outbound picks one carrier.

const (
	maxLinkBytes          = 32768
	maxRemarksBytes       = 256
	maxWebSocketPathBytes = 512
	defaultWebSocketPath  = "/core"
	defaultResolver       = "1.1.1.1:53"
)

// Settings is one server: the fields of an orbit:// link. Key is a bearer
// credential; never log a Settings value.
type Settings struct {
	Address     string
	Port        uint32
	Key         string
	Transport   string
	Host        string
	Path        string
	Peer        string
	Fingerprint string
	UserAgent   string
	Headers     map[string]string
	// Browser is "" (browser-style handshake, the default) or "off".
	Browser string
	Remarks string
	// Security is "" or "reality" (VPN-Core 0.12: tcp only). With "reality"
	// the outer TCP stream is a REALITY handshake authenticated by Reality's
	// public key instead of the inner pinned TLS; the private key is still
	// required for the account.
	Security string
	Reality  RealitySettings
}

// RealitySettings are the REALITY fields of an orbit link: sni, pbk, sid and,
// with security=reality, fp. They are public (the server's private REALITY
// key never leaves it), but they travel inside a private link.
type RealitySettings struct {
	// ServerName is the cover name the server accepts: an ASCII DNS name
	// with at least one letter (lower-cased).
	ServerName string
	// PublicKey is the server's X25519 public key, 43 unpadded base64url
	// characters.
	PublicKey string
	// ShortID is empty or up to 16 hex digits in byte pairs (lower-cased).
	ShortID string
	// Fingerprint is "" (chrome), chrome, firefox or safari.
	Fingerprint string
}

// FieldError names the setting that failed validation. It never carries the
// value, which may be a private key, a header or a whole private link.
type FieldError struct {
	Field  string
	Reason string
}

func (e *FieldError) Error() string { return fmt.Sprintf("orbit: %q: %s", e.Field, e.Reason) }

func fieldError(field, reason string) error { return &FieldError{Field: field, Reason: reason} }

func connectionIP(raw string) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(raw)
	if err != nil || ip.Zone() != "" {
		return netip.Addr{}, false
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
		return netip.Addr{}, false
	}
	return ip, true
}

func dnsHost(raw string) (string, bool) {
	if len(raw) == 0 || len(raw) > 253 {
		return "", false
	}
	for i := range raw {
		if raw[i] > 127 {
			return "", false
		}
	}
	raw = strings.ToLower(raw)
	hasLetter := false
	for _, label := range strings.Split(raw, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, ch := range label {
			if ch >= 'a' && ch <= 'z' {
				hasLetter = true
			} else if !(ch >= '0' && ch <= '9') && ch != '-' {
				return "", false
			}
		}
	}
	if !hasLetter {
		return "", false
	}
	return raw, true
}

func connectionHost(raw string) (string, bool) {
	if ip, ok := connectionIP(raw); ok {
		return ip.String(), true
	}
	return dnsHost(raw)
}

func validWebSocketPath(value string) bool {
	if len(value) == 0 || len(value) > maxWebSocketPathBytes || value[0] != '/' || strings.Contains(value, "//") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	for _, ch := range value {
		if !(ch >= 'a' && ch <= 'z') && !(ch >= 'A' && ch <= 'Z') && !(ch >= '0' && ch <= '9') && !strings.ContainsRune("/-._~", ch) {
			return false
		}
	}
	return true
}

func validRemarks(value string) bool {
	if len(value) > maxRemarksBytes || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return false
		}
	}
	return true
}

// Normalize validates the settings and returns their canonical form: the
// numeric IP or lower-case name, the default path "/core", peer defaulting
// to host, canonical header names and Browser "on" folded into "".
func (s Settings) Normalize() (Settings, error) {
	switch s.Transport {
	case "tcp", "quic", "ws", "wss":
	case "":
		return Settings{}, fieldError("transport", "is required: tcp, quic, ws or wss")
	case "auto":
		return Settings{}, fieldError("transport", `"auto" (VPN-Core's pooled TCP+QUIC race) is not supported; choose tcp, quic, ws or wss`)
	default:
		return Settings{}, fieldError("transport", "must be tcp, quic, ws or wss")
	}
	switch s.Security {
	case "":
		if s.Reality != (RealitySettings{}) {
			return Settings{}, fieldError("security", `must be "reality" when REALITY settings are given (a link's sni, pbk and sid need security=reality)`)
		}
	case "reality":
		if s.Transport != "tcp" {
			return Settings{}, fieldError("security", `"reality" is only for transport tcp (VPN-Core offers REALITY on direct TCP only)`)
		}
	default:
		return Settings{}, fieldError("security", `must be "reality" or empty`)
	}
	webSocket := s.Transport == "ws" || s.Transport == "wss"
	if s.Port == 0 || s.Port > 65535 {
		return Settings{}, fieldError("port", "must be in 1..65535")
	}
	if s.Address == "" {
		return Settings{}, fieldError("address", "is required")
	}
	if webSocket {
		host, ok := connectionHost(s.Address)
		if !ok {
			return Settings{}, fieldError("address", "must be a numeric IP or a DNS name")
		}
		s.Address = host
	} else {
		ip, ok := connectionIP(s.Address)
		if !ok {
			return Settings{}, fieldError("address", "must be a numeric unicast IP for "+s.Transport+" (the inner certificate is pinned to it); only ws/wss accept a DNS name")
		}
		s.Address = ip.String()
	}
	if s.Key == "" {
		return Settings{}, fieldError("key", "is required")
	}
	if _, _, err := connectionkey.Decode(s.Key); err != nil {
		return Settings{}, fieldError("key", "is not a valid private connection key (the 91-character vck1 key of an orbit:// link)")
	}
	if !validRemarks(s.Remarks) {
		return Settings{}, fieldError("remarks", "must be at most 256 bytes of printable UTF-8")
	}
	if webSocket {
		if s.Browser == "on" {
			s.Browser = ""
		}
		if err := wsoptions.ValidateBrowser(s.Browser); err != nil {
			return Settings{}, fieldError("browser", `must be on or off`)
		}
		if s.Fingerprint != "" && s.Transport != "wss" {
			return Settings{}, fieldError("fingerprint", "applies to wss only (ws has no outer TLS)")
		}
		if err := wsoptions.Validate(s.Fingerprint, "", nil, true); err != nil {
			return Settings{}, fieldError("fingerprint", "must be one of chrome, firefox, safari, ios, android, edge, 360, qq, random, randomized, randomizednoalpn, unsafe")
		}
		if err := wsoptions.Validate("", s.UserAgent, nil, false); err != nil {
			return Settings{}, fieldError("userAgent", "must be at most 512 printable ASCII bytes")
		}
		if err := wsoptions.Validate("", "", s.Headers, false); err != nil {
			return Settings{}, fieldError("headers", "must be at most 16 valid HTTP headers (no Host, User-Agent, Origin, Connection, Upgrade, Sec-WebSocket-*, Proxy-* or length headers; 4096 bytes in all)")
		}
		s.Headers = wsoptions.CanonicalHeaders(s.Headers)
		host, ok := dnsHost(s.Host)
		if !ok {
			return Settings{}, fieldError("host", "is required for ws/wss and must be a DNS name without a port")
		}
		s.Host = host
		if s.Path == "" {
			s.Path = defaultWebSocketPath
		}
		if !validWebSocketPath(s.Path) {
			return Settings{}, fieldError("path", `must start with "/" and hold only unreserved ASCII and slashes, with no query, dot segments or repeated slashes (at most 512 bytes)`)
		}
		if s.Peer == "" {
			s.Peer = s.Host
		} else {
			peer, ok := connectionHost(s.Peer)
			if !ok {
				return Settings{}, fieldError("peer", "must be a numeric IP or a DNS name")
			}
			s.Peer = peer
		}
	} else {
		for field, set := range map[string]bool{"host": s.Host != "", "path": s.Path != "", "peer": s.Peer != "",
			"fingerprint": s.Fingerprint != "", "userAgent": s.UserAgent != "", "headers": len(s.Headers) != 0, "browser": s.Browser != ""} {
			if set {
				if field == "fingerprint" && s.Security == "reality" {
					return Settings{}, fieldError(field, `applies to wss only; REALITY's goes in "reality.fingerprint" (fp= in a link with security=reality)`)
				}
				return Settings{}, fieldError(field, "applies to ws/wss only")
			}
		}
		if s.Security == "reality" {
			r, err := s.Reality.normalize()
			if err != nil {
				return Settings{}, err
			}
			s.Reality = r
		}
	}
	return s, nil
}

// normalize applies VPN-Core 0.12's REALITY rules (config/reality.go
// RealityClient.Validate and config/uri.go): the server name is a lower-case
// ASCII DNS name with a letter, the public key a canonical unpadded base64url
// X25519 key that is not a low-order point, the short ID empty or up to 16
// lower-case hex digits in byte pairs, and the fingerprint chrome, firefox or
// safari ("" means chrome).
func (r RealitySettings) normalize() (RealitySettings, error) {
	name, ok := dnsHost(r.ServerName)
	if !ok {
		return RealitySettings{}, fieldError("reality.serverName", "is required: an ASCII DNS name with at least one letter, no IP literal, port, wildcard or trailing dot (sni= in a link)")
	}
	r.ServerName = name
	if !validRealityPublicKey(r.PublicKey) {
		return RealitySettings{}, fieldError("reality.publicKey", "must be the server's X25519 public key as 43 unpadded base64url characters (pbk= in a link)")
	}
	r.ShortID = strings.ToLower(r.ShortID)
	if len(r.ShortID) > 16 || len(r.ShortID)%2 != 0 {
		return RealitySettings{}, fieldError("reality.shortId", "must be empty or up to 16 hex digits in byte pairs (sid= in a link; omit it for the empty short ID)")
	}
	if _, err := hex.DecodeString(r.ShortID); err != nil {
		return RealitySettings{}, fieldError("reality.shortId", "must be empty or up to 16 hex digits in byte pairs (sid= in a link; omit it for the empty short ID)")
	}
	switch r.Fingerprint {
	case "", "chrome", "firefox", "safari":
	default:
		return RealitySettings{}, fieldError("reality.fingerprint", "must be chrome, firefox or safari (fp= in a link with security=reality)")
	}
	return r, nil
}

func validRealityPublicKey(value string) bool {
	if len(value) != 43 {
		return false
	}
	key, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(key) != 32 || base64.RawURLEncoding.EncodeToString(key) != value {
		return false
	}
	public, err := ecdh.X25519().NewPublicKey(key)
	if err != nil {
		return false
	}
	// A low-order point gives an all-zero shared secret, which X25519 ECDH
	// refuses; reject it before dialing, as VPN-Core does.
	var scalar [32]byte
	scalar[0] = 1
	private, err := ecdh.X25519().NewPrivateKey(scalar[:])
	if err != nil {
		return false
	}
	_, err = private.ECDH(public)
	return err == nil
}

// LinkScheme is the scheme of an orbit share link. LegacyLinkScheme is the
// one VPN-Core's own tools write (its README and KEY-MODE.md): the same
// layout under another name, accepted as an alias so a link copied from them
// works unchanged.
const (
	LinkScheme       = "orbit://"
	LegacyLinkScheme = "core://"
)

// IsLink reports whether raw starts with an orbit link scheme (orbit://, or
// the legacy core://). It says nothing about the rest of the link.
func IsLink(raw string) bool {
	return strings.HasPrefix(raw, LinkScheme) || strings.HasPrefix(raw, LegacyLinkScheme)
}

// ParseLink reads an orbit share link -- VPN-Core's private link:
//
//	orbit://IP:PORT@PRIVATE_KEY&transport=tcp#Remarks
//	orbit://DIAL_HOST:PORT@PRIVATE_KEY&transport=wss&host=OWNED_HOST&path=%2Fcore
//	orbit://IP:PORT@PRIVATE_KEY&transport=tcp&security=reality&sni=COVER&pbk=PUBLIC_KEY&sid=HEX&fp=chrome
//
// with the optional peer=, fp=, ua=, headers= and browser= parameters for
// ws/wss, and sid= and fp= for REALITY (fp= is then the REALITY preset). There
// is no "?": the parameters follow the key after "&". VPN-Core's own core://
// spelling is accepted as an alias with the same meaning. The result is
// normalized. Errors name the part of the link, never its value.
func ParseLink(raw string) (Settings, error) {
	if len(raw) == 0 || len(raw) > maxLinkBytes || !IsLink(raw) || !utf8.ValidString(raw) {
		return Settings{}, fieldError("link", "must be an orbit:// link of at most 32768 bytes")
	}
	scheme := LinkScheme
	if strings.HasPrefix(raw, LegacyLinkScheme) {
		scheme = LegacyLinkScheme
	}
	for _, r := range raw {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return Settings{}, fieldError("link", "must not contain spaces or control characters")
		}
	}
	body, fragment, hasFragment := strings.Cut(raw[len(scheme):], "#")
	if strings.Contains(fragment, "#") {
		return Settings{}, fieldError("link", "has more than one #remarks")
	}
	address, keyAndParams, found := strings.Cut(body, "@")
	if !found || strings.Contains(keyAndParams, "@") {
		return Settings{}, fieldError("link", "must have the form orbit://HOST:PORT@KEY&transport=...")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || len(port) == 0 || len(port) > 5 || strings.TrimLeft(port, "0123456789") != "" || len(address) > 260 {
		return Settings{}, fieldError("address", "the link needs HOST:PORT with an explicit port (IPv6 in brackets)")
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return Settings{}, fieldError("port", "must be in 1..65535")
	}
	if strings.HasPrefix(address, "[") {
		// Brackets delimit IPv6 literals, never DNS names or IPv4.
		if ip, e := netip.ParseAddr(host); e != nil || !ip.Is6() {
			return Settings{}, fieldError("address", "brackets may only hold an IPv6 literal")
		}
	}
	key, params, hasParams := strings.Cut(keyAndParams, "&")
	s := Settings{Address: host, Port: uint32(n), Key: key, Transport: "auto"}
	if hasParams {
		parts := strings.Split(params, "&")
		if len(parts) > 16 {
			return Settings{}, fieldError("link", "has too many parameters")
		}
		seen := make(map[string]bool, len(parts))
		for _, part := range parts {
			name, value, ok := strings.Cut(part, "=")
			if !ok || value == "" {
				return Settings{}, fieldError("link", "has an empty or malformed parameter")
			}
			if seen[name] {
				return Settings{}, fieldError(name, "is repeated in the link")
			}
			seen[name] = true
			var e error
			switch name {
			case "transport":
				s.Transport = value
			case "host":
				s.Host = value
			case "peer":
				s.Peer = value
			case "fp":
				s.Fingerprint = value
			case "browser":
				s.Browser = value
			case "ua":
				s.UserAgent, e = url.PathUnescape(value)
			case "headers":
				var decoded string
				decoded, e = url.PathUnescape(value)
				if e == nil {
					s.Headers, e = wsoptions.DecodeHeaders([]byte(decoded))
				}
				if e != nil {
					return Settings{}, fieldError("headers", "must be a percent-encoded JSON object of header strings")
				}
			case "path":
				s.Path, e = url.PathUnescape(value)
			case "security":
				s.Security = value
			case "sni":
				s.Reality.ServerName = value
			case "pbk":
				s.Reality.PublicKey = value
			case "sid":
				s.Reality.ShortID = value
			default:
				return Settings{}, fieldError("link", "has an unknown parameter (allowed: transport, host, path, peer, fp, ua, headers, browser, security, sni, pbk, sid)")
			}
			if e != nil {
				return Settings{}, fieldError(name, "has a malformed percent escape")
			}
		}
	}
	if hasFragment {
		remarks, e := url.PathUnescape(fragment)
		if e != nil {
			return Settings{}, fieldError("remarks", "has a malformed percent escape")
		}
		s.Remarks = remarks
	}
	if s.Security == "reality" {
		// One fp= parameter: the REALITY preset when security=reality, the
		// outer WSS preset otherwise (VPN-Core's Connection.Fingerprint).
		s.Reality.Fingerprint, s.Fingerprint = s.Fingerprint, ""
	}
	return s.Normalize()
}

// Config returns the protobuf configuration of normalized settings.
func (s Settings) Config(handshakeTimeout uint32, resolver string) (*Config, error) {
	n, err := s.Normalize()
	if err != nil {
		return nil, err
	}
	if handshakeTimeout > 90 {
		return nil, fieldError("handshakeTimeout", "must be at most 90 seconds")
	}
	if resolver != "" {
		r, e := netip.ParseAddrPort(resolver)
		if e != nil || !r.Addr().Is4() || r.Port() == 0 {
			return nil, fieldError("resolver", "must be a numeric IPv4 host:port")
		}
	}
	c := &Config{Address: n.Address, Port: n.Port, Key: n.Key, Transport: n.Transport, Host: n.Host, Path: n.Path,
		Peer: n.Peer, Fingerprint: n.Fingerprint, UserAgent: n.UserAgent, Headers: n.Headers, Browser: n.Browser,
		HandshakeTimeout: handshakeTimeout, Resolver: resolver}
	if n.Security == "reality" {
		c.Reality = &Reality{ServerName: n.Reality.ServerName, PublicKey: n.Reality.PublicKey,
			ShortId: n.Reality.ShortID, Fingerprint: n.Reality.Fingerprint}
	}
	return c, nil
}

func settingsOf(c *Config) Settings {
	s := Settings{Address: c.Address, Port: c.Port, Key: c.Key, Transport: c.Transport, Host: c.Host, Path: c.Path,
		Peer: c.Peer, Fingerprint: c.Fingerprint, UserAgent: c.UserAgent, Headers: c.Headers, Browser: c.Browser}
	if r := c.GetReality(); r != nil {
		s.Security = "reality"
		s.Reality = RealitySettings{ServerName: r.ServerName, PublicKey: r.PublicKey, ShortID: r.ShortId, Fingerprint: r.Fingerprint}
	}
	return s
}

var errNoConfig = errors.New("orbit: missing configuration")
