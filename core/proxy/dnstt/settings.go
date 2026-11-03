package dnstt

import (
	"crypto/ecdh"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

func settingError(field, detail string) error {
	return errors.New("dnstt: " + field + ": " + detail)
}

// NormalizeConfig validates and copies settings. It starts no worker or socket,
// never modifies the caller's protobuf, and never includes secrets in errors.
func NormalizeConfig(input *Config) (*Config, error) {
	if input == nil {
		return nil, settingError("settings", "are required")
	}
	c := proto.Clone(input).(*Config)
	c.Domain = strings.TrimSuffix(strings.ToLower(c.Domain), ".")
	if !validDomain(c.Domain) || net.ParseIP(c.Domain) != nil {
		return nil, settingError("domain", "must be an ASCII DNS tunnel domain")
	}
	key, err := hex.DecodeString(c.PublicKey)
	if err != nil || len(key) != 32 {
		return nil, settingError("publicKey", "must be the server's 64 hexadecimal public-key digits")
	}
	// X25519 accepts some encodings whose shared secret is always zero. Fail
	// before dialing rather than treating such a value as a usable pin.
	pub, err := ecdh.X25519().NewPublicKey(key)
	if err != nil {
		return nil, settingError("publicKey", "is not a valid X25519 public key")
	}
	var scalar [32]byte
	scalar[0] = 1
	priv, _ := ecdh.X25519().NewPrivateKey(scalar[:])
	if _, err = priv.ECDH(pub); err != nil {
		return nil, settingError("publicKey", "is not a valid X25519 public key")
	}
	c.PublicKey = hex.EncodeToString(key)
	if len(c.Resolvers) == 0 || len(c.Resolvers) > 16 {
		return nil, settingError("resolvers", "must contain between 1 and 16 resolvers")
	}
	for _, r := range c.Resolvers {
		if r != nil {
			r.Transport = strings.ToLower(r.Transport)
		}
		if err := ValidateResolver(r); err != nil {
			return nil, err
		}
	}
	if c.Inner == nil {
		return nil, settingError("inner", "authenticated SOCKS5 or VLESS settings are required")
	}
	c.Inner.Protocol = strings.ToLower(c.Inner.Protocol)
	switch c.Inner.Protocol {
	case "vless":
		id, err := uuid.Parse(c.Inner.Uuid)
		if err != nil || id == uuid.Nil {
			return nil, settingError("inner.uuid", "must be a nonzero UUID")
		}
		c.Inner.Uuid = id.String()
		if c.Inner.Username != "" || c.Inner.Password != "" {
			return nil, settingError("inner", "VLESS uses uuid only")
		}
	case "socks":
		if len(c.Inner.Username) < 1 || len(c.Inner.Username) > 255 || len(c.Inner.Password) < 1 || len(c.Inner.Password) > 255 {
			return nil, settingError("inner", "SOCKS5 username and password must each contain 1..255 bytes")
		}
		if c.Inner.Uuid != "" {
			return nil, settingError("inner", "SOCKS5 uses username and password only")
		}
	default:
		return nil, settingError("inner.protocol", "must be vless or socks")
	}
	if c.HandshakeTimeout == 0 {
		c.HandshakeTimeout = 30
	}
	if c.QueryTimeout == 0 {
		c.QueryTimeout = 5
	}
	if c.MaxConcurrentQueries == 0 {
		c.MaxConcurrentQueries = 32
	}
	if c.EdnsPayloadSize == 0 {
		c.EdnsPayloadSize = 1232
	}
	if c.MaxQnameLength == 0 {
		c.MaxQnameLength = 255
	}
	if c.LabelMax == 0 {
		c.LabelMax = 63
	}
	if c.LabelMin == 0 {
		c.LabelMin = c.LabelMax
	}
	for field, bad := range map[string]bool{
		"handshakeTimeout":     c.HandshakeTimeout > 300,
		"queryTimeout":         c.QueryTimeout > 60,
		"maxConcurrentQueries": c.MaxConcurrentQueries > 256,
		"minQueryIntervalMs":   c.MinQueryIntervalMs > 60000,
		"ednsPayloadSize":      c.EdnsPayloadSize < 512 || c.EdnsPayloadSize > 4096,
		"maxQnameLength":       c.MaxQnameLength < 64 || c.MaxQnameLength > 255,
		"labelMin/labelMax":    c.LabelMax > 63 || c.LabelMin > c.LabelMax,
	} {
		if bad {
			return nil, settingError(field, "is outside its supported bounds")
		}
	}
	if _, err := packetMTU(c); err != nil {
		return nil, err
	}
	return c, nil
}

// ValidateConfig accepts the same zero-valued defaults as NormalizeConfig.
func ValidateConfig(c *Config) error {
	_, err := NormalizeConfig(c)
	return err
}

// ValidateResolver verifies endpoint syntax and authenticated TLS settings.
// A hostname requires an explicit numeric bootstrap to avoid a DNS dependency
// on the tunnel being established.
func ValidateResolver(r *Resolver) error {
	if r == nil {
		return settingError("resolvers", "contains a missing resolver")
	}
	var host string
	switch r.Transport {
	case "udp", "dot":
		var port string
		var err error
		host, port, err = net.SplitHostPort(r.Address)
		if err != nil || host == "" {
			return settingError("resolver.address", "must contain a host and numeric port")
		}
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return settingError("resolver.address", "must contain a port in 1..65535")
		}
	case "doh":
		u, err := url.Parse(r.Address)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
			return settingError("resolver.address", "must be an HTTPS URL without credentials or fragment")
		}
		host = u.Hostname()
		if p := u.Port(); p != "" {
			n, err := strconv.ParseUint(p, 10, 16)
			if err != nil || n == 0 {
				return settingError("resolver.address", "must contain a port in 1..65535")
			}
		}
	default:
		return settingError("resolver.transport", "must be udp, dot or doh")
	}
	ip, ipErr := netip.ParseAddr(host)
	if ipErr != nil && !validDomain(strings.TrimSuffix(strings.ToLower(host), ".")) {
		return settingError("resolver.address", "must contain a DNS hostname or numeric IP")
	}
	if r.Bootstrap != "" {
		b, err := netip.ParseAddr(r.Bootstrap)
		if err != nil || b.Zone() != "" || b.IsUnspecified() || b.IsMulticast() {
			return settingError("resolver.bootstrap", "must be a unicast numeric IP without port")
		}
	} else if ipErr != nil {
		return settingError("resolver.bootstrap", "is required for a hostname resolver")
	}
	if ipErr == nil && (ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast()) {
		return settingError("resolver.address", "must contain a unicast IP without zone")
	}
	if r.Transport == "udp" {
		if r.ServerName != "" || r.Fingerprint != "" || r.CaPem != "" {
			return settingError("resolver", "UDP does not accept TLS settings")
		}
		return nil
	}
	if r.ServerName != "" && net.ParseIP(r.ServerName) == nil && !validDomain(strings.ToLower(r.ServerName)) {
		return settingError("resolver.serverName", "must be a certificate DNS hostname or IP")
	}
	switch r.Fingerprint {
	case "", "chrome", "firefox", "safari":
	default:
		return settingError("resolver.fingerprint", "must be chrome, firefox or safari")
	}
	if len(r.CaPem) > 1<<20 {
		return settingError("resolver.caPem", "exceeds one MiB")
	}
	if r.CaPem != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(r.CaPem)) {
		return settingError("resolver.caPem", "contains no usable CA certificate")
	}
	return nil
}

func validDomain(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, b := range []byte(label) {
			if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-') {
				return false
			}
		}
	}
	return true
}
