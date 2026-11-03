package openvpn

import (
	"bytes"
	"crypto/hmac"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"
	"unicode"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/clientproof"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/ctlwrap"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/datachan"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/handshake"
	"google.golang.org/protobuf/proto"
)

// ServerSettings is the native inbound's complete, portable configuration.
type ServerSettings struct {
	Network              string             `json:"network,omitempty"`
	Certificates         ServerCertificates `json:"certificates"`
	Crypto               ServerCrypto       `json:"crypto,omitempty"`
	Tunnel               ServerTunnel       `json:"tunnel,omitempty"`
	Clients              []ServerUser       `json:"clients"`
	ClientProof          ServerProofPolicy  `json:"clientProof,omitempty"`
	Limits               ServerLimits       `json:"limits,omitempty"`
	RenegotiationSeconds int                `json:"renegotiationSeconds,omitempty"`
}
type ServerCertificates struct {
	CA           string `json:"ca"`
	Cert         string `json:"cert"`
	Key          string `json:"key"`
	TLSAuth      string `json:"tlsAuth,omitempty"`
	KeyDirection *int   `json:"keyDirection,omitempty"`
	TLSCrypt     string `json:"tlsCrypt,omitempty"`
	TLSCryptV2   string `json:"tlsCryptV2,omitempty"`
}
type ServerCrypto struct {
	DataCiphers []string `json:"dataCiphers,omitempty"`
	AuthHash    string   `json:"authHash,omitempty"`
}
type ServerTunnel struct {
	IPv4 string   `json:"ipv4,omitempty"`
	IPv6 string   `json:"ipv6,omitempty"`
	DNS  []string `json:"dns"`
	MTU  int      `json:"mtu,omitempty"`
}
type ServerProofPolicy struct {
	Required bool `json:"required,omitempty"`
}
type ServerLimits struct {
	MaxSessions        int `json:"maxSessions,omitempty"`
	MaxSessionsPerIP   int `json:"maxSessionsPerIP,omitempty"`
	MaxFlowsPerSession int `json:"maxFlowsPerSession,omitempty"`
	HandshakeSeconds   int `json:"handshakeSeconds,omitempty"`
	IdleSeconds        int `json:"idleSeconds,omitempty"`
}
type ServerUser struct {
	Email       string           `json:"email"`
	CommonName  string           `json:"commonName"`
	Level       uint32           `json:"level,omitempty"`
	Username    string           `json:"username,omitempty"`
	Password    string           `json:"password,omitempty"`
	ClientProof *ServerUserProof `json:"clientProof,omitempty"`
}
type ServerUserProof struct {
	KeyID string `json:"keyId"`
	Key   string `json:"key"`
}

func (s ServerSettings) Format(f fmt.State, _ rune) {
	fmt.Fprint(f, "OpenVPN server settings (private)")
}
func (u ServerUser) Format(f fmt.State, _ rune)      { fmt.Fprint(f, "OpenVPN server user (private)") }
func (u ServerUserProof) Format(f fmt.State, _ rune) { fmt.Fprint(f, "OpenVPN server proof (private)") }
func (c ServerCertificates) Format(f fmt.State, _ rune) {
	fmt.Fprint(f, "OpenVPN server certificates (private)")
}

// ParseServerSettings rejects unknown fields, duplicate object keys and trailing data.
func ParseServerSettings(b []byte) (*ServerSettings, error) {
	if len(b) > 8<<20 {
		return nil, errors.New("OpenVPN server settings too large")
	}
	if err := rejectDuplicateJSON(b); err != nil {
		return nil, err
	}
	var s ServerSettings
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&s); err != nil {
		return nil, errors.New("invalid OpenVPN server settings")
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}
func rejectDuplicateJSON(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 32 {
			return errors.New("OpenVPN JSON nesting limit")
		}
		tok, e := d.Token()
		if e != nil {
			return errors.New("invalid OpenVPN JSON")
		}
		switch t := tok.(type) {
		case json.Delim:
			if t == '{' {
				seen := map[string]bool{}
				for d.More() {
					k, e := d.Token()
					if e != nil {
						return e
					}
					name, ok := k.(string)
					if !ok || seen[strings.ToLower(name)] {
						return errors.New("duplicate OpenVPN JSON field")
					}
					seen[strings.ToLower(name)] = true
					if e = walk(depth + 1); e != nil {
						return e
					}
				}
			} else if t == '[' {
				for d.More() {
					if e = walk(depth + 1); e != nil {
						return e
					}
				}
			} else {
				return errors.New("invalid OpenVPN JSON")
			}
			_, e = d.Token()
			return e
		}
		return nil
	}
	if e := walk(0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return errors.New("trailing OpenVPN JSON")
	}
	return nil
}
func cleanIdentity(s string) bool {
	return s != "" && len(s) <= 255 && !strings.ContainsAny(s, "\x00\r\n\t") && strings.IndexFunc(s, unicode.IsControl) < 0
}
func (u *ServerUser) validate(proofRequired bool) error {
	if !cleanIdentity(u.Email) || !cleanIdentity(u.CommonName) {
		return errors.New("OpenVPN client requires a valid email and commonName")
	}
	if (u.Username == "") != (u.Password == "") || len(u.Username) > 255 || len(u.Password) > 1024 || strings.ContainsAny(u.Username+u.Password, "\x00\r\n") {
		return errors.New("invalid OpenVPN client username/password")
	}
	if proofRequired && u.ClientProof == nil {
		return errors.New("OpenVPN proof required but client has no key")
	}
	if p := u.ClientProof; p != nil {
		key, e := hex.DecodeString(p.Key)
		if e != nil || len(key) != 32 || clientproof.ValidateKeyID(p.KeyID) != nil {
			return errors.New("invalid OpenVPN client proof key")
		}
	}
	return nil
}
func (s *ServerSettings) Validate() error {
	if s.Network == "" {
		s.Network = "udp"
	}
	if s.Network != "udp" && s.Network != "tcp" {
		return errors.New("OpenVPN network must be udp or tcp")
	}
	if s.Tunnel.IPv4 == "" {
		s.Tunnel.IPv4 = "10.88.0.0/24"
	}
	p, e := netip.ParsePrefix(s.Tunnel.IPv4)
	if e != nil || !p.Addr().Is4() || p != p.Masked() || p.Bits() < 8 || p.Bits() > 30 {
		return errors.New("invalid OpenVPN IPv4 subnet")
	}
	if s.Tunnel.IPv6 != "" {
		v, e := netip.ParsePrefix(s.Tunnel.IPv6)
		if e != nil || !v.Addr().Is6() || v.Addr().Is4In6() || v != v.Masked() || v.Bits() < 48 || v.Bits() > 120 {
			return errors.New("invalid OpenVPN IPv6 subnet")
		}
	}
	if s.Tunnel.MTU == 0 {
		s.Tunnel.MTU = 1400
	}
	if s.Tunnel.MTU < 1280 || s.Tunnel.MTU > 8000 {
		return errors.New("OpenVPN server MTU must be 1280..8000")
	}
	if s.Tunnel.DNS == nil {
		s.Tunnel.DNS = []string{"1.1.1.1"}
	}
	if len(s.Tunnel.DNS) > 8 {
		return errors.New("too many OpenVPN DNS servers")
	}
	for _, v := range s.Tunnel.DNS {
		if _, e := netip.ParseAddr(v); e != nil {
			return errors.New("OpenVPN DNS server must be an IP")
		}
	}
	if len(s.Crypto.DataCiphers) == 0 {
		s.Crypto.DataCiphers = []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"}
	}
	if len(s.Crypto.DataCiphers) > 12 {
		return errors.New("too many OpenVPN ciphers")
	}
	if s.Crypto.AuthHash == "" {
		// OpenVPN's --auth defaults to SHA1 for both the tls-auth
		// control-channel HMAC and the (CBC) data-channel HMAC. A non-default
		// SHA256 here silently breaks tls-auth interop with stock OpenVPN and
		// the project's own client, both of which default the control-channel
		// HMAC to SHA1 when the config omits an explicit auth directive.
		s.Crypto.AuthHash = "SHA1"
	}
	digest, ok := datachan.CanonicalDigest(s.Crypto.AuthHash)
	if !ok {
		return errors.New("invalid OpenVPN auth hash")
	}
	s.Crypto.AuthHash = digest
	if _, e := ctlwrap.NewTLSAuth(&ctlwrap.StaticKey{}, ctlwrap.Normal, s.Crypto.AuthHash); e != nil {
		return errors.New("invalid OpenVPN auth hash")
	}
	seenCipher := map[string]bool{}
	for i, c := range s.Crypto.DataCiphers {
		canonical, ok := datachan.CanonicalCipher(c)
		if !ok {
			return errors.New("invalid OpenVPN cipher")
		}
		c = canonical
		s.Crypto.DataCiphers[i] = c
		if seenCipher[c] {
			return errors.New("duplicate OpenVPN cipher")
		}
		seenCipher[c] = true
		if _, e := datachan.NewKeyState(0, c, s.Crypto.AuthHash, &handshake.Key{}, &handshake.Key{}); e != nil {
			return errors.New("invalid OpenVPN cipher or auth hash")
		}
	}
	l := &s.Limits
	if l.MaxSessions == 0 {
		l.MaxSessions = 128
	}
	if l.MaxSessionsPerIP == 0 {
		l.MaxSessionsPerIP = min(16, l.MaxSessions)
	}
	if l.MaxFlowsPerSession == 0 {
		l.MaxFlowsPerSession = 256
	}
	if l.HandshakeSeconds == 0 {
		l.HandshakeSeconds = 15
	}
	if l.IdleSeconds == 0 {
		l.IdleSeconds = 120
	}
	if l.MaxSessions < 1 || l.MaxSessions > 4096 || l.MaxSessionsPerIP < 1 || l.MaxSessionsPerIP > l.MaxSessions || l.MaxFlowsPerSession < 1 || l.MaxFlowsPerSession > 4096 || l.HandshakeSeconds < 1 || l.HandshakeSeconds > 120 || l.IdleSeconds < 10 || l.IdleSeconds > 86400 {
		return errors.New("invalid OpenVPN server limits")
	}
	if uint64(l.MaxSessions) > ((uint64(1) << (32 - p.Bits())) - 3) {
		return errors.New("OpenVPN IPv4 pool smaller than maxSessions")
	}
	if s.Tunnel.IPv6 != "" {
		v := netip.MustParsePrefix(s.Tunnel.IPv6)
		if v.Bits() >= 112 && uint64(l.MaxSessions) > ((uint64(1)<<(128-v.Bits()))-2) {
			return errors.New("OpenVPN IPv6 pool smaller than maxSessions")
		}
	}
	if s.RenegotiationSeconds == 0 {
		s.RenegotiationSeconds = 3600
	}
	if s.RenegotiationSeconds < 1 || s.RenegotiationSeconds > 86400 {
		return errors.New("invalid OpenVPN renegotiation interval")
	}
	if len(s.Clients) > 4096 {
		return errors.New("OpenVPN supports at most 4096 clients")
	}
	emails, cns, ids := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i := range s.Clients {
		u := &s.Clients[i]
		if e := u.validate(s.ClientProof.Required); e != nil {
			return e
		}
		if emails[u.Email] || cns[u.CommonName] {
			return errors.New("duplicate OpenVPN email or commonName")
		}
		emails[u.Email] = true
		cns[u.CommonName] = true
		if u.ClientProof != nil {
			if ids[u.ClientProof.KeyID] {
				return errors.New("duplicate OpenVPN proof keyId")
			}
			ids[u.ClientProof.KeyID] = true
		}
	}
	if _, e := s.tlsConfig(); e != nil {
		return e
	}
	wrappers := 0
	for _, v := range []string{s.Certificates.TLSAuth, s.Certificates.TLSCrypt, s.Certificates.TLSCryptV2} {
		if v != "" {
			wrappers++
		}
	}
	if wrappers > 1 {
		return errors.New("OpenVPN control wrappers are mutually exclusive")
	}
	if d := s.Certificates.KeyDirection; d != nil {
		if s.Certificates.TLSAuth == "" || (*d != 0 && *d != 1) {
			return errors.New("OpenVPN keyDirection requires tlsAuth and 0 or 1")
		}
	}
	for _, v := range []string{s.Certificates.TLSAuth, s.Certificates.TLSCrypt} {
		if v != "" {
			if _, e := ctlwrap.ParseStaticKey([]byte(v)); e != nil {
				return errors.New("invalid OpenVPN control key")
			}
		}
	}
	if s.Certificates.TLSCryptV2 != "" {
		if _, e := ctlwrap.ParseTLSCryptV2ServerKey([]byte(s.Certificates.TLSCryptV2)); e != nil {
			return errors.New("invalid OpenVPN TLS-crypt-v2 server key")
		}
	}
	return nil
}
func (s *ServerSettings) tlsConfig() (*tls.Config, error) {
	if s.Certificates.CA == "" || s.Certificates.Cert == "" || s.Certificates.Key == "" {
		return nil, errors.New("OpenVPN ca, cert and key are required")
	}
	cert, e := tls.X509KeyPair([]byte(s.Certificates.Cert), []byte(s.Certificates.Key))
	if e != nil {
		return nil, errors.New("invalid OpenVPN server certificate/key")
	}
	leaf, e := x509.ParseCertificate(cert.Certificate[0])
	if e != nil {
		return nil, errors.New("invalid OpenVPN server certificate")
	}
	cert.Leaf = leaf
	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, errors.New("OpenVPN server certificate is outside its validity period")
	}
	allowed := len(leaf.ExtKeyUsage) == 0
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
			allowed = true
		}
	}
	if !allowed {
		return nil, errors.New("OpenVPN server certificate lacks server authentication usage")
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(s.Certificates.CA)) {
		return nil, errors.New("invalid OpenVPN client CA")
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12}, nil
}

// authenticateUser binds certificate, optional password and channel proof.
func authenticateUser(u ServerUser, m *handshake.ClientMessage, cs tls.ConnectionState) error {
	deny := errors.New("OpenVPN client authentication rejected")
	if len(cs.VerifiedChains) == 0 || len(cs.PeerCertificates) == 0 || cs.PeerCertificates[0].Subject.CommonName != u.CommonName {
		return deny
	}
	if u.Username != "" && (!hmac.Equal([]byte(m.Username), []byte(u.Username)) || !hmac.Equal([]byte(m.Password), []byte(u.Password))) {
		return deny
	}
	proof := ""
	count := 0
	for _, line := range strings.Split(m.PeerInfo, "\n") {
		if v, ok := strings.CutPrefix(line, clientproof.PeerInfoKey+"="); ok {
			proof = v
			count++
		}
	}
	if count > 1 {
		return deny
	}
	if u.ClientProof == nil {
		if count != 0 {
			return deny
		}
		return nil
	}
	id, _, e := clientproof.Parse(proof)
	if e != nil || id != u.ClientProof.KeyID {
		return deny
	}
	exporter, e := cs.ExportKeyingMaterial(clientproof.ExporterLabel, nil, clientproof.ExporterLength)
	if e != nil {
		return deny
	}
	key, e := hex.DecodeString(u.ClientProof.Key)
	if e != nil || clientproof.Verify(proof, exporter, key) != nil {
		return deny
	}
	return nil
}

// MemoryServerAccount lets native users be updated through Xray's existing API.
type MemoryServerAccount struct{ User ServerUser }

func (a *ServerAccount) AsAccount() (protocol.Account, error) {
	if a == nil || len(a.Settings) > 8192 {
		return nil, errors.New("invalid OpenVPN account")
	}
	if e := rejectDuplicateJSON(a.Settings); e != nil {
		return nil, e
	}
	var u ServerUser
	d := json.NewDecoder(bytes.NewReader(a.Settings))
	d.DisallowUnknownFields()
	if e := d.Decode(&u); e != nil {
		return nil, errors.New("invalid OpenVPN account")
	}
	if e := u.validate(false); e != nil {
		return nil, e
	}
	return &MemoryServerAccount{User: u}, nil
}
func (a *MemoryServerAccount) Equals(other protocol.Account) bool {
	b, ok := other.(*MemoryServerAccount)
	if !ok {
		return false
	}
	aa, _ := json.Marshal(a.User)
	bb, _ := json.Marshal(b.User)
	return hmac.Equal(aa, bb)
}
func (a *MemoryServerAccount) ToProto() proto.Message {
	b, _ := json.Marshal(a.User)
	return &ServerAccount{Settings: b}
}
func (a *MemoryServerAccount) Format(f fmt.State, _ rune) { fmt.Fprint(f, "OpenVPN account (private)") }

func (c *ServerConfig) Format(f fmt.State, _ rune) { fmt.Fprint(f, "OpenVPN server config (private)") }
func (c *ServerConfig) GoString() string           { return "OpenVPN server config (private)" }
func (c *ServerAccount) Format(f fmt.State, _ rune) {
	fmt.Fprint(f, "OpenVPN server account (private)")
}
func (c *ServerAccount) GoString() string { return "OpenVPN server account (private)" }
