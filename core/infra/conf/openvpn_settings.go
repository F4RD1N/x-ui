package conf

import (
	"strconv"
	"strings"
	"unicode"

	"github.com/xtls/xray-core/common/errors"
)

// OpenVPNSettings is the structured form of the "ov" (OpenVPN) outbound,
// used instead of "ovpn"/"ovpnBase64":
//
//	"server":       {"address": "vpn.example.com", "port": 1194, "network": "udp"},
//	"auth":         {"user": "", "pass": ""},
//	"crypto":       {"cipher": "AES-256-GCM", "dataCiphers": ["AES-256-GCM", ...], "authHash": "SHA256"},
//	"certificates": {"ca": "PEM", "cert": "PEM", "key": "PEM", "tlsCrypt": "PEM",
//	                 "tlsAuth": "PEM", "keyDirection": 1, "tlsCryptV2": "PEM"},
//	"advanced":     {"dev": "tun", "nobind": true, "remoteCertTls": "server", "mtu": 1400}
//
// It is turned into .ovpn text, so it means exactly what the same directives
// mean in "ovpn". Empty fields are left out.
type OpenVPNSettings struct {
	Server       *OpenVPNServer       `json:"server"`
	Auth         *OpenVPNAuth         `json:"auth"`
	Crypto       *OpenVPNCrypto       `json:"crypto"`
	Certificates *OpenVPNCertificates `json:"certificates"`
	Advanced     *OpenVPNAdvanced     `json:"advanced"`
}

// OpenVPNServer is "server": the remote directive.
type OpenVPNServer struct {
	Address string `json:"address"`
	Port    uint16 `json:"port"`
	Network string `json:"network"` // udp (default), tcp, udp4, udp6, tcp4, tcp6
}

// OpenVPNAuth is "auth": the auth-user-pass credentials.
type OpenVPNAuth struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

// OpenVPNCrypto is "crypto": cipher, data-ciphers and auth.
type OpenVPNCrypto struct {
	Cipher      string   `json:"cipher"`
	DataCiphers []string `json:"dataCiphers"`
	AuthHash    string   `json:"authHash"`
}

// OpenVPNCertificates is "certificates": the inline blocks, as PEM text.
type OpenVPNCertificates struct {
	CA           string `json:"ca"`
	Cert         string `json:"cert"`
	Key          string `json:"key"`
	TLSCrypt     string `json:"tlsCrypt"`
	TLSAuth      string `json:"tlsAuth"`
	KeyDirection *int   `json:"keyDirection"` // for tlsAuth: 0 or 1
	TLSCryptV2   string `json:"tlsCryptV2"`
}

// OpenVPNAdvanced is "advanced".
type OpenVPNAdvanced struct {
	Dev           string `json:"dev"` // only "tun"
	Nobind        bool   `json:"nobind"`
	RemoteCertTLS string `json:"remoteCertTls"` // "server" checks the server certificate's usage
	MTU           int32  `json:"mtu"`           // the same as the top-level "mtu"
}

func (s *OpenVPNSettings) used() bool {
	return s.Server != nil || s.Auth != nil || s.Crypto != nil || s.Certificates != nil || s.Advanced != nil
}

// ovpnText writes the settings as .ovpn text. Every value is checked so that
// it cannot add a directive of its own (no whitespace in single arguments,
// no tags in PEM text). Errors name the field, never its value.
func (s *OpenVPNSettings) ovpnText() (string, error) {
	var b strings.Builder
	line := func(args ...string) {
		b.WriteString(strings.Join(args, " "))
		b.WriteByte('\n')
	}

	if s.Server == nil || s.Server.Address == "" {
		return "", errors.New(`"server.address" is required`)
	}
	if err := checkOpenVPNArg("server.address", s.Server.Address); err != nil {
		return "", err
	}
	if s.Server.Port == 0 {
		return "", errors.New(`"server.port" is required`)
	}
	network := strings.ToLower(s.Server.Network)
	switch network {
	case "":
		network = "udp"
	case "udp", "udp4", "udp6", "tcp", "tcp4", "tcp6":
	case "tcp-client", "tcp4-client", "tcp6-client":
	default:
		return "", errors.New(`"server.network" must be udp or tcp`)
	}

	line("client")
	if a := s.Advanced; a != nil && a.Dev != "" && strings.ToLower(a.Dev) != "tun" {
		return "", errors.New(`"advanced.dev": only tun is supported`)
	}
	line("dev", "tun")
	line("remote", s.Server.Address, strconv.Itoa(int(s.Server.Port)), network)

	if a := s.Advanced; a != nil {
		if a.Nobind {
			line("nobind")
		}
		if a.RemoteCertTLS != "" {
			if err := checkOpenVPNArg("advanced.remoteCertTls", a.RemoteCertTLS); err != nil {
				return "", err
			}
			line("remote-cert-tls", a.RemoteCertTLS)
		}
	}

	if c := s.Crypto; c != nil {
		if c.Cipher != "" {
			if err := checkOpenVPNArg("crypto.cipher", c.Cipher); err != nil {
				return "", err
			}
			line("cipher", c.Cipher)
		}
		if len(c.DataCiphers) > 0 {
			for _, name := range c.DataCiphers {
				if err := checkOpenVPNArg("crypto.dataCiphers", name); err != nil {
					return "", err
				}
				if name == "" || strings.Contains(name, ":") {
					return "", errors.New(`"crypto.dataCiphers": one cipher name per entry`)
				}
			}
			line("data-ciphers", strings.Join(c.DataCiphers, ":"))
		}
		if c.AuthHash != "" {
			if err := checkOpenVPNArg("crypto.authHash", c.AuthHash); err != nil {
				return "", err
			}
			line("auth", c.AuthHash)
		}
	}

	if s.Auth != nil && (s.Auth.User != "" || s.Auth.Pass != "") {
		line("auth-user-pass")
	}

	if c := s.Certificates; c != nil {
		wrappers := 0
		for _, v := range []string{c.TLSCrypt, c.TLSAuth, c.TLSCryptV2} {
			if strings.TrimSpace(v) != "" {
				wrappers++
			}
		}
		if wrappers > 1 {
			return "", errors.New(`"certificates": set only one of tlsCrypt, tlsAuth and tlsCryptV2`)
		}
		if c.KeyDirection != nil {
			if *c.KeyDirection != 0 && *c.KeyDirection != 1 {
				return "", errors.New(`"certificates.keyDirection" must be 0 or 1`)
			}
			line("key-direction", strconv.Itoa(*c.KeyDirection))
		}
		for _, blk := range []struct{ field, tag, pem string }{
			{"certificates.ca", "ca", c.CA},
			{"certificates.cert", "cert", c.Cert},
			{"certificates.key", "key", c.Key},
			{"certificates.tlsCrypt", "tls-crypt", c.TLSCrypt},
			{"certificates.tlsAuth", "tls-auth", c.TLSAuth},
			{"certificates.tlsCryptV2", "tls-crypt-v2", c.TLSCryptV2},
		} {
			pem := strings.TrimSpace(strings.ReplaceAll(blk.pem, "\r\n", "\n"))
			if pem == "" {
				continue
			}
			if strings.Contains(pem, "<") || strings.Contains(pem, ">") {
				return "", errors.New(`"`, blk.field, `" must be the PEM text only, without <`, blk.tag, `> tags`)
			}
			b.WriteString("<" + blk.tag + ">\n" + pem + "\n</" + blk.tag + ">\n")
		}
	}
	return b.String(), nil
}

// checkOpenVPNArg rejects a value that would not stay one directive argument.
func checkOpenVPNArg(field, v string) error {
	bad := v == "" || strings.ContainsAny(v, "\"'\\#;<>") ||
		strings.ContainsFunc(v, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) })
	if bad {
		return errors.New(`"`, field, `" is not a valid value`)
	}
	return nil
}
