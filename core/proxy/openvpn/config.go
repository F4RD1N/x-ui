package openvpn

import (
	"fmt"
	"strings"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/clientproof"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/runtime/protoimpl"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/options"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/tlsconf"
)

// Bounds of Config.Mtu when it is set.
const (
	MinMTU = 576
	MaxMTU = 65535
)

// defaultMTU caps the userspace stack's MTU when Config.Mtu is 0, so that a
// full-size packet still fits one transport datagram on common paths after
// the OpenVPN overhead.
const defaultMTU = 1400

// ParseOptions parses c.Ovpn and checks the rest of c: what New does before
// it accepts a configuration, and what the JSON loader does to reject a bad
// one early. It never puts secrets (keys, passwords) in its errors.
//
// Besides options.Parse it requires a remote, an Mtu of 0 or within
// [MinMTU, MaxMTU], a known DomainStrategy, no Password without a Username,
// credentials when the configuration asks for them (auth-user-pass without
// an inline block needs Username), and certificates and keys that
// tlsconf.Build accepts, so that a broken one fails when the configuration
// loads rather than on every request.
func (c *Config) ParseOptions() (*options.Options, error) {
	if c == nil {
		return nil, errors.New("no configuration")
	}
	if _, err := c.proofKey(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(c.Ovpn) == "" {
		return nil, errors.New("the ovpn configuration is empty")
	}
	o, err := options.Parse(c.Ovpn)
	if err != nil {
		return nil, errors.New("invalid ovpn configuration").Base(err)
	}
	if len(o.Remotes) == 0 {
		return nil, errors.New("the ovpn configuration has no remote")
	}
	if c.Mtu != 0 && (c.Mtu < MinMTU || c.Mtu > MaxMTU) {
		return nil, errors.New("mtu ", c.Mtu, " is out of range: use 0 (automatic) or ", MinMTU, "..", MaxMTU)
	}
	if _, ok := Config_DomainStrategy_name[int32(c.DomainStrategy)]; !ok {
		return nil, errors.New("unknown domain strategy ", int32(c.DomainStrategy))
	}
	if c.Username == "" && c.Password != "" {
		return nil, errors.New("a password is set without a username")
	}
	if o.AuthUserPass && c.Username == "" && o.Username == "" {
		return nil, errors.New("the ovpn configuration asks for a username and password (auth-user-pass) but none is given: set username and password, or put them in an <auth-user-pass> block")
	}
	if _, err := tlsconf.Build(o); err != nil {
		return nil, errors.New("unusable certificate or key in the ovpn configuration").Base(err)
	}
	return o, nil
}

// The domain strategy has the meaning it has for WireGuard: which address
// families a domain destination is first resolved to, and which family is
// tried when that finds nothing.

func (c *Config) preferIP4() bool {
	return c.DomainStrategy == Config_FORCE_IP ||
		c.DomainStrategy == Config_FORCE_IP4 ||
		c.DomainStrategy == Config_FORCE_IP46
}

func (c *Config) preferIP6() bool {
	return c.DomainStrategy == Config_FORCE_IP ||
		c.DomainStrategy == Config_FORCE_IP6 ||
		c.DomainStrategy == Config_FORCE_IP64
}

func (c *Config) hasFallback() bool {
	return c.DomainStrategy == Config_FORCE_IP46 || c.DomainStrategy == Config_FORCE_IP64
}

func (c *Config) fallbackIP4() bool {
	return c.DomainStrategy == Config_FORCE_IP64
}

func (c *Config) fallbackIP6() bool {
	return c.DomainStrategy == Config_FORCE_IP46
}

// proofKey validates protobuf configurations too, not just JSON input.
func (c *Config) proofKey() (*clientproof.Key, error) {
	if c == nil || c.ClientProof == nil {
		return nil, nil
	}
	return clientproof.New(c.ClientProof.KeyId, c.ClientProof.Key)
}

// These formatters redact the newly introduced secret for every fmt verb.
// Protocol buffers and explicit JSON serialization still intentionally contain
// configured credentials and must be treated as private configuration files.
func (c *Config) Format(f fmt.State, _ rune) { fmt.Fprint(f, c.String()) }
func (c *Config) GoString() string           { return c.String() }
func configString(c *Config) string {
	if c == nil {
		return "<nil>"
	}
	cp := proto.Clone(c).(*Config)
	if cp.ClientProof != nil {
		clear(cp.ClientProof.Key)
		cp.ClientProof.Key = nil
	}
	return protoimpl.X.MessageStringOf(cp)
}
func (c *ClientProofConfig) Format(f fmt.State, _ rune) { fmt.Fprint(f, c.String()) }
func (c *ClientProofConfig) GoString() string           { return c.String() }
func proofConfigString(c *ClientProofConfig) string {
	if c == nil {
		return "<nil>"
	}
	return fmt.Sprintf("ClientProofConfig{KeyId:%q, Key:<redacted>}", c.KeyId)
}
