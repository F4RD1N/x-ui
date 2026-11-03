package conf

import (
	"errors"

	"github.com/xtls/xray-core/proxy/dnstt"
	"github.com/xtls/xray-core/proxy/nativebridge"
	"google.golang.org/protobuf/proto"
)

// Registration does not start a DNS transport or change another outbound.
func init() {
	outboundConfigLoader.cache["dnstt"] = func() interface{} { return new(DNSTTConfig) }
}

type DNSTTResolverConfig struct {
	Transport   string `json:"transport"`
	Address     string `json:"address"`
	Bootstrap   string `json:"bootstrap"`
	ServerName  string `json:"serverName"`
	Fingerprint string `json:"fingerprint"`
	CAPEM       string `json:"caPem"`
}

type DNSTTInnerConfig struct {
	Protocol string `json:"protocol"`
	UUID     string `json:"uuid"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// DNSTTConfig describes the native DNS carrier and the authenticated proxy
// inside the DNS tunnel. Timeout values are seconds; pacing is ms.
type DNSTTConfig struct {
	Domain               string                 `json:"domain"`
	PublicKey            string                 `json:"publicKey"`
	Resolvers            []*DNSTTResolverConfig `json:"resolvers"`
	Inner                *DNSTTInnerConfig      `json:"inner"`
	HandshakeTimeout     uint32                 `json:"handshakeTimeout"`
	QueryTimeout         uint32                 `json:"queryTimeout"`
	MaxConcurrentQueries uint32                 `json:"maxConcurrentQueries"`
	MinQueryIntervalMS   uint32                 `json:"minQueryIntervalMs"`
	EDNSPayloadSize      uint32                 `json:"ednsPayloadSize"`
	MaxQNameLength       uint32                 `json:"maxQnameLength"`
	LabelMin             uint32                 `json:"labelMin"`
	LabelMax             uint32                 `json:"labelMax"`
}

func (c *DNSTTConfig) Build() (message proto.Message, err error) {
	defer nativebridge.Recover(&err, nil)
	if c == nil {
		return nil, errors.New("dnstt: settings are required")
	}
	config := &dnstt.Config{
		Domain:               c.Domain,
		PublicKey:            c.PublicKey,
		HandshakeTimeout:     c.HandshakeTimeout,
		QueryTimeout:         c.QueryTimeout,
		MaxConcurrentQueries: c.MaxConcurrentQueries,
		MinQueryIntervalMs:   c.MinQueryIntervalMS,
		EdnsPayloadSize:      c.EDNSPayloadSize,
		MaxQnameLength:       c.MaxQNameLength,
		LabelMin:             c.LabelMin,
		LabelMax:             c.LabelMax,
		Resolvers:            make([]*dnstt.Resolver, len(c.Resolvers)),
	}
	for i, resolver := range c.Resolvers {
		if resolver == nil {
			return nil, errors.New("dnstt: each resolver must be an object")
		}
		config.Resolvers[i] = &dnstt.Resolver{
			Transport:   resolver.Transport,
			Address:     resolver.Address,
			Bootstrap:   resolver.Bootstrap,
			ServerName:  resolver.ServerName,
			Fingerprint: resolver.Fingerprint,
			CaPem:       resolver.CAPEM,
		}
	}
	if c.Inner != nil {
		config.Inner = &dnstt.Inner{
			Protocol: c.Inner.Protocol,
			Uuid:     c.Inner.UUID,
			Username: c.Inner.Username,
			Password: c.Inner.Password,
		}
	}
	return dnstt.NormalizeConfig(config)
}
