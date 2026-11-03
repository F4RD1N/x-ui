package shadowtls

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy/nativebridge"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

type Client struct {
	config *Config
	policy policy.Manager
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, c interface{}) (result interface{}, err error) {
		defer nativebridge.Recover(&err, nil)
		return New(ctx, c.(*Config))
	}))
}
func New(ctx context.Context, c *Config) (*Client, error) {
	if c.Address == "" || c.Port == 0 || c.Port > 65535 || c.ServerName == "" {
		return nil, errors.New("ShadowTLS requires address, port and serverName")
	}
	if c.Version == 0 {
		c.Version = 3
	}
	if c.Version < 1 || c.Version > 3 {
		return nil, errors.New("unsupported ShadowTLS version")
	}
	if c.Version >= 2 && c.Password == "" {
		return nil, errors.New("ShadowTLS password is required")
	}
	if c.UuidSessionId {
		if c.Version != 3 {
			return nil, errors.New("uuidSessionId requires ShadowTLS v3")
		}
		if _, e := uuid.Parse(c.Password); e != nil {
			return nil, errors.New("uuidSessionId requires UUID password")
		}
	}
	return &Client{c, core.MustFromContext(ctx).GetFeature(policy.ManagerType()).(policy.Manager)}, nil
}
func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) (err error) {
	defer nativebridge.Recover(&err, nil)
	target, e := nativebridge.Target(ctx, "shadowtls")
	if e != nil {
		return e
	}
	if target.Network != xnet.Network_TCP {
		return errors.New("ShadowTLS is a TCP transport; use an inner proxy for UDP")
	}
	dest := xnet.TCPDestination(xnet.ParseAddress(c.config.Address), xnet.Port(c.config.Port))
	raw, e := dialer.Dial(nativebridge.DialContext(ctx, dest, "shadowtls"), dest)
	if e != nil {
		return e
	}
	defer raw.Close()
	timeout := c.config.HandshakeTimeout
	if timeout == 0 {
		timeout = 10
	}
	clear := nativebridge.SetupDeadline(ctx, raw, time.Duration(timeout)*time.Second)
	conn, e := Handshake(ctx, raw, c.config)
	clear()
	if e != nil {
		return e
	}
	return nativebridge.Relay(ctx, link, conn, nil, target, c.policy.ForLevel(0))
}
