package mieru

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
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
	if c.Address == "" || c.Port == 0 || c.Port > 65535 || c.Username == "" || c.Password == "" {
		return nil, errors.New("Mieru requires address, port, username and password")
	}
	c.Transport = strings.ToLower(c.Transport)
	if c.Transport == "" {
		c.Transport = "tcp"
	}
	if c.Transport != "tcp" && c.Transport != "udp" {
		return nil, errors.New("Mieru transport must be tcp or udp")
	}
	if c.UuidMetadataTrailer {
		if _, e := uuid.Parse(c.Username); e != nil {
			return nil, errors.New("uuidMetadataTrailer requires a UUID username")
		}
	}
	return &Client{c, core.MustFromContext(ctx).GetFeature(policy.ManagerType()).(policy.Manager)}, nil
}

func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) (err error) {
	defer nativebridge.Recover(&err, nil)
	target, e := nativebridge.Target(ctx, "mieru")
	if e != nil {
		return e
	}
	network := xnet.Network_TCP
	if c.config.Transport == "udp" {
		network = xnet.Network_UDP
	}
	dest := xnet.Destination{Network: network, Address: xnet.ParseAddress(c.config.Address), Port: xnet.Port(c.config.Port)}
	raw, e := dialer.Dial(nativebridge.DialContext(ctx, dest, "mieru"), dest)
	if e != nil {
		return e
	}
	defer raw.Close()
	timeout := c.config.HandshakeTimeout
	if timeout == 0 {
		timeout = 10
	}
	clear := nativebridge.SetupDeadline(ctx, raw, time.Duration(timeout)*time.Second)
	defer clear()
	w, e := newWire(raw, c.config.Username, c.config.Password, network == xnet.Network_UDP, c.config.UuidMetadataTrailer)
	if e != nil {
		return e
	}
	conn, e := Open(w)
	if e != nil {
		return e
	}
	defer conn.Close()
	addressTarget := target
	cmd := byte(1)
	if target.Network == xnet.Network_UDP {
		cmd = 3
		addressTarget = xnet.UDPDestination(xnet.AnyIP, 0)
	}
	addr, e := nativebridge.Address(addressTarget)
	if e != nil {
		return e
	}
	if e = socksRequest(conn, cmd, addr); e != nil {
		return e
	}
	clear()
	var packets nativebridge.PacketCodec
	if target.Network == xnet.Network_UDP {
		packets = &packetConn{Conn: conn}
	}
	return nativebridge.Relay(ctx, link, conn, packets, target, c.policy.ForLevel(0))
}

type packetConn struct{ net.Conn }

func (c *packetConn) WritePacket(p []byte, d xnet.Destination) error {
	a, e := nativebridge.Address(d)
	if e != nil {
		return e
	}
	payload := append([]byte{0, 0, 0}, a...)
	payload = append(payload, p...)
	if len(payload) > 65535 {
		return errors.New("Mieru UDP packet too large")
	}
	frame := []byte{0, byte(len(payload) >> 8), byte(len(payload))}
	frame = append(frame, payload...)
	frame = append(frame, 255)
	return nativebridge.WriteFull(c.Conn, frame)
}
func (c *packetConn) ReadPacket() ([]byte, xnet.Destination, error) {
	var h [3]byte
	if _, e := io.ReadFull(c.Conn, h[:]); e != nil {
		return nil, xnet.Destination{}, e
	}
	if h[0] != 0 {
		return nil, xnet.Destination{}, errors.New("invalid Mieru UDP start marker")
	}
	p := make([]byte, int(binary.BigEndian.Uint16(h[1:]))+1)
	if _, e := io.ReadFull(c.Conn, p); e != nil {
		return nil, xnet.Destination{}, e
	}
	if len(p) < 5 || p[len(p)-1] != 255 || p[0] != 0 || p[1] != 0 || p[2] != 0 {
		return nil, xnet.Destination{}, errors.New("invalid Mieru UDP frame")
	}
	r := &sliceReader{p: p[3 : len(p)-1]}
	d, e := nativebridge.ReadAddress(r)
	if e != nil {
		return nil, d, e
	}
	return r.p, d, nil
}
