//go:build !linux

package freedom

import (
	"context"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

// echoConn is not implemented off Linux: pings are dropped, which the
// client sees as a timeout.
type echoConn struct {
	wireID uint16
}

func openEchoConn(context.Context, bool, net.IP, *internet.SocketConfig, func(net.IP, []byte)) (*echoConn, error) {
	return nil, errors.New("ICMP echo is not supported on this platform")
}

func (c *echoConn) write(net.IP, []byte) error {
	return errors.New("ICMP echo is not supported on this platform")
}

func (c *echoConn) Close() error { return nil }
