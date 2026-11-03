package openvpn

import (
	"context"
	gonet "net"
	"syscall"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// transportNotSentLowat bounds the data written to a TCP transport's socket
// that the kernel has not sent yet (TCP_NOTSENT_LOWAT): a write blocks once
// that much is waiting.
//
// Over a TCP transport the stack's connections see no loss (tunnel.go), and
// reno grows each one's window up to the stack's send-buffer limit (4 MiB).
// Unbounded, the excess left the stack at once and waited in the socket's
// send buffer, one queue in front of every connection in the tunnel: at 20
// Mbit/s every new request and every reply on another connection waited
// 0.6-1.2 s behind an upload. Bounded, the excess stays in the uploading
// connection's own queue in the stack, and the others' packets get to the
// socket within a fraction of a second; a fast path still fills (128 KiB
// is about 7 ms at 150 Mbit/s, and the kernel keeps its whole congestion
// window in flight besides).
const transportNotSentLowat = 128 << 10

// boundTransportBacklog sets transportNotSentLowat on conn's TCP socket. A
// connection that is no socket of this system (a transport chained through
// another outbound) or a system without the option keeps its default; that
// is only logged.
func boundTransportBacklog(ctx context.Context, conn gonet.Conn) {
	s := transportSocket(conn)
	if s == nil {
		errors.LogDebug(ctx, "the OpenVPN transport is not a socket of this system; its send queue keeps the default bound")
		return
	}
	rc, err := s.SyscallConn()
	if err == nil {
		err = setNotSentLowat(rc, transportNotSentLowat)
	}
	if err != nil {
		errors.LogDebugInner(ctx, err, "failed to bound the OpenVPN transport's send queue")
	}
}

// transportSocket is the socket under the wrappers Xray's dialer puts around
// a connection (stats counters, the rate limiter, TLS), nil when there is
// none.
func transportSocket(c gonet.Conn) syscall.Conn {
	for i := 0; i < 8 && c != nil; i++ {
		if s, ok := c.(syscall.Conn); ok {
			return s
		}
		switch w := c.(type) {
		case *stat.CounterConnection:
			c = w.Connection
		case interface{ Inner() gonet.Conn }: // app/ratelimit
			c = w.Inner()
		case interface{ NetConn() gonet.Conn }: // TLS
			c = w.NetConn()
		default:
			return nil
		}
	}
	return nil
}
