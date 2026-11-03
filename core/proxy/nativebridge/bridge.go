// Package nativebridge connects native protocol clients to Xray's links and dialer.
// It contains no protocol implementation from a third-party VPN core.
package nativebridge

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
)

func WriteFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

// DialContext gives the transport a private outbound record. A pooled session
// must not keep writing into the request that originally opened it.
func DialContext(ctx context.Context, dest xnet.Destination, name string) context.Context {
	old := session.OutboundsFromContext(ctx)
	list := append([]*session.Outbound(nil), old...)
	if len(list) == 0 {
		list = append(list, &session.Outbound{})
	}
	last := *list[len(list)-1]
	last.Target, last.Name, last.Conn = dest, name, nil
	list[len(list)-1] = &last
	return session.ContextWithOutbounds(ctx, list)
}

func Target(ctx context.Context, name string) (xnet.Destination, error) {
	obs := session.OutboundsFromContext(ctx)
	if len(obs) == 0 || !obs[len(obs)-1].Target.IsValid() {
		return xnet.Destination{}, errors.New("target not specified")
	}
	ob := obs[len(obs)-1]
	ob.Name, ob.CanSpliceCopy = name, 3
	return ob.Target, nil
}

// Address is the RFC1928 address/port representation (without VER/CMD/RSV).
func Address(d xnet.Destination) ([]byte, error) {
	var b []byte
	switch d.Address.Family() {
	case xnet.AddressFamilyIPv4:
		b = append([]byte{1}, d.Address.IP().To4()...)
	case xnet.AddressFamilyIPv6:
		b = append([]byte{4}, d.Address.IP().To16()...)
	case xnet.AddressFamilyDomain:
		s := d.Address.Domain()
		if len(s) == 0 || len(s) > 255 {
			return nil, errors.New("invalid destination domain length")
		}
		b = append([]byte{3, byte(len(s))}, []byte(s)...)
	default:
		return nil, errors.New("invalid destination address")
	}
	return binary.BigEndian.AppendUint16(b, d.Port.Value()), nil
}

func ReadAddress(r io.Reader) (xnet.Destination, error) {
	var b [1]byte
	if _, e := io.ReadFull(r, b[:]); e != nil {
		return xnet.Destination{}, e
	}
	var a xnet.Address
	switch b[0] {
	case 1, 4:
		n := 4
		if b[0] == 4 {
			n = 16
		}
		ip := make([]byte, n)
		if _, e := io.ReadFull(r, ip); e != nil {
			return xnet.Destination{}, e
		}
		a = xnet.IPAddress(ip)
	case 3:
		if _, e := io.ReadFull(r, b[:]); e != nil {
			return xnet.Destination{}, e
		}
		if b[0] == 0 {
			return xnet.Destination{}, errors.New("empty destination")
		}
		p := make([]byte, int(b[0]))
		if _, e := io.ReadFull(r, p); e != nil {
			return xnet.Destination{}, e
		}
		a = xnet.DomainAddress(string(p))
	default:
		return xnet.Destination{}, errors.New("unknown address family")
	}
	var p [2]byte
	if _, e := io.ReadFull(r, p[:]); e != nil {
		return xnet.Destination{}, e
	}
	return xnet.UDPDestination(a, xnet.Port(binary.BigEndian.Uint16(p[:]))), nil
}

// PacketCodec preserves datagram boundaries and per-packet destinations.
type PacketCodec interface {
	WritePacket([]byte, xnet.Destination) error
	ReadPacket() ([]byte, xnet.Destination, error)
}

func Relay(ctx context.Context, link *transport.Link, conn net.Conn, packets PacketCodec, target xnet.Destination, p policy.Session) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() {
		defer RecoverWorker(func(error) {})
		_ = conn.Close()
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
	})
	defer stop()
	timer := signal.CancelAfterInactivity(ctx, cancel, p.Timeouts.ConnectionIdle)
	defer timer.SetTimeout(0)
	up := func() error {
		defer timer.SetTimeout(p.Timeouts.DownlinkOnly)
		var e error
		if packets == nil {
			e = buf.Copy(link.Reader, buf.NewWriter(conn), buf.UpdateActivity(timer))
		} else {
			e = copyPacketsUp(link.Reader, packets, target, timer)
		}
		if c, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
		return e
	}
	down := func() error {
		defer timer.SetTimeout(p.Timeouts.UplinkOnly)
		if packets == nil {
			return buf.Copy(buf.NewReader(conn), link.Writer, buf.UpdateActivity(timer))
		}
		for {
			b, d, e := packets.ReadPacket()
			if e != nil {
				return e
			}
			timer.Update()
			out := buf.New()
			if len(b) > int(buf.Size) {
				out.Release()
				return errors.New("UDP datagram exceeds Xray buffer size")
			}
			_, _ = out.Write(b)
			out.UDP = &d
			if e = link.Writer.WriteMultiBuffer(buf.MultiBuffer{out}); e != nil {
				return e
			}
		}
	}
	safe := func(fn func() error) func() error {
		return func() (err error) { defer Recover(&err, func() { cancel(); _ = conn.Close() }); return fn() }
	}
	return task.Run(ctx, safe(up), safe(task.OnSuccess(down, task.Close(link.Writer))))
}

func copyPacketsUp(r buf.Reader, c PacketCodec, d xnet.Destination, t signal.ActivityUpdater) error {
	for {
		mb, e := r.ReadMultiBuffer()
		for i, b := range mb {
			dest := d
			if b.UDP != nil {
				dest = *b.UDP
			}
			err := c.WritePacket(b.Bytes(), dest)
			b.Release()
			mb[i] = nil
			if err != nil {
				buf.ReleaseMulti(mb)
				return err
			}
			t.Update()
		}
		if e != nil {
			return e
		}
	}
}

// SetupDeadline binds a handshake to request cancellation and a finite timeout.
// Stop it before putting a successful connection into an idle pool.
func SetupDeadline(ctx context.Context, c net.Conn, timeout time.Duration) func() {
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	return func() { stop(); _ = c.SetDeadline(time.Time{}) }
}
