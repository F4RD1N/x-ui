package dnstt

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/nativebridge"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/proxy/vless"
	vencoding "github.com/xtls/xray-core/proxy/vless/encoding"
)

// innerConnection writes the authenticated destination request inside one
// dnstt smux stream. The native server dispatches through a private inner inbound.
func innerConnection(ctx context.Context, raw net.Conn, target xnet.Destination, cfg *Config) (net.Conn, nativebridge.PacketCodec, error) {
	stop := nativebridge.SetupDeadline(ctx, raw, time.Duration(cfg.HandshakeTimeout)*time.Second)
	defer stop()
	if cfg.Inner.Protocol == "socks" {
		if target.Network != xnet.Network_TCP {
			return nil, nil, errors.New("dnstt: SOCKS5 inner protocol supports TCP only")
		}
		request := &protocol.RequestHeader{Version: 5, Command: protocol.RequestCommandTCP,
			Address: target.Address, Port: target.Port,
			User: &protocol.MemoryUser{Account: &socks.Account{Username: cfg.Inner.Username, Password: cfg.Inner.Password}}}
		if _, err := socks.ClientHandshake(request, raw, raw); err != nil {
			return nil, nil, errors.New("dnstt: inner SOCKS5 authentication or CONNECT failed")
		}
		return raw, nil, nil
	}
	id, err := uuid.ParseString(cfg.Inner.Uuid)
	if err != nil {
		return nil, nil, settingError("inner.uuid", "is invalid")
	}
	command := protocol.RequestCommandTCP
	if target.Network == xnet.Network_UDP {
		command = protocol.RequestCommandUDP
	}
	request := &protocol.RequestHeader{Version: vencoding.Version, Command: command,
		Address: target.Address, Port: target.Port,
		User: &protocol.MemoryUser{Account: &vless.MemoryAccount{ID: protocol.NewID(id), Encryption: "none"}}}
	if err := vencoding.EncodeRequestHeader(raw, request, &vencoding.Addons{}); err != nil {
		return nil, nil, errors.New("dnstt: writing inner VLESS request failed")
	}
	// Xray buffers the VLESS response header until the destination sends its
	// first payload. Waiting for that header here would deadlock HTTP and TLS:
	// their request must be relayed before the destination answers.
	deadline := time.Now().Add(time.Duration(cfg.HandshakeTimeout) * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn := &vlessResponseConn{Conn: raw, request: request, responseDeadline: deadline}
	if target.Network == xnet.Network_UDP {
		return conn, &vlessPackets{conn: conn, target: target}, nil
	}
	return conn, nil, nil
}

type vlessResponseConn struct {
	net.Conn
	request          *protocol.RequestHeader
	responseDeadline time.Time
	once             sync.Once
	err              error
}

func (c *vlessResponseConn) Read(p []byte) (int, error) {
	c.once.Do(func() {
		_ = c.Conn.SetReadDeadline(c.responseDeadline)
		if _, err := vencoding.DecodeResponseHeader(c.Conn, c.request); err != nil {
			c.err = errors.New("dnstt: inner VLESS response was rejected or timed out")
			return
		}
		_ = c.Conn.SetReadDeadline(time.Time{})
	})
	if c.err != nil {
		return 0, c.err
	}
	return c.Conn.Read(p)
}

// Preserve the half-close offered by smux through the response-header wrapper.
func (c *vlessResponseConn) CloseWrite() error {
	if w, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return nil
}

// VLESS UDP binds one stream to one destination; its framing is a uint16
// payload length followed by that datagram, without a destination per packet.
type vlessPackets struct {
	conn   net.Conn
	target xnet.Destination
}

func (p *vlessPackets) WritePacket(data []byte, target xnet.Destination) error {
	if target != p.target {
		return errors.New("dnstt: VLESS UDP stream cannot change its destination")
	}
	if len(data) > int(buf.Size) {
		return errors.New("dnstt: UDP datagram exceeds Xray buffer size")
	}
	frame := binary.BigEndian.AppendUint16(nil, uint16(len(data)))
	frame = append(frame, data...)
	return nativebridge.WriteFull(p.conn, frame)
}

func (p *vlessPackets) ReadPacket() ([]byte, xnet.Destination, error) {
	var head [2]byte
	if _, err := io.ReadFull(p.conn, head[:]); err != nil {
		return nil, p.target, err
	}
	n := int(binary.BigEndian.Uint16(head[:]))
	if n > int(buf.Size) {
		return nil, p.target, errors.New("dnstt: UDP datagram exceeds Xray buffer size")
	}
	data := make([]byte, n)
	_, err := io.ReadFull(p.conn, data)
	return data, p.target, err
}
