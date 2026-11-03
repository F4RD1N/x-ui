package anytls

import (
	"encoding/binary"
	"errors"
	"io"
	"net"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/nativebridge"
)

// UOT v2 uses RFC1928 for its request, but 0/1/2 address tags in packets.
type uotConn struct{ net.Conn }

func newUOT(c net.Conn, target xnet.Destination) (*uotConn, error) {
	b, e := nativebridge.Address(target)
	if e != nil {
		return nil, e
	}
	if e = nativebridge.WriteFull(c, append([]byte{0}, b...)); e != nil {
		return nil, e
	}
	return &uotConn{c}, nil
}
func (c *uotConn) WritePacket(p []byte, d xnet.Destination) error {
	if len(p) > 65535 {
		return errors.New("UDP packet too large")
	}
	b, e := nativebridge.Address(d)
	if e != nil {
		return e
	}
	switch b[0] {
	case 1:
		b[0] = 0
	case 4:
		b[0] = 1
	case 3:
		b[0] = 2
	}
	b = binary.BigEndian.AppendUint16(b, uint16(len(p)))
	return nativebridge.WriteFull(c.Conn, append(b, p...))
}

type firstByteReader struct {
	first byte
	r     io.Reader
	used  bool
}

func (r *firstByteReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if !r.used {
		p[0] = r.first
		r.used = true
		return 1, nil
	}
	return r.r.Read(p)
}
func (c *uotConn) ReadPacket() ([]byte, xnet.Destination, error) {
	var t [1]byte
	if _, e := io.ReadFull(c.Conn, t[:]); e != nil {
		return nil, xnet.Destination{}, e
	}
	switch t[0] {
	case 0:
		t[0] = 1
	case 1:
		t[0] = 4
	case 2:
		t[0] = 3
	default:
		return nil, xnet.Destination{}, errors.New("invalid UOT address family")
	}
	d, e := nativebridge.ReadAddress(&firstByteReader{first: t[0], r: c.Conn})
	if e != nil {
		return nil, d, e
	}
	var l [2]byte
	if _, e = io.ReadFull(c.Conn, l[:]); e != nil {
		return nil, d, e
	}
	p := make([]byte, binary.BigEndian.Uint16(l[:]))
	_, e = io.ReadFull(c.Conn, p)
	return p, d, e
}
