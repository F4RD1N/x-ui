package openvpn

import (
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/proxy/nativebridge"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/wire"
	"github.com/xtls/xray-core/transport/internet/stat"
	"io"
	"sync"
	"time"
)

// serverPacketConn preserves UDP datagrams (Xray UDP connections expose buf.Reader,
// their io.Reader deliberately panics) and adds OpenVPN TCP length framing.
type serverPacketConn struct {
	conn       stat.Connection
	tcp        bool
	frames     *wire.FrameReader
	reader     buf.Reader
	readCallMu sync.Mutex
	readMu     sync.Mutex
	pending    buf.MultiBuffer
	closed     bool
	writeMu    sync.Mutex
	once       sync.Once
}

func newServerPacketConn(c stat.Connection, tcp bool) *serverPacketConn {
	p := &serverPacketConn{conn: c, tcp: tcp}
	if tcp {
		p.frames = wire.NewFrameReader(c)
	} else {
		p.reader = buf.NewPacketReader(c)
	}
	return p
}
func (p *serverPacketConn) ReadPacket(b []byte) (int, error) {
	p.readCallMu.Lock()
	defer p.readCallMu.Unlock()
	if p.tcp {
		return p.frames.ReadPacket(b)
	}
	for {
		p.readMu.Lock()
		if p.closed {
			p.readMu.Unlock()
			return 0, io.EOF
		}
		if len(p.pending) > 0 {
			v := p.pending[0]
			p.pending[0] = nil
			p.pending = p.pending[1:]
			if v == nil {
				p.readMu.Unlock()
				continue
			}
			n := int(v.Len())
			if n > len(b) {
				v.Release()
				p.readMu.Unlock()
				return 0, io.ErrShortBuffer
			}
			copy(b, v.Bytes())
			v.Release()
			p.readMu.Unlock()
			return n, nil
		}
		p.readMu.Unlock()
		mb, e := p.reader.ReadMultiBuffer()
		p.readMu.Lock()
		if p.closed {
			buf.ReleaseMulti(mb)
			p.readMu.Unlock()
			return 0, io.EOF
		}
		p.pending = mb
		p.readMu.Unlock()
		if e != nil && len(mb) == 0 {
			return 0, e
		}
	}
}
func (p *serverPacketConn) WritePacket(b []byte) error {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	_ = p.conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	if p.tcp {
		f, e := wire.AppendFrame(nil, b)
		if e != nil {
			return e
		}
		return nativebridge.WriteFull(p.conn, f)
	}
	n, e := p.conn.Write(b)
	if e == nil && n != len(b) {
		return io.ErrShortWrite
	}
	return e
}
func (p *serverPacketConn) Close() error {
	var e error
	p.once.Do(func() {
		p.readMu.Lock()
		p.closed = true
		buf.ReleaseMulti(p.pending)
		p.pending = nil
		p.readMu.Unlock()
		e = p.conn.Close()
	})
	return e
}
