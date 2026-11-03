package openvpn

import (
	"net"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// packetTransportConn keeps a chained UDP transport's MultiBuffer datagrams
// separate. Generic net.Conn.Read on the target core's chain is stream-oriented.
// This adapter is local to OpenVPN and preserves all existing write/deadline
// behavior and every nested transport byte counter.
type packetTransportConn struct {
	net.Conn
	packets  *serverPacketConn
	counters []stats.Counter
}

func preserveTransportPackets(c net.Conn) net.Conn {
	raw := c
	var counters []stats.Counter
	for i := 0; i < 64; i++ {
		wrapped, ok := raw.(*stat.CounterConnection)
		if !ok {
			break
		}
		if wrapped.ReadCounter != nil {
			counters = append(counters, wrapped.ReadCounter)
		}
		raw = wrapped.Connection
	}
	reader, ok := raw.(buf.Reader)
	if !ok {
		return c
	}
	packets := newServerPacketConn(c, false)
	packets.reader = reader
	return &packetTransportConn{Conn: c, packets: packets, counters: counters}
}
func (c *packetTransportConn) Read(p []byte) (int, error) {
	n, e := c.packets.ReadPacket(p)
	for _, counter := range c.counters {
		counter.Add(int64(n))
	}
	return n, e
}
func (c *packetTransportConn) Close() error { return c.packets.Close() }
