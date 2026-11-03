package fixture

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// An empty dnstt poll may block at the authority while a later query contains
// new upstream data. A DoT resolver must let the latter overtake the former,
// otherwise a window of empty polls can stall an active tunnel for seconds.
func TestDoTPipelinesQueriesWithoutHeadOfLineBlocking(t *testing.T) {
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	defer close(release)
	slowStarted := make(chan struct{}, 1)
	authority := &dns.Server{PacketConn: udp, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		if q.Question[0].Name == "slow.tunnel.test." {
			slowStarted <- struct{}{}
			<-release
		}
		a := new(dns.Msg)
		a.SetReply(q)
		w.WriteMsg(a)
	})}
	go authority.ActivateAndServe()
	t.Cleanup(func() { authority.Shutdown() })
	r, err := Start(t.TempDir(), "tunnel.test", udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(r.CAPEM)) {
		t.Fatal("fixture CA is invalid")
	}
	conn, err := tls.Dial("tcp", r.DoT, &tls.Config{ServerName: ServerName, RootCAs: roots, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	writeQuery := func(name string, id uint16) {
		t.Helper()
		q := new(dns.Msg)
		q.SetQuestion(name, dns.TypeTXT)
		q.Id = id
		wire, _ := q.Pack()
		frame := binary.BigEndian.AppendUint16(nil, uint16(len(wire)))
		if _, err := conn.Write(append(frame, wire...)); err != nil {
			t.Fatal(err)
		}
	}
	writeQuery("slow.tunnel.test.", 100)
	select {
	case <-slowStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("slow request never reached authority")
	}
	writeQuery("fast.tunnel.test.", 101)
	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		t.Fatalf("fast query was blocked behind the empty poll: %v", err)
	}
	wire := make([]byte, int(binary.BigEndian.Uint16(size[:])))
	if _, err := io.ReadFull(conn, wire); err != nil {
		t.Fatal(err)
	}
	var reply dns.Msg
	if err := reply.Unpack(wire); err != nil || reply.Id != 101 {
		t.Fatalf("first DoT reply ID=%d err=%v, want fast query 101", reply.Id, err)
	}
}
