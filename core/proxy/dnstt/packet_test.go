package dnstt

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"github.com/xtls/xray-core/common/session"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/stat"
	"www.bamsoftware.com/git/dnstt.git/dns"
)

func wireSettings() *Config {
	return &Config{Domain: "tunnel.test", EdnsPayloadSize: 1232, MaxQnameLength: 255, LabelMin: 25, LabelMax: 40, MaxConcurrentQueries: 2, QueryTimeout: 1}
}
func TestPacketQueryStockEncodingAndQnameBudget(t *testing.T) {
	cfg := wireSettings()
	domain, _ := dns.ParseName(cfg.Domain)
	pc := &dnsPacketConn{cfg: cfg, domain: domain}
	if _, err := rand.Read(pc.clientID[:]); err != nil {
		t.Fatal(err)
	}
	mtu, err := packetMTU(cfg)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x8d}, mtu)
	seen := map[int]bool{}
	for i := 0; i < 100; i++ {
		packet, err := pc.query(payload)
		if err != nil {
			t.Fatal(err)
		}
		q, err := dns.MessageFromWireFormat(packet)
		if err != nil {
			t.Fatal(err)
		}
		if len(q.Question) != 1 || q.Question[0].Type != dns.RRTypeTXT || q.Additional[0].Class != 1232 {
			t.Fatal("wrong stock DNS framing")
		}
		prefix, ok := q.Question[0].Name.TrimSuffix(domain)
		if !ok {
			t.Fatal("lost tunnel suffix")
		}
		total := 1
		for _, l := range q.Question[0].Name {
			total += len(l) + 1
		}
		if total > 255 {
			t.Fatal("QNAME exceeds wire limit")
		}
		for index, l := range prefix {
			if index < len(prefix)-1 && (len(l) < 25 || len(l) > 40) {
				t.Fatal("label bound")
			}
			seen[len(l)] = true
		}
		decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(string(bytes.Join(prefix, nil))))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decoded[:8], pc.clientID[:]) || decoded[8] != 227 || int(decoded[12]) != len(payload) || !bytes.Equal(decoded[13:], payload) {
			t.Fatal("stock server would decode different bytes")
		}
	}
	if len(seen) < 3 {
		t.Fatal("labels did not vary")
	}
	a, _ := pc.query(nil)
	b, _ := pc.query(nil)
	if bytes.Equal(a, b) {
		t.Fatal("empty polls can be cached")
	}
	cfg.MaxQnameLength = 64
	if _, err := packetMTU(cfg); err == nil {
		t.Fatal("accepted unusable KCP capacity")
	}
}
func TestPacketResponseCorrelationAndDatagramBoundaries(t *testing.T) {
	cfg := wireSettings()
	domain, _ := dns.ParseName(cfg.Domain)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pc := &dnsPacketConn{cfg: cfg, ctx: ctx, domain: domain, incoming: make(chan []byte, 8), poll: make(chan struct{}, 16)}
	query, _ := pc.query([]byte("upstream"))
	q, _ := dns.MessageFromWireFormat(query)
	one, two := []byte("one"), []byte("second packet")
	payload := binary.BigEndian.AppendUint16(nil, uint16(len(one)))
	payload = append(payload, one...)
	payload = binary.BigEndian.AppendUint16(payload, uint16(len(two)))
	payload = append(payload, two...)
	// TXT strings split at any position without changing the stream payload.
	txt := append([]byte{byte(len(payload))}, payload...)
	answer := dns.RR{Name: q.Question[0].Name, Type: dns.RRTypeTXT, Class: dns.ClassIN, Data: txt}
	response := dns.Message{ID: q.ID, Flags: 0x8000, Question: q.Question, Answer: []dns.RR{answer}}
	for _, field := range []string{"id", "truncated", "rcode", "question", "answer"} {
		bad := response
		bad.Question = append([]dns.Question(nil), response.Question...)
		bad.Answer = append([]dns.RR(nil), response.Answer...)
		switch field {
		case "id":
			bad.ID++
		case "truncated":
			bad.Flags |= 0x0200
		case "rcode":
			bad.Flags |= 3
		case "question":
			bad.Question[0].Type = 1
		case "answer":
			bad.Answer[0].Name, _ = dns.ParseName("unrelated.test")
		}
		wire, _ := bad.WireFormat()
		pc.consume(query, wire)
		if len(pc.incoming) != 0 {
			t.Fatal("accepted uncorrelated response", field)
		}
	}
	wire, _ := response.WireFormat()
	pc.consume(query, wire)
	if len(pc.incoming) != 2 || !bytes.Equal(<-pc.incoming, one) || !bytes.Equal(<-pc.incoming, two) || len(pc.poll) != 1 {
		t.Fatal("changed datagrams or lost response-triggered poll")
	}
}

type noNetworkWireDialer struct{}

func (noNetworkWireDialer) Dial(context.Context, xnet.Destination) (stat.Connection, error) {
	return nil, errors.New("network forbidden in test")
}
func (noNetworkWireDialer) Address() xnet.Address  { return nil }
func (noNetworkWireDialer) DestIpAddress() xnet.IP { return nil }
func TestPacketDeadlineCancellationAndClose(t *testing.T) {
	cfg := wireSettings()
	cfg.Resolvers = []*Resolver{{Transport: "udp", Address: "127.0.0.1:53"}}
	pc, err := newPacketConn(context.Background(), cfg, noNetworkWireDialer{})
	if err != nil {
		t.Fatal(err)
	}
	pc.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if _, _, err = pc.ReadFrom(make([]byte, 8)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("read deadline ignored", err)
	}
	done := make(chan error, 1)
	pc.SetReadDeadline(time.Time{})
	go func() { _, _, err := pc.ReadFrom(make([]byte, 8)); done <- err }()
	if err = pc.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("close retained reader")
	}
	if err = pc.Close(); err != nil {
		t.Fatal(err)
	}
}

func (noNetworkWireDialer) SetOutboundGateway(context.Context, *session.Outbound) {}
