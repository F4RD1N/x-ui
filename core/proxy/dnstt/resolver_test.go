package dnstt

import (
	"context"
	"errors"
	"fmt"
	"github.com/xtls/xray-core/common/session"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/dnstt/internal/fixture"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type wireTestDialer struct {
	mu           sync.Mutex
	destinations []xnet.Destination
	slow         bool
}

func (d *wireTestDialer) Dial(ctx context.Context, destination xnet.Destination) (stat.Connection, error) {
	d.mu.Lock()
	d.destinations = append(d.destinations, destination)
	d.mu.Unlock()
	if d.slow {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	network := "tcp"
	if destination.Network == xnet.Network_UDP {
		network = "udp"
	}
	return new(net.Dialer).DialContext(ctx, network, destination.NetAddr())
}
func (d *wireTestDialer) Address() xnet.Address  { return nil }
func (d *wireTestDialer) DestIpAddress() xnet.IP { return nil }

func testResolverFixture(t *testing.T) *fixture.Resolver {
	t.Helper()
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	authority := &mdns.Server{PacketConn: packet, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, q *mdns.Msg) {
		answer := new(mdns.Msg)
		answer.SetReply(q)
		if len(q.Question) > 0 {
			answer.Answer = []mdns.RR{&mdns.TXT{Hdr: mdns.RR_Header{Name: q.Question[0].Name, Rrtype: mdns.TypeTXT, Class: mdns.ClassINET}, Txt: []string{q.Question[0].Name}}}
		}
		w.WriteMsg(answer)
	})}
	go authority.ActivateAndServe()
	t.Cleanup(func() { authority.Shutdown() })
	fixture, err := fixture.Start(t.TempDir(), "tunnel.test", packet.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fixture.Close)
	return fixture
}
func resolverQuery(i int) []byte {
	query := new(mdns.Msg)
	query.SetQuestion(fmt.Sprintf("q%d.tunnel.test.", i), mdns.TypeTXT)
	query.Id = uint16(i + 500)
	wire, _ := query.Pack()
	return wire
}

func TestResolverTLSBootstrapAndConcurrentTransactions(t *testing.T) {
	f := testResolverFixture(t)
	for _, mode := range []string{"udp", "dot", "doh"} {
		for _, fingerprint := range []string{"", "chrome", "firefox", "safari"} {
			if mode == "udp" && fingerprint != "" {
				continue
			}
			t.Run(mode+"/"+fingerprint, func(t *testing.T) {
				dialer := &wireTestDialer{}
				resolver := &Resolver{Transport: mode}
				switch mode {
				case "udp":
					resolver.Address = f.UDP
				case "dot":
					_, port, _ := net.SplitHostPort(f.DoT)
					resolver.Address = net.JoinHostPort(fixture.ServerName, port)
				case "doh":
					resolver.Address = strings.Replace(f.DoH, "127.0.0.1", fixture.ServerName, 1)
				}
				if mode != "udp" {
					resolver.Bootstrap = "127.0.0.1"
					resolver.ServerName = fixture.ServerName
					resolver.CaPem = f.CAPEM
					resolver.Fingerprint = fingerprint
				}
				ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
				defer cancel()
				set, err := newResolverSet(ctx, &Config{Resolvers: []*Resolver{resolver}, QueryTimeout: 2, MaxConcurrentQueries: 8}, dialer)
				if err != nil {
					t.Fatal(err)
				}
				defer set.Close()
				var wg sync.WaitGroup
				for i := 0; i < 8; i++ {
					wg.Add(1)
					go func(i int) {
						defer wg.Done()
						query := resolverQuery(i)
						wire, err := set.exchange(ctx, query)
						if err != nil {
							t.Error(err)
							return
						}
						reply := new(mdns.Msg)
						if err = reply.Unpack(wire); err != nil || reply.Id != uint16(i+500) || len(reply.Answer) != 1 {
							t.Error("mismatched concurrent transaction", err)
						}
					}(i)
				}
				wg.Wait()
				dialer.mu.Lock()
				defer dialer.mu.Unlock()
				if len(dialer.destinations) == 0 {
					t.Fatal("bypassed core dialer")
				}
				for _, d := range dialer.destinations {
					if d.Address.String() != "127.0.0.1" {
						t.Fatal("bootstrap hostname escaped to system resolver", d)
					}
				}
				if mode != "doh" && len(dialer.destinations) != 1 {
					t.Fatal("physical resolver connection was not reused", len(dialer.destinations))
				}
			})
		}
	}
}
func TestResolverRejectsWrongTLSIdentityAndHonorsDialCancellation(t *testing.T) {
	f := testResolverFixture(t)
	for _, mode := range []string{"dot", "doh"} {
		resolver := &Resolver{Transport: mode, Bootstrap: "127.0.0.1", ServerName: "wrong.test", CaPem: f.CAPEM}
		if mode == "dot" {
			resolver.Address = f.DoT
		} else {
			resolver.Address = f.DoH
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		set, err := newResolverSet(ctx, &Config{Resolvers: []*Resolver{resolver}, QueryTimeout: 1, MaxConcurrentQueries: 2}, &wireTestDialer{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = set.exchange(ctx, resolverQuery(1)); err == nil {
			t.Fatal("accepted wrong resolver certificate identity")
		}
		cancel()
		set.Close()
	}
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	slow := &wireTestDialer{slow: true}
	set, err := newResolverSet(base, &Config{Resolvers: []*Resolver{{Transport: "udp", Address: "127.0.0.1:53"}}, QueryTimeout: 5}, slow)
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close()
	request, stop := context.WithTimeout(base, 30*time.Millisecond)
	defer stop()
	started := time.Now()
	if _, err = set.exchange(request, resolverQuery(2)); !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatal("lost cancellation", err)
	}
	if time.Since(started) > 300*time.Millisecond {
		t.Fatal("physical dial ignored query deadline")
	}
}
func TestResolverExplicitRoundRobin(t *testing.T) {
	f := testResolverFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	set, err := newResolverSet(ctx, &Config{Resolvers: []*Resolver{{Transport: "udp", Address: f.UDP}, {Transport: "dot", Address: f.DoT, ServerName: fixture.ServerName, CaPem: f.CAPEM}}, QueryTimeout: 1}, &wireTestDialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close()
	var success atomic.Int64
	for i := 0; i < 6; i++ {
		if _, err = set.exchange(ctx, resolverQuery(i)); err != nil {
			t.Fatal(err)
		}
		success.Add(1)
	}
	if success.Load() != 6 || f.Queries.Load() != 3 || f.TLSQueries.Load() != 3 {
		t.Fatal("did not rotate only explicitly configured resolvers", f.Queries.Load(), f.TLSQueries.Load())
	}
}

// A chained Xray connection is tied to the context used to create its pipe,
// unlike a direct OS socket. Model that lifecycle explicitly.
type contextBoundWireDialer struct{ wireTestDialer }

func (d *contextBoundWireDialer) Dial(ctx context.Context, destination xnet.Destination) (stat.Connection, error) {
	raw, err := d.wireTestDialer.Dial(ctx, destination)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	return &contextBoundWireConn{Conn: raw, stop: stop}, nil
}

type contextBoundWireConn struct {
	net.Conn
	stop func() bool
}

func (c *contextBoundWireConn) Close() error { c.stop(); return c.Conn.Close() }
func TestResolverPooledSocketOutlivesSetupRequest(t *testing.T) {
	f := testResolverFixture(t)
	for _, mode := range []string{"udp", "dot", "doh"} {
		t.Run(mode, func(t *testing.T) {
			base, cancel := context.WithCancel(context.Background())
			defer cancel()
			resolver := &Resolver{Transport: mode}
			switch mode {
			case "udp":
				resolver.Address = f.UDP
			case "dot":
				resolver.Address = f.DoT
				resolver.ServerName = fixture.ServerName
				resolver.CaPem = f.CAPEM
			case "doh":
				resolver.Address = f.DoH
				resolver.ServerName = fixture.ServerName
				resolver.CaPem = f.CAPEM
			}
			d := &contextBoundWireDialer{}
			set, err := newResolverSet(base, &Config{Resolvers: []*Resolver{resolver}, QueryTimeout: 1, MaxConcurrentQueries: 2}, d)
			if err != nil {
				t.Fatal(err)
			}
			defer set.Close()
			first, stop := context.WithTimeout(base, time.Second)
			if _, err = set.exchange(first, resolverQuery(81)); err != nil {
				t.Fatal(err)
			}
			stop() // Must not cancel the pooled chained physical connection.
			if _, err = set.exchange(base, resolverQuery(82)); err != nil {
				t.Fatal("setup request killed pooled carrier", err)
			}
			d.mu.Lock()
			count := len(d.destinations)
			d.mu.Unlock()
			if count != 1 {
				t.Fatal("carrier silently redialed after first request ended", count)
			}
		})
	}
}
func TestResolverConcurrentDuplicateIDsKeepTheirQuestions(t *testing.T) {
	f := testResolverFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	set, err := newResolverSet(ctx, &Config{Resolvers: []*Resolver{{Transport: "udp", Address: f.UDP}}, QueryTimeout: 1}, &wireTestDialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close()
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			query := new(mdns.Msg)
			query.Unpack(resolverQuery(i))
			query.Id = 42
			wire, _ := query.Pack()
			response, err := set.exchange(ctx, wire)
			if err != nil {
				t.Error(err)
				return
			}
			reply := new(mdns.Msg)
			if err = reply.Unpack(response); err != nil || reply.Id != 42 || len(reply.Question) != 1 || reply.Question[0].Name != query.Question[0].Name {
				t.Error("ID collision changed response ownership", err)
			}
		}(i)
	}
	wg.Wait()
}

func (*wireTestDialer) SetOutboundGateway(context.Context, *session.Outbound) {}
