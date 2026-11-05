package dnstt

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/dnstt/internal/fixture"
)

// A silent TLS endpoint exercises the real derived setup context. Both an
// original query deadline and the resolver's own setup timer may surface as
// context.Canceled from TLS, but neither is an explicit user cancellation.
func TestResolverHealthSilentTLSHandshake(t *testing.T) {
	healthy := testResolverFixture(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var connections sync.Map
	var accepted atomic.Int64
	var workers sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Store(conn, struct{}{})
			accepted.Add(1)
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer connections.Delete(conn)
				defer conn.Close()
				_, _ = io.Copy(io.Discard, conn) // Read ClientHello, never answer it.
			}()
		}
	}()
	defer func() {
		listener.Close()
		<-acceptDone
		connections.Range(func(key, _ any) bool { key.(net.Conn).Close(); return true })
		workers.Wait()
	}()
	for _, mode := range []string{"dot", "doh"} {
		for _, origin := range []string{"query-deadline", "setup-timer"} {
			t.Run(mode+"/"+origin, func(t *testing.T) {
				bad := &Resolver{Transport: mode, Address: listener.Addr().String(), ServerName: fixture.ServerName, CaPem: healthy.CAPEM}
				if mode == "doh" {
					bad.Address = "https://" + listener.Addr().String() + "/dns-query"
				}
				cfg := &Config{Resolvers: []*Resolver{bad, {Transport: "udp", Address: healthy.UDP}}, QueryTimeout: 1, MaxConcurrentQueries: 32}
				set, err := newResolverSet(context.Background(), cfg, &wireTestDialer{})
				if err != nil {
					t.Fatal(err)
				}
				defer set.Close()
				timeout := 50 * time.Millisecond
				if origin == "setup-timer" {
					timeout = 5 * time.Second
				}
				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				defer cancel()
				before := accepted.Load()
				if _, err := set.exchange(ctx, resolverQuery(1)); err == nil {
					t.Fatal("silent TLS endpoint answered query")
				}
				if origin == "setup-timer" && ctx.Err() != nil {
					t.Fatal("original caller expired before independent setup timer")
				}
				set.scheduler.mu.Lock()
				unhealthy := set.scheduler.members[0].unhealthy
				set.scheduler.mu.Unlock()
				if !unhealthy {
					t.Fatal("silent TLS setup failure did not trigger cooldown")
				}
				for i := 0; i < 3; i++ {
					query, stop := context.WithTimeout(context.Background(), time.Second)
					_, err := set.exchange(query, resolverQuery(i+2))
					stop()
					if err != nil {
						t.Fatalf("healthy member failed after TLS cooldown: %v", err)
					}
				}
				if used := accepted.Load() - before; used != 1 {
					t.Fatalf("silent member received %d TLS attempts during cooldown", used)
				}
			})
		}
	}
}

// A permanently silent member must not keep occupying half of every query
// window after its first timeout. These owned loopback fixtures cover all
// healthy resolver transports with the same deliberately unavailable UDP peer.
func TestNativeServerResolverHealthAvoidsSilentResolver(t *testing.T) {
	serverConfig := nativeServerConfig(t)
	_, authority := startNativeServer(t, serverConfig, 0)
	echo := nativeTCPServer(t)
	forward, err := fixture.Start(t.TempDir(), serverConfig.Domain, authority)
	if err != nil {
		t.Fatal(err)
	}
	defer forward.Close()
	silent, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	var dropped atomic.Int64
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		buffer := make([]byte, 4096)
		for {
			if _, _, err := silent.ReadFrom(buffer); err != nil {
				return
			}
			dropped.Add(1)
		}
	}()
	defer func() { silent.Close(); <-stopped }()
	for _, mode := range []string{"udp", "dot", "doh"} {
		t.Run(mode, func(t *testing.T) {
			healthy := &Resolver{Transport: mode, Address: forward.UDP}
			if mode == "dot" {
				healthy.Address = forward.DoT
			}
			if mode == "doh" {
				healthy.Address = forward.DoH
			}
			if mode != "udp" {
				healthy.ServerName = fixture.ServerName
				healthy.CaPem = forward.CAPEM
			}
			cfg := nativeClientConfig(t, serverConfig, healthy)
			cfg.Resolvers = []*Resolver{{Transport: "udp", Address: silent.LocalAddr().String()}, healthy}
			cfg.QueryTimeout = 1
			cfg.HandshakeTimeout = 10
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			before := dropped.Load()
			generation, err := newGeneration(ctx, cfg, &wireTestDialer{})
			if err != nil {
				t.Fatal(err)
			}
			defer generation.close()
			if err = nativeEcho(ctx, generation, cfg, echo.Addr(), 32<<10); err != nil {
				t.Fatal(err)
			}
			first := dropped.Load()
			if first <= before {
				t.Fatal("silent resolver was not exercised")
			}
			if err = nativeEcho(ctx, generation, cfg, echo.Addr(), 64<<10); err != nil {
				t.Fatal(err)
			}
			// Recovery remains possible, but no burst of concurrent probes is
			// allowed to refill the query window with the known silent member.
			if more := dropped.Load() - first; more > 8 {
				t.Fatalf("known silent member received %d queries during healthy transfer", more)
			}
		})
	}
}
