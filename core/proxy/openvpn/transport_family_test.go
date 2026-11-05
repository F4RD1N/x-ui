package openvpn

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
)

type familyResolverFunc func(context.Context, string, string) ([]net.IP, error)

func (f familyResolverFunc) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	return f(ctx, network, host)
}

func TestOpenVPNTransportFamilySelectors(t *testing.T) {
	for _, network := range []string{"tcp", "udp", "tcp4", "udp4", "tcp6", "udp6"} {
		t.Run(network, func(t *testing.T) {
			d := &fakeDNS{answers: map[string][]net.IP{"localhost": {net.ParseIP("127.0.0.1"), net.ParseIP("::1")}}}
			var lookups []string
			h := &Handler{dns: d, transportResolver: familyResolverFunc(func(_ context.Context, family, host string) ([]net.IP, error) {
				lookups = append(lookups, family)
				if host != "localhost" {
					t.Errorf("unexpected bootstrap host %s", host)
				}
				return []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, nil
			})}
			dialer := &fakeDialer{}
			conn, err := h.dialFunc(context.Background(), dialer)(context.Background(), network, "localhost:1194")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			dialer.mu.Lock()
			got := dialer.dests[0]
			dialer.mu.Unlock()
			want := "localhost"
			if network[len(network)-1] == '4' {
				want = "127.0.0.1"
			}
			if network[len(network)-1] == '6' {
				want = "::1"
			}
			if got.Address.String() != xnet.ParseAddress(want).String() {
				t.Fatalf("dialed %v, want %s", got, want)
			}
			d.mu.Lock()
			defer d.mu.Unlock()
			if len(d.calls) != 0 {
				t.Fatal("bootstrap re-entered application DNS")
			}
			if want == "localhost" {
				if len(lookups) != 0 {
					t.Fatal("unsuffixed transport unexpectedly resolved hostname")
				}
			} else if len(lookups) != 1 || lookups[0] != "ip"+network[len(network)-1:] {
				t.Fatalf("wrong DNS family request: %v", lookups)
			}
		})
	}
}

func TestOpenVPNTransportFamilyLiteralMismatch(t *testing.T) {
	for _, tc := range []struct {
		network, address string
		good             bool
	}{
		{"udp4", "127.0.0.1:1194", true}, {"udp6", "[::1]:1194", true},
		{"tcp4", "127.0.0.1:1194", true}, {"tcp6", "[::1]:1194", true},
		{"udp4", "[::1]:1194", false}, {"udp6", "127.0.0.1:1194", false},
		{"tcp4", "[::1]:1194", false}, {"tcp6", "127.0.0.1:1194", false},
		{"udp6", "[::ffff:127.0.0.1]:1194", false},
	} {
		t.Run(tc.network+"/"+tc.address, func(t *testing.T) {
			dest, err := transportDestination(tc.network, tc.address)
			if err != nil {
				t.Fatal(err)
			}
			_, err = (&Handler{}).transportFamily(context.Background(), tc.network, dest)
			if (err == nil) != tc.good {
				t.Fatalf("accepted=%v, want=%v: %v", err == nil, tc.good, err)
			}
		})
	}
}

func TestOpenVPNTransportFamilyFiltersResolverAnswers(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		for _, answers := range [][]net.IP{nil, {net.IP{1, 2, 3}}, {net.ParseIP("127.0.0.1")}, {net.ParseIP("::1")}, {net.ParseIP("127.0.0.1"), net.ParseIP("::1")}} {
			h := &Handler{transportResolver: familyResolverFunc(func(context.Context, string, string) ([]net.IP, error) { return answers, nil })}
			dest := xnet.UDPDestination(xnet.DomainAddress("vpn.test"), 1194)
			got, err := h.transportFamily(context.Background(), network, dest)
			want := len(keepFamilies(answers, network == "udp4", network == "udp6")) > 0
			if (err == nil) != want {
				t.Fatalf("%s answers%v: got%v error%v", network, answers, got, err)
			}
			if err == nil && got.Address.Family().IsIPv4() != (network == "udp4") {
				t.Fatalf("wrong resolved family: %v", got)
			}
		}
	}
}

type blockedFamilyDNS struct {
	entered, release, finished chan struct{}
	ignoreCancellation         bool
}

func (d *blockedFamilyDNS) LookupIP(ctx context.Context, _, _ string) ([]net.IP, error) {
	if d.finished != nil {
		defer close(d.finished)
	}
	close(d.entered)
	if d.ignoreCancellation {
		<-d.release
	} else {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-d.release:
		}
	}
	return []net.IP{net.ParseIP("::1")}, nil
}

func TestOpenVPNTransportFamilyCancellationDoesNotDialLate(t *testing.T) {
	d := &blockedFamilyDNS{entered: make(chan struct{}), release: make(chan struct{}), finished: make(chan struct{})}
	defer close(d.release)
	h := &Handler{transportResolver: d}
	dialer := &fakeDialer{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := h.dialFunc(context.Background(), dialer)(ctx, "udp6", "localhost:1194")
		result <- err
	}()
	<-d.entered
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("resolver blocked cancellation")
	}
	select {
	case <-d.finished:
	case <-time.After(time.Second):
		t.Fatal("bootstrap resolver did not observe cancellation")
	}
	// Await the family helper directly in a separate fixture to prove a DNS
	// answer completing after cancellation is rejected, not merely that the
	// caller stopped waiting before the dialer goroutine was scheduled.
	lateDNS := &blockedFamilyDNS{entered: make(chan struct{}), release: make(chan struct{}), ignoreCancellation: true}
	lateCtx, lateCancel := context.WithCancel(context.Background())
	defer lateCancel()
	lateResult := make(chan error, 1)
	go func() {
		_, err := (&Handler{transportResolver: lateDNS}).transportFamily(lateCtx, "udp6", xnet.UDPDestination(xnet.DomainAddress("localhost"), 1194))
		lateResult <- err
	}()
	<-lateDNS.entered
	lateCancel()
	close(lateDNS.release)
	select {
	case err := <-lateResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("late resolution accepted: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("late resolver did not return")
	}
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	if len(dialer.dests) != 0 {
		t.Fatal("canceled lookup opened a transport")
	}
}
