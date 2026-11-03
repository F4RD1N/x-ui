package openvpn

import (
	"context"
	goerrors "errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/client"
)

// fakeClock is the Handler's back-off clock in these tests.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func (f *fixture) fakeClock() *fakeClock {
	c := &fakeClock{now: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}
	f.h.now = c.Now
	return c
}

// failingHook fails every session dial with err while fail is set.
func failingHook(fail *atomic.Bool, err error) func(context.Context, client.Config) error {
	return func(context.Context, client.Config) error {
		if fail.Load() {
			return err
		}
		return nil
	}
}

// A server that rejects the credentials (AUTH_FAILED) or halts the client
// is not asked again by later requests, however long after: OpenVPN's own
// client exits there (auth-retry none). Every refused request still gets
// the server's error, at once.
func TestRejectedSetupIsNotRetried(t *testing.T) {
	cases := []struct {
		name string
		err  error
		is   error
	}{
		{"auth failed", fmt.Errorf("remote 192.0.2.10:1194/udp: %w: bad password", client.ErrAuthFailed), client.ErrAuthFailed},
		{"auth failed without reason", fmt.Errorf("remote 192.0.2.10:1194/udp: %w", client.ErrAuthFailed), client.ErrAuthFailed},
		{"halt", fmt.Errorf("openvpn: no remote worked: remote 192.0.2.10:1194/udp: %w", client.ErrServerHalt), client.ErrServerHalt},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, &Config{Ovpn: testOVPN, Username: "alice", Password: "wrong"})
			clock := f.fakeClock()
			var fail atomic.Bool
			fail.Store(true)
			f.hook = failingHook(&fail, tc.err)
			for i := 0; i < 30; i++ {
				start := time.Now()
				err := f.start(context.Background(), tcpDest(srvV4, echoTCPPort)).wait(t, waitLong)
				if !goerrors.Is(err, tc.is) {
					t.Fatalf("request %d: %v, want an error that is %v", i, err, tc.is)
				}
				if i > 0 && time.Since(start) > time.Second {
					t.Fatalf("request %d waited %v for a cached error", i, time.Since(start))
				}
				if i == 10 {
					clock.Advance(24 * time.Hour)
					fail.Store(false) // even a server that would now accept is not asked
				}
			}
			if n := f.dials(); n != 1 {
				t.Fatalf("30 requests made %d session dials with the rejected configuration, want 1", n)
			}
		})
	}
}

// A session the server ends with HALT (or AUTH_FAILED, on a renegotiation)
// after it was up stops the outbound as a rejected setup does.
func TestServerHaltAfterSetupStops(t *testing.T) {
	f := newFixture(t, nil)
	clock := f.fakeClock()
	r := f.start(context.Background(), tcpDest(srvV4, echoTCPPort))
	r.echo(t, []byte("up"))
	f.session(0).fail(fmt.Errorf("%w: maintenance", client.ErrServerHalt))
	if err := r.wait(t, waitLong); err == nil {
		t.Fatal("Process ended without an error after the server halted the session")
	}
	for i := 0; i < 5; i++ {
		err := f.start(context.Background(), tcpDest(srvV4, echoTCPPort)).wait(t, waitLong)
		if !goerrors.Is(err, client.ErrServerHalt) {
			t.Fatalf("request %d after HALT: %v", i, err)
		}
		clock.Advance(time.Hour)
	}
	if n := f.dials(); n != 1 {
		t.Fatalf("%d sessions dialled after the server halted the client, want 1", n)
	}
}

// A session the server ends with an AUTH_FAILED that refused the pushed
// auth-token (client.ErrAuthTokenRejected) does not stop the outbound: as
// OpenVPN 2.x does, the next request sets up a new session, which logs in
// with the username and password, at once. Only when the server refuses
// those too does the outbound stop, so each refused token costs one login.
func TestRefusedAuthTokenLogsInAgain(t *testing.T) {
	f := newFixture(t, &Config{Ovpn: testOVPN, Username: "alice", Password: "pw"})
	clock := f.fakeClock()
	var fail atomic.Bool
	f.hook = failingHook(&fail, fmt.Errorf("remote 192.0.2.10:1194/udp: %w: bad password", client.ErrAuthFailed))
	tokenRefused := fmt.Errorf("%w: SESSION:token expired (%w)", client.ErrAuthFailed, client.ErrAuthTokenRejected)

	r := f.start(context.Background(), tcpDest(srvV4, echoTCPPort))
	r.echo(t, []byte("first session"))
	for i := 1; i <= 2; i++ {
		f.session(i - 1).fail(tokenRefused)
		if err := r.wait(t, waitLong); err == nil {
			t.Fatal("Process ended without an error after the session died")
		}
		r = f.start(context.Background(), tcpDest(srvV4, echoTCPPort))
		r.echo(t, []byte("after the refused token"))
		if n := f.dials(); n != i+1 {
			t.Fatalf("%d sessions dialled after %d refused tokens, want %d", n, i, i+1)
		}
		f.mu.Lock()
		cfg := f.cfgs[i]
		f.mu.Unlock()
		if cfg.Username != "alice" || cfg.Password != "pw" {
			t.Fatalf("session %d dialled with %q/%q, want the configured credentials", i, cfg.Username, cfg.Password)
		}
	}

	// The token is refused once more and so is the password: stop.
	fail.Store(true)
	f.session(2).fail(tokenRefused)
	if err := r.wait(t, waitLong); err == nil {
		t.Fatal("Process ended without an error after the session died")
	}
	for i := 0; i < 5; i++ {
		err := f.start(context.Background(), tcpDest(srvV4, echoTCPPort)).wait(t, waitLong)
		if !goerrors.Is(err, client.ErrAuthFailed) || goerrors.Is(err, client.ErrAuthTokenRejected) {
			t.Fatalf("request %d after the password was refused: %v", i, err)
		}
		clock.Advance(time.Hour)
		fail.Store(false) // even a server that would now accept is not asked
	}
	if n := f.dials(); n != 4 {
		t.Fatalf("%d sessions dialled, want 4 (three that worked, one the server refused)", n)
	}
}

// Other failed setups back off as OpenVPN's connect-retry 1 300 does, capped
// at 30s: 1s after each of the first five failures in a row, then doubling.
// Inside the wait a request fails at once with the last error and dials
// nothing; the first request after it dials once. A setup that works resets
// the back-off, and a session that dies after it was up is rebuilt by the
// next request without waiting.
func TestFailedSetupBacksOff(t *testing.T) {
	f := newFixture(t, nil)
	clock := f.fakeClock()
	var fail atomic.Bool
	fail.Store(true)
	f.hook = failingHook(&fail, fmt.Errorf("openvpn: no remote worked: remote 192.0.2.10:1194/udp: %w", client.ErrHandshakeTimeout))

	request := func(what string) error {
		t.Helper()
		start := time.Now()
		err := f.start(context.Background(), tcpDest(srvV4, echoTCPPort)).wait(t, waitLong)
		if el := time.Since(start); el > 2*time.Second {
			t.Fatalf("%s: request took %v", what, el)
		}
		return err
	}
	expectDials := func(what string, want int) {
		t.Helper()
		if n := f.dials(); n != want {
			t.Fatalf("%s: %d session dials, want %d", what, n, want)
		}
	}

	want := []time.Duration{1, 1, 1, 1, 1, 2, 4, 8, 16, 30, 30}
	if err := request("first"); !goerrors.Is(err, client.ErrHandshakeTimeout) {
		t.Fatalf("first request: %v", err)
	}
	expectDials("first", 1)
	for i, w := range want {
		wait := w * time.Second
		clock.Advance(wait - time.Millisecond)
		for j := 0; j < 3; j++ {
			err := request(fmt.Sprintf("failure %d, %v later", i+1, wait-time.Millisecond))
			if !goerrors.Is(err, client.ErrHandshakeTimeout) {
				t.Fatalf("failure %d: request inside the back-off: %v", i+1, err)
			}
			if !strings.Contains(err.Error(), "next attempt") {
				t.Errorf("failure %d: the refusal does not say when the next attempt is: %v", i+1, err)
			}
		}
		expectDials(fmt.Sprintf("inside the wait after failure %d (%v)", i+1, wait), i+1)
		clock.Advance(time.Millisecond)
		if err := request(fmt.Sprintf("after failure %d", i+1)); !goerrors.Is(err, client.ErrHandshakeTimeout) {
			t.Fatalf("failure %d: request after the back-off: %v", i+1, err)
		}
		expectDials(fmt.Sprintf("after the wait after failure %d (%v)", i+1, wait), i+2)
	}

	// The server works again: the next attempt after the wait succeeds.
	fail.Store(false)
	clock.Advance(30 * time.Second)
	r := f.start(context.Background(), tcpDest(srvV4, echoTCPPort))
	r.echo(t, []byte("back"))
	dials := f.dials()

	// The session dies: the next request rebuilds at once, and a failure
	// then waits 1s again (the success reset the count).
	f.session(0).fail(client.ErrPingTimeout)
	_ = r.wait(t, waitLong)
	fail.Store(true)
	if err := request("rebuild after the session died"); !goerrors.Is(err, client.ErrHandshakeTimeout) {
		t.Fatalf("rebuild: %v", err)
	}
	expectDials("rebuild after the session died", dials+1)
	clock.Advance(time.Second - time.Millisecond)
	_ = request("inside the reset back-off")
	expectDials("inside the reset back-off", dials+1)
	clock.Advance(time.Millisecond)
	fail.Store(false)
	r = f.start(context.Background(), tcpDest(srvV4, echoTCPPort))
	r.echo(t, []byte("again"))
	expectDials("after the reset back-off", dials+2)
	_ = r.end(t)
}

// AUTH_FAILED,TEMP is a temporary refusal: it backs off (for at least the
// server's "backoff" seconds) instead of stopping.
func TestTemporaryAuthFailureBacksOff(t *testing.T) {
	f := newFixture(t, &Config{Ovpn: testOVPN, Username: "alice", Password: "pw"})
	clock := f.fakeClock()
	var fail atomic.Bool
	fail.Store(true)
	f.hook = failingHook(&fail, fmt.Errorf("remote 192.0.2.10:1194/udp: %w: TEMP[backoff 30,advance no]:try again later", client.ErrAuthFailed))

	if err := f.start(context.Background(), tcpDest(srvV4, echoTCPPort)).wait(t, waitLong); !goerrors.Is(err, client.ErrAuthFailed) {
		t.Fatalf("first request: %v", err)
	}
	clock.Advance(30*time.Second - time.Millisecond)
	if err := f.start(context.Background(), tcpDest(srvV4, echoTCPPort)).wait(t, waitLong); !goerrors.Is(err, client.ErrAuthFailed) {
		t.Fatalf("request inside the server's backoff: %v", err)
	}
	if n := f.dials(); n != 1 {
		t.Fatalf("%d dials inside the server's backoff, want 1", n)
	}
	fail.Store(false)
	clock.Advance(time.Millisecond)
	r := f.start(context.Background(), tcpDest(srvV4, echoTCPPort))
	r.echo(t, []byte("accepted after TEMP"))
	_ = r.end(t)
	if n := f.dials(); n != 2 {
		t.Fatalf("%d dials, want 2", n)
	}
}

func TestRetryPolicy(t *testing.T) {
	delays := []time.Duration{0, 1, 1, 1, 1, 1, 2, 4, 8, 16, 30, 30, 30}
	for n := 1; n < len(delays); n++ {
		if got := retryDelay(n); got != delays[n]*time.Second {
			t.Errorf("retryDelay(%d) = %v, want %v", n, got, delays[n]*time.Second)
		}
	}
	if got := retryDelay(1 << 30); got != retryMax {
		t.Errorf("retryDelay(huge) = %v", got)
	}

	cases := []struct {
		err      error
		rejected bool
		backoff  time.Duration
	}{
		{client.ErrAuthFailed, true, 0},
		{fmt.Errorf("x: %w: expired", client.ErrAuthFailed), true, 0},
		{fmt.Errorf("x: %w", client.ErrServerHalt), true, 0},
		{fmt.Errorf("x: %w: TEMP", client.ErrAuthFailed), false, 0},
		{fmt.Errorf("x: %w: TEMP:busy", client.ErrAuthFailed), false, 0},
		{fmt.Errorf("x: %w: TEMP[backoff 42]:busy", client.ErrAuthFailed), false, 42 * time.Second},
		{fmt.Errorf("x: %w: TEMP[advance no, backoff 7]", client.ErrAuthFailed), false, 7 * time.Second},
		{fmt.Errorf("x: %w: TEMP[backoff 99999999]", client.ErrAuthFailed), false, maxServerBackoff},
		{fmt.Errorf("x: %w: TEMP[backoff -3]", client.ErrAuthFailed), false, 0},
		{fmt.Errorf("x: %w: TEMP[backoff x]", client.ErrAuthFailed), false, 0},
		{fmt.Errorf("x: %w (%w)", client.ErrAuthFailed, client.ErrAuthTokenRejected), false, 0},
		{fmt.Errorf("x: %w: SESSION:expired (%w)", client.ErrAuthFailed, client.ErrAuthTokenRejected), false, 0},
		{fmt.Errorf("x: %w: TEMP[backoff 5] (%w)", client.ErrAuthFailed, client.ErrAuthTokenRejected), false, 5 * time.Second},
		{client.ErrServerRestart, false, 0},
		{client.ErrHandshakeTimeout, false, 0},
		{goerrors.New("dial tcp: connection refused"), false, 0},
	}
	for _, tc := range cases {
		if got := rejected(tc.err); got != tc.rejected {
			t.Errorf("rejected(%v) = %v", tc.err, got)
		}
		if _, got := tempAuthFailure(tc.err); got != tc.backoff {
			t.Errorf("tempAuthFailure(%v) backoff %v, want %v", tc.err, got, tc.backoff)
		}
	}
}
