package session

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/orbit/internal/protocol"
)

// Unlike the codec-only golden, this captures the request emitted by Client.
// The old server reply and both startup modes must accept the native flag byte.
func TestClientConnectFlagsMatchNativeRequest(t *testing.T) {
	for _, reachID := range []uint32{0, 42} {
		t.Run(strconv.FormatUint(uint64(reachID), 10), func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			options := startupOptions()
			options.InitialReachID = reachID
			options.ConnectionID = 0x11223344
			options.ChannelID = [16]byte{1, 2, 3, 4}
			done := make(chan error, 1)
			go func() {
				err := func() error {
					f, err := protocol.ReadFrame(b)
					if err != nil {
						return err
					}
					if f.Type != 1 || f.Flags != 2 || len(f.Payload) != 151 {
						return errors.New("runtime connect header differs from original native default")
					}
					req, err := protocol.ParseConnectRequest(f)
					if err != nil {
						return err
					}
					user, err := protocol.DecodeUserInfo(req.UserInfo[:])
					if err != nil || user != options.User || req.ChannelID != options.ChannelID || req.ConnectionID != options.ConnectionID {
						return errors.New("runtime connection identity changed")
					}
					if reachID != 0 {
						f, err = protocol.ReadFrame(b)
						if err != nil {
							return err
						}
						m, err := protocol.ParseAppMessage(f)
						if err != nil || m.Type != 1 || m.RequestID != reachID || len(m.Data) != 0 {
							return errors.New("initial reach changed")
						}
					}
					return protocol.WriteFrame(b, protocol.Frame{Type: protocol.TypeConnectResponse})
				}()
				if err != nil {
					b.Close()
				}
				done <- err
			}()
			s, err := Client(ctx, a, options)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNativeTCPIdleDefaultsAndOverrides(t *testing.T) {
	o, err := (Options{}).normalized()
	if err != nil || o.HeartbeatInterval != 25*time.Second || o.IdleTimeout != 35*time.Second {
		t.Fatalf("native TCP idle defaults: %+v, %v", o, err)
	}
	o, err = (Options{HeartbeatInterval: 90 * time.Second, IdleTimeout: 3 * time.Minute}).normalized()
	if err != nil || o.HeartbeatInterval != 90*time.Second || o.IdleTimeout != 3*time.Minute {
		t.Fatal("explicit timeout overrides changed")
	}
}

func idleSession(t *testing.T) *Session {
	t.Helper()
	a, b := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	o, err := (Options{}).normalized()
	if err != nil {
		t.Fatal(err)
	}
	s := &Session{conn: a, ctx: ctx, cancel: cancel, options: o,
		done: make(chan struct{}), streams: make(map[uint32]*Stream), out: make(chan writeRequest, 256)}
	t.Cleanup(func() { s.Close(); b.Close() })
	return s
}

// These exact boundaries were executed against original on_timer0x132bb0;
// the receive-expiry branch must take precedence over heartbeat transmission.
func TestNativeTCPIdleBoundaries(t *testing.T) {
	for _, tc := range []struct {
		rx, tx int
		action string
	}{
		{34999, 24999, "none"}, {0, 25000, "heartbeat"},
		{34999, 25000, "heartbeat"}, {35000, 0, "disconnect"},
		{35000, 25000, "disconnect"}, {100, 100, "none"},
	} {
		t.Run(strconv.Itoa(tc.rx)+"/"+strconv.Itoa(tc.tx), func(t *testing.T) {
			s := idleSession(t)
			now := time.Now()
			s.lastRead.Store(activityTime(now.Add(-time.Duration(tc.rx) * time.Millisecond)))
			s.lastWrite.Store(activityTime(now.Add(-time.Duration(tc.tx) * time.Millisecond)))
			s.maintain(now)
			action := "none"
			select {
			case <-s.Done():
				action = "disconnect"
			default:
				if len(s.out) != 0 {
					action = "heartbeat"
				}
			}
			if action != tc.action {
				t.Fatalf("got %s, want %s", action, tc.action)
			}
			if action == "heartbeat" {
				// The physical writer remains blocked: repeated maintenance must
				// not grow the queue or create a burst when it becomes writable.
				for i := 0; i < 100; i++ {
					s.maintain(now)
				}
				if len(s.out) != 1 {
					t.Fatalf("pending heartbeat queue grew to %d", len(s.out))
				}
				r := <-s.out
				if r.frame.Type != protocol.TypeHeartbeat || r.frame.Flags != 0 || len(r.frame.Payload) != 0 {
					t.Fatal("heartbeat bytes changed")
				}
			}
		})
	}
}

func TestNativeTCPTracksPartialInboundAndOutboundTraffic(t *testing.T) {
	s, peer := rawPeerClient(t, Options{})
	old := activityTime(time.Now().Add(-time.Minute))
	s.lastRead.Store(old)
	// One header byte is activity despite not being a complete frame.
	if _, err := peer.Write([]byte{protocol.TypeHeartbeat}); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(time.Second)
	for s.lastRead.Load() == old && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if s.lastRead.Load() == old {
		t.Fatal("partial native frame failed to refresh receive activity")
	}
	s.maintain(time.Now())
	select {
	case <-s.Done():
		t.Fatal("active partial receive was treated as idle")
	default:
	}
	if _, err := peer.Write([]byte{0, 0, 0}); err != nil {
		t.Fatal(err)
	}

	s.lastWrite.Store(old)
	read := make(chan error, 1)
	go func() {
		f, err := protocol.ReadFrame(peer)
		if err == nil && f.Type != protocol.TypeApp {
			err = errors.New("unexpected control instead of application traffic")
		}
		read <- err
	}()
	if err := s.SendApp(context.Background(), protocol.AppMessage{Type: 1, RequestID: 123}); err != nil {
		t.Fatal(err)
	}
	if err := <-read; err != nil {
		t.Fatal(err)
	}
	if s.lastWrite.Load() == old {
		t.Fatal("ordinary outbound traffic failed to reset heartbeat activity")
	}
	s.maintain(time.Now())
	if s.heartbeatQueued.Load() || len(s.out) != 0 {
		t.Fatal("active outbound traffic still triggered a heartbeat")
	}
}

func TestNativeTCPQueuedHeartbeatSuppressedAfterTrafficAndSuccessfulSendResets(t *testing.T) {
	s := idleSession(t)
	s.conn = &activityConn{Conn: s.conn, session: s}
	s.space = make(chan struct{}, 1)
	now := time.Now()
	s.lastRead.Store(activityTime(now))
	s.lastWrite.Store(activityTime(now.Add(-30 * time.Second)))
	s.maintain(now)
	if !s.heartbeatQueued.Load() {
		t.Fatal("idle heartbeat not queued")
	}
	r := <-s.out
	s.lastWrite.Store(activityTime(time.Now())) // Earlier queued traffic completed.
	s.out <- r
	go s.writeLoop()
	select {
	case err := <-r.done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("unnecessary queued heartbeat attempted a blocked physical write")
	}
	if s.heartbeatQueued.Load() {
		t.Fatal("suppressed heartbeat kept pending state")
	}

	client, peer := rawPeerClient(t, Options{})
	client.lastWrite.Store(activityTime(time.Now().Add(-30 * time.Second)))
	client.maintain(time.Now())
	peer.SetReadDeadline(time.Now().Add(time.Second))
	f, err := protocol.ReadFrame(peer)
	if err != nil || f.Type != protocol.TypeHeartbeat || f.Flags != 0 || len(f.Payload) != 0 {
		t.Fatalf("heartbeat: %+v, %v", f, err)
	}
	until := time.Now().Add(time.Second)
	for client.heartbeatQueued.Load() && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if client.heartbeatQueued.Load() || activityAge(time.Now(), client.lastWrite.Load()) > time.Second {
		t.Fatal("completed heartbeat failed to update activity/clear pending state")
	}
	client.maintain(time.Now())
	if client.heartbeatQueued.Load() {
		t.Fatal("completed heartbeat immediately queued another")
	}
	peer.Close()
	select {
	case <-client.Done():
		if !errors.Is(client.Err(), io.EOF) && !errors.Is(client.Err(), io.ErrClosedPipe) {
			t.Fatal(client.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("physical close did not stop session")
	}
}
