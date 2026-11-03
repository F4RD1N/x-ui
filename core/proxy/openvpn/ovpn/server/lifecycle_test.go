package server

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/handshake"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/wire"
)

type blockedPacketConn struct {
	once sync.Once
	done chan struct{}
}

func (c *blockedPacketConn) ReadPacket([]byte) (int, error) { <-c.done; return 0, net.ErrClosed }
func (c *blockedPacketConn) WritePacket([]byte) error       { <-c.done; return net.ErrClosed }
func (c *blockedPacketConn) Close() error                   { c.once.Do(func() { close(c.done) }); return nil }
func TestSilentPeerDeadlineAndCancellation(t *testing.T) {
	for _, cancelNow := range []bool{false, true} {
		t.Run(map[bool]string{false: "timeout", true: "cancel"}[cancelNow], func(t *testing.T) {
			p := getPKI(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			pc := &blockedPacketConn{done: make(chan struct{})}
			cfg := Config{TLSConfig: &tls.Config{Certificates: []tls.Certificate{p.serverCert}}, HandshakeTimeout: 50 * time.Millisecond, Authenticate: func(context.Context, *handshake.ClientMessage, tls.ConnectionState) (Admission, error) {
				t.Fatal("unauthenticated callback")
				return Admission{}, nil
			}}
			if cancelNow {
				cancel()
			}
			result := make(chan error, 1)
			go func() { _, err := Serve(ctx, pc, cfg); result <- err }()
			select {
			case err := <-result:
				if !cancelNow && !errors.Is(err, ErrHandshakeTimeout) {
					t.Fatalf("error %v", err)
				}
				if cancelNow && !errors.Is(err, context.Canceled) {
					t.Fatalf("error %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("lifecycle deadlocked")
			}
		})
	}
}
func TestConcurrentPacketIOAndClose(t *testing.T) {
	h := startHarness(t, Config{TCP: true})
	c, e := dialHarness(t, h, "", nil)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	s := <-h.result
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = s.WritePacket(make([]byte, 128))
				_ = s.Identity()
				_ = s.Err()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		b := make([]byte, 2048)
		for {
			if _, e := c.ReadPacket(b); e != nil {
				return
			}
		}
	}()
	time.Sleep(20 * time.Millisecond)
	var closeWG sync.WaitGroup
	for i := 0; i < 5; i++ {
		closeWG.Add(1)
		go func() { defer closeWG.Done(); s.Close() }()
	}
	closeWG.Wait()
	c.Close()
	wg.Wait()
	select {
	case <-s.Done():
	default:
		t.Fatal("not closed")
	}
}
func TestRekeyOldControlEOFDoesNotDropPrimary(t *testing.T) {
	// Closing an expired TLS generation is normal; only a failing active or
	// negotiating generation terminates the admitted session.
	old := &keyState{id: 1, adapter: newTLSAdapter(1000, nil, nil, nil), exchanged: true}
	current := &keyState{id: 2}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &Session{ctx: ctx, cancel: cancel, keys: map[uint8]*keyState{1: old, 2: current}, primary: current, old: old}
	s.event(event{key: old, err: io.EOF})
	if ctx.Err() != nil || s.keys[1] != nil || s.primary != current {
		t.Fatal("old EOF killed active generation")
	}
}
func TestMalformedResetCannotStartTLS(t *testing.T) {
	h := startHarness(t, Config{HandshakeTimeout: 100 * time.Millisecond})
	c, e := net.Dial("udp", h.address)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	for _, b := range [][]byte{{0}, {0x38}, make([]byte, 40), {wire.Header(wire.ControlV1, 0), 1, 2, 3, 4, 5, 6, 7, 8}} {
		c.Write(b)
	}
	select {
	case err := <-h.errors:
		if !errors.Is(err, ErrHandshakeTimeout) {
			t.Fatalf("wrong error %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("malformed packets kept session alive")
	}
}

func TestBlockedTransportWriteStillTimesOut(t *testing.T) {
	p := getPKI(t)
	left, right := net.Pipe()
	defer right.Close()
	cfg := Config{TLSConfig: &tls.Config{Certificates: []tls.Certificate{p.serverCert}}, TCP: true, HandshakeTimeout: 80 * time.Millisecond, Authenticate: func(context.Context, *handshake.ClientMessage, tls.ConnectionState) (Admission, error) {
		return Admission{}, ErrAuthentication
	}}
	result := make(chan error, 1)
	go func() {
		_, e := Serve(context.Background(), &testPacketConn{Conn: left, tcp: true, fr: wire.NewFrameReader(left)}, cfg)
		result <- e
	}()
	packet := wire.Marshal(&wire.ControlPacket{Opcode: wire.ControlHardResetClientV2, SessionID: wire.SessionID{1}})
	frame, err := wire.AppendFrame(nil, packet)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = right.Write(frame); err != nil {
		t.Fatal(err)
	}
	// No read from right: server's transport writer blocks on the reset reply.
	select {
	case err = <-result:
		if !errors.Is(err, ErrHandshakeTimeout) {
			t.Fatalf("deadline cause: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("stalled writer defeated handshake timer")
	}
}
func TestNoCommonCipherDenied(t *testing.T) {
	h := startHarness(t, Config{TCP: true, Ciphers: []string{"AES-256-CBC"}})
	c, e := dialHarness(t, h, "", nil)
	if e == nil {
		c.Close()
		t.Fatal("no common cipher admitted")
	}
}
func TestIdentityCannotChangeDuringRekey(t *testing.T) {
	calls := 0
	h := startHarness(t, Config{TCP: true, Renegotiate: 100 * time.Millisecond, Authenticate: func(context.Context, *handshake.ClientMessage, tls.ConnectionState) (Admission, error) {
		calls++
		identity := "first"
		if calls > 1 {
			identity = "different"
		}
		return Admission{Identity: identity, Push: []string{"topology subnet", "ifconfig 10.8.0.2 255.255.255.0"}}, nil
	}})
	c, e := dialHarness(t, h, "", nil)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	select {
	case <-c.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("identity change retained tunnel")
	}
}

type panicPacketConn struct {
	blockedPacketConn
	mode  string
	first bool
}

func (c *panicPacketConn) ReadPacket(b []byte) (int, error) {
	if c.mode == "read" {
		panic("SENSITIVE-TRANSPORT-PANIC")
	}
	if !c.first {
		c.first = true
		return copy(b, wire.Marshal(&wire.ControlPacket{Opcode: wire.ControlHardResetClientV2, SessionID: wire.SessionID{1}})), nil
	}
	return c.blockedPacketConn.ReadPacket(b)
}
func (c *panicPacketConn) WritePacket([]byte) error { panic("SENSITIVE-TRANSPORT-PANIC") }
func TestTransportPanicContained(t *testing.T) {
	for _, mode := range []string{"read", "write"} {
		t.Run(mode, func(t *testing.T) {
			p := getPKI(t)
			pc := &panicPacketConn{blockedPacketConn: blockedPacketConn{done: make(chan struct{})}, mode: mode}
			cfg := Config{TLSConfig: &tls.Config{Certificates: []tls.Certificate{p.serverCert}}, Authenticate: func(context.Context, *handshake.ClientMessage, tls.ConnectionState) (Admission, error) {
				return Admission{}, nil
			}}
			done := make(chan error, 1)
			go func() { _, e := Serve(context.Background(), pc, cfg); done <- e }()
			select {
			case e := <-done:
				if !errors.Is(e, ErrInternal) {
					t.Fatalf("panic not redacted: %v", e)
				}
			case <-time.After(time.Second):
				t.Fatal("panic containment deadlocked")
			}
		})
	}
}
func TestAdmissionPanicContained(t *testing.T) {
	h := startHarness(t, Config{TCP: true, Authenticate: func(context.Context, *handshake.ClientMessage, tls.ConnectionState) (Admission, error) {
		panic("SENSITIVE-ADMISSION-PANIC")
	}})
	c, e := dialHarness(t, h, "", nil)
	if e == nil {
		c.Close()
		t.Fatal("panicking admission accepted client")
	}
	select {
	case e = <-h.errors:
		if !errors.Is(e, ErrInternal) {
			t.Fatalf("panic not contained: %v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("panic cleanup stalled")
	}
}

func TestPeerIDAndCompressionPolicy(t *testing.T) {
	h := startHarness(t, Config{TCP: true, PeerID: 7654321})
	c, e := dialHarness(t, h, "", nil)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	s := <-h.result
	if s.peerID != 7654321 {
		t.Fatalf("peer ID %d", s.peerID)
	}
	echoPacket(t, c, 1400)
	for _, occ := range []string{"V4,comp-lzo,cipher AES-256-GCM", "V4,comp-lzo no", "V4,compress stub-v2"} {
		if validateClientOCC(occ) == nil {
			t.Fatal("compression accepted")
		}
	}
	if validateClientOCC("V4,cipher AES-256-GCM") != nil {
		t.Fatal("ordinary OCC rejected")
	}
	if _, e = peerFields("IV_LZ4=1\nIV_COMP_STUBv2=1\n"); e != nil {
		t.Fatal("capability mistaken for enabled compression")
	}
	cfg := h.cfg
	cfg.PeerID = wire.NoPeerID
	if validate(&cfg) == nil {
		t.Fatal("reserved peer ID accepted")
	}
	// The current client always advertises decompression capabilities; its
	// successful echo above proves these flags are not mistaken for framing.
}
func TestEnabledCompressionRejected(t *testing.T) {
	h := startHarness(t, Config{TCP: true})
	c, e := dialHarness(t, h, "comp-lzo no", nil)
	if e == nil {
		c.Close()
		t.Fatal("enabled LZO framing admitted")
	}
}
