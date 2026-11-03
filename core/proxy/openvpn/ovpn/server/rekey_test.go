package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/datachan"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/handshake"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/wire"
)

// delayedRekeyControl models valid UDP reordering: after the server accepts a
// new TLS key generation, delay its key-method reply while old-key data packets
// continue arriving. A peer cannot decrypt data with a new key before it has
// received that reply.
type delayedRekeyControl struct {
	PacketConn
	armed *atomic.Bool
	once  sync.Once
	hits  atomic.Int32
	wg    sync.WaitGroup
}

func (d *delayedRekeyControl) WritePacket(b []byte) error {
	op, kid := wire.SplitHeader(b[0])
	delayed := false
	if op == wire.ControlV1 && kid != 0 && d.armed.Load() {
		d.once.Do(func() {
			delayed = true
			d.hits.Add(1)
			d.wg.Add(1)
			packet := bytes.Clone(b)
			time.AfterFunc(250*time.Millisecond, func() { defer d.wg.Done(); _ = d.PacketConn.WritePacket(packet) })
		})
	}
	if delayed {
		return nil
	}
	return d.PacketConn.WritePacket(b)
}
func TestRekeyReplyReorderingPreservesOldKeyTraffic(t *testing.T) {
	var calls atomic.Int32
	var armed atomic.Bool
	wrapped := make(chan *delayedRekeyControl, 1)
	auth := func(context.Context, *handshake.ClientMessage, tls.ConnectionState) (Admission, error) {
		if calls.Add(1) > 1 {
			armed.Store(true)
		}
		return Admission{Identity: "client", Push: []string{"topology subnet", "ifconfig 10.8.0.2 255.255.255.0"}}, nil
	}
	h := startHarnessTransport(t, Config{Authenticate: auth, Renegotiate: 100 * time.Millisecond}, nil, func(pc PacketConn) PacketConn {
		d := &delayedRekeyControl{PacketConn: pc, armed: &armed}
		wrapped <- d
		return d
	})
	c, e := dialHarness(t, h, "", nil)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	d := <-wrapped
	defer d.wg.Wait()
	until := time.Now().Add(650 * time.Millisecond)
	for time.Now().Before(until) {
		echoPacket(t, c, 512)
		time.Sleep(15 * time.Millisecond)
	}
	if d.hits.Load() != 1 || calls.Load() < 2 {
		t.Fatal("rekey control was not delayed")
	}
}

func readinessSession(t *testing.T) (*Session, *datachan.Channel) {
	t.Helper()
	var secret handshake.Key
	oldData, e := datachan.NewKeyState(0, "AES-256-GCM", "SHA256", &secret, &secret)
	if e != nil {
		t.Fatal(e)
	}
	nextData, e := datachan.NewKeyState(1, "AES-256-GCM", "SHA256", &secret, &secret)
	if e != nil {
		t.Fatal(e)
	}
	peerData, e := datachan.NewKeyState(1, "AES-256-GCM", "SHA256", &secret, &secret)
	if e != nil {
		t.Fatal(e)
	}
	old := &keyState{id: 0, dataKey: oldData, exchanged: true, adapter: newTLSAdapter(1000, nil, nil, nil)}
	next := &keyState{id: 1, dataKey: nextData, exchanged: true, established: time.Now(), adapter: newTLSAdapter(1000, nil, nil, nil)}
	data := datachan.New(datachan.Options{PeerID: 0})
	data.SetPrimary(nextData)
	data.SetPrimary(oldData)
	peer := datachan.New(datachan.Options{PeerID: 0})
	peer.SetPrimary(peerData)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := &Session{cfg: Config{IdleTimeout: 120 * time.Second, Renegotiate: time.Hour}, ctx: ctx, cancel: cancel, keys: map[uint8]*keyState{0: old, 1: next}, primary: next, old: old, sendKey: old, data: data, lastAuthenticated: time.Now(), lastPing: time.Now()}
	return s, peer
}
func TestOldTLSCloseKeepsSendingKeyUntilAuthenticatedReadiness(t *testing.T) {
	s, peer := readinessSession(t)
	s.event(event{key: s.old, err: io.EOF})
	if s.sendKey != s.old || !s.old.controlEnded {
		t.Fatal("old TLS EOF prematurely promoted sending key")
	}
	forged := wire.AppendDataHeader(nil, 1, 0)
	forged = append(forged, make([]byte, 32)...)
	s.packet(forged)
	if s.sendKey != s.old {
		t.Fatal("unauthenticated data promoted key")
	}
	packet, e := peer.Seal(nil, []byte{0x45, 1, 2, 3})
	if e != nil {
		t.Fatal(e)
	}
	s.packet(packet)
	if s.sendKey != s.primary {
		t.Fatal("authenticated readiness did not promote key")
	}
	sealed, e := s.data.Seal(nil, []byte{0x45})
	if e != nil {
		t.Fatal(e)
	}
	_, kid := wire.SplitHeader(sealed[0])
	if kid != 1 {
		t.Fatal("response still uses old generation")
	}
}
func TestRekeyReadinessWaitIsBounded(t *testing.T) {
	s, _ := readinessSession(t)
	s.primary.established = time.Now().Add(-61 * time.Second)
	s.timers()
	if !errors.Is(s.Err(), ErrHandshakeTimeout) {
		t.Fatalf("unconfirmed key retained beyond transition: %v", s.Err())
	}
}
