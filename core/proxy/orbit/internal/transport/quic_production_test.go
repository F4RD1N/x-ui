package transport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/orbit/internal/protocol"
)

func testInitial() QUICInitialOptions {
	return QUICInitialOptions{ConnectionID: 123, ChannelID: [16]byte{1, 2, 3}, EncodeUserInfo: func(r io.Reader) ([128]byte, error) {
		return protocol.EncodeUserInfo(protocol.UserInfo{UID: "test", Token: "local-only-token", DeviceID: "test-device"}, r)
	}}
}
func testVerify(meta QUICMetadata, _ net.Addr) error {
	u, err := protocol.DecodeUserInfo(meta.UserInfo[:])
	if err != nil {
		return err
	}
	if u.Token != "local-only-token" || len(meta.ProxyBuffer) > 0 {
		return errors.New("denied")
	}
	return nil
}

func TestQUICOwnedLoopbackStreamAndDatagram(t *testing.T) {
	st, ct := testTLS(t)
	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l, err := ListenQUIC(raw, st, testVerify)
	if err != nil {
		raw.Close()
		t.Fatal(err)
	}
	defer l.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() {
		s, err := l.Accept(ctx)
		if err != nil {
			serverDone <- err
			return
		}
		defer s.Close()
		if s.User().UID != "test" || s.ConnectionID() != 123 {
			serverDone <- errors.New("metadata lost")
			return
		}
		flow, err := s.Accept(ctx)
		if err != nil {
			serverDone <- err
			return
		}
		host, err := flow.Destination().Host()
		if err != nil || host != "example.test" || flow.Destination().Port != 443 {
			serverDone <- errors.New("wrong destination")
			return
		}
		if err = flow.Accept(); err != nil {
			serverDone <- err
			return
		}
		payload, err := io.ReadAll(flow)
		if err != nil {
			serverDone <- err
			return
		}
		if _, err = flow.Write(append(payload, []byte("-reply")...)); err == nil {
			err = flow.CloseWrite()
		}
		if err != nil {
			serverDone <- err
			return
		}
		u, err := s.ReceiveUDP(ctx)
		if err == nil {
			u.Source, u.Destination = u.Destination, u.Source
			err = s.SendUDP(ctx, u)
		}
		// Keep the transport alive until the peer consumes reliable and unreliable
		// replies; a QUIC close is not an acknowledgement for queued datagrams.
		if err == nil {
			<-s.Done()
		}
		serverDone <- err
	}()
	c, err := DialQUIC(ctx, l.Addr().String(), ct, testInitial())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	flow, err := c.Open(ctx, "example.test", 443)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("over-reference-quic-"), 200)
	if _, err = flow.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err = flow.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(flow)
	if err != nil || !bytes.Equal(got, append(payload, []byte("-reply")...)) {
		t.Fatalf("TCP reply %d: %v", len(got), err)
	}
	u := protocol.UDPEnvelope{Kind: protocol.UDPKindData, Source: netip.MustParseAddrPort("192.0.2.10:1234"), Destination: netip.MustParseAddrPort("198.51.100.10:5353"), Data: []byte("udp-payload")}
	if err = c.SendUDP(ctx, u); err != nil {
		t.Fatal(err)
	}
	reply, err := c.ReceiveUDP(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply.Data, u.Data) || reply.Source != u.Destination || reply.Destination != u.Source {
		t.Fatal("UDP envelope changed")
	}
	c.Close()
	if err = <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestQUICRejectCertificateAndAuthentication(t *testing.T) {
	for _, kind := range []string{"certificate", "token"} {
		t.Run(kind, func(t *testing.T) {
			st, ct := testTLS(t)
			raw, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			l, err := ListenQUIC(raw, st, testVerify)
			if err != nil {
				raw.Close()
				t.Fatal(err)
			}
			defer l.Close()
			if kind == "certificate" {
				ct.ServerName = "wrong.example"
			}
			o := testInitial()
			if kind == "token" {
				o.EncodeUserInfo = func(r io.Reader) ([128]byte, error) {
					return protocol.EncodeUserInfo(protocol.UserInfo{UID: "bad", Token: "wrong"}, r)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			c, err := DialQUIC(ctx, l.Addr().String(), ct, o)
			if err == nil {
				c.Close()
				t.Fatal("invalid identity accepted")
			}
		})
	}
}

func TestQUICParallelSocketStreamsAndReject(t *testing.T) {
	st, ct := testTLS(t)
	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l, err := ListenQUIC(raw, st, testVerify)
	if err != nil {
		raw.Close()
		t.Fatal(err)
	}
	defer l.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() {
		s, e := l.Accept(ctx)
		if e != nil {
			serverDone <- e
			return
		}
		defer s.Close()
		var wg sync.WaitGroup
		for i := 0; i < 9; i++ {
			f, e := s.Accept(ctx)
			if e != nil {
				serverDone <- e
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				if f.Destination().Port == 1 {
					f.Reject()
					return
				}
				if e := f.Accept(); e != nil {
					return
				}
				io.Copy(f, f)
				f.CloseWrite()
			}()
		}
		wg.Wait()
		<-s.Done()
		serverDone <- nil
	}()
	c, err := DialQUIC(ctx, l.Addr().String(), ct, testInitial())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var wg sync.WaitGroup
	wg.Add(8)
	for i := 0; i < 8; i++ {
		go func(i int) {
			defer wg.Done()
			f, e := c.Open(ctx, "127.0.0.1", uint16(1000+i))
			if e != nil {
				t.Error(e)
				return
			}
			data := bytes.Repeat([]byte{byte(i)}, 100)
			if _, e = f.Write(data); e != nil {
				t.Error(e)
				return
			}
			f.CloseWrite()
			got, e := io.ReadAll(f)
			if e != nil || !bytes.Equal(data, got) {
				t.Error("stream data", e)
			}
		}(i)
	}
	if f, e := c.Open(ctx, "127.0.0.1", 1); e == nil {
		f.Close()
		t.Error("rejected open accepted")
	}
	wg.Wait()
	c.Close()
	if err = <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func quicPair(t *testing.T) (*QUICSession, *QUICSession) {
	t.Helper()
	st, ct := testTLS(t)
	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l, err := ListenQUIC(raw, st, testVerify)
	if err != nil {
		raw.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	type result struct {
		s *QUICSession
		e error
	}
	ch := make(chan result, 1)
	go func() { s, e := l.Accept(ctx); ch <- result{s, e} }()
	c, err := DialQUIC(ctx, l.Addr().String(), ct, testInitial())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	r := <-ch
	if r.e != nil {
		t.Fatal(r.e)
	}
	t.Cleanup(func() { r.s.Close() })
	if err = c.waitReady(ctx); err != nil {
		t.Fatal(err)
	}
	return c, r.s
}

func TestQUICNativeOversizeAndCurrentDatagramBoundary(t *testing.T) {
	v := fixtures(t).OversizeDatagram
	if v.PayloadSize != 1489 || v.MSS != 1300 || v.Error != -681 {
		t.Fatal("missing native MSS rejection proof", v)
	}
	c, s := quicPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	u := protocol.UDPEnvelope{Kind: protocol.UDPKindData, Source: netip.MustParseAddrPort("192.0.2.1:1000"), Destination: netip.MustParseAddrPort("198.51.100.1:2000"), Data: make([]byte, 1470)}
	var tooLarge *UDPTooLargeError
	if err := c.SendUDP(ctx, u); !errors.As(err, &tooLarge) || tooLarge.PayloadSize != 1470 || tooLarge.MaxPayloadSize < 1000 || tooLarge.MaxPayloadSize >= 1470 {
		t.Fatalf("current MSS not exposed: %v (%+v)", err, tooLarge)
	}
	for _, size := range []int{0, 17, tooLarge.MaxPayloadSize} {
		u.Data = bytes.Repeat([]byte{byte(size)}, size)
		if err := c.SendUDP(ctx, u); err != nil {
			t.Fatalf("size%d: %v", size, err)
		}
		received, err := s.ReceiveUDP(ctx)
		if err != nil || !bytes.Equal(received.Data, u.Data) || received.Source != u.Source || received.Destination != u.Destination {
			t.Fatalf("boundary datagram size%d changed/dropped=%d: %v", size, s.DroppedUDP(), err)
		}
	}
	u.Data = make([]byte, tooLarge.MaxPayloadSize+1)
	if err := c.SendUDP(ctx, u); !errors.As(err, &tooLarge) {
		t.Fatal("above MSS accepted", err)
	}
}

func TestQUICControlHeartbeatMalformedAndCancellation(t *testing.T) {
	c, s := quicPair(t)
	if c.LocalAddr() == nil || c.RemoteAddr() == nil || c.ChannelID() != testInitial().ChannelID || c.BufferedBytes() != 0 {
		t.Fatal("session metadata")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Accept(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := s.ReceiveUDP(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := s.Open(ctx, "localhost", 1); err == nil {
		t.Fatal("server open")
	}
	if _, err := c.Open(ctx, "", 0); err == nil {
		t.Fatal("invalid destination")
	}
	c.logical.mu.Lock()
	control := c.logical.control
	c.logical.mu.Unlock()
	before := uint32(17)
	c.logical.heartbeatTicks.Store(before)
	if err := c.writeControl(control, protocol.Frame{Type: protocol.TypeHeartbeat}); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(time.Second)
	for c.logical.heartbeatTicks.Load() == before && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if c.logical.heartbeatTicks.Load() == before {
		t.Fatal("heartbeat did not get acknowledgment")
	}
	if err := c.SendDatagram([]byte{18, 0, 255, 255}); err != nil {
		t.Fatal(err)
	}
	until = time.Now().Add(time.Second)
	for s.DroppedUDP() == 0 && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if s.DroppedUDP() == 0 {
		t.Fatal("malformed datagram not dropped")
	}
	if err := c.writeControl(control, protocol.Frame{Type: protocol.TypeHeartbeat, Payload: []byte{1}}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.Done():
	case <-time.After(time.Second):
		t.Fatal("malformed heartbeat did not close")
	}
	if s.Err() == nil {
		t.Fatal("closed session missing reason")
	}
}

func TestQUICHeartbeatTimeout(t *testing.T) {
	c, _ := quicPair(t)
	c.logical.heartbeatTicks.Store(37)
	select {
	case <-c.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("heartbeat timeout did not close")
	}
}

func TestQUICInitialProxyRoundtripAndMalformedFields(t *testing.T) {
	v := fixtures(t).QUIC[0]
	packet := unhex(t, v.InputHex)
	_, meta, err := StripQUICInitial(unhex(t, v.FormattedHex))
	if err != nil {
		t.Fatal(err)
	}
	o := QUICInitialOptions{Random: &lcgReader{state: 1}, ProxyBuffer: []byte{1, 2, 3}, ConnectionID: meta.ConnectionID, ChannelID: meta.ChannelID, EncodeUserInfo: func(io.Reader) ([128]byte, error) { return meta.UserInfo, nil }}
	b, err := FormatQUICInitial(packet, o)
	if err != nil {
		t.Fatal(err)
	}
	out, m, err := StripQUICInitial(b)
	if err != nil || !bytes.Equal(out, packet) || !bytes.Equal(m.ProxyBuffer, o.ProxyBuffer) {
		t.Fatal("proxy roundtrip", err)
	}
	_, start, _, _ := initialOffsets(b)
	consumed, _, _ := FindHeader(b[start:])
	frameAt := start + consumed
	for _, offset := range []int{frameAt + 1, frameAt + 2, frameAt + 4, frameAt + 5, frameAt + 6, frameAt + 155} {
		bad := append([]byte(nil), b...)
		bad[offset] ^= 0x40
		if _, _, err = StripQUICInitial(bad); err == nil {
			t.Fatalf("accepted mutated metadata byte %d", offset)
		}
	}
	o.ProxyBuffer = make([]byte, 1025)
	if _, err = FormatQUICInitial(packet, o); !errors.Is(err, ErrProxyBuffer) {
		t.Fatal(err)
	}
	o.ProxyBuffer = nil
	o.EncodeUserInfo = nil
	if _, err = FormatQUICInitial(packet, o); err == nil {
		t.Fatal("missing encoder")
	}
	for _, src := range [][]byte{{}, make([]byte, 4), make([]byte, 40)} {
		o.Random = bytes.NewReader(src)
		o.EncodeUserInfo = func(io.Reader) ([128]byte, error) { return [128]byte{}, nil }
		_, err = FormatQUICInitial(unhex(t, fixtures(t).QUIC[1].InputHex), o)
		if err == nil {
			t.Fatal("short entropy accepted")
		}
	}
}
