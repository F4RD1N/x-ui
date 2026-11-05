package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/client"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/handshake"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/options"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/reliable"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/wire"
)

// This uses a byte pipe rather than host sockets. It keeps a TCP transport
// busy across multiple TLS/key generations without opening network listeners.
func TestSustainedRekeyMemoryTransport(t *testing.T) {
	p := getPKI(t)
	for _, interval := range []time.Duration{time.Hour, 100 * time.Millisecond} {
		t.Run(interval.String(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			var admissions atomic.Int32
			serverReady := make(chan *Session, 1)
			serverErrors := make(chan error, 1)
			go func() {
				s, err := Serve(ctx, &testPacketConn{Conn: a, tcp: true, fr: wire.NewFrameReader(a)}, Config{
					TCP: true, Renegotiate: interval,
					TLSConfig: &tls.Config{Certificates: []tls.Certificate{p.serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: p.pool, MinVersion: tls.VersionTLS12},
					Authenticate: func(context.Context, *handshake.ClientMessage, tls.ConnectionState) (Admission, error) {
						admissions.Add(1)
						return Admission{Identity: "memory-client", Push: []string{"topology subnet", "ifconfig 10.8.0.2 255.255.255.0"}}, nil
					},
				})
				if err != nil {
					serverErrors <- err
					return
				}
				serverReady <- s
			}()
			profile := fmt.Sprintf("client\ndev tun\nremote 127.0.0.1 1194 tcp-client\nremote-cert-tls server\nauth SHA256\n<ca>\n%s</ca>\n<cert>\n%s</cert>\n<key>\n%s</key>\n", p.caPEM, p.clientCertPEM, p.clientKeyPEM)
			o, err := options.Parse(profile)
			if err != nil {
				t.Fatal(err)
			}
			c, err := client.Dial(ctx, client.Config{Options: o, Dial: func(context.Context, string, string) (net.Conn, error) { return b, nil }})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			var s *Session
			select {
			case s = <-serverReady:
			case err := <-serverErrors:
				t.Fatal(err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			defer s.Close()
			packet := make([]byte, 1400)
			packet[0] = 0x45
			var sent, received atomic.Int64
			pumpErrors := make(chan error, 4)
			go func() {
				for ctx.Err() == nil {
					if err := s.WritePacket(packet); err != nil {
						pumpErrors <- err
						return
					}
					sent.Add(1)
				}
			}()
			go func() {
				buf := make([]byte, 65536)
				for ctx.Err() == nil {
					n, err := c.ReadPacket(buf)
					if err != nil {
						pumpErrors <- err
						return
					}
					if !bytes.Equal(buf[:n], packet) {
						pumpErrors <- errors.New("download packet integrity mismatch")
						return
					}
					received.Add(1)
				}
			}()
			go func() {
				tick := time.NewTicker(time.Millisecond)
				defer tick.Stop()
				for {
					select {
					case <-tick.C:
						if err := c.WritePacket(packet); err != nil {
							pumpErrors <- err
							return
						}
					case <-ctx.Done():
						return
					}
				}
			}()
			go func() {
				buf := make([]byte, 65536)
				for ctx.Err() == nil {
					n, err := s.ReadPacket(buf)
					if err != nil {
						pumpErrors <- err
						return
					}
					if !bytes.Equal(buf[:n], packet) {
						pumpErrors <- errors.New("upload packet integrity mismatch")
						return
					}
				}
			}()
			select {
			case err := <-pumpErrors:
				t.Fatalf("pump error=%v server=%v client=%v sent=%d received=%d admissions=%d", err, s.Err(), c.Err(), sent.Load(), received.Load(), admissions.Load())
			case <-time.After(2 * time.Second):
			}
			if received.Load() < 100 {
				t.Fatalf("too few delivered packets: %d", received.Load())
			}
			if interval < time.Hour && admissions.Load() < 5 {
				t.Fatalf("too few rekeys: %d", admissions.Load())
			}
			cancel()
		})
	}
}

func TestApplicationBackpressureResumesAndCancels(t *testing.T) {
	s, _ := readinessSession(t)
	s.done = make(chan struct{})
	s.outgoing = make(chan []byte, 256)
	s.writes = make(chan writeRequest)
	s.wake = make(chan struct{}, 1)
	s.conn = &blockedPacketConn{done: make(chan struct{})}
	for _, k := range s.keys {
		k.layer = reliable.New(reliable.Options{})
	}
	for i := 0; i < cap(s.outgoing)/2; i++ {
		s.outgoing <- []byte{1}
	}
	go s.loop()
	t.Cleanup(func() { s.cancel(); <-s.Done() })
	write := func() <-chan error {
		r := make(chan error, 1)
		go func() { r <- s.WritePacket([]byte{0x45, 1, 2, 3}) }()
		return r
	}
	waiting := write()
	select {
	case err := <-waiting:
		t.Fatalf("application write bypassed backpressure: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	// Releasing one queued packet and notifying the loop simulates the
	// transport writer making forward progress without binding any socket.
	<-s.outgoing
	s.signal()
	select {
	case err := <-waiting:
		if err != nil {
			t.Fatalf("resumed write failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("application write did not resume after capacity returned")
	}
	waiting = write()
	select {
	case err := <-waiting:
		t.Fatalf("second application write bypassed backpressure: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	s.cancel()
	select {
	case err := <-waiting:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel cause: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("backpressured application write did not cancel")
	}
	if errors.Is(s.Err(), ErrBacklog) {
		t.Fatal("ordinary application backpressure terminated session")
	}
}
