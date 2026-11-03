package dnstt

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
)

func pipePair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	_ = a.SetDeadline(time.Now().Add(3 * time.Second))
	_ = b.SetDeadline(time.Now().Add(3 * time.Second))
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

func normalizedTestConfig(t *testing.T) *Config {
	t.Helper()
	c, err := NormalizeConfig(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestInnerVLESSIsExactAndResponseWaitsForPayload(t *testing.T) {
	client, server := pipePair(t)
	cfg := normalizedTestConfig(t)
	target := xnet.TCPDestination(xnet.DomainAddress("owned.example"), 443)
	serverDone := make(chan error, 1)
	go func() {
		// The UUID is the configured bytes, despite this fork's optional
		// endpoint mapping. VLESS's port precedes its address.
		uuidBytes, _ := hex.DecodeString("b831381d63244d53ad4f8cda48b30811")
		expected := append([]byte{0}, uuidBytes...)
		expected = append(expected, 0, 1, 1, 187, 2, byte(len("owned.example")))
		expected = append(expected, "owned.example"...)
		got := make([]byte, len(expected))
		if _, err := io.ReadFull(server, got); err != nil {
			serverDone <- err
			return
		}
		if !bytes.Equal(got, expected) {
			serverDone <- errors.New("VLESS version, UUID or destination changed")
			return
		}
		payload := make([]byte, 4)
		if _, err := io.ReadFull(server, payload); err != nil || string(payload) != "ping" {
			serverDone <- errors.New("payload not delivered before response header")
			return
		}
		_, err := server.Write([]byte{0, 0, 'p', 'o', 'n', 'g'})
		serverDone <- err
	}()
	conn, packets, err := innerConnection(context.Background(), client, target, cfg)
	if err != nil || packets != nil {
		t.Fatalf("inner connection: %v", err)
	}
	if _, err = conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	if _, err = io.ReadFull(conn, b); err != nil || string(b) != "pong" {
		t.Fatalf("response: %q, %v", b, err)
	}
	if err = <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestInnerSOCKSAuthenticatesAndRefusesDowngrade(t *testing.T) {
	for _, downgrade := range []bool{false, true} {
		t.Run(map[bool]string{true: "downgrade", false: "authenticated"}[downgrade], func(t *testing.T) {
			client, server := pipePair(t)
			cfg := normalizedTestConfig(t)
			cfg.Inner = &Inner{Protocol: "socks", Username: "owned-user", Password: "owned-password"}
			done := make(chan error, 1)
			go func() {
				greeting := make([]byte, 3)
				if _, err := io.ReadFull(server, greeting); err != nil || !bytes.Equal(greeting, []byte{5, 1, 2}) {
					done <- errors.New("did not exclusively offer password authentication")
					return
				}
				if downgrade {
					_, err := server.Write([]byte{5, 0})
					done <- err
					return
				}
				if _, err := server.Write([]byte{5, 2}); err != nil {
					done <- err
					return
				}
				auth := make([]byte, 2+len(cfg.Inner.Username)+1+len(cfg.Inner.Password))
				if _, err := io.ReadFull(server, auth); err != nil {
					done <- err
					return
				}
				expected := append([]byte{1, byte(len(cfg.Inner.Username))}, cfg.Inner.Username...)
				expected = append(expected, byte(len(cfg.Inner.Password)))
				expected = append(expected, cfg.Inner.Password...)
				if !bytes.Equal(auth, expected) {
					done <- errors.New("wrong SOCKS credentials")
					return
				}
				if _, err := server.Write([]byte{1, 0}); err != nil {
					done <- err
					return
				}
				req := make([]byte, 10)
				if _, err := io.ReadFull(server, req); err != nil || !bytes.Equal(req, []byte{5, 1, 0, 1, 192, 0, 2, 3, 1, 187}) {
					done <- errors.New("wrong SOCKS destination")
					return
				}
				_, err := server.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				done <- err
			}()
			_, _, err := innerConnection(context.Background(), client, xnet.TCPDestination(xnet.ParseAddress("192.0.2.3"), 443), cfg)
			if (err != nil) != downgrade {
				t.Fatalf("downgrade=%v: %v", downgrade, err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestVLESSDatagramBoundariesAndDestination(t *testing.T) {
	client, server := pipePair(t)
	target := xnet.UDPDestination(xnet.DomainAddress("owned.example"), 53)
	p := &vlessPackets{conn: client, target: target}
	done := make(chan error, 1)
	go func() {
		for _, expected := range [][]byte{[]byte("one"), []byte("second packet")} {
			var length [2]byte
			if _, err := io.ReadFull(server, length[:]); err != nil {
				done <- err
				return
			}
			b := make([]byte, int(binary.BigEndian.Uint16(length[:])))
			if _, err := io.ReadFull(server, b); err != nil || !bytes.Equal(b, expected) {
				done <- errors.New("datagram boundary lost")
				return
			}
			frame := binary.BigEndian.AppendUint16(nil, uint16(len(b)))
			if _, err := server.Write(append(frame, b...)); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	for _, b := range [][]byte{[]byte("one"), []byte("second packet")} {
		if err := p.WritePacket(b, target); err != nil {
			t.Fatal(err)
		}
		got, dest, err := p.ReadPacket()
		if err != nil || !bytes.Equal(got, b) || dest != target {
			t.Fatalf("packet: %q, %v", got, err)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := p.WritePacket([]byte("x"), xnet.UDPDestination(xnet.LocalHostIP, 53)); err == nil {
		t.Fatal("per-packet destination changed silently")
	}
	if err := p.WritePacket(make([]byte, int(buf.Size)+1), target); err == nil {
		t.Fatal("oversize datagram accepted")
	}
}

func TestVLESSRejectsOversizeIncomingDatagram(t *testing.T) {
	client, server := pipePair(t)
	p := &vlessPackets{conn: client}
	go func() { _, _ = server.Write(binary.BigEndian.AppendUint16(nil, uint16(buf.Size+1))) }()
	if _, _, err := p.ReadPacket(); err == nil {
		t.Fatal("oversize packet accepted")
	}
}
