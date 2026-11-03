package orbit

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net"
	"testing"
	"time"
)

func TestServerRealityPendingInitializationCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, e := listener.Accept()
		if e == nil {
			accepted <- c
		}
	}()
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: &ServerConfig{HandshakeTimeout: 2, Reality: &ServerReality{PrivateKey: base64.RawURLEncoding.EncodeToString(private.Bytes()), ServerNames: []string{"cover.test"}, ShortIds: []string{"01"}, Dest: listener.Addr().String()}}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, e := s.realityServer(ctx); result <- e }()
	select {
	case conn := <-accepted:
		defer conn.Close()
	case <-time.After(time.Second):
		t.Fatal("cover probe did not start")
	}
	waitCtx, stop := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer stop()
	start := time.Now()
	_, err = s.realityServer(waitCtx)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatal("pending initialization ignored caller cancellation", err)
	}
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("silent cover initialized")
		}
	case <-time.After(time.Second):
		t.Fatal("cover initialization ignored cancellation")
	}
}

func TestServerRealityNamesValidatedOffline(t *testing.T) {
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := &ServerConfig{Transport: "tcp", Security: "reality", Reality: &ServerReality{PrivateKey: base64.RawURLEncoding.EncodeToString(private.Bytes()), ServerNames: []string{"Cover.TEST"}, ShortIds: []string{""}, Dest: "127.0.0.1:1"}}
	s, err := NewServer(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.cfg.Reality.ServerNames[0] != "cover.test" || c.Reality.ServerNames[0] != "Cover.TEST" {
		t.Fatal("server names not normalized privately")
	}
	c.Reality.ServerNames = []string{"Cover.TEST", "cover.test"}
	if _, err = NewServer(context.Background(), c); err == nil {
		t.Fatal("duplicate normalized server names accepted")
	}
	c.Reality.ServerNames = []string{"cover.test"}
	c.HandshakeTimeout = 91
	if _, err = NewServer(context.Background(), c); err == nil {
		t.Fatal("timeout exceeds supported transport bound")
	}
}
