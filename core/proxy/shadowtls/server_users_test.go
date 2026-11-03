package shadowtls

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
)

func TestNativeServerUserManagement(t *testing.T) {
	s := &Server{config: &ServerConfig{Version: 3}, connections: make(map[net.Conn]*serverConnection)}
	ctx := context.Background()
	account, err := (&ServerUser{Password: "password"}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	u := &protocol.MemoryUser{Email: "User@Example.invalid", Level: 7, Account: account}
	if err := s.AddUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if s.GetUsersCount(ctx) != 1 {
		t.Fatal("added user missing")
	}
	if err := s.AddUser(ctx, u); err == nil {
		t.Fatal("duplicate accepted")
	}
	got := s.GetUser(ctx, "user@example.invalid")
	if got == nil || got.Level != 7 {
		t.Fatal("user lookup lost metadata")
	}
	got.Account.(*serverAccount).value.Password = "changed-copy"
	if s.GetUser(ctx, u.Email).Account.(*serverAccount).value.Password != "password" {
		t.Fatal("returned account aliases mutable server data")
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				s.GetUser(ctx, u.Email)
				s.GetUsers(ctx)
				s.GetUsersCount(ctx)
			}
		}()
	}
	if err := s.RemoveUser(ctx, "USER@EXAMPLE.INVALID"); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if s.GetUsersCount(ctx) != 0 || s.GetUser(ctx, u.Email) != nil {
		t.Fatal("removed user remained")
	}
	if err := s.RemoveUser(ctx, u.Email); err == nil {
		t.Fatal("unknown removal accepted")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.AddUser(ctx, u); err == nil {
		t.Fatal("closed server accepted user")
	}
	if err := s.Close(); err != nil {
		t.Fatal("close not idempotent")
	}
}

func TestNativeServerCloseCancelsConnections(t *testing.T) {
	raw, peer := net.Pipe()
	defer peer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{connections: map[net.Conn]*serverConnection{raw: {cancel: cancel}}}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if ctx.Err() == nil {
		t.Fatal("active connection context not canceled")
	}
	if _, err := peer.Write([]byte("closed")); err == nil {
		t.Fatal("active connection not closed")
	}
}

func TestNativeServerV2PartialReadChallenge(t *testing.T) {
	const password = "partial-read-password"
	first := record(23, [2]byte{3, 3}, bytes.Repeat([]byte{5}, 130))
	ticket := record(23, [2]byte{3, 3}, bytes.Repeat([]byte{7}, 81))
	for _, partial := range []int{1, 7, 13, 30} {
		h := &challengeHistory{mac: newMAC(password, nil), password: password}
		h.add(first)
		h.add(ticket)
		client := newMAC(password, nil)
		client.Write(first)
		client.Write(ticket[:partial])
		if !h.match(client.Sum(nil)[:8]) {
			t.Fatalf("partial ticket prefix %d rejected", partial)
		}
		for i := 0; i < 10; i++ {
			if h.match(make([]byte, 8)) {
				t.Fatal("invalid tag accepted")
			}
		}
		if h.partialChecks > 4 {
			t.Fatal("partial challenge work is unbounded")
		}
	}
}

func TestNativeServerRevocationGeneration(t *testing.T) {
	ctx := context.Background()
	old := &ServerUser{Email: "same@example.invalid", Password: "same-password"}
	s := &Server{config: &ServerConfig{Version: 3}, users: []*ServerUser{old}, connections: make(map[net.Conn]*serverConnection)}
	active, activePeer := net.Pipe()
	defer activePeer.Close()
	activeCtx, activeCancel := context.WithCancel(ctx)
	s.connections[active] = &serverConnection{cancel: activeCancel}
	if err := s.admit(active, old); err != nil {
		t.Fatal(err)
	}
	inflight, inflightPeer := net.Pipe()
	defer inflightPeer.Close()
	_, inflightCancel := context.WithCancel(ctx)
	s.connections[inflight] = &serverConnection{cancel: inflightCancel}
	if err := s.RemoveUser(ctx, old.Email); err != nil {
		t.Fatal(err)
	}
	if activeCtx.Err() == nil {
		t.Fatal("removal did not cancel active session")
	}
	if _, err := activePeer.Write([]byte("revoked")); err == nil {
		t.Fatal("revoked session socket remains writable")
	}
	account, err := (&ServerUser{Password: old.Password}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddUser(ctx, &protocol.MemoryUser{Email: old.Email, Account: account}); err != nil {
		t.Fatal(err)
	}
	if err := s.admit(inflight, old); err == nil {
		t.Fatal("old in-flight handshake admitted after same credentials were re-added")
	}
	if err := s.admit(inflight, s.users[0]); err != nil {
		t.Fatal("new generation rejected")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func FuzzNativeServerClientHello(f *testing.F) {
	f.Add([]byte{22, 3, 3, 0, 4, 1, 0, 0, 0})
	f.Add([]byte{22, 3, 3, 255, 255})
	f.Fuzz(func(t *testing.T, data []byte) {
		hello, _, err := readHello(bytes.NewReader(data), 1)
		if err == nil {
			_ = authenticatedHello(hello, []*ServerUser{{Password: "test"}})
		}
		_ = serverHelloTLS13(data)
	})
}
