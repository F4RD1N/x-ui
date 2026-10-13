package xray

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/vless"
	"google.golang.org/grpc"
)

// fakeHandler stands in for a core's handler API and keeps the users added.
type fakeHandler struct {
	command.UnimplementedHandlerServiceServer
	mu    sync.Mutex
	added []*command.AddUserOperation
}

func (f *fakeHandler) AlterInbound(ctx context.Context, r *command.AlterInboundRequest) (*command.AlterInboundResponse, error) {
	op, err := r.Operation.GetInstance()
	if err != nil {
		return nil, err
	}
	if add, ok := op.(*command.AddUserOperation); ok {
		f.mu.Lock()
		f.added = append(f.added, add)
		f.mu.Unlock()
	}
	return &command.AlterInboundResponse{}, nil
}

func fakeCoreAPI(t *testing.T) (*XrayAPI, *fakeHandler) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	h := &fakeHandler{}
	command.RegisterHandlerServiceServer(gs, h)
	go gs.Serve(l)
	t.Cleanup(gs.Stop)
	var api XrayAPI
	if err := api.Init(l.Addr().(*net.TCPAddr).Port); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(api.Close)
	return &api, h
}

// A user map that lacks an optional field -- a VLESS client stored without
// "flow", a shadowsocks client without "cipher" -- is added with it empty; a
// missing required field is an error. Neither panics.
func TestAddUserWithMissingFields(t *testing.T) {
	api, h := fakeCoreAPI(t)

	if err := api.AddUser("vless", "in", map[string]any{"email": "v@x", "id": "6b0e9c1c-2d6f-4c6e-9b8a-000000000001"}); err != nil {
		t.Fatalf("vless without flow: %v", err)
	}
	if err := api.AddUser("shadowsocks", "in", map[string]any{"email": "s@x", "password": "p"}); err != nil {
		t.Fatalf("shadowsocks without cipher: %v", err)
	}
	if err := api.AddUser("shadowsocks", "in", map[string]any{"email": "c@x", "password": "p", "cipher": "aes-128-gcm"}); err != nil {
		t.Fatalf("shadowsocks with cipher: %v", err)
	}
	for _, c := range []struct {
		protocol string
		user     map[string]any
	}{
		{"vless", map[string]any{"email": "v@x"}},
		{"vmess", map[string]any{"email": "m@x"}},
		{"trojan", map[string]any{"email": "t@x"}},
		{"shadowsocks", map[string]any{"email": "s@x"}},
		{"hysteria", map[string]any{"email": "h@x"}},
		{"vless", map[string]any{"id": "6b0e9c1c-2d6f-4c6e-9b8a-000000000001", "email": 7}},
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s %v panicked: %v", c.protocol, c.user, r)
				}
			}()
			err := api.AddUser(c.protocol, "in", c.user)
			if _, hasEmail := c.user["email"].(string); hasEmail && err == nil {
				t.Errorf("%s %v was accepted without its key", c.protocol, c.user)
			}
		}()
	}

	if len(h.added) < 3 {
		t.Fatalf("%d users reached the core", len(h.added))
	}
	acc, err := h.added[0].User.Account.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	if v := acc.(*vless.Account); v.Flow != "" || h.added[0].User.Email != "v@x" {
		t.Errorf("vless user %+v", v)
	}
	if acc, _ := h.added[2].User.Account.GetInstance(); acc.(*shadowsocks.Account).CipherType != shadowsocks.CipherType_AES_128_GCM {
		t.Errorf("shadowsocks cipher %v", acc)
	}
}
