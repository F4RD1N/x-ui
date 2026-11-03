package inbound

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vmess"
	"github.com/xtls/xray-core/proxy/vmess/aead"
)

func rawInboundUser(t *testing.T, id, email string, raw bool) *protocol.MemoryUser {
	t.Helper()
	a, e := (&vmess.Account{Id: id, RawUuidAuth: raw}).AsAccount()
	if e != nil {
		t.Fatal(e)
	}
	return &protocol.MemoryUser{Email: email, Account: a}
}
func rawInboundHandler() *Handler {
	return &Handler{clients: vmess.NewTimedUserValidator(), usersByEmail: newUserByEmail(&DefaultConfig{})}
}

func TestRawUUIDAuthDynamicUserRegistration(t *testing.T) {
	h := rawInboundHandler()
	ctx := context.Background()
	newID := uuid.New()
	id := newID.String()
	raw := rawInboundUser(t, id, "raw", true)
	std := rawInboundUser(t, id, "standard", false)
	for _, u := range []*protocol.MemoryUser{raw, std} {
		if e := h.AddUser(ctx, u); e != nil {
			t.Fatal(e)
		}
	}
	duplicate := rawInboundUser(t, id, "duplicate", true)
	if e := h.AddUser(ctx, duplicate); e == nil {
		t.Fatal("duplicate raw accepted")
	}
	if h.GetUser(ctx, "duplicate") != nil || h.GetUsersCount(ctx) != 2 {
		t.Fatal("failed add did not roll back")
	}
	if e := h.RemoveUser(ctx, "RAW"); e != nil {
		t.Fatal(e)
	}
	var rawID [16]byte
	copy(rawID[:], raw.Account.(*vmess.MemoryAccount).ID.Bytes())
	if _, ok, _ := h.clients.GetAEAD(rawID[:]); ok {
		t.Fatal("removed raw user remains")
	}
	token := aead.CreateAuthID(std.Account.(*vmess.MemoryAccount).ID.CmdKey(), time.Now().Unix())
	if got, ok, e := h.clients.GetAEAD(token[:]); e != nil || !ok || got != std {
		t.Fatalf("standard user lost: %v", e)
	}
	if e := h.AddUser(ctx, duplicate); e != nil {
		t.Fatal("rolled-back email cannot be reused", e)
	}
	if e := h.RemoveUser(ctx, "duplicate"); e != nil {
		t.Fatal(e)
	}
	if e := h.RemoveUser(ctx, "standard"); e != nil {
		t.Fatal(e)
	}
	if h.GetUsersCount(ctx) != 0 {
		t.Fatal("users leaked")
	}
}

func TestRawUUIDAuthDynamicInvalidUserRollback(t *testing.T) {
	h := rawInboundHandler()
	ctx := context.Background()
	if e := h.AddUser(ctx, &protocol.MemoryUser{Email: "bad"}); e == nil {
		t.Fatal("invalid account accepted")
	}
	if e := h.AddUser(ctx, nil); e == nil {
		t.Fatal("nil user accepted")
	}
	if h.GetUser(ctx, "bad") != nil || h.GetUsersCount(ctx) != 0 {
		t.Fatal("invalid user leaked")
	}
}

func TestRawUUIDAuthDynamicConcurrentUsers(t *testing.T) {
	h := rawInboundHandler()
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		id := uuid.New()
		u := rawInboundUser(t, id.String(), fmt.Sprintf("u%d", i), i%2 == 0)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if e := h.AddUser(ctx, u); e != nil {
					t.Error(e)
					return
				}
				h.GetUser(ctx, u.Email)
				h.GetUsers(ctx)
				if e := h.RemoveUser(ctx, u.Email); e != nil {
					t.Error(e)
				}
			}
		}()
	}
	wg.Wait()
	if h.GetUsersCount(ctx) != 0 {
		t.Fatal("users leaked")
	}
}
