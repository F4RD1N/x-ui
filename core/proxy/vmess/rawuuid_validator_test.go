package vmess_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	. "github.com/xtls/xray-core/proxy/vmess"
	"github.com/xtls/xray-core/proxy/vmess/aead"
)

func rawValidatorUser(t *testing.T, id, email string, raw bool) *protocol.MemoryUser {
	t.Helper()
	a, err := (&Account{Id: id, RawUuidAuth: raw}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	return &protocol.MemoryUser{Email: email, Account: a}
}

func validatorToken(u *protocol.MemoryUser) [16]byte {
	a := u.Account.(*MemoryAccount)
	var token [16]byte
	if a.RawUUIDAuth {
		copy(token[:], a.ID.Bytes())
	} else {
		token = aead.CreateAuthID(a.ID.CmdKey(), time.Now().Unix())
	}
	return token
}

func TestRawUUIDAuthValidatorIsolationAndRemoval(t *testing.T) {
	const id = "00112233-4455-6677-8899-aabbccddeeff"
	for _, removeRaw := range []bool{true, false} {
		t.Run(fmt.Sprint(removeRaw), func(t *testing.T) {
			v := NewTimedUserValidator()
			users := []*protocol.MemoryUser{rawValidatorUser(t, id, "standard", false), rawValidatorUser(t, id, "raw", true)}
			for _, u := range users {
				if err := v.Add(u); err != nil {
					t.Fatal(err)
				}
			}
			for _, u := range users {
				token := validatorToken(u)
				got, ok, err := v.GetAEAD(token[:])
				if err != nil || !ok || got != u {
					t.Fatalf("match %s: %v", u.Email, err)
				}
			}
			dup := rawValidatorUser(t, id, "duplicate", true)
			if err := v.Add(dup); err == nil {
				t.Fatal("duplicate raw UUID accepted")
			}
			if v.GetCount() != 2 {
				t.Fatal("rejected duplicate mutated count")
			}
			removed, survivor := users[0], users[1]
			if removeRaw {
				removed, survivor = survivor, removed
			}
			if !v.Remove(removed.Email) {
				t.Fatal("remove failed")
			}
			token := validatorToken(removed)
			if _, ok, _ := v.GetAEAD(token[:]); ok {
				t.Fatal("removed mode still matched")
			}
			for i := 0; i < 4; i++ {
				token = validatorToken(survivor)
				got, ok, err := v.GetAEAD(token[:])
				if err != nil || !ok || got != survivor {
					t.Fatalf("surviving mode failed: %v", err)
				}
			}
			if !v.Remove(survivor.Email) || v.GetCount() != 0 {
				t.Fatal("final removal failed")
			}
		})
	}
}

func TestRawUUIDAuthValidatorNoFallback(t *testing.T) {
	const id = "00112233-4455-6677-8899-aabbccddeeff"
	for _, raw := range []bool{false, true} {
		v := NewTimedUserValidator()
		u := rawValidatorUser(t, id, "registered", raw)
		if err := v.Add(u); err != nil {
			t.Fatal(err)
		}
		other := rawValidatorUser(t, id, "other-mode", !raw)
		token := validatorToken(other)
		if _, ok, _ := v.GetAEAD(token[:]); ok {
			t.Fatalf("raw=%v accepted opposite mode", raw)
		}
		for _, bad := range [][]byte{nil, make([]byte, 15), make([]byte, 17)} {
			if _, ok, _ := v.GetAEAD(bad); ok {
				t.Fatal("invalid prefix length accepted")
			}
		}
	}
}

func TestRawUUIDAuthValidatorConcurrentUpdates(t *testing.T) {
	v := NewTimedUserValidator()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		id := uuid.New()
		u := rawValidatorUser(t, id.String(), fmt.Sprintf("worker%d", g), g%2 == 0)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if err := v.Add(u); err != nil {
					t.Error(err)
					return
				}
				token := validatorToken(u)
				if got, ok, err := v.GetAEAD(token[:]); err != nil || !ok || got != u {
					t.Errorf("match: %v", err)
				}
				v.GetUsers()
				v.GetCount()
				v.GetBehaviorSeed()
				if !v.Remove(u.Email) {
					t.Error("remove failed")
				}
			}
		}()
	}
	wg.Wait()
	if v.GetCount() != 0 {
		t.Fatal("users leaked")
	}
}

func TestRawUUIDAuthInvalidAccountDoesNotMutate(t *testing.T) {
	v := NewTimedUserValidator()
	for _, u := range []*protocol.MemoryUser{nil, {}, {Account: (*MemoryAccount)(nil)}, {Account: &MemoryAccount{}}} {
		if err := v.Add(u); err == nil {
			t.Fatal("invalid account accepted")
		}
	}
	if v.GetCount() != 0 {
		t.Fatal("invalid account added to users")
	}
}
