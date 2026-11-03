package trojan

import (
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
)

// Validator stores valid trojan users.
type Validator struct {
	// Serialize the two-index updates when accounts are hot-added or removed.
	mutation sync.Mutex
	// Considering email's usage here, map + sync.Mutex/RWMutex may have better performance.
	email sync.Map
	users sync.Map
}

// Add a trojan user, Email must be empty or unique.
func (v *Validator) Add(u *protocol.MemoryUser) error {
	if u == nil {
		return errors.New("Trojan user is required")
	}
	a, ok := u.Account.(*MemoryAccount)
	if !ok || a == nil {
		return errors.New("Trojan account is required")
	}
	v.mutation.Lock()
	defer v.mutation.Unlock()
	key := hexString(a.Key)
	if existing, loaded := v.users.Load(key); loaded {
		// A non-UUID custom password has the ordinary wire key. Reject an
		// ambiguous custom mapping rather than replacing another identity.
		if a.UUIDHashPrefix || existing.(*protocol.MemoryUser).Account.(*MemoryAccount).UUIDHashPrefix {
			return errors.New("Trojan compatibility authentication key already exists")
		}
	}
	if u.Email != "" {
		_, loaded := v.email.LoadOrStore(strings.ToLower(u.Email), u)
		if loaded {
			return errors.New("User ", u.Email, " already exists.")
		}
	}
	v.users.Store(key, u)
	return nil
}

// Del a trojan user with a non-empty Email.
func (v *Validator) Del(e string) error {
	v.mutation.Lock()
	defer v.mutation.Unlock()
	if e == "" {
		return errors.New("Email must not be empty.")
	}
	le := strings.ToLower(e)
	u, _ := v.email.Load(le)
	if u == nil {
		return errors.New("User ", e, " not found.")
	}
	v.email.Delete(le)
	v.users.Delete(hexString(u.(*protocol.MemoryUser).Account.(*MemoryAccount).Key))
	return nil
}

// Get a trojan user with hashed key, nil if user doesn't exist.
func (v *Validator) Get(hash string) *protocol.MemoryUser {
	u, _ := v.users.Load(hash)
	if u != nil {
		return u.(*protocol.MemoryUser)
	}
	return nil
}

// Get a trojan user with hashed key, nil if user doesn't exist.
func (v *Validator) GetByEmail(email string) *protocol.MemoryUser {
	email = strings.ToLower(email)
	u, _ := v.email.Load(email)
	if u != nil {
		return u.(*protocol.MemoryUser)
	}
	return nil
}

// Get all users
func (v *Validator) GetAll() []*protocol.MemoryUser {
	var u = make([]*protocol.MemoryUser, 0, 100)
	v.email.Range(func(key, value interface{}) bool {
		u = append(u, value.(*protocol.MemoryUser))
		return true
	})
	return u
}

// Get users count
func (v *Validator) GetCount() int64 {
	var c int64 = 0
	v.email.Range(func(key, value interface{}) bool {
		c++
		return true
	})
	return c
}
