package anytls

import (
	"errors"

	"github.com/xtls/xray-core/common/protocol"
	"google.golang.org/protobuf/proto"
)

// MemoryAccount retains the exact authentication mode of a configured user.
type MemoryAccount struct {
	Password       string
	UUIDHashMiddle bool
	Key            [32]byte
}

func (a *Account) AsAccount() (protocol.Account, error) {
	if a == nil {
		return nil, errors.New("AnyTLS account is required")
	}
	if a.Password == "" || len(a.Password) > 4096 {
		return nil, errors.New("AnyTLS password must contain 1..4096 bytes")
	}
	return &MemoryAccount{Password: a.Password, UUIDHashMiddle: a.UuidHashMiddle, Key: Auth(a.Password, a.UuidHashMiddle)}, nil
}
func (a *MemoryAccount) Equals(b protocol.Account) bool {
	other, ok := b.(*MemoryAccount)
	return ok && a.Key == other.Key
}
func (a *MemoryAccount) ToProto() proto.Message {
	return &Account{Password: a.Password, UuidHashMiddle: a.UUIDHashMiddle}
}
