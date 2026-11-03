package vmess

import (
	"google.golang.org/protobuf/proto"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
)

// MemoryAccount is an in-memory form of VMess account.
type MemoryAccount struct {
	// ID is the main ID of the account.
	ID *protocol.ID
	// Security type of the account. Used for client connections.
	Security protocol.SecurityType

	AuthenticatedLengthExperiment bool
	NoTerminationSignal           bool
	// RawUUIDAuth opts this account into raw UUID authentication. It must be
	// explicitly enabled on both peers and does not change standard users.
	RawUUIDAuth bool
}

// Equals implements protocol.Account.
func (a *MemoryAccount) Equals(account protocol.Account) bool {
	vmessAccount, ok := account.(*MemoryAccount)
	if !ok {
		return false
	}
	return a.RawUUIDAuth == vmessAccount.RawUUIDAuth && a.ID.Equals(vmessAccount.ID)
}

func (a *MemoryAccount) ToProto() proto.Message {
	var test = ""
	if a.AuthenticatedLengthExperiment {
		test = "AuthenticatedLength|"
	}
	if a.NoTerminationSignal {
		test = test + "NoTerminationSignal"
	}
	return &Account{
		Id:               a.ID.String(),
		TestsEnabled:     test,
		RawUuidAuth:      a.RawUUIDAuth,
		SecuritySettings: &protocol.SecurityConfig{Type: a.Security},
	}
}

// AsAccount implements protocol.Account.
func (a *Account) AsAccount() (protocol.Account, error) {
	id, err := uuid.ParseString(a.Id)
	if err != nil {
		return nil, errors.New("failed to parse ID").Base(err).AtError()
	}
	protoID := protocol.NewID(id)
	var AuthenticatedLength, NoTerminationSignal bool
	if strings.Contains(a.TestsEnabled, "AuthenticatedLength") {
		AuthenticatedLength = true
	}
	if strings.Contains(a.TestsEnabled, "NoTerminationSignal") {
		NoTerminationSignal = true
	}
	return &MemoryAccount{
		ID:                            protoID,
		Security:                      a.SecuritySettings.GetSecurityType(),
		AuthenticatedLengthExperiment: AuthenticatedLength,
		NoTerminationSignal:           NoTerminationSignal,
		RawUUIDAuth:                   a.GetRawUuidAuth(),
	}, nil
}
