package encoding_test

import (
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vless"
	. "github.com/xtls/xray-core/proxy/vless/encoding"
)

func TestDialectAccepted(t *testing.T) {
	cases := []struct {
		name     string
		version  byte
		accepted []byte
		want     bool
	}{
		// An inbound that names no dialect is stock VLESS: version 0 only.
		{"empty set takes stock", 0, nil, true},
		{"empty set refuses others", 4, nil, false},

		// A named set replaces the default rather than extending it, so an
		// inbound that lists only 4 and 5 no longer answers a stock client.
		{"listed dialect", 4, []byte{4, 5}, true},
		{"other listed dialect", 5, []byte{4, 5}, true},
		{"unlisted dialect", 6, []byte{4, 5}, false},
		{"stock is not implied", 0, []byte{4, 5}, false},

		// A staged migration lists both, and both must pass.
		{"migration keeps stock", 0, []byte{0, 4}, true},
		{"migration takes new", 4, []byte{0, 4}, true},

		// The ends of the byte range are ordinary values.
		{"max dialect", 255, []byte{255}, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := DialectAccepted(c.version, c.accepted); got != c.want {
				t.Errorf("DialectAccepted(%d, %v) = %v, want %v", c.version, c.accepted, got, c.want)
			}
		})
	}
}

// dialectRequest builds a VLESS request header for an account speaking the
// given dialect, and returns it alongside a validator that knows the user.
func dialectRequest(t *testing.T, dialect uint32) (*buf.Buffer, vless.Validator) {
	t.Helper()

	id := uuid.New()
	user := &protocol.MemoryUser{
		Level: 0,
		Email: "dialect@example.com",
	}
	user.Account = toAccount(&vless.Account{Id: id.String(), Dialect: dialect})

	account := user.Account.(*vless.MemoryAccount)
	request := &protocol.RequestHeader{
		Version: account.RequestVersion(),
		User:    user,
		Command: protocol.RequestCommandTCP,
		Address: net.DomainAddress("www.example.com"),
		Port:    net.Port(443),
	}

	buffer := buf.New()
	common.Must(EncodeRequestHeader(buffer, request, &Addons{}))

	validator := new(vless.MemoryValidator)
	validator.Add(user)
	return buffer, validator
}

// A client speaking a dialect the inbound serves is read exactly as a stock
// request is, and the version it sent survives the round trip.
func TestDecodeAcceptsServedDialect(t *testing.T) {
	buffer, validator := dialectRequest(t, 4)
	defer buffer.Release()

	_, request, _, _, err := DecodeRequestHeader(false, nil, buffer, validator, 4, 5)
	common.Must(err)

	if request.Version != 4 {
		t.Errorf("request version = %d, want 4", request.Version)
	}
	if request.Address.Domain() != "www.example.com" {
		t.Errorf("request address = %v, want www.example.com", request.Address)
	}
}

// The dialect check happens before the user id is read, so a client speaking an
// unserved dialect is turned away even though its id is one the inbound knows.
func TestDecodeRefusesUnservedDialect(t *testing.T) {
	buffer, validator := dialectRequest(t, 6)
	defer buffer.Release()

	_, _, _, _, err := DecodeRequestHeader(false, nil, buffer, validator, 4, 5)
	if err == nil {
		t.Error("expected an error for a dialect the inbound does not serve")
	}
}

// An account that names no dialect still sends version 0, which is what keeps
// every config written before this feature working against a stock server.
func TestAccountWithoutDialectSpeaksStock(t *testing.T) {
	buffer, validator := dialectRequest(t, 0)
	defer buffer.Release()

	_, request, _, _, err := DecodeRequestHeader(false, nil, buffer, validator)
	common.Must(err)

	if request.Version != Version {
		t.Errorf("request version = %d, want %d", request.Version, Version)
	}
}

// A stock client reaching an inbound that has moved on to its own dialect is
// refused: this is the property the whole feature exists for.
func TestStockClientRefusedByDialectInbound(t *testing.T) {
	buffer, validator := dialectRequest(t, 0)
	defer buffer.Release()

	_, _, _, _, err := DecodeRequestHeader(false, nil, buffer, validator, 4, 5)
	if err == nil {
		t.Error("expected a stock client to be refused by an inbound serving only 4 and 5")
	}
}
