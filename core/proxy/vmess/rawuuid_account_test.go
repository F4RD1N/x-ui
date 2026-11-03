package vmess_test

import (
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/vmess"
	"google.golang.org/protobuf/proto"
)

const syntheticUUID = "00112233-4455-6677-8899-aabbccddeeff"

func memAccount(t *testing.T, a *vmess.Account) *vmess.MemoryAccount {
	t.Helper()
	acc, err := a.AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	return acc.(*vmess.MemoryAccount)
}

func TestRawUUIDAuthToProtoRoundTrip(t *testing.T) {
	for _, raw := range []bool{false, true} {
		a := memAccount(t, &vmess.Account{
			Id:               syntheticUUID,
			SecuritySettings: &protocol.SecurityConfig{Type: protocol.SecurityType_AES128_GCM},
			TestsEnabled:     "AuthenticatedLength|NoTerminationSignal",
			RawUuidAuth:      raw,
		})
		if a.RawUUIDAuth != raw {
			t.Fatalf("AsAccount: RawUUIDAuth = %v, want %v", a.RawUUIDAuth, raw)
		}
		pb := a.ToProto().(*vmess.Account)
		if pb.RawUuidAuth != raw {
			t.Fatalf("ToProto: RawUuidAuth = %v, want %v", pb.RawUuidAuth, raw)
		}
		// Through the wire format too, as reloads and API calls do.
		wire, err := proto.Marshal(pb)
		if err != nil {
			t.Fatal(err)
		}
		back := new(vmess.Account)
		if err := proto.Unmarshal(wire, back); err != nil {
			t.Fatal(err)
		}
		b := memAccount(t, back)
		if b.RawUUIDAuth != raw || !b.Equals(a) || !b.AuthenticatedLengthExperiment || !b.NoTerminationSignal || b.Security != a.Security {
			t.Fatalf("round trip lost data: %+v vs %+v", b, a)
		}
	}
}

func TestStandardAccountProtoUnchanged(t *testing.T) {
	// A standard account serialises to exactly the bytes it did before the
	// field existed (proto3 omits a false bool).
	pb := memAccount(t, &vmess.Account{Id: syntheticUUID}).ToProto().(*vmess.Account)
	wire, err := proto.Marshal(pb)
	if err != nil {
		t.Fatal(err)
	}
	old, err := proto.Marshal(&vmess.Account{Id: pb.Id, SecuritySettings: pb.SecuritySettings, TestsEnabled: pb.TestsEnabled})
	if err != nil {
		t.Fatal(err)
	}
	if string(wire) != string(old) {
		t.Fatalf("standard account bytes changed: %x vs %x", wire, old)
	}
}

func TestRawUUIDAuthEquals(t *testing.T) {
	std := memAccount(t, &vmess.Account{Id: syntheticUUID})
	std2 := memAccount(t, &vmess.Account{Id: syntheticUUID})
	raw := memAccount(t, &vmess.Account{Id: syntheticUUID, RawUuidAuth: true})
	raw2 := memAccount(t, &vmess.Account{Id: syntheticUUID, RawUuidAuth: true})
	if !std.Equals(std2) || !raw.Equals(raw2) {
		t.Fatal("same UUID and mode must be equal")
	}
	if std.Equals(raw) || raw.Equals(std) {
		t.Fatal("same UUID in different modes must not be equal")
	}

}
