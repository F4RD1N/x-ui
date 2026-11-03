package conf_test

import (
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/trojan"
	"google.golang.org/protobuf/proto"
)

const trojanPrefixUUID = "00112233-4455-6677-8899-aabbccddeeff"

func trojanPrefixAccount(t *testing.T, user *protocol.User) *trojan.Account {
	t.Helper()
	i, err := user.Account.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	return i.(*trojan.Account)
}

func TestTrojanUUIDHashPrefixParsing(t *testing.T) {
	for _, mode := range []struct {
		field string
		want  bool
	}{{"", false}, {`,"uuidHashPrefix":false`, false}, {`,"uuidHashPrefix":null`, false}, {`,"uuidHashPrefix":true`, true}} {
		for _, shape := range []string{
			`{"address":"example.test","port":443,"password":"` + trojanPrefixUUID + `"` + mode.field + `}`,
			`{"servers":[{"address":"example.test","port":443,"password":"` + trojanPrefixUUID + `"` + mode.field + `}]}`,
		} {
			var c conf.TrojanClientConfig
			if err := json.Unmarshal([]byte(shape), &c); err != nil {
				t.Fatal(err)
			}
			m, err := c.Build()
			if err != nil {
				t.Fatal(err)
			}
			a := trojanPrefixAccount(t, m.(*trojan.ClientConfig).Server.User)
			if a.UuidHashPrefix != mode.want || a.Password != trojanPrefixUUID {
				t.Fatal("outbound lost account mode")
			}
			b, err := proto.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			var restored trojan.ClientConfig
			if err := proto.Unmarshal(b, &restored); err != nil || !proto.Equal(m, &restored) {
				t.Fatal("protobuf restore lost mode", err)
			}
		}
	}
}

func TestTrojanUUIDHashPrefixInboundMixedAndRestore(t *testing.T) {
	raw := `{"clients":[{"password":"` + trojanPrefixUUID + `","email":"stock@example.test"},{"password":"` + trojanPrefixUUID + `","email":"custom@example.test","uuidHashPrefix":true}]}`
	var c conf.TrojanServerConfig
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatal(err)
	}
	m, err := c.Build()
	if err != nil {
		t.Fatal(err)
	}
	users := m.(*trojan.ServerConfig).Users
	if len(users) != 2 || trojanPrefixAccount(t, users[0]).UuidHashPrefix || !trojanPrefixAccount(t, users[1]).UuidHashPrefix {
		t.Fatal("per-user mode was lost")
	}
	encoded, err := json.Marshal(&c)
	if err != nil {
		t.Fatal(err)
	}
	var restored conf.TrojanServerConfig
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	got, err := restored.Build()
	if err != nil || !proto.Equal(m, got) {
		t.Fatal("JSON restore changed authentication", err)
	}
}

func TestTrojanUUIDHashPrefixRejectsMalformedTypes(t *testing.T) {
	for _, bad := range []string{`"true"`, `1`, `{}`, `[]`} {
		for _, shape := range []string{
			`{"address":"example.test","port":443,"password":"p","uuidHashPrefix":` + bad + `}`,
			`{"servers":[{"address":"example.test","port":443,"password":"p","uuidHashPrefix":` + bad + `}]}`,
		} {
			if err := json.Unmarshal([]byte(shape), new(conf.TrojanClientConfig)); err == nil {
				t.Fatal("invalid outbound flag accepted", bad)
			}
		}
		shape := `{"clients":[{"password":"p","uuidHashPrefix":` + bad + `}]}`
		if err := json.Unmarshal([]byte(shape), new(conf.TrojanServerConfig)); err == nil {
			t.Fatal("invalid inbound flag accepted", bad)
		}
	}
}
