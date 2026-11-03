package conf_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/vmess"
	"github.com/xtls/xray-core/proxy/vmess/inbound"
	"github.com/xtls/xray-core/proxy/vmess/outbound"
	"google.golang.org/protobuf/proto"
)

const rawUUIDConfigID = "00112233-4455-6677-8899-aabbccddeeff"

func TestVMessRawUUIDAuthConfig(t *testing.T) {
	for _, shape := range []string{"inbound", "vnext", "flat"} {
		for _, flag := range []string{"", "false", "null", "true", "\"true\"", "1", "{}", "[]"} {
			t.Run(shape+"/"+flag, func(t *testing.T) {
				field := ""
				if flag != "" {
					field = `,"rawUuidAuth":` + flag
				}
				user := fmt.Sprintf(`{"id":%q%s}`, rawUUIDConfigID, field)
				var c conf.Buildable
				var input string
				switch shape {
				case "inbound":
					c = &conf.VMessInboundConfig{}
					input = `{"clients":[` + user + `]}`
				case "vnext":
					c = &conf.VMessOutboundConfig{}
					input = `{"vnext":[{"address":"127.0.0.1","port":443,"users":[` + user + `]}]}`
				case "flat":
					c = &conf.VMessOutboundConfig{}
					input = fmt.Sprintf(`{"address":"127.0.0.1","port":443,"id":%q%s}`, rawUUIDConfigID, field)
				}
				err := json.Unmarshal([]byte(input), c)
				var built proto.Message
				if err == nil {
					built, err = c.Build()
				}
				valid := flag == "" || flag == "false" || flag == "null" || flag == "true"
				if !valid {
					if err == nil {
						t.Fatal("wrong flag type accepted")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				var account *vmess.Account
				switch cfg := built.(type) {
				case *inbound.Config:
					a, e := cfg.User[0].Account.GetInstance()
					if e != nil {
						t.Fatal(e)
					}
					account = a.(*vmess.Account)
				case *outbound.Config:
					a, e := cfg.Receiver.User.Account.GetInstance()
					if e != nil {
						t.Fatal(e)
					}
					account = a.(*vmess.Account)
				}
				if account.GetRawUuidAuth() != (flag == "true") {
					t.Fatal("mode lost")
				}
				wire, e := proto.Marshal(account)
				if e != nil {
					t.Fatal(e)
				}
				var restored vmess.Account
				if e = proto.Unmarshal(wire, &restored); e != nil {
					t.Fatal(e)
				}
				if restored.GetRawUuidAuth() != account.GetRawUuidAuth() {
					t.Fatal("protobuf round-trip lost flag")
				}
				if flag != "true" {
					standard := proto.Clone(account).(*vmess.Account)
					standard.RawUuidAuth = false
					want, _ := proto.Marshal(standard)
					if string(wire) != string(want) {
						t.Fatal("standard protobuf changed")
					}
				}
			})
		}
	}
}

func TestVMessRawUUIDAuthMixedInboundConfig(t *testing.T) {
	var c conf.VMessInboundConfig
	if e := json.Unmarshal([]byte(fmt.Sprintf(`{"clients":[{"id":%q,"email":"normal"},{"id":%q,"email":"raw","rawUuidAuth":true}]}`, rawUUIDConfigID, rawUUIDConfigID)), &c); e != nil {
		t.Fatal(e)
	}
	built, e := c.Build()
	if e != nil {
		t.Fatal(e)
	}
	for i, u := range built.(*inbound.Config).User {
		a, e := u.Account.GetInstance()
		if e != nil {
			t.Fatal(e)
		}
		if a.(*vmess.Account).GetRawUuidAuth() != (i == 1) {
			t.Fatal("mixed flags contaminated")
		}
	}
}
