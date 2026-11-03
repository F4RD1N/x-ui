package service

import (
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database/model"
)

// Clients with a string tgId, as older panels and API scripts send, parse.
func TestGetClientsStringTgID(t *testing.T) {
	in := &model.Inbound{Protocol: model.VLESS, Settings: `{"clients":[
		{"id":"0b0b7a5e-8c7a-4e0f-9a51-6c0a3f1f7d10","email":"a","tgId":"","enable":true},
		{"id":"1b0b7a5e-8c7a-4e0f-9a51-6c0a3f1f7d10","email":"b","tgId":"123 456","enable":true},
		{"id":"2b0b7a5e-8c7a-4e0f-9a51-6c0a3f1f7d10","email":"c","tgId":789,"enable":true},
		{"id":"3b0b7a5e-8c7a-4e0f-9a51-6c0a3f1f7d10","email":"d","tgId":"x","enable":true},
		{"id":"4b0b7a5e-8c7a-4e0f-9a51-6c0a3f1f7d10","email":"e","enable":true}],"decryption":"none"}`}
	clients, err := (&InboundService{}).GetClients(in)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int64{"a": 0, "b": 123456, "c": 789, "d": 0, "e": 0}
	if len(clients) != len(want) {
		t.Fatalf("%d clients", len(clients))
	}
	for _, c := range clients {
		if c.TgID != want[c.Email] {
			t.Errorf("%s: tgId %d, want %d", c.Email, c.TgID, want[c.Email])
		}
	}
	// Not JSON at all still fails.
	if _, err := (&InboundService{}).GetClients(&model.Inbound{Protocol: model.VLESS, Settings: `{bad`}); err == nil {
		t.Error("broken settings were taken")
	}
}
