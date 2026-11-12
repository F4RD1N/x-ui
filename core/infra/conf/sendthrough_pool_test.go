package conf_test

import (
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	. "github.com/xtls/xray-core/infra/conf"
)

func buildSender(t *testing.T, sendThrough string) (*proxyman.SenderConfig, error) {
	t.Helper()
	raw := `{"protocol":"freedom","tag":"direct","sendThrough":` + mustJSON(sendThrough) + `}`
	var c OutboundDetourConfig
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatal(err)
	}
	h, err := c.Build()
	if err != nil {
		return nil, err
	}
	s, err := h.SenderSettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	return s.(*proxyman.SenderConfig), nil
}

func mustJSON(s string) string { b, _ := json.Marshal(s); return string(b) }

func TestSendThroughPool(t *testing.T) {
	s, err := buildSender(t, " 10.0.0.1, 10.0.0.2 ,10.0.0.1,2001:db8::5 ")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.1", "10.0.0.2", "2001:db8::5"}
	if len(s.ViaPool) != len(want) {
		t.Fatalf("pool = %v", s.ViaPool)
	}
	for i := range want {
		if s.ViaPool[i] != want[i] {
			t.Fatalf("pool = %v, want %v", s.ViaPool, want)
		}
	}
	if got := s.Via.AsAddress().String(); got != "10.0.0.1" {
		t.Fatalf("via = %s", got)
	}
}

func TestSendThroughPoolRefusesNonIP(t *testing.T) {
	for _, v := range []string{"10.0.0.1,origin", "10.0.0.1,10.0.0.0/30", "10.0.0.1,example.com", " , "} {
		if _, err := buildSender(t, v); err == nil {
			t.Errorf("%q was accepted", v)
		}
	}
}

func TestSendThroughSingleUnchanged(t *testing.T) {
	s, err := buildSender(t, "10.0.0.7")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.ViaPool) != 0 || s.Via.AsAddress().String() != "10.0.0.7" {
		t.Fatalf("via=%v pool=%v", s.Via, s.ViaPool)
	}
}
