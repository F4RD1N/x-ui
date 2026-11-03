package openvpn

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestNativeServerDNSRoundTrip(t *testing.T) {
	pki := makeNativePKI(t)
	for _, tc := range []struct {
		name    string
		present bool
		dns     any
		want    []string
	}{
		{name: "legacy omitted", want: []string{"1.1.1.1"}},
		{name: "legacy null", present: true, want: []string{"1.1.1.1"}},
		{name: "explicit empty", present: true, dns: []string{}, want: []string{}},
		{name: "explicit resolvers", present: true, dns: []string{"192.0.2.53", "2001:db8::53"}, want: []string{"192.0.2.53", "2001:db8::53"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var input map[string]json.RawMessage
			if err := json.Unmarshal(serverJSON(t, nativeSettings(pki)), &input); err != nil {
				t.Fatal(err)
			}
			tunnel := map[string]any{}
			if tc.present {
				tunnel["dns"] = tc.dns
			}
			input["tunnel"], _ = json.Marshal(tunnel)
			raw, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			for round := 0; round < 3; round++ {
				settings, err := ParseServerSettings(raw)
				if err != nil {
					t.Fatalf("parse round %d: %v", round, err)
				}
				if !reflect.DeepEqual(settings.Tunnel.DNS, tc.want) {
					t.Fatalf("DNS changed during parse round %d: got %v, want %v", round, settings.Tunnel.DNS, tc.want)
				}
				if err := settings.Validate(); err != nil {
					t.Fatalf("revalidation round %d: %v", round, err)
				}
				raw = serverJSON(t, *settings)
				var serialized struct {
					Tunnel struct {
						DNS json.RawMessage `json:"dns"`
					} `json:"tunnel"`
				}
				if err := json.Unmarshal(raw, &serialized); err != nil {
					t.Fatal(err)
				}
				if len(tc.want) == 0 && string(serialized.Tunnel.DNS) != "[]" {
					t.Fatalf("explicit empty DNS disappeared during serialization round %d", round)
				}
			}
		})
	}
}
