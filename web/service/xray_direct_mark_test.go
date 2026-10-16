package service

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/util/json_util"
)

// stubMarkProbe makes canMarkSockets answer ok, as if probed afresh.
func stubMarkProbe(t *testing.T, ok bool) {
	t.Helper()
	old := markProbe
	markProbe = func() (bool, error) {
		if ok {
			return true, nil
		}
		return false, errors.New("operation not permitted")
	}
	canMarkOnce = sync.Once{}
	t.Cleanup(func() {
		markProbe = old
		canMarkOnce = sync.Once{}
	})
}

func TestWithDirectMark(t *testing.T) {
	stubMarkProbe(t, true)
	raw := json_util.RawMessage(`[
		{"tag":"direct","protocol":"freedom","settings":{"domainStrategy":"AsIs"}},
		{"tag":"alias","protocol":"direct"},
		{"tag":"case","protocol":"Freedom"},
		{"tag":"stream","protocol":"freedom","streamSettings":{"sockopt":{"tcpFastOpen":true}}},
		{"tag":"nullstream","protocol":"freedom","streamSettings":null},
		{"tag":"zero","protocol":"freedom","streamSettings":{"sockopt":{"mark":0}}},
		{"tag":"own","protocol":"freedom","streamSettings":{"sockopt":{"mark":4294967295}}},
		{"tag":"blocked","protocol":"blackhole","settings":{}},
		{"tag":"proxy","protocol":"vless","settings":{}}
	]`)
	out := withDirectMark(raw)
	var obs []map[string]any
	dec := json.NewDecoder(strings.NewReader(string(out)))
	dec.UseNumber()
	if err := dec.Decode(&obs); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"direct": "4242", "alias": "4242", "case": "4242", "stream": "4242", "nullstream": "4242",
		"zero": "4242", "own": "4294967295", "blocked": "", "proxy": ""}
	for _, ob := range obs {
		tag := ob["tag"].(string)
		got := ""
		if ss, ok := ob["streamSettings"].(map[string]any); ok {
			if so, ok := ss["sockopt"].(map[string]any); ok {
				if m, ok := so["mark"].(json.Number); ok {
					got = m.String()
				}
			}
		}
		if got != want[tag] {
			t.Errorf("%s: mark %q, want %q", tag, got, want[tag])
		}
		if tag == "stream" && ob["streamSettings"].(map[string]any)["sockopt"].(map[string]any)["tcpFastOpen"] != true {
			t.Error("the outbound's other socket settings were lost")
		}
	}
	if again := withDirectMark(out); string(again) != string(out) {
		t.Error("marking twice changed the outbounds")
	}
	none := json_util.RawMessage(`[{"tag":"blocked","protocol":"blackhole"}]`)
	if got := withDirectMark(none); string(got) != string(none) {
		t.Error("outbounds without freedom were rewritten")
	}
	if got := withDirectMark(json_util.RawMessage(`not json`)); string(got) != "not json" {
		t.Error("outbounds that do not parse were rewritten")
	}
}

// A process that may not mark sockets gives no mark: the core would fail
// every connection of a marked outbound.
func TestWithDirectMarkWithoutPermission(t *testing.T) {
	stubMarkProbe(t, false)
	raw := json_util.RawMessage(`[{"tag":"direct","protocol":"freedom"}]`)
	if got := withDirectMark(raw); string(got) != string(raw) {
		t.Errorf("marked without permission: %s", got)
	}
}

// The mark is in the config the cores are built from, whatever the template.
func TestXrayConfigCarriesDirectMark(t *testing.T) {
	stubMarkProbe(t, true)
	if err := database.InitDB(filepath.Join(t.TempDir(), "x-ui.db")); err != nil {
		t.Fatal(err)
	}
	defer database.CloseDB()
	cfg, err := (&XrayService{}).GetXrayConfigFor(`{"outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"blocked","protocol":"blackhole"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cfg.OutboundConfigs), `"mark":4242`) {
		t.Errorf("no direct mark in the built config: %s", cfg.OutboundConfigs)
	}
}
