package model

import (
	"sort"
	"testing"
)

func TestNextXrayInstanceName(t *testing.T) {
	if got := NextXrayInstanceName(nil); got != "xray-1" {
		t.Fatalf("empty: %s", got)
	}
	used := map[string]bool{"xray-1": true, "xray-2": true, "xray-4": true, "edge": true}
	if got := NextXrayInstanceName(used); got != "xray-3" {
		t.Fatalf("gap: %s", got)
	}
}

func TestLessInstanceName(t *testing.T) {
	names := []string{"xray-10", "xray-2", "b", "xray-1", "a", "xray-02", "xray-1a"}
	sort.Slice(names, func(i, j int) bool { return LessInstanceName(names[i], names[j]) })
	want := []string{"a", "b", "xray-1", "xray-1a", "xray-2", "xray-02", "xray-10"}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("order: %v", names)
		}
	}
	if LessInstanceName("x", "x") {
		t.Fatal("not strict")
	}
}

func TestSubInbounds(t *testing.T) {
	in := &Inbound{Id: 7, Tag: "inbound-443", Port: 443, Enable: true, XrayInstance: "xray-1", XrayCores: 4, Settings: `{"clients":[]}`}
	in.SetSubs([]SubInbound{{Port: 444, Instance: "xray-2", Cores: 2, Enable: true}, {Port: 445, Instance: "xray-3", Enable: false}})
	all := ExpandSubInbounds([]*Inbound{in})
	if len(all) != 3 || all[0] != in {
		t.Fatalf("expand: %d", len(all))
	}
	a, b := all[1], all[2]
	if a.Port != 444 || a.Tag != "inbound-443~sub444" || a.XrayInstance != "xray-2" || a.XrayCores != 2 || !a.Enable || a.SubOf != 7 || a.Settings != in.Settings || a.SubInbounds != "" {
		t.Fatalf("sub 1: %+v", a)
	}
	if b.Enable {
		t.Fatal("a disabled sub-inbound came out enabled")
	}
	in.Enable = false
	if ExpandSubInbounds([]*Inbound{in})[1].Enable {
		t.Fatal("sub-inbound of a disabled inbound came out enabled")
	}
	if ParentTag("inbound-443~sub444") != "inbound-443" || ParentTag("inbound-443") != "inbound-443" {
		t.Fatal("ParentTag")
	}
	in.SetSubs(nil)
	if in.SubInbounds != "" || len(in.Subs()) != 0 {
		t.Fatal("clearing")
	}
	in.SubInbounds = "not json"
	if in.Subs() != nil {
		t.Fatal("bad json")
	}
}
