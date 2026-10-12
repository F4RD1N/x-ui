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
