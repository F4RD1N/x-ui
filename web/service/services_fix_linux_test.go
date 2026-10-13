//go:build linux

package service

import (
	"syscall"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

// A removal that fails on a sub-inbound's core restarts that core, not the
// inbound's own healthy one, and the client is gone from both.
func TestSubCoreRemoveFailureRestartsThatCore(t *testing.T) {
	in, subTag := subInboundSetup(t, 1)
	var xs XrayService
	var is InboundService
	p1, p2 := pidOf(t, "xray-1"), pidOf(t, "xray-2")
	if !hasUser(coreUsers(t, "xray-2", subTag), "gone1@v") {
		t.Fatal("the sub-inbound does not serve the client")
	}

	// Depleted while xray-2 stalls past the API deadline.
	database.GetDB().Model(xray.ClientTraffic{}).Where("email = ?", "gone1@v").Updates(map[string]any{"total": 1, "up": 10})
	syscall.Kill(p2, syscall.SIGSTOP)
	_, needRestart := is.AddTraffic(nil, nil)
	syscall.Kill(p2, syscall.SIGCONT)
	instMu.RLock()
	d1, d2 := dirty["xray-1"], dirty["xray-2"]
	instMu.RUnlock()
	if !needRestart || d1 || !d2 {
		t.Fatalf("needRestart=%v dirty xray-1=%v xray-2=%v; want only xray-2", needRestart, d1, d2)
	}
	if err := xs.RestartXray(false); err != nil {
		t.Fatal(err)
	}
	if pidOf(t, "xray-1") != p1 {
		t.Error("the healthy core of the inbound restarted")
	}
	if pidOf(t, "xray-2") == p2 {
		t.Error("the core of the sub-inbound was not restarted")
	}
	if u := coreUsers(t, "xray-2", subTag); hasUser(u, "gone1@v") || !hasUser(u, "keep1@v") {
		t.Errorf("sub-inbound serves %v", u)
	}
	if u := coreUsers(t, "xray-1", in.Tag); hasUser(u, "gone1@v") {
		t.Errorf("inbound serves %v", u)
	}

	// The admin deletes a client while xray-2 stalls.
	waitAPI(t)
	p1, p2 = pidOf(t, "xray-1"), pidOf(t, "xray-2")
	syscall.Kill(p2, syscall.SIGSTOP)
	needRestart, err := is.DelInboundClient(in.Id, "7b0e9c1c-2d6f-4c6e-9b8a-000000000101")
	syscall.Kill(p2, syscall.SIGCONT)
	if err != nil || !needRestart {
		t.Fatalf("DelInboundClient: needRestart=%v err=%v", needRestart, err)
	}
	xs.RestartXray(false)
	if pidOf(t, "xray-1") != p1 || pidOf(t, "xray-2") == p2 {
		t.Error("the wrong core restarted")
	}
	if u := coreUsers(t, "xray-2", subTag); hasUser(u, "keep1@v") {
		t.Errorf("the deleted client is still served on the sub-inbound: %v", u)
	}
}
