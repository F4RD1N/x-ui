//go:build linux

package service

import (
	"fmt"
	"syscall"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database/model"
)

// A change that fails on a sub-inbound's core restarts that core, not the
// inbound's own one, and does not stay on the core it failed on.
func TestSubCoreFailureRestartsThatCore(t *testing.T) {
	integrationCore(t)
	var xs XrayService
	var is InboundService
	if err := xs.RestartXray(true); err != nil {
		t.Fatal(err)
	}
	base := freeRun(t, 2)
	src := vlessInbound(t, "", 0)
	src.Port, src.Tag = base, fmt.Sprintf("inbound-%d", base)
	src.Settings = `{"clients":[{"id":"6b0e9c1c-2d6f-4c6e-9b8a-000000000001","email":"alice","enable":true,"flow":""},{"id":"6b0e9c1c-2d6f-4c6e-9b8a-000000000002","email":"bob","enable":true,"flow":""}],"decryption":"none","fallbacks":[]}`
	src, _, err := is.AddInbound(src)
	if err != nil {
		t.Fatal(err)
	}
	xs.ApplyInboundChanges()
	if _, _, err := is.SaveSubInbounds(src.Id, []model.SubInbound{{Port: base + 1, Enable: true}}); err != nil {
		t.Fatal(err)
	}
	if err := xs.ApplyInboundChanges(); err != nil {
		t.Fatal(err)
	}
	p1, p2 := pidOf(t, "xray-1"), pidOf(t, "xray-2")

	// The sub-inbound's core hangs while bob is deleted.
	syscall.Kill(p2, syscall.SIGSTOP)
	needRestart, err := is.DelInboundClientByEmail(src.Id, "bob")
	syscall.Kill(p2, syscall.SIGCONT)
	if err != nil || !needRestart {
		t.Fatalf("delete with a hung core: restart=%v err=%v", needRestart, err)
	}
	if err := xs.ApplyInboundChanges(); err != nil {
		t.Fatal(err)
	}
	if pidOf(t, "xray-1") != p1 {
		t.Fatal("the inbound's own core restarted for its sub-inbound's failure")
	}
	if pidOf(t, "xray-2") == p2 {
		t.Fatal("the sub-inbound's core was not restarted")
	}
	if userOn(t, "xray-2", model.SubTag(src.Tag, base+1), "bob") {
		t.Fatal("bob still on the sub-inbound's core")
	}
	if userOn(t, "xray-1", src.Tag, "bob") {
		t.Fatal("bob still on the inbound's core")
	}
}
