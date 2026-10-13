package service

import "testing"

// An inbound or client edit while every core is stopped by hand marks a
// restart; the periodic job must not act on it and start them all again.
func TestNeedRestartWaitsWhileStopped(t *testing.T) {
	var xs XrayService
	isNeedXrayRestart.Store(false)
	isManuallyStopped.Store(true)
	t.Cleanup(func() {
		isManuallyStopped.Store(false)
		isNeedXrayRestart.Store(false)
	})
	xs.SetToNeedRestart()
	if xs.IsNeedRestartAndSetFalse() {
		t.Fatal("a restart is due while the cores are stopped by hand")
	}
	isManuallyStopped.Store(false)
	if !xs.IsNeedRestartAndSetFalse() {
		t.Fatal("the change was dropped instead of kept for the next start")
	}
	if xs.IsNeedRestartAndSetFalse() {
		t.Fatal("the flag was not reset")
	}
}
