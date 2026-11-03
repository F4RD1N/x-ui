package nativebridge

import (
	"errors"
	"testing"
)

func TestRecoverChangesOnlyTheFailedRequest(t *testing.T) {
	unchanged := errors.New("other outbound")
	func() (err error) { defer Recover(&err, nil); panic("secret") }()
	if unchanged.Error() != "other outbound" {
		t.Fatal("unrelated state changed")
	}
	cleaned := false
	err := func() (err error) { defer Recover(&err, func() { cleaned = true }); panic("secret") }()
	if !cleaned || err == nil || err.Error() != "native outbound internal failure" {
		t.Fatal("panic boundary failed")
	}
}

func TestCleanupPanicIsAlsoContained(t *testing.T) {
	err := func() (err error) { defer Recover(&err, func() { panic("broken cleanup") }); panic("broken request") }()
	if err == nil {
		t.Fatal("missing failure")
	}
}
