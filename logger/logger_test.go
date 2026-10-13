package logger

import "testing"

// The command line tools log without InitLogger, which would truncate the
// running panel's log file: that must not dereference a nil logger.
func TestLogBeforeInit(t *testing.T) {
	if logger != nil {
		t.Skip("initialised")
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("logging before InitLogger panicked: %v", r)
		}
	}()
	Debug("debug")
	Infof("info %d", 1)
	Warningf("warning %s", "w")
	Error("error")
	if len(GetLogs(10, "DEBUG")) != 4 {
		t.Errorf("buffer holds %v", GetLogs(10, "DEBUG"))
	}
}
