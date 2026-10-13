package xray

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Cores crashing together each get a report of their own, named after
// their instance; what one core prints in pieces stays in one report.
func TestCrashReportsPerInstance(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XUI_BIN_FOLDER", dir)
	a := &LogWriter{prefix: "xray-1"}
	b := &LogWriter{prefix: "xray/2"}
	a.Write([]byte("panic: one\n"))
	b.Write([]byte("panic: two\n"))
	a.Write([]byte("fatal error: more of one\n"))
	files, _ := filepath.Glob(filepath.Join(dir, "core_crash_*.log"))
	if len(files) < 2 {
		t.Fatalf("reports: %v", files)
	}
	var one, two string
	for _, f := range files {
		b, _ := os.ReadFile(f)
		switch {
		case strings.HasPrefix(filepath.Base(f), "core_crash_xray-1_"):
			one += string(b)
		case strings.HasPrefix(filepath.Base(f), "core_crash_xray_2_"):
			two += string(b)
		default:
			t.Errorf("report without its instance: %s", f)
		}
		if fi, _ := os.Stat(f); fi.Mode().Perm() != 0o600 {
			t.Errorf("%s has mode %v", f, fi.Mode().Perm())
		}
	}
	if !strings.Contains(one, "one") || !strings.Contains(one, "more of one") || strings.Contains(one, "two") || !strings.Contains(two, "two") {
		t.Fatalf("reports mixed up: %q / %q", one, two)
	}
}
