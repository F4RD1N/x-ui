//go:build linux

package xray

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/memlimit"
	"github.com/op/go-logging"
)

// The core starts with the memory limit of this machine, not the GOMEMLIMIT
// the panel was started with (here 449MiB, as a snapshot of a 1 GB server
// carries it onto a bigger one).
func TestCoreGetsTheMemoryLimitOfThisMachine(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XUI_BIN_FOLDER", dir)
	t.Setenv("XUI_LOG_FOLDER", dir)
	t.Setenv("GOMEMLIMIT", "449MiB")
	logger.InitLogger(logging.ERROR)

	// a stand-in core: answers -version, or writes down its environment and
	// waits to be stopped
	envFile := filepath.Join(dir, "core.env")
	script := "#!/bin/sh\n[ \"$1\" = -version ] && { echo 'Xray 26.3.27 (stand-in)'; exit 0; }\n" +
		"env > " + envFile + ".tmp && mv " + envFile + ".tmp " + envFile + "\nexec sleep 60\n"
	if err := os.WriteFile(GetBinaryPath(), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	p := newProcess(&Config{})
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()

	var env []byte
	for i := 0; i < 100 && env == nil; i++ {
		env, _ = os.ReadFile(envFile)
		time.Sleep(50 * time.Millisecond)
	}
	if env == nil {
		t.Fatal("the core never started")
	}
	want := memlimit.Environ(nil, memlimit.Limit(memlimit.Detect()))[0]
	var got []string
	for _, l := range strings.Split(string(env), "\n") {
		if strings.HasPrefix(l, "GOMEMLIMIT=") {
			got = append(got, l)
		}
	}
	if len(got) != 1 || got[0] != want {
		t.Errorf("the core's GOMEMLIMIT: %q, want only %q", got, want)
	}
}
