//go:build linux

package xray

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A core started by a panel whose unit sets OOMScoreAdjust=-500 inherits
// -500; resetOOMScore puts it back to 0, and leaves a positive score alone.
func TestResetOOMScore(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("lowering an oom_score_adj needs root")
	}
	read := func(pid int) string {
		b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/oom_score_adj")
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(b))
	}
	for _, c := range []struct{ start, want string }{{"-500", "0"}, {"300", "300"}} {
		cmd := exec.Command("sh", "-c", "echo "+c.start+" > /proc/self/oom_score_adj && exec sleep 30")
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		pid := cmd.Process.Pid
		deadline := time.Now().Add(5 * time.Second)
		for read(pid) != c.start && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}
		resetOOMScore(pid)
		got := read(pid)
		cmd.Process.Kill()
		cmd.Wait()
		if got != c.want {
			t.Fatalf("start %s: oom_score_adj %s, want %s", c.start, got, c.want)
		}
	}
}
