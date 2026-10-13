//go:build linux

package xray

import (
	"os"
	"strconv"
	"strings"
)

// resetOOMScore gives a started core the kernel's default OOM score. The unit
// protects the panel (OOMScoreAdjust=-500): if the OOM killer took the panel,
// Pdeathsig would take every core with it, while a killed core is restarted
// on its own. The cores inherit the panel's protection and must not keep it.
// Only a negative score is reset; raising one needs no privilege.
func resetOOMScore(pid int) {
	p := "/proc/" + strconv.Itoa(pid) + "/oom_score_adj"
	cur, err := os.ReadFile(p)
	if err != nil {
		return
	}
	if n, err := strconv.Atoi(strings.TrimSpace(string(cur))); err != nil || n >= 0 {
		return
	}
	_ = os.WriteFile(p, []byte("0"), 0)
}
