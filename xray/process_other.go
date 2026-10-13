//go:build !linux && !windows

package xray

import (
	"os/exec"
	"syscall"
)

// setSysProcAttr puts the core in its own process group. These systems have
// no parent-death signal: a panel that dies leaves its cores running.
func setSysProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}
