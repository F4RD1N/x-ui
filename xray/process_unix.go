//go:build !windows

package xray

import (
	"os/exec"
	"syscall"
)

// setSysProcAttr puts the core in its own process group and asks the kernel to
// kill it if this panel dies. Without the second part a panel that is
// SIGKILLed or OOM-killed leaves the core running and holding every inbound
// port, so the next panel start fails to bind.
func setSysProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid:   true,
		Pdeathsig: syscall.SIGKILL,
	}
}
