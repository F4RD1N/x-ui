//go:build windows

package xray

import "os/exec"

// setSysProcAttr is a no-op on Windows, which has no process-group or
// parent-death signal equivalent to use here.
func setSysProcAttr(cmd *exec.Cmd) {}
