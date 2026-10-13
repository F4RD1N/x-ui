//go:build !linux

package xray

// resetOOMScore is a no-op where there is no OOM score to reset.
func resetOOMScore(pid int) {}
