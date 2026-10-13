//go:build !windows

package main

import "syscall"

// setPrivateUmask has new files readable by their owner only.
func setPrivateUmask() {
	syscall.Umask(0o077)
}
