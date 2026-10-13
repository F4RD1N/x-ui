//go:build windows

package main

// setPrivateUmask does nothing on Windows, which has no umask.
func setPrivateUmask() {}
