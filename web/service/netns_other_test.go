//go:build !linux

package service

// reexecInOwnNetns runs the tests here: network namespaces are Linux's.
func reexecInOwnNetns() (int, bool) { return 0, false }
