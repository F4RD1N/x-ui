//go:build !linux

// Package netnstest runs a package's tests in a network namespace of their
// own; on this system there are none, and the tests run where they are.
package netnstest

// Reexec does nothing here: the tests run where they are.
func Reexec(env string) (int, bool) { return 0, false }

// Own is false here.
func Own(env string) bool { return false }
