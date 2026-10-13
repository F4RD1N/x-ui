//go:build !linux

// Package diag is "x-ui diag", a read-only report of the server for x-ui.
// It works on Linux only.
package diag

import (
	"fmt"
	"os"
)

// Main reports that the diagnostics need Linux and returns 1.
func Main(args []string, version string) int {
	fmt.Fprintln(os.Stderr, "x-ui diag: Linux only")
	return 1
}
