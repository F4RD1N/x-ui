//go:build !linux

// Package tune applies the server settings an x-ui box needs. It is the
// "x-ui tune" command, and it works on Linux only.
package tune

import (
	"fmt"
	"os"
)

// Main reports that server tuning needs Linux and returns 1.
func Main(args []string, version string) int {
	fmt.Fprintln(os.Stderr, "x-ui tune: server tuning works on Linux only")
	return 1
}

// Summary has nothing to report outside Linux.
func Summary() []string { return nil }
