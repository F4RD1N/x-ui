//go:build !linux

package sys

// OpenedBy cannot tell on this system: it always returns 0.
func OpenedBy(path string) int { return 0 }
