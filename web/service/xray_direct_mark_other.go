//go:build !linux

package service

import "errors"

// probeSocketMark: socket marks are Linux's.
func probeSocketMark() (bool, error) {
	return false, errors.New("socket marks are Linux only")
}
