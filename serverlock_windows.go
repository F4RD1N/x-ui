//go:build windows

package main

import (
	"errors"
	"os"
)

// serverLock is unused on Windows.
var serverLock *os.File

var errServerRunning = errors.New("another x-ui panel is running")

// lockServer takes no lock on Windows: the panel's port still keeps a
// second one out there only as far as the bind does.
func lockServer(string) (*os.File, error) { return nil, nil }
