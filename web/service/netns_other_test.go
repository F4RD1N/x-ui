//go:build !linux

package service

// reexecInOwnNetns runs the tests here: network namespaces are Linux's.
func reexecInOwnNetns() (int, bool) { return 0, false }

// ownNetnsEnv is never set here.
const ownNetnsEnv = "XUI_SERVICE_TEST_NETNS"
