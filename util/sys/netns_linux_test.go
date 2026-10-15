//go:build linux

package sys

import (
	"os"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/util/netnstest"
)

// The tests close sockets with SOCK_DESTROY by their port. On the host
// that could close another program's connection on the same port, so as
// root the test binary runs itself again in a network namespace of its
// own; the tests that close sockets run only there.
const ownNetnsEnv = "XUI_SYS_TEST_NETNS"

func TestMain(m *testing.M) {
	if code, done := netnstest.Reexec(ownNetnsEnv); done {
		os.Exit(code)
	}
	os.Exit(m.Run())
}

// inOwnNetns skips a test that closes sockets unless it runs in the
// tests' own network namespace.
func inOwnNetns(t *testing.T) {
	t.Helper()
	if !netnstest.Own(ownNetnsEnv) {
		t.Skip("closes sockets: runs only as root, in a network namespace of its own")
	}
}
