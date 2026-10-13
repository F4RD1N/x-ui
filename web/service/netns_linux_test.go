//go:build linux

package service

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

// The integration tests run real cores on loopback ports, picked as free
// just before a core binds them. Two test runs on one host -- two
// worktrees, or another package's tests next to these -- take each other's
// ports in between. As root, the test binary runs itself again in a network
// namespace of its own, with only its loopback.
const ownNetnsEnv = "XUI_SERVICE_TEST_NETNS"

// reexecInOwnNetns runs the tests in a new network namespace and returns
// their exit code with true, or false when the tests are to run here: in
// the namespace already, without root, or with XUI_SERVICE_TEST_NETNS=off.
func reexecInOwnNetns() (int, bool) {
	switch {
	case os.Getenv(ownNetnsEnv) == "1":
		if err := loopbackUp(); err != nil {
			fmt.Fprintln(os.Stderr, "bring up the loopback of the test namespace:", err)
			return 1, true
		}
		return 0, false
	case os.Getenv(ownNetnsEnv) == "off" || os.Geteuid() != 0:
		return 0, false
	}
	cmd := exec.Command(os.Args[0], os.Args[1:]...)
	cmd.Env = append(os.Environ(), ownNetnsEnv+"=1")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET, Pdeathsig: syscall.SIGKILL}
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0, true
	case errors.As(err, &exit):
		return exit.ExitCode(), true
	}
	// No namespace to be had, as in a container without the right: run here.
	return 0, false
}

func loopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}
