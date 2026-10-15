//go:build linux

// Package netnstest runs a package's tests in a network namespace of their
// own. Tests that close sockets by port, or write the kernel's network
// settings, would otherwise reach the host's: another program's
// connections, the host's ip_local_reserved_ports.
package netnstest

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

// Reexec runs the test binary again in a new network namespace, with only
// its loopback, and returns its exit code with true; TestMain exits with
// it. It returns false when the tests are to run here: in the namespace
// already (env is "1" there), without root, with env set to "off", or
// where no namespace can be had, as in a container without the right.
func Reexec(env string) (int, bool) {
	switch {
	case os.Getenv(env) == "1":
		if err := loopbackUp(); err != nil {
			fmt.Fprintln(os.Stderr, "bring up the loopback of the test namespace:", err)
			return 1, true
		}
		return 0, false
	case os.Getenv(env) == "off" || os.Geteuid() != 0:
		return 0, false
	}
	cmd := exec.Command(os.Args[0], os.Args[1:]...)
	cmd.Env = append(os.Environ(), env+"=1")
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
	return 0, false
}

// Own says whether the tests run in the namespace Reexec made for them.
func Own(env string) bool {
	return os.Getenv(env) == "1"
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
