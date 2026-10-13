package freedom

import (
	"os"
	"syscall"
	"testing"

	"github.com/xtls/xray-core/common/errors"
	gonet "net"
)

func TestOutOfLocalPorts(t *testing.T) {
	bind := &gonet.OpError{Op: "listen", Net: "udp", Err: os.NewSyscallError("bind", syscall.EADDRINUSE)}
	connect := &gonet.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.EADDRNOTAVAIL)}
	refused := &gonet.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	for _, c := range []struct {
		err  error
		want bool
	}{
		{bind, true},
		{errors.New("dial failed").Base(bind), true},
		{connect, true},
		{refused, false},
		{errors.New("timeout"), false},
	} {
		if got := outOfLocalPorts(c.err); got != c.want {
			t.Errorf("outOfLocalPorts(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}
