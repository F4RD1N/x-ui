package internet

import (
	"context"
	gonet "net"
	"syscall"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"golang.org/x/sys/unix"
)

func TestDialFromAddressDefersPort(t *testing.T) {
	l, err := gonet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	port := l.Addr().(*gonet.TCPAddr).Port

	for _, tc := range []struct {
		src  net.Address
		want int
	}{
		{net.ParseAddress("127.0.0.1"), 1},
		{nil, 0},
	} {
		conn, err := new(DefaultSystemDialer).Dial(context.Background(), tc.src, net.TCPDestination(net.LocalHostIP, net.Port(port)), nil)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := conn.(syscall.Conn).SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var got int
		var gerr error
		raw.Control(func(fd uintptr) {
			got, gerr = unix.GetsockoptInt(int(fd), unix.SOL_IP, unix.IP_BIND_ADDRESS_NO_PORT)
		})
		if gerr != nil {
			t.Fatal(gerr)
		}
		if got != tc.want {
			t.Errorf("src %v: IP_BIND_ADDRESS_NO_PORT = %d, want %d", tc.src, got, tc.want)
		}
		if tc.src != nil && conn.LocalAddr().(*gonet.TCPAddr).IP.String() != "127.0.0.1" {
			t.Errorf("src %v: local address %v", tc.src, conn.LocalAddr())
		}
		conn.Close()
	}
}
