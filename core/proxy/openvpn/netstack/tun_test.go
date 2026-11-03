package gvisortun

import (
	"errors"
	"io"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// icmpEchoRequest is an IPv4 ping from src to dst.
func icmpEchoRequest(src, dst netip.Addr) []byte {
	b := make([]byte, header.IPv4MinimumSize+header.ICMPv4MinimumSize+8)
	ip := header.IPv4(b)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(b)),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4(src.As4()),
		DstAddr:     tcpip.AddrFrom4(dst.As4()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	icmp := header.ICMPv4(b[header.IPv4MinimumSize:])
	icmp.SetType(header.ICMPv4Echo)
	icmp.SetIdent(7)
	icmp.SetSequence(1)
	copy(icmp[header.ICMPv4MinimumSize:], "pingpong")
	icmp.SetChecksum(header.ICMPv4Checksum(icmp, 0))
	return b
}

// A packet the stack sends while the device is being closed -- here the
// echo reply the stack makes, in the writer's own goroutine, to a ping that
// goroutine is injecting -- is dropped; it must not be sent on a closed
// channel (a panic that kills the process).
func TestCloseWhileStackIsSending(t *testing.T) {
	local := netip.MustParseAddr("10.9.0.2")
	dev, _, _, err := CreateNetTUN([]netip.Addr{local}, 1500, false)
	if err != nil {
		t.Fatal(err)
	}
	held, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	hook := func() {
		once.Do(func() {
			close(held)
			<-release
		})
	}
	testHookWriteNotify.Store(&hook)
	defer testHookWriteNotify.Store(nil)

	result := make(chan any, 1)
	go func() {
		defer func() { result <- recover() }()
		_, _ = dev.Write([][]byte{icmpEchoRequest(netip.MustParseAddr("10.9.0.1"), local)}, 0)
	}()
	select {
	case <-held:
	case <-time.After(10 * time.Second):
		t.Fatal("the stack did not answer the ping")
	}

	closed := make(chan struct{})
	go func() {
		_ = dev.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		close(release)
		t.Fatal("Close hangs while the stack is handing the device a packet")
	}
	close(release)
	select {
	case p := <-result:
		if p != nil {
			t.Fatalf("the stack's writer panicked after Close: %v", p)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the stack's writer never returned after Close")
	}

	bufs, sizes := [][]byte{make([]byte, 1500)}, []int{0}
	if _, err := dev.Read(bufs, sizes, 0); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Read after Close: %v, want os.ErrClosed", err)
	}
	func() {
		defer func() {
			if p := recover(); p != nil {
				t.Fatalf("second Close panicked: %v", p)
			}
		}()
		_ = dev.Close()
	}()
}

// Packets the stack sends reach Read.
func TestReadGetsStackPackets(t *testing.T) {
	local := netip.MustParseAddr("10.9.0.2")
	dev, _, _, err := CreateNetTUN([]netip.Addr{local}, 1500, false)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	go func() {
		_, _ = dev.Write([][]byte{icmpEchoRequest(netip.MustParseAddr("10.9.0.1"), local)}, 0)
	}()
	bufs, sizes := [][]byte{make([]byte, 1500)}, []int{0}
	n, err := dev.Read(bufs, sizes, 0)
	if err != nil || n != 1 {
		t.Fatalf("Read: %d, %v", n, err)
	}
	reply := header.IPv4(bufs[0][:sizes[0]])
	if !reply.IsValid(sizes[0]) || reply.DestinationAddress() != tcpip.AddrFrom4([4]byte{10, 9, 0, 1}) ||
		header.ICMPv4(reply.Payload()).Type() != header.ICMPv4EchoReply {
		t.Fatalf("Read %d bytes that are not the echo reply: % x", sizes[0], bufs[0][:sizes[0]])
	}
}

// pump moves the packets one device sends into the other until either is
// closed.
func pump(from, to interface {
	Read([][]byte, []int, int) (int, error)
	Write([][]byte, int) (int, error)
}) {
	bufs, sizes := [][]byte{make([]byte, 65535)}, []int{0}
	for {
		n, err := from.Read(bufs, sizes, 0)
		if err != nil {
			return
		}
		if n == 1 {
			if _, err := to.Write([][]byte{bufs[0][:sizes[0]]}, 0); err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
				return
			}
		}
	}
}

// ListenPing pings another stack through the device, in both families, and
// the endpoint reports io.EOF once closed.
func TestListenPing(t *testing.T) {
	cli4, cli6 := netip.MustParseAddr("10.9.0.2"), netip.MustParseAddr("fd00:9::2")
	srv4, srv6 := netip.MustParseAddr("10.9.0.1"), netip.MustParseAddr("fd00:9::1")
	cdev, cnet, _, err := CreateNetTUN([]netip.Addr{cli4, cli6}, 1500, false)
	if err != nil {
		t.Fatal(err)
	}
	defer cdev.Close()
	sdev, _, _, err := CreateNetTUN([]netip.Addr{srv4, srv6}, 1500, false)
	if err != nil {
		t.Fatal(err)
	}
	defer sdev.Close()
	go pump(cdev, sdev)
	go pump(sdev, cdev)

	for _, dst := range []netip.Addr{srv4, srv6} {
		v6 := dst.Is6()
		c, err := cnet.ListenPing(v6)
		if err != nil {
			t.Fatalf("ListenPing(%v): %v", v6, err)
		}
		typ := byte(8)
		if v6 {
			typ = 128
		}
		// type, code, checksum, identifier 0x0101, sequence 0x0203, data
		req := append([]byte{typ, 0, 0, 0, 1, 1, 2, 3}, "ping through the stack"...)
		if err := c.WriteEcho(req, dst); err != nil {
			t.Fatalf("WriteEcho(%v): %v", dst, err)
		}
		b := make([]byte, 2048)
		done := make(chan struct{})
		var n int
		var src netip.Addr
		go func() {
			n, src, err = c.ReadEcho(b)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("no echo reply from %v", dst)
		}
		if err != nil {
			t.Fatalf("ReadEcho: %v", err)
		}
		wantType := byte(0)
		if v6 {
			wantType = 129
		}
		if src != dst || n != len(req) || b[0] != wantType || b[6] != 2 || b[7] != 3 || string(b[8:n]) != string(req[8:]) {
			t.Fatalf("reply from %v: % x", src, b[:n])
		}
		// A read that is waiting ends when the endpoint is closed (an echo
		// flow closes an idle socket under its reader).
		waiting := make(chan struct{})
		go func() {
			_, _, err = c.ReadEcho(b)
			close(waiting)
		}()
		time.Sleep(50 * time.Millisecond)
		c.Close()
		select {
		case <-waiting:
		case <-time.After(5 * time.Second):
			t.Fatal("a waiting ReadEcho did not end when the endpoint was closed")
		}
		if !errors.Is(err, io.EOF) {
			t.Fatalf("waiting ReadEcho ended with %v, want io.EOF", err)
		}
		if _, _, err := c.ReadEcho(b); !errors.Is(err, io.EOF) {
			t.Fatalf("ReadEcho after Close: %v, want io.EOF", err)
		}
	}
}
