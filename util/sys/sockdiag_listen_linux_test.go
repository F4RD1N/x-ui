//go:build linux

package sys

import (
	"net"
	"slices"
	"testing"
)

// A listening TCP socket and an unconnected UDP socket are found; a
// connected UDP socket is not a listener.
func TestListeningPorts(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	conn, err := net.Dial("udp4", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tcpPort := ln.Addr().(*net.TCPAddr).Port
	udpPort := pc.LocalAddr().(*net.UDPAddr).Port
	connPort := conn.LocalAddr().(*net.UDPAddr).Port

	ports, err := ListeningPorts()
	if err != nil {
		t.Skip("no sock_diag here:", err)
	}
	if !slices.Contains(ports, tcpPort) || !slices.Contains(ports, udpPort) {
		t.Fatalf("missing %d/%d in %v", tcpPort, udpPort, ports)
	}
	if slices.Contains(ports, connPort) {
		t.Errorf("connected UDP port %d listed as listening", connPort)
	}
	for _, p := range []int{tcpPort, udpPort} {
		eps, err := PortListeners(p)
		if err != nil || len(eps) != 1 || eps[0].IP != "127.0.0.1" || eps[0].Port != p {
			t.Errorf("PortListeners(%d) = %v, %v", p, eps, err)
		}
	}
	if eps, _ := PortListeners(connPort); len(eps) != 0 {
		t.Errorf("connected UDP socket listed: %v", eps)
	}
}
