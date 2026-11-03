// Command testsrv is the interop harness's test server: HTTP
// (interop.NewTestHandler) and UDP echo, both IPv4 and IPv6. harness.sh runs
// it inside the ovpntest namespace; see package interop for what it answers.
//
// The UDP echo answers from the address each datagram was sent to (packet
// info), so a connected client gets its reply back whatever interface the
// kernel would route it out of.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/interop"
)

func main() {
	httpAddr := flag.String("http", "[::]:8080", "HTTP listen address (dual-stack by default)")
	udpPort := flag.Int("udpport", interop.UDPEchoPort, "UDP echo port, on 0.0.0.0 and [::]")
	pidFile := flag.String("pidfile", "", "write the process id here")
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	ln, err := net.Listen("tcp", *httpAddr)
	if err != nil {
		log.Fatalf("testsrv: %v", err)
	}
	port := strconv.Itoa(*udpPort)
	c4, err := net.ListenPacket("udp4", "0.0.0.0:"+port)
	if err != nil {
		log.Fatalf("testsrv: %v", err)
	}
	c6, err := net.ListenPacket("udp6", "[::]:"+port) // IPV6_V6ONLY
	if err != nil {
		log.Fatalf("testsrv: %v", err)
	}
	if *pidFile != "" {
		if err := os.WriteFile(*pidFile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644); err != nil {
			log.Fatalf("testsrv: %v", err)
		}
		defer os.Remove(*pidFile)
	}

	srv := &http.Server{
		Handler:           interop.NewTestHandler(),
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	errc := make(chan error, 3)
	go func() { errc <- srv.Serve(ln) }()
	go func() { errc <- echo4(c4) }()
	go func() { errc <- echo6(c6) }()
	log.Printf("testsrv: HTTP on %s, UDP echo on %s and %s", ln.Addr(), c4.LocalAddr(), c6.LocalAddr())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case s := <-sig:
		log.Printf("testsrv: %v, stopping", s)
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Printf("testsrv: %v", err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	srv.Shutdown(ctx) //nolint:errcheck
	c4.Close()
	c6.Close()
}

func echo4(c net.PacketConn) error {
	p := ipv4.NewPacketConn(c)
	if err := p.SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true); err != nil {
		return err
	}
	buf := make([]byte, 65535)
	for {
		n, cm, src, err := p.ReadFrom(buf)
		if err != nil {
			return err
		}
		var reply *ipv4.ControlMessage
		if cm != nil {
			reply = &ipv4.ControlMessage{Src: cm.Dst}
		}
		p.WriteTo(buf[:n], reply, src) //nolint:errcheck // one bad peer must not stop the echo
	}
}

func echo6(c net.PacketConn) error {
	p := ipv6.NewPacketConn(c)
	if err := p.SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface, true); err != nil {
		return err
	}
	buf := make([]byte, 65535)
	for {
		n, cm, src, err := p.ReadFrom(buf)
		if err != nil {
			return err
		}
		var reply *ipv6.ControlMessage
		if cm != nil {
			reply = &ipv6.ControlMessage{Src: cm.Dst}
			if cm.Dst.IsLinkLocalUnicast() {
				reply.IfIndex = cm.IfIndex
			}
		}
		p.WriteTo(buf[:n], reply, src) //nolint:errcheck
	}
}
