//go:build linux

// Command xsim simulates the users of a VLESS (TCP + HTTP header) server the
// way a live one behaves: devices with an Xray mux client, opening sessions
// to sites of every kind through the core, over slow and distant networks.
//
//	xsim sites -ips 1.2.3.1-1.2.3.8 ...             the sites (the far end)
//	xsim users -model model.json -phases 1:600,2:600 ...   the devices
//	xsim fit   -model model.json -observed observe.json    the model in virtual time
//
// See sim/README.md for the model and how it was fitted to a live server.
package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: xsim sites|users|fit [flags]")
		os.Exit(2)
	}
	raiseNofile()
	switch os.Args[1] {
	case "sites":
		sitesMain(os.Args[2:])
	case "users":
		usersMain(os.Args[2:])
	case "fit":
		fitMain(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "usage: xsim sites|users|fit [flags]")
		os.Exit(2)
	}
}

func raiseNofile() {
	lim := syscall.Rlimit{Cur: 4 << 20, Max: 4 << 20}
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		lim = syscall.Rlimit{Cur: 1 << 20, Max: 1 << 20}
		syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim)
	}
}

func parsePorts(s string) []int {
	var out []int
	for _, part := range strings.Split(s, ",") {
		a, b, ok := strings.Cut(part, "-")
		lo, _ := strconv.Atoi(a)
		hi := lo
		if ok {
			hi, _ = strconv.Atoi(b)
		}
		for p := lo; p <= hi && p > 0; p++ {
			out = append(out, p)
		}
	}
	return out
}

// parseIPs takes "a,b,c" or "a-b" (IPv4).
func parseIPs(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		a, b, ok := strings.Cut(part, "-")
		if !ok {
			if part != "" {
				out = append(out, part)
			}
			continue
		}
		lo, hi := net.ParseIP(a).To4(), net.ParseIP(b).To4()
		for x := binary.BigEndian.Uint32(lo); x <= binary.BigEndian.Uint32(hi); x++ {
			ip := make(net.IP, 4)
			binary.BigEndian.PutUint32(ip, x)
			out = append(out, ip.String())
		}
	}
	return out
}
