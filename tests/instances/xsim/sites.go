package main

// xsim sites: the far end of the simulated users' connections — the web
// sites, push services, video servers and UDP services they reach through
// the core. Each TCP connection is driven by the user: every message starts
// with a command header saying what to answer (see proto.go), so the sites
// keep no model of their own.

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"time"
)

var (
	siteConns   atomic.Int64
	siteTCPOut  atomic.Int64 // bytes sent
	siteTCPIn   atomic.Int64
	siteUDPIn   atomic.Int64 // datagrams
	siteUDPOut  atomic.Int64
	siteBadCmds atomic.Int64
	zeros       = make([]byte, 64<<10)
)

func sitesMain(args []string) {
	fs := flag.NewFlagSet("sites", flag.ExitOnError)
	ips := fs.String("ips", "0.0.0.0", "addresses to listen on (comma list or a-b range)")
	tcpPorts := fs.String("tcp", "443,80,5228,5222,8080,22", "TCP ports")
	udpPorts := fs.String("udp", "443,53,3478,50000", "UDP ports")
	fs.Parse(args)
	for _, ip := range parseIPs(*ips) {
		for _, p := range parsePorts(*tcpPorts) {
			ln, err := net.Listen("tcp", net.JoinHostPort(ip, strconv.Itoa(p)))
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			go acceptLoop(ln)
		}
		for _, p := range parsePorts(*udpPorts) {
			pc, err := net.ListenPacket("udp", net.JoinHostPort(ip, strconv.Itoa(p)))
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			go udpLoop(pc)
		}
	}
	var lastOut, lastIn, lastUI, lastUO int64
	for {
		time.Sleep(10 * time.Second)
		o, i, ui, uo := siteTCPOut.Load(), siteTCPIn.Load(), siteUDPIn.Load(), siteUDPOut.Load()
		fmt.Fprintf(os.Stderr, "%s sites conns=%d tcp out=%.1fMB/s in=%.1fMB/s udp in=%d/s out=%d/s bad=%d\n", time.Now().Format("15:04:05"),
			siteConns.Load(), float64(o-lastOut)/10e6, float64(i-lastIn)/10e6, (ui-lastUI)/10, (uo-lastUO)/10, siteBadCmds.Load())
		lastOut, lastIn, lastUI, lastUO = o, i, ui, uo
	}
}

func acceptLoop(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		go serveSite(c)
	}
}

func serveSite(c net.Conn) {
	siteConns.Add(1)
	defer siteConns.Add(-1)
	defer c.Close()
	br := bufio.NewReaderSize(c, 4096)
	var h [cmdHeaderLen]byte
	var pushStop chan struct{}
	defer func() {
		if pushStop != nil {
			close(pushStop)
		}
	}()
	for {
		if _, err := io.ReadFull(br, h[:]); err != nil {
			return
		}
		cmd, err := parseSiteCmd(h[:])
		if err != nil {
			siteBadCmds.Add(1)
			return
		}
		if cmd.ReqLen > 0 {
			n, err := br.Discard(int(cmd.ReqLen))
			siteTCPIn.Add(int64(n + cmdHeaderLen))
			if err != nil {
				return
			}
		} else {
			siteTCPIn.Add(cmdHeaderLen)
		}
		switch cmd.Op {
		case opRespond:
			if cmd.DelayMs > 0 {
				time.Sleep(time.Duration(cmd.DelayMs) * time.Millisecond)
			}
			if err := sendPaced(c, int64(cmd.RespLen), int(cmd.RateKBps)); err != nil {
				return
			}
		case opPush:
			if pushStop == nil && cmd.DelayMs > 0 {
				pushStop = make(chan struct{})
				go push(c, int(cmd.RespLen), time.Duration(cmd.DelayMs)*10*time.Millisecond, pushStop)
			}
		case opClose:
			// in 100 ms units; the client may close first
			go func() {
				time.Sleep(time.Duration(cmd.DelayMs) * 100 * time.Millisecond)
				c.Close()
			}()
		}
	}
}

// sendPaced writes n bytes, at rateKBps if set, in chunks of up to 16 KB.
func sendPaced(c net.Conn, n int64, rateKBps int) error {
	const chunk = 16 << 10
	start := time.Now()
	var sent int64
	for sent < n {
		k := n - sent
		if k > chunk {
			k = chunk
		}
		c.SetWriteDeadline(time.Now().Add(60 * time.Second))
		w, err := c.Write(zeros[:k])
		sent += int64(w)
		siteTCPOut.Add(int64(w))
		if err != nil {
			return err
		}
		if rateKBps > 0 {
			due := start.Add(time.Duration(float64(sent) / float64(rateKBps*1000) * float64(time.Second)))
			if d := time.Until(due); d > 0 {
				time.Sleep(d)
			}
		}
	}
	return nil
}

func push(c net.Conn, size int, every time.Duration, stop chan struct{}) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			c.SetWriteDeadline(time.Now().Add(30 * time.Second))
			n, err := c.Write(zeros[:size])
			siteTCPOut.Add(int64(n))
			if err != nil {
				return
			}
		}
	}
}

func udpLoop(pc net.PacketConn) {
	buf := make([]byte, 65536)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		siteUDPIn.Add(1)
		if n < udpHeaderLen || buf[0] != 'X' || buf[1] != 'U' {
			siteBadCmds.Add(1)
			continue
		}
		count := int(buf[2])
		size := int(buf[4])<<8 | int(buf[5])
		delay := time.Duration(int(buf[6])<<8|int(buf[7])) * time.Millisecond
		if size > len(zeros) {
			size = len(zeros)
		}
		reply := func() {
			for i := 0; i < count; i++ {
				if _, err := pc.WriteTo(zeros[:size], from); err != nil {
					return
				}
				siteUDPOut.Add(1)
			}
		}
		if delay > 0 {
			time.AfterFunc(delay, reply)
		} else {
			reply()
		}
	}
}
