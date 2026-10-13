package main

// The wire formats xsim speaks: the VLESS request (with the dialect version
// byte) behind the TCP HTTP header, VLESS UDP (2-byte length per packet),
// Mux.Cool with XUDP for other UDP (what a stock Xray client sends for UDP
// to ports other than 53 and 443), and the small command header the users
// send the sites to say what to answer.

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

const (
	cmdTCP = 1
	cmdUDP = 2
	cmdMux = 3
)

// The request a stock Xray client sends with the TCP "http" header type.
var httpRequestHeader = []byte("GET / HTTP/1.1\r\nHost: www.bing.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\nPragma: no-cache\r\n\r\n")

// vlessRequest builds the HTTP header (when http), the VLESS request header
// and nothing else. addr is an IPv4 or IPv6 address, or a domain.
func vlessRequest(dst []byte, http bool, version byte, uuid [16]byte, cmd byte, port int, addr string) []byte {
	if http {
		dst = append(dst, httpRequestHeader...)
	}
	dst = append(dst, version)
	dst = append(dst, uuid[:]...)
	dst = append(dst, 0) // no addons
	dst = append(dst, cmd)
	if cmd == cmdMux {
		return dst
	}
	dst = append(dst, byte(port>>8), byte(port))
	return appendAddr(dst, addr)
}

func appendAddr(dst []byte, addr string) []byte {
	if ip := net.ParseIP(addr); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return append(append(dst, 1), v4...)
		}
		return append(append(dst, 3), ip.To16()...)
	}
	return append(append(dst, 2, byte(len(addr))), addr...)
}

// readVlessResponse reads the HTTP response header (when http) and the
// VLESS response header.
func readVlessResponse(br *bufio.Reader, http bool) error {
	if http {
		line, err := br.ReadString('\n')
		if err != nil {
			return fmt.Errorf("http response: %w", err)
		}
		if !strings.HasPrefix(line, "HTTP/1.1 200") {
			return fmt.Errorf("http response: %q", strings.TrimSpace(line))
		}
		for {
			line, err = br.ReadString('\n')
			if err != nil {
				return fmt.Errorf("http response: %w", err)
			}
			if line == "\r\n" {
				break
			}
		}
	}
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return fmt.Errorf("vless response: %w", err)
	}
	if hdr[1] > 0 {
		if _, err := br.Discard(int(hdr[1])); err != nil {
			return fmt.Errorf("vless response: %w", err)
		}
	}
	return nil
}

// ------------------------------------------------------------ VLESS UDP

// appendUDPPacket frames one packet for a VLESS UDP connection.
func appendUDPPacket(dst, p []byte) []byte {
	return append(append(dst, byte(len(p)>>8), byte(len(p))), p...)
}

func readUDPPacket(br *bufio.Reader, buf []byte) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(br, l[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(l[:]))
	if n > len(buf) {
		return nil, errors.New("udp packet too big")
	}
	_, err := io.ReadFull(br, buf[:n])
	return buf[:n], err
}

// ------------------------------------------------------------ Mux.Cool + XUDP

// appendXUDP frames one packet of a UDP session inside a mux connection,
// as common/xudp.PacketWriter does: the first packet opens the session
// (status New, with the target and the global id), the rest are Keep with
// the target again.
func appendXUDP(dst []byte, first bool, port int, addr string, globalID [8]byte, p []byte) []byte {
	start := len(dst)
	dst = append(dst, 0, 0, 0, 0) // metadata length, session id 0
	if first {
		dst = append(dst, 1, 1, 2) // New, data, UDP
		dst = append(dst, byte(port>>8), byte(port))
		dst = appendAddrMux(dst, addr)
		dst = append(dst, globalID[:]...)
	} else {
		dst = append(dst, 2, 1, 2) // Keep, data, UDP
		dst = append(dst, byte(port>>8), byte(port))
		dst = appendAddrMux(dst, addr)
	}
	l := len(dst) - start - 2
	dst[start], dst[start+1] = byte(l>>8), byte(l)
	return append(append(dst, byte(len(p)>>8), byte(len(p))), p...)
}

// Mux addresses use the same type bytes as VLESS (1 IPv4, 2 domain, 3 IPv6).
func appendAddrMux(dst []byte, addr string) []byte { return appendAddr(dst, addr) }

// readXUDP reads one mux frame and returns its data (nil for frames with
// none, such as keepalives).
func readXUDP(br *bufio.Reader, buf []byte) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(br, l[:]); err != nil {
		return nil, err
	}
	ml := int(binary.BigEndian.Uint16(l[:]))
	if ml < 4 || ml > 512 {
		return nil, fmt.Errorf("mux metadata length %d", ml)
	}
	var meta [512]byte
	if _, err := io.ReadFull(br, meta[:ml]); err != nil {
		return nil, err
	}
	status, opt := meta[2], meta[3]
	if status == 3 { // End
		return nil, io.EOF
	}
	if opt&1 == 0 {
		return nil, nil
	}
	if _, err := io.ReadFull(br, l[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(l[:]))
	if n > len(buf) {
		return nil, errors.New("mux packet too big")
	}
	_, err := io.ReadFull(br, buf[:n])
	return buf[:n], err
}

// ------------------------------------------------------------ site commands

// Every message a user sends a site starts with this header. It says how
// many bytes of padding follow (the rest of the request) and what the site
// should answer.
//
//	magic 'X','S' | op | 0 | reqLen u32 | respLen u32 | delayMs u16 | rateKBps u16
const (
	cmdHeaderLen = 16
	opRespond    = 1 // after delayMs, send respLen bytes at rateKBps (0 = as fast as it can)
	opPush       = 2 // from now on, send respLen bytes every delayMs*10 ms, until closed
	opNothing    = 3 // just take the request (an upload, a heartbeat)
	opClose      = 4 // close the connection after delayMs*100 ms (a keep-alive timeout)
)

type siteCmd struct {
	Op       byte
	ReqLen   uint32
	RespLen  uint32
	DelayMs  uint16
	RateKBps uint16
}

func (c siteCmd) append(dst []byte) []byte {
	var h [cmdHeaderLen]byte
	h[0], h[1], h[2] = 'X', 'S', c.Op
	binary.BigEndian.PutUint32(h[4:], c.ReqLen)
	binary.BigEndian.PutUint32(h[8:], c.RespLen)
	binary.BigEndian.PutUint16(h[12:], c.DelayMs)
	binary.BigEndian.PutUint16(h[14:], c.RateKBps)
	return append(dst, h[:]...)
}

func parseSiteCmd(h []byte) (siteCmd, error) {
	if len(h) < cmdHeaderLen || h[0] != 'X' || h[1] != 'S' {
		return siteCmd{}, errors.New("bad command header")
	}
	return siteCmd{Op: h[2], ReqLen: binary.BigEndian.Uint32(h[4:]), RespLen: binary.BigEndian.Uint32(h[8:]),
		DelayMs: binary.BigEndian.Uint16(h[12:]), RateKBps: binary.BigEndian.Uint16(h[14:])}, nil
}

// UDP datagrams to a site start with
//
//	magic 'X','U' | count u8 | 0 | size u16 | delayMs u16
//
// and the site answers with count datagrams of size bytes after delayMs.
const udpHeaderLen = 8

func udpCmd(dst []byte, count int, size, delayMs int) []byte {
	return append(dst, 'X', 'U', byte(count), 0, byte(size>>8), byte(size), byte(delayMs>>8), byte(delayMs))
}
