// Package tunneldns resolves SOCKS UDP domain names through the authenticated
// tunnel. Bootstrap name resolution is a separate protected physical socket.
package tunneldns

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/xtls/xray-core/proxy/orbit/internal/datagram"
	"github.com/xtls/xray-core/proxy/orbit/internal/protocol"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"
)

type Resolver struct {
	UDP     *datagram.Hub
	OpenTCP func(context.Context, string, uint16) (net.Conn, error)
	Server  netip.AddrPort
	Timeout time.Duration
}

func (r *Resolver) LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, e := netip.ParseAddr(host); e == nil {
		if !ip.Is4() {
			return nil, protocol.ErrUnsupported
		}
		return []netip.Addr{ip}, nil
	}
	if len(host) > 253 || host == "" || strings.ContainsAny(host, "\x00 /:@[]\\\r\n\t") {
		return nil, errors.New("invalid DNS name")
	}
	if r.UDP == nil || !r.Server.Addr().Is4() || r.Server.Port() == 0 {
		return nil, errors.New("numeric IPv4 tunnel DNS resolver required")
	}
	timeout := r.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	name, e := dnsmessage.NewName(strings.TrimSuffix(host, ".") + ".")
	if e != nil {
		return nil, e
	}
	var rb [2]byte
	if _, e = rand.Read(rb[:]); e != nil {
		return nil, e
	}
	id := binary.BigEndian.Uint16(rb[:])
	q := dnsmessage.Message{Header: dnsmessage.Header{ID: id, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	wire, e := q.Pack()
	if e != nil {
		return nil, e
	}
	a, e := r.UDP.Open(netip.AddrPort{}, protocol.UDPKindDNS)
	if e != nil {
		return nil, e
	}
	defer a.Close()
	if e = a.Send(ctx, r.Server, wire); e != nil {
		return nil, e
	}
	var response dnsmessage.Message
	for {
		u, e := a.Receive(ctx)
		if e != nil {
			return nil, e
		}
		if e = response.Unpack(u.Data); e != nil {
			continue
		}
		if response.ID != id || !response.Response || response.OpCode != 0 {
			continue
		}
		if len(response.Questions) != 1 || !strings.EqualFold(response.Questions[0].Name.String(), name.String()) || response.Questions[0].Type != dnsmessage.TypeA || response.Questions[0].Class != dnsmessage.ClassINET {
			continue
		}
		break
	}
	if response.Truncated {
		if r.OpenTCP == nil {
			return nil, errors.New("DNS truncated and TCP resolver unavailable")
		}
		c, e := r.OpenTCP(ctx, r.Server.Addr().String(), r.Server.Port())
		if e != nil {
			return nil, e
		}
		defer c.Close()
		stop := context.AfterFunc(ctx, func() { c.Close() })
		defer stop()
		if d, ok := ctx.Deadline(); ok {
			c.SetDeadline(d)
		}
		b := make([]byte, 2+len(wire))
		binary.BigEndian.PutUint16(b, uint16(len(wire)))
		copy(b[2:], wire)
		for len(b) > 0 {
			n, e := c.Write(b)
			if e != nil {
				return nil, e
			}
			if n == 0 {
				return nil, io.ErrShortWrite
			}
			b = b[n:]
		}
		var h [2]byte
		if _, e = io.ReadFull(c, h[:]); e != nil {
			return nil, e
		}
		b = make([]byte, int(binary.BigEndian.Uint16(h[:])))
		if _, e = io.ReadFull(c, b); e != nil {
			return nil, e
		}
		if e = response.Unpack(b); e != nil {
			return nil, e
		}
		if response.ID != id || !response.Response || response.Truncated || response.OpCode != 0 || len(response.Questions) != 1 || response.Questions[0] != q.Questions[0] {
			return nil, errors.New("invalid DNS TCP response")
		}
	}
	if response.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("DNS response code %d", response.RCode)
	}
	target := strings.ToLower(name.String())
	seen := map[string]bool{}
	for range 8 {
		if seen[target] {
			return nil, errors.New("DNS CNAME loop")
		}
		seen[target] = true
		var out []netip.Addr
		var alias string
		unique := map[netip.Addr]bool{}
		for _, answer := range response.Answers {
			if answer.Header.Class != dnsmessage.ClassINET || !strings.EqualFold(answer.Header.Name.String(), target) {
				continue
			}
			switch body := answer.Body.(type) {
			case *dnsmessage.AResource:
				ip := netip.AddrFrom4(body.A)
				if !unique[ip] {
					out = append(out, ip)
					unique[ip] = true
				}
			case *dnsmessage.CNAMEResource:
				alias = strings.ToLower(body.CNAME.String())
			}
		}
		if len(out) > 0 {
			return out, nil
		}
		if alias == "" {
			break
		}
		target = alias
	}
	return nil, errors.New("DNS response contains no IPv4 address")
}
