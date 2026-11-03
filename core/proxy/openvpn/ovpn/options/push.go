package options

import (
	"errors"
	"fmt"
	"math/bits"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Bounds on what Pushed keeps, so that a server sending PUSH_REPLY parts
// without end cannot grow it (or the work each part does) without limit.
const (
	maxPushedRoutes  = 1024
	maxPushedDNS     = 32 // from "dns server" options, and again from dhcp-option
	maxPushedIgnored = 256
	maxPushedFlags   = 32
)

// dnsServer is one "dns server N address A..." entry.
type dnsServer struct {
	priority int
	addrs    []netip.Addr
}

func (p *Pushed) ignore(name string) {
	name = ignoredName(name)
	if p.ignored == nil {
		p.ignored = map[string]bool{}
		for _, n := range p.Ignored {
			p.ignored[n] = true
		}
	}
	if !p.ignored[name] && len(p.Ignored) < maxPushedIgnored {
		p.ignored[name] = true
		p.Ignored = append(p.Ignored, name)
	}
}

// filterAction returns the action of the first filter whose text is a
// prefix of opt, "accept" when none matches.
func filterAction(opt string, filters []PullFilter) string {
	for _, f := range filters {
		if strings.HasPrefix(opt, f.Prefix) {
			return strings.ToLower(f.Action)
		}
	}
	return "accept"
}

func (p *Pushed) applyPushReply(msg string, filters []PullFilter) (bool, error) {
	msg = strings.Trim(msg, "\x00 \t\r\n")
	rest, ok := strings.CutPrefix(msg, "PUSH_REPLY")
	if !ok || rest != "" && rest[0] != ',' {
		return false, errors.New("options: not a PUSH_REPLY message")
	}
	more := false
	for _, opt := range strings.Split(rest, ",") {
		opt = strings.TrimSpace(opt)
		if opt == "" {
			continue
		}
		args, err := splitArgs(opt)
		if err != nil {
			return false, fmt.Errorf("options: PUSH_REPLY: %w", err)
		}
		if len(args) == 0 {
			continue
		}
		name := directiveName(args[0])
		if name == "push-continuation" {
			more = len(args) > 1 && args[1] == "2"
			continue
		}
		switch filterAction(opt, filters) {
		case "reject":
			return false, fmt.Errorf("options: PUSH_REPLY: pushed %q rejected by pull-filter", name)
		case "ignore":
			p.ignore(name)
			continue
		}
		if err := p.applyOption(name, args[1:]); err != nil {
			return false, fmt.Errorf("options: PUSH_REPLY: %s: %w", name, err)
		}
	}
	if err := p.settle(); err != nil {
		return false, fmt.Errorf("options: PUSH_REPLY: %w", err)
	}
	return more, nil
}

func pushArg(args []string, i int) (string, error) {
	if i >= len(args) {
		return "", errors.New("missing argument")
	}
	return args[i], nil
}

func (p *Pushed) applyOption(name string, args []string) error {
	switch name {
	case "ifconfig":
		if len(args) < 2 {
			return errors.New("needs an address and a netmask or peer")
		}
		local, err1 := netip.ParseAddr(args[0])
		x, err2 := netip.ParseAddr(args[1])
		if err1 != nil || err2 != nil || !local.Is4() || !x.Is4() {
			return errors.New("bad IPv4 address")
		}
		p.ifconfig = [2]netip.Addr{local, x}
		p.hasIfconfig = true
	case "ifconfig-ipv6":
		a, err := pushArg(args, 0)
		if err != nil {
			return err
		}
		pfx, err := parseV6Prefix(a)
		if err != nil {
			return err
		}
		p.IPv6 = pfx
		p.GatewayV6 = netip.Addr{}
		if len(args) > 1 {
			gw, err := netip.ParseAddr(args[1])
			if err != nil || !gw.Is6() || gw.Is4In6() {
				return errors.New("bad IPv6 gateway")
			}
			p.GatewayV6 = gw.WithZone("")
		}
	case "route-gateway":
		if len(args) > 0 {
			if a, err := netip.ParseAddr(args[0]); err == nil && a.Is4() {
				p.GatewayV4 = a
				return nil
			}
		}
		p.ignore(name) // "dhcp" or malformed
	case "route":
		if pfx, ok := parseRoute(args); ok && len(p.Routes) < maxPushedRoutes {
			p.Routes = append(p.Routes, pfx)
			return nil
		}
		p.ignore(name) // malformed, or past the cap
	case "route-ipv6":
		if len(args) > 0 {
			if pfx, err := parseV6Prefix(args[0]); err == nil && len(p.Routes) < maxPushedRoutes {
				p.Routes = append(p.Routes, pfx.Masked())
				return nil
			}
		}
		p.ignore(name)
	case "dhcp-option":
		if len(args) > 1 {
			if t := strings.ToUpper(args[0]); t == "DNS" || t == "DNS6" {
				if a, err := netip.ParseAddr(args[1]); err == nil {
					a = a.WithZone("")
					switch {
					case slices.Contains(p.dhcpDNS, a):
					case len(p.dhcpDNS) < maxPushedDNS:
						p.dhcpDNS = append(p.dhcpDNS, a)
					default:
						p.ignore(name)
					}
					return nil
				}
			}
		}
		p.ignore(name)
	case "dns":
		if !p.dns(args) {
			p.ignore(name)
		}
	case "topology":
		a, err := pushArg(args, 0)
		if err != nil {
			return err
		}
		switch t := strings.ToLower(a); t {
		case "net30", "p2p", "subnet":
			p.Topology = t
		default:
			return fmt.Errorf("unknown topology %q", a)
		}
	case "cipher", "auth":
		a, err := pushArg(args, 0)
		if err != nil {
			return err
		}
		if a == "" {
			return errors.New("empty name")
		}
		if name == "cipher" {
			p.Cipher = strings.ToUpper(a)
		} else {
			p.Auth = strings.ToUpper(a)
		}
	case "peer-id":
		a, err := pushArg(args, 0)
		if err != nil {
			return err
		}
		n, err := strconv.ParseUint(a, 10, 32)
		if err != nil || n > 0xFFFFFF {
			return fmt.Errorf("bad peer id %q", a)
		}
		p.PeerID = uint32(n)
	case "key-derivation":
		a, err := pushArg(args, 0)
		if err != nil {
			return err
		}
		if strings.ToLower(a) != "tls-ekm" {
			return fmt.Errorf("unsupported method %q", a)
		}
		p.KeyDerivation = "tls-ekm"
	case "protocol-flags":
		for _, f := range args {
			f = strings.ToLower(f)
			if f == "tls-ekm" {
				p.KeyDerivation = "tls-ekm"
			}
			if p.flags == nil {
				p.flags = map[string]bool{}
				for _, g := range p.ProtocolFlags {
					p.flags[g] = true
				}
			}
			if !p.flags[f] && len(p.ProtocolFlags) < maxPushedFlags {
				p.flags[f] = true
				p.ProtocolFlags = append(p.ProtocolFlags, f)
			}
		}
	case "ping", "ping-restart":
		a, err := pushArg(args, 0)
		if err != nil {
			return err
		}
		d, err := parseSeconds(a)
		if err != nil {
			return err
		}
		if name == "ping" {
			p.Ping = d
		} else {
			p.PingRestart = d
		}
	case "keepalive":
		if len(args) < 2 {
			return errors.New("needs two arguments")
		}
		ping, err := parseSeconds(args[0])
		if err != nil {
			return err
		}
		restart, err := parseSeconds(args[1])
		if err != nil {
			return err
		}
		p.Ping, p.PingRestart = ping, restart
	case "tun-mtu":
		a, err := pushArg(args, 0)
		if err != nil {
			return err
		}
		mtu, err := parseMTU(a)
		if err != nil {
			return err
		}
		p.TunMTU = mtu
	case "comp-lzo", "compress":
		a := ""
		if len(args) > 0 {
			a = args[0]
		}
		m, err := parseCompression(name, a)
		if err != nil {
			return err
		}
		p.Compression, p.CompressionSet = m, true
	case "auth-token":
		a, err := pushArg(args, 0)
		if err != nil {
			return err
		}
		p.AuthToken = a
	case "auth-token-user":
		if len(args) > 0 {
			if u, err := decodeBase64(args[0]); err == nil {
				p.AuthTokenUser = string(u)
				return nil
			}
		}
		p.ignore(name)
	case "explicit-exit-notify":
		n := 1
		if len(args) > 0 {
			v, err := strconv.Atoi(args[0])
			if err != nil || v < 0 || v > 1000 {
				return fmt.Errorf("bad count %q", args[0])
			}
			n = v
		}
		p.ExplicitExitNotify = n
	default:
		p.ignore(name)
	}
	return nil
}

// dns handles "dns server N address A [A...]"; other dns options and
// server attributes are not used here. It reports whether it used args.
func (p *Pushed) dns(args []string) bool {
	if len(args) < 4 || strings.ToLower(args[0]) != "server" || strings.ToLower(args[2]) != "address" {
		return false
	}
	prio, err := strconv.Atoi(args[1])
	if err != nil || prio < -128 || prio > 127 {
		return false
	}
	parsed := false
	for _, s := range args[3:] {
		if a, ok := parseDNSAddr(s); ok {
			parsed = true
			p.addDNSServer(prio, a)
		}
	}
	return parsed
}

// addDNSServer stores a once for its priority, while fewer than
// maxPushedDNS addresses are stored for all priorities together.
func (p *Pushed) addDNSServer(prio int, a netip.Addr) {
	n := 0
	var s *dnsServer
	for i := range p.dnsServers {
		n += len(p.dnsServers[i].addrs)
		if p.dnsServers[i].priority == prio {
			s = &p.dnsServers[i]
		}
	}
	switch {
	case s != nil && slices.Contains(s.addrs, a):
	case n >= maxPushedDNS:
		p.ignore("dns")
	case s != nil:
		s.addrs = append(s.addrs, a)
	default:
		p.dnsServers = append(p.dnsServers, dnsServer{priority: prio, addrs: []netip.Addr{a}})
	}
}

// parseDNSAddr reads "A", "A:port", "[A6]:port" or "[A6]" and returns A.
func parseDNSAddr(s string) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().WithZone(""), true
	}
	s = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	if a, err := netip.ParseAddr(s); err == nil {
		return a.WithZone(""), true
	}
	return netip.Addr{}, false
}

// parseRoute reads "network [netmask [gateway [metric]]]" with a literal
// IPv4 network.
func parseRoute(args []string) (netip.Prefix, bool) {
	if len(args) == 0 {
		return netip.Prefix{}, false
	}
	n, err := netip.ParseAddr(args[0])
	if err != nil || !n.Is4() {
		return netip.Prefix{}, false
	}
	bitsN := 32
	if len(args) > 1 && strings.ToLower(args[1]) != "default" {
		m, err := netip.ParseAddr(args[1])
		if err != nil || !m.Is4() {
			return netip.Prefix{}, false
		}
		var ok bool
		if bitsN, ok = maskBits(m); !ok {
			return netip.Prefix{}, false
		}
	}
	return netip.PrefixFrom(n, bitsN).Masked(), true
}

// parseV6Prefix reads "addr/bits" or "addr" (as /64).
func parseV6Prefix(s string) (netip.Prefix, error) {
	addr, bitsS, hasBits := strings.Cut(s, "/")
	a, err := netip.ParseAddr(addr)
	if err != nil || !a.Is6() || a.Is4In6() {
		return netip.Prefix{}, fmt.Errorf("bad IPv6 address %q", s)
	}
	b := 64
	if hasBits {
		if b, err = strconv.Atoi(bitsS); err != nil || b < 0 || b > 128 {
			return netip.Prefix{}, fmt.Errorf("bad IPv6 prefix length %q", s)
		}
	}
	return netip.PrefixFrom(a.WithZone(""), b), nil
}

// maskBits returns the prefix length of a contiguous IPv4 netmask.
func maskBits(m netip.Addr) (int, bool) {
	if !m.Is4() {
		return 0, false
	}
	b := m.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	ones := bits.LeadingZeros32(^v)
	if v<<ones != 0 {
		return 0, false
	}
	return ones, true
}

// settle derives the fields that depend on more than one option: IPv4 and
// PeerV4 from ifconfig and the topology, DNS from both of its sources.
func (p *Pushed) settle() error {
	if p.hasIfconfig {
		local, x := p.ifconfig[0], p.ifconfig[1]
		n, isMask := maskBits(x)
		switch {
		case p.Topology == "subnet" && !isMask:
			return fmt.Errorf("ifconfig: %s is not a netmask (topology subnet)", x)
		case p.Topology == "subnet" || isMask && n > 0:
			p.IPv4, p.PeerV4 = netip.PrefixFrom(local, n), netip.Addr{}
		default:
			p.IPv4, p.PeerV4 = netip.PrefixFrom(local, 32), x
		}
	}
	servers := make([]dnsServer, len(p.dnsServers))
	copy(servers, p.dnsServers)
	sort.SliceStable(servers, func(i, j int) bool { return servers[i].priority < servers[j].priority })
	seen := map[netip.Addr]bool{}
	var dns []netip.Addr
	add := func(a netip.Addr) {
		if !seen[a] {
			seen[a] = true
			dns = append(dns, a)
		}
	}
	for _, s := range servers {
		for _, a := range s.addrs {
			add(a)
		}
	}
	for _, a := range p.dhcpDNS {
		add(a)
	}
	p.DNS = dns
	return nil
}
