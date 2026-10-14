package service

// Outgoing IPs.
//
// Freedom gives every UDP flow a socket of its own on a free local port. When
// every core sends from the host's default address they all draw on that
// address's ~64k ports, and close to full each new socket's search for a port
// spins in the kernel: the CPU goes to 100% and traffic collapses, however
// big the server. An instance with an outgoing IP of its own binds its
// sockets there, so they have that address's whole port range, as a
// separate server with its own IP would -- all but the system resolver's,
// which need a port free on every address. Its TCP connections leave from
// that IP too.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/json_util"
	"github.com/mhsanaei/3x-ui/v2/util/sys"
)

const egressSettingKey = "xrayInstanceEgress"

// GetInstanceEgress returns the outgoing IP of each instance that has one.
func (s *SettingService) GetInstanceEgress() (map[string]string, error) {
	v, err := s.getString(egressSettingKey)
	if err != nil {
		return map[string]string{}, err
	}
	m := map[string]string{}
	if strings.TrimSpace(v) == "" {
		return m, nil
	}
	if err := json.Unmarshal([]byte(v), &m); err != nil {
		return map[string]string{}, fmt.Errorf("read the instances' outgoing IPs: %w", err)
	}
	for name, ip := range m {
		if ip == "" {
			delete(m, name)
		}
	}
	return m, nil
}

// SetInstanceEgress stores the outgoing IP of each instance.
func (s *SettingService) SetInstanceEgress(m map[string]string) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return s.setString(egressSettingKey, string(b))
}

// hostIP is an address on one of the host's interfaces.
type hostIP struct {
	IP    net.IP
	Iface string
	// NoCarrier: the interface is up but has no link at the moment -- a
	// cable or switch port that drops for a few seconds, or a Docker bridge
	// without containers.
	NoCarrier bool
}

// hostIface is an interface with its flags and addresses.
type hostIface struct {
	Name  string
	Flags net.Flags
	Addrs []net.Addr
}

// hostAddressList returns the addresses on the host's interfaces that are
// up: no loopback, link-local or multicast ones. Those on an interface
// without a carrier are marked.
var hostAddressList = func() ([]hostIP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	list := make([]hostIface, 0, len(ifaces))
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		list = append(list, hostIface{Name: ifc.Name, Flags: ifc.Flags, Addrs: addrs})
	}
	return hostAddressesOf(list), nil
}

// hostAddressesOf picks the addresses hostAddressList returns.
func hostAddressesOf(ifaces []hostIface) []hostIP {
	var out []hostIP
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		noCarrier := ifc.Flags&net.FlagRunning == 0
		for _, a := range ifc.Addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipn.IP
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				ip = v4
			}
			out = append(out, hostIP{IP: ip, Iface: ifc.Name, NoCarrier: noCarrier})
		}
	}
	return out
}

// defaultRouteIfaces returns the interfaces the host's IPv4 default routes
// leave through.
var defaultRouteIfaces = func() map[string]bool {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return map[string]bool{}
	}
	return parseDefaultRoutes(b)
}

// parseDefaultRoutes reads the interfaces of the default routes from the
// contents of /proc/net/route.
func parseDefaultRoutes(b []byte) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		// Iface Destination Gateway Flags RefCnt Use Metric Mask ...
		if len(f) >= 8 && f[1] == "00000000" && f[7] == "00000000" {
			out[f[0]] = true
		}
	}
	return out
}

// hostAddressSet returns, in their usual form, the addresses a running core
// keeps sending from. An address on the interface of the default route
// stays one while its link is down: a cable or switch port that drops for a
// few seconds takes nothing from the host, the default address is on the
// same dead link, and moving every core there and back would cut all their
// connections twice. One on another interface without a carrier -- a Docker
// bridge without containers, an unplugged second port -- is not one.
func hostAddressSet() map[string]bool {
	list, _ := hostAddressList()
	out := make(map[string]bool, len(list))
	var uplinks map[string]bool
	for _, a := range list {
		if a.NoCarrier {
			if uplinks == nil {
				uplinks = defaultRouteIfaces()
			}
			if !uplinks[a.Iface] {
				continue
			}
		}
		out[a.IP.String()] = true
	}
	return out
}

// isHostAddress reports whether ip can be chosen as an outgoing IP: an
// address on an interface that is up and has a carrier.
func isHostAddress(ip net.IP) bool {
	list, err := hostAddressList()
	if err != nil {
		return false
	}
	for _, a := range list {
		if a.IP.Equal(ip) && !a.NoCarrier {
			return true
		}
	}
	return false
}

// usableEgress returns ip when a core can send from it now -- an IPv4
// address on the host -- and "" otherwise.
func usableEgress(ip string, host map[string]bool) string {
	if parsed := net.ParseIP(ip); parsed == nil || parsed.To4() == nil || !host[ip] {
		return ""
	}
	return ip
}

// egressProbe checks that something on the internet answers a connection
// from ip: one of a few public resolvers on port 443.
var egressProbe = func(ip net.IP) error {
	targets := []string{"1.1.1.1:443", "8.8.8.8:443", "9.9.9.9:443"}
	errs := make(chan error, len(targets))
	for _, t := range targets {
		go func(t string) {
			d := net.Dialer{Timeout: 4 * time.Second, LocalAddr: &net.TCPAddr{IP: ip}}
			c, err := d.Dial("tcp", t)
			if err == nil {
				c.Close()
			}
			errs <- err
		}(t)
	}
	var last error
	for range targets {
		if err := <-errs; err == nil {
			return nil
		} else {
			last = err
		}
	}
	return last
}

// CheckEgressIP parses and checks an outgoing IP; it returns the address in
// its usual form.
func CheckEgressIP(s string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return "", fmt.Errorf("%q is not an IP address", s)
	}
	v4 := ip.To4()
	if v4 == nil {
		// Every freedom outbound sends from it, and a core sending from an
		// IPv6 address cannot reach IPv4 ones.
		return "", fmt.Errorf("%s is not an IPv4 address: an outgoing IP must be IPv4", ip)
	}
	ip = v4
	if !isHostAddress(ip) {
		return "", fmt.Errorf("%s is not an address of this server", ip)
	}
	if err := egressProbe(ip); err != nil {
		return "", fmt.Errorf("nothing on the internet answers from %s: %v", ip, err)
	}
	return ip.String(), nil
}

// ipv6First lists the domain strategies that resolve to IPv6 first or only:
// an outbound with one of them cannot send from an IPv4 address.
var ipv6First = map[string]bool{"useipv6": true, "useipv6v4": true, "forceipv6": true, "forceipv6v4": true}

// withEgress makes the freedom outbounds of an instance's config send from
// ip, an IPv4 address. Outbounds that choose their own source, leave through
// another outbound, or ask for IPv6, are left as they are.
func withEgress(raw json_util.RawMessage, ip string) json_util.RawMessage {
	if ip == "" || len(raw) == 0 {
		return raw
	}
	var obs []map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if dec.Decode(&obs) != nil {
		return raw
	}
	changed := false
	for _, ob := range obs {
		// The core takes the protocol in any case, and "direct" for freedom.
		if p, _ := ob["protocol"].(string); !strings.EqualFold(p, "freedom") && !strings.EqualFold(p, "direct") {
			continue
		}
		if v, _ := ob["sendThrough"].(string); v != "" {
			continue
		}
		if st, ok := ob["settings"].(map[string]any); ok {
			ds, _ := st["domainStrategy"].(string)
			ts, _ := st["targetStrategy"].(string)
			if ipv6First[strings.ToLower(ds)] || ipv6First[strings.ToLower(ts)] {
				continue
			}
		}
		if ps, ok := ob["proxySettings"].(map[string]any); ok {
			if tag, _ := ps["tag"].(string); tag != "" {
				continue
			}
		}
		if ss, ok := ob["streamSettings"].(map[string]any); ok {
			if so, ok := ss["sockopt"].(map[string]any); ok {
				dp, _ := so["dialerProxy"].(string)
				iface, _ := so["interface"].(string)
				ds, _ := so["domainStrategy"].(string)
				if dp != "" || iface != "" || ipv6First[strings.ToLower(ds)] {
					continue
				}
			}
		}
		ob["sendThrough"] = ip
		changed = true
	}
	if !changed {
		return raw
	}
	b, err := json.Marshal(obs)
	if err != nil {
		return raw
	}
	return b
}

// applyEgress gives each planned core its outgoing IP, and returns the IP
// each core sends from. An IP no longer on the host is skipped -- the core
// sends from the default address -- rather than leaving the core unable to
// connect anywhere.
func applyEgress(plan *instancePlan, egress map[string]string) map[string]string {
	applied := map[string]string{}
	if len(egress) == 0 {
		return applied
	}
	host := hostAddressSet()
	for name, cfg := range plan.configs {
		ip := egress[name]
		if ip == "" {
			continue
		}
		if usableEgress(ip, host) == "" {
			logger.Warning("xray instance", name, "has outgoing IP", ip, "which is not an IPv4 address on this server; it sends from the default address")
			continue
		}
		cfg.OutboundConfigs = withEgress(cfg.OutboundConfigs, ip)
		applied[name] = ip
	}
	return applied
}

// egressSettle is how long a core's outgoing IP must stay gone before the
// core is moved to the default address: an address that goes for a moment
// and comes back -- a network service reconfiguring the interface --
// restarts nothing.
const egressSettle = 50 * time.Second

var (
	egressDriftMu    sync.Mutex
	egressDriftSince time.Time // when a core's outgoing IP was first seen gone; zero otherwise
	egressNow        = time.Now
)

// resetEgressDrift starts the wait over: the cores were just applied to the
// addresses the host has now.
func resetEgressDrift() {
	egressDriftMu.Lock()
	egressDriftSince = time.Time{}
	egressDriftMu.Unlock()
}

// EgressOutOfLine reports whether a running core sends from another address
// than it should: its outgoing IP came onto the host after the core started
// -- an address added late at boot -- or left it. Applying the cores again
// puts it right. A core that can send from its IP is moved onto it at once;
// one whose IP left is moved to the default address only when it has been
// gone for egressSettle -- the panel checks every 30 seconds, so at the
// third check that sees it gone.
func (s *XrayService) EgressOutOfLine() bool {
	out, leaving := s.egressOutOfLineNow()
	egressDriftMu.Lock()
	defer egressDriftMu.Unlock()
	if !out || !leaving {
		egressDriftSince = time.Time{}
		return out
	}
	now := egressNow()
	if egressDriftSince.IsZero() {
		egressDriftSince = now
		return false
	}
	if now.Sub(egressDriftSince) < egressSettle {
		return false
	}
	egressDriftSince = time.Time{}
	return true
}

// egressOutOfLineNow reports whether a running core sends from another
// address than it should at this moment, and whether one of them sends from
// an outgoing IP that is no longer on the host.
func (s *XrayService) egressOutOfLineNow() (out, leaving bool) {
	stored, _ := s.settingService.GetInstanceEgress()
	instMu.RLock()
	applied := make(map[string]string, len(egressApplied))
	for name, ip := range egressApplied {
		applied[name] = ip
	}
	instMu.RUnlock()
	if len(stored) == 0 && len(applied) == 0 {
		return false, false
	}
	host := hostAddressSet()
	for _, p := range snapshotProcs() {
		if !p.IsRunning() {
			continue
		}
		want := usableEgress(stored[p.Name()], host)
		if want == applied[p.Name()] {
			continue
		}
		out = true
		if want == "" {
			leaving = true
		}
	}
	return out, leaving
}

// pruneEgress forgets the outgoing IPs of instances no inbound names any
// more, so a new instance that gets the name does not send from one.
func (s *XrayService) pruneEgress(egress map[string]string, inbounds []*model.Inbound) {
	names := map[string]bool{}
	for _, in := range inbounds {
		names[instanceName(in)] = true
	}
	changed := false
	for name := range egress {
		if !names[name] {
			delete(egress, name)
			changed = true
		}
	}
	if changed {
		if err := s.settingService.SetInstanceEgress(egress); err != nil {
			logger.Warning("forget the outgoing IPs of removed instances:", err)
		}
	}
}

// XrayInstanceNames returns every instance an inbound names, enabled or not.
func XrayInstanceNames() (map[string]bool, error) {
	var inbounds []*model.Inbound
	if err := database.GetDB().Model(model.Inbound{}).Select("id", "tag", "port", "listen", "enable", "xray_instance", "xray_cores", "sub_inbounds").
		Find(&inbounds).Error; err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, in := range model.ExpandSubInbounds(inbounds) {
		out[instanceName(in)] = true
	}
	return out, nil
}

// SetInstanceEgress gives an instance its own outgoing IP, or with ip ""
// sends it from the host's default address again. Its core restarts to
// take the change, or to catch up with one it missed; the other cores keep
// running.
func (s *XrayService) SetInstanceEgress(name, ip string) error {
	name = strings.TrimSpace(name)
	names, err := XrayInstanceNames()
	if err != nil {
		return err
	}
	if strings.TrimSpace(ip) != "" {
		if !names[name] {
			return fmt.Errorf("no inbound runs in an instance named %q", name)
		}
		if ip, err = CheckEgressIP(ip); err != nil {
			return err
		}
	} else {
		ip = "" // clearing is always safe, for an instance that is gone too
	}
	lock.Lock()
	defer lock.Unlock()
	m, err := s.settingService.GetInstanceEgress()
	if err != nil {
		return err
	}
	if m[name] != ip {
		if ip == "" {
			delete(m, name)
		} else {
			m[name] = ip
		}
		if err := s.settingService.SetInstanceEgress(m); err != nil {
			return err
		}
	}
	if isManuallyStopped.Load() {
		return nil
	}
	return s.applyInstances(false)
}

// HostAddress is an address of the host an instance can send from.
type HostAddress struct {
	IP     string   `json:"ip"`
	Iface  string   `json:"iface"`  // the interface it is on
	UsedBy []string `json:"usedBy"` // instances sending from it
}

// HostAddresses lists the host's IPv4 addresses, with the interface each is
// on and the instances that send from it.
func (s *XrayService) HostAddresses() ([]HostAddress, error) {
	all, err := hostAddressList()
	if err != nil {
		return nil, err
	}
	var list []hostIP
	for _, a := range all {
		if a.IP.To4() != nil && !a.NoCarrier {
			list = append(list, a)
		}
	}
	egress, _ := s.settingService.GetInstanceEgress()
	names, _ := XrayInstanceNames()
	sort.Slice(list, func(i, j int) bool { return bytes.Compare(list[i].IP.To16(), list[j].IP.To16()) < 0 })
	out := make([]HostAddress, 0, len(list))
	for _, a := range list {
		h := HostAddress{IP: a.IP.String(), Iface: a.Iface, UsedBy: []string{}}
		for name, e := range egress {
			if e == h.IP && names[name] {
				h.UsedBy = append(h.UsedBy, name)
			}
		}
		sortNames(h.UsedBy)
		out = append(out, h)
	}
	return out, nil
}

// ------------------------------------------------------------ UDP ports

const udpUseEvery = 10 * time.Second

var (
	udpMu  sync.Mutex
	udpAt  time.Time
	udpUse *sys.UDPPortUse
)

// currentUDPPortUse returns the UDP port use, read at most every
// udpUseEvery, and only while the status is watched; nil when it cannot be
// read.
func currentUDPPortUse() *sys.UDPPortUse {
	udpMu.Lock()
	defer udpMu.Unlock()
	if time.Since(udpAt) < udpUseEvery || (!statusWatched.Load() && !udpAt.IsZero()) {
		return udpUse
	}
	udpAt = time.Now()
	u, err := sys.ReadUDPPortUse(sys.UDPSockets)
	if err != nil {
		logger.Debug("count UDP ports:", err)
		udpUse = nil
		return nil
	}
	udpUse = u
	return u
}
