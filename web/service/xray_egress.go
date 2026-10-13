package service

// Outgoing IPs.
//
// Freedom gives every UDP flow a socket of its own on a free local port. When
// every core sends from the host's default address they all draw on that
// address's ~64k ports, and close to full each new socket's search for a port
// spins in the kernel: the CPU goes to 100% and traffic collapses, however
// big the server. An instance with an outgoing IP of its own binds its
// sockets there, so it has the whole port range to itself, as a separate
// server with its own IP would. Its TCP connections leave from that IP too.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
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

// hostAddressList returns the addresses on the host's interfaces that
// traffic can leave from: no loopback, link-local or multicast ones.
var hostAddressList = func() ([]net.IP, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []net.IP
	for _, a := range addrs {
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
		out = append(out, ip)
	}
	return out, nil
}

// hostAddressSet returns the host's addresses in their usual form.
func hostAddressSet() map[string]bool {
	list, _ := hostAddressList()
	out := make(map[string]bool, len(list))
	for _, ip := range list {
		out[ip.String()] = true
	}
	return out
}

func isHostAddress(ip net.IP) bool {
	list, err := hostAddressList()
	if err != nil {
		return false
	}
	for _, a := range list {
		if a.Equal(ip) {
			return true
		}
	}
	return false
}

// egressProbe checks that something on the internet answers a connection
// from ip: one of a few public resolvers on port 443.
var egressProbe = func(ip net.IP) error {
	targets := []string{"1.1.1.1:443", "8.8.8.8:443", "9.9.9.9:443"}
	if ip.To4() == nil {
		targets = []string{"[2606:4700:4700::1111]:443", "[2001:4860:4860::8888]:443", "[2620:fe::fe]:443"}
	}
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
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if !isHostAddress(ip) {
		return "", fmt.Errorf("%s is not an address of this server", ip)
	}
	if err := egressProbe(ip); err != nil {
		return "", fmt.Errorf("nothing on the internet answers from %s: %v", ip, err)
	}
	return ip.String(), nil
}

// withEgress makes the freedom outbounds of an instance's config send from
// ip. Outbounds that choose their own source, or leave through another
// outbound, are left as they are.
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
		if p, _ := ob["protocol"].(string); p != "freedom" {
			continue
		}
		if v, _ := ob["sendThrough"].(string); v != "" {
			continue
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
				if dp != "" || iface != "" {
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

// applyEgress gives each planned core its outgoing IP. An IP no longer on
// the host is skipped -- the core sends from the default address -- rather
// than leaving the core unable to connect anywhere.
func applyEgress(plan *instancePlan, egress map[string]string) {
	for name, cfg := range plan.configs {
		ip := egress[name]
		if ip == "" {
			continue
		}
		parsed := net.ParseIP(ip)
		if parsed == nil || !isHostAddress(parsed) {
			logger.Warning("xray instance", name, "has outgoing IP", ip, "which is not on this server; it sends from the default address")
			continue
		}
		cfg.OutboundConfigs = withEgress(cfg.OutboundConfigs, ip)
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
// take the change; the other cores keep running.
func (s *XrayService) SetInstanceEgress(name, ip string) error {
	name = strings.TrimSpace(name)
	names, err := XrayInstanceNames()
	if err != nil {
		return err
	}
	if !names[name] {
		return fmt.Errorf("no inbound runs in an instance named %q", name)
	}
	if strings.TrimSpace(ip) != "" {
		if ip, err = CheckEgressIP(ip); err != nil {
			return err
		}
	} else {
		ip = ""
	}
	lock.Lock()
	defer lock.Unlock()
	m, err := s.settingService.GetInstanceEgress()
	if err != nil {
		return err
	}
	if m[name] == ip {
		return nil
	}
	if ip == "" {
		delete(m, name)
	} else {
		m[name] = ip
	}
	if err := s.settingService.SetInstanceEgress(m); err != nil {
		return err
	}
	if isManuallyStopped.Load() {
		return nil
	}
	return s.applyInstances(false)
}

// HostAddress is an address of the host an instance can send from.
type HostAddress struct {
	IP     string   `json:"ip"`
	UsedBy []string `json:"usedBy"` // instances sending from it
}

// HostAddresses lists the host's addresses, IPv4 first, with the instances
// that send from each.
func (s *XrayService) HostAddresses() ([]HostAddress, error) {
	list, err := hostAddressList()
	if err != nil {
		return nil, err
	}
	egress, _ := s.settingService.GetInstanceEgress()
	sort.Slice(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if (a.To4() == nil) != (b.To4() == nil) {
			return a.To4() != nil
		}
		return bytes.Compare(a.To16(), b.To16()) < 0
	})
	out := make([]HostAddress, 0, len(list))
	for _, ip := range list {
		h := HostAddress{IP: ip.String(), UsedBy: []string{}}
		for name, e := range egress {
			if e == h.IP {
				h.UsedBy = append(h.UsedBy, name)
			}
		}
		sortNames(h.UsedBy)
		out = append(out, h)
	}
	return out, nil
}

// ------------------------------------------------------------ UDP ports

// udpPortUse is how much of the local port range UDP sockets hold.
type udpPortUse struct {
	pool   int            // ports a socket can be given
	wild   int            // held by sockets on all addresses
	byIP   map[string]int // held in each address's share: its own sockets plus the wildcard ones
	shared int            // held in the default address's share: by any socket
}

// used returns the ports held in the share an instance sending from egress
// draws on.
func (u *udpPortUse) used(egress string) int {
	if egress == "" {
		return u.shared
	}
	if n, ok := u.byIP[egress]; ok {
		return n
	}
	return u.wild
}

const udpUseEvery = 10 * time.Second

var (
	udpMu  sync.Mutex
	udpAt  time.Time
	udpUse *udpPortUse
)

var localPortRangePath = "/proc/sys/net/ipv4/ip_local_port_range"

func localPortRange() (int, int, error) {
	b, err := os.ReadFile(localPortRangePath)
	if err != nil {
		return 0, 0, err
	}
	f := strings.Fields(string(b))
	if len(f) != 2 {
		return 0, 0, errors.New("unexpected ip_local_port_range")
	}
	lo, err1 := strconv.Atoi(f[0])
	hi, err2 := strconv.Atoi(f[1])
	if err1 != nil || err2 != nil || lo < 1 || hi < lo {
		return 0, 0, errors.New("unexpected ip_local_port_range")
	}
	return lo, hi, nil
}

// currentUDPPortUse returns the UDP port use, read at most every
// udpUseEvery; nil when it cannot be read.
func currentUDPPortUse() *udpPortUse {
	udpMu.Lock()
	defer udpMu.Unlock()
	if time.Since(udpAt) < udpUseEvery {
		return udpUse
	}
	udpAt = time.Now()
	u, err := readUDPPortUse(sys.UDPSockets)
	if err != nil {
		logger.Debug("count UDP ports:", err)
		udpUse = nil
		return nil
	}
	udpUse = u
	return u
}

func readUDPPortUse(list func(func(sys.LocalEndpoint)) error) (*udpPortUse, error) {
	lo, hi, err := localPortRange()
	if err != nil {
		return nil, err
	}
	var reserved map[int]bool
	if b, err := os.ReadFile(reservedPortsPath); err == nil {
		reserved = parsePortList(string(b))
	}
	pool := 0
	for p := lo; p <= hi; p++ {
		if !reserved[p] {
			pool++
		}
	}
	wild := map[int]bool{}
	all := map[int]bool{}
	byIP := map[string]map[int]bool{}
	err = list(func(ep sys.LocalEndpoint) {
		if ep.Port < lo || ep.Port > hi || reserved[ep.Port] {
			return // not taken from the range
		}
		all[ep.Port] = true
		if ep.IP == "" {
			wild[ep.Port] = true
			return
		}
		m := byIP[ep.IP]
		if m == nil {
			m = map[int]bool{}
			byIP[ep.IP] = m
		}
		m[ep.Port] = true
	})
	if err != nil {
		return nil, err
	}
	u := &udpPortUse{pool: pool, wild: len(wild), shared: len(all), byIP: map[string]int{}}
	for ip, ports := range byIP {
		n := len(wild)
		for p := range ports {
			if !wild[p] {
				n++
			}
		}
		u.byIP[ip] = n
	}
	return u, nil
}
