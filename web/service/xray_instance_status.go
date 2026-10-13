package service

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/sys"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

// Idle is the state of an instance none of whose inbounds is enabled: it has
// no core running.
const Idle ProcessState = "idle"

// XrayInstanceStatus is one core as the overview shows it.
type XrayInstanceStatus struct {
	Name       string                `json:"name"`
	State      ProcessState          `json:"state"`
	ErrorMsg   string                `json:"errorMsg"`
	Pid        int                   `json:"pid"`
	Cores      int                   `json:"cores"`    // configured; 0 = auto
	Cpus       []int                 `json:"cpus"`     // CPUs it is pinned to
	CpuUsage   float64               `json:"cpuUsage"` // % of its own CPUs
	CpuBusy    float64               `json:"cpuBusy"`  // CPUs' worth of work
	Mem        uint64                `json:"mem"`      // resident bytes
	Threads    int                   `json:"threads"`
	Uptime     uint64                `json:"uptime"`
	TcpCount   int                   `json:"tcpCount"`   // established client connections; -1 = unknown
	Egress     string                `json:"egress"`     // outgoing IP; "" = the host's default
	EgressGone bool                  `json:"egressGone"` // the outgoing IP is not on the host: it sends from the default
	UdpPorts   int                   `json:"udpPorts"`   // local ports held where its UDP sockets get theirs; -1 = unknown
	UdpPool    int                   `json:"udpPool"`    // ports there are to hold
	RetryIn    int                   `json:"retryIn"`    // seconds until a failed core is tried again
	Inbounds   []XrayInstanceInbound `json:"inbounds"`
}

// XrayCpuSummary is how the CPUs are shared out.
type XrayCpuSummary struct {
	Total     int `json:"total"`
	Reserved  int `json:"reserved"`  // by instances with a fixed number of cores
	Available int `json:"available"` // left for the instances on auto
}

const tcpCountEvery = 10 * time.Second

var (
	statMu    sync.Mutex
	lastTicks = map[int]cpuSample{} // by pid
	tcpAt     time.Time
	tcpCounts map[string]int // by instance
	tcpErr    bool
)

type cpuSample struct {
	ticks uint64
	at    time.Time
}

// XrayInstancesStatus reports every instance an inbound names, and every
// core running, in name order.
func (s *XrayService) XrayInstancesStatus() ([]XrayInstanceStatus, XrayCpuSummary) {
	var inbounds []*model.Inbound
	err := database.GetDB().Model(model.Inbound{}).
		Select("id", "remark", "port", "listen", "protocol", "enable", "tag", "xray_instance", "xray_cores", "sub_inbounds").
		Order("id").Find(&inbounds).Error
	if err != nil {
		logger.Warning("read inbounds for the xray instance status:", err)
	}
	inbounds = model.ExpandSubInbounds(inbounds)
	cores := instanceCores(inbounds)
	byName := map[string]*XrayInstanceStatus{}
	var names []string
	add := func(name string) *XrayInstanceStatus {
		if st, ok := byName[name]; ok {
			return st
		}
		st := &XrayInstanceStatus{Name: name, State: Idle, Cores: cores[name], TcpCount: -1, Inbounds: []XrayInstanceInbound{}, Cpus: []int{}}
		byName[name] = st
		names = append(names, name)
		return st
	}
	for _, in := range inbounds {
		st := add(instanceName(in))
		st.Inbounds = append(st.Inbounds, XrayInstanceInbound{Id: in.Id, Remark: in.Remark, Port: in.Port, Protocol: string(in.Protocol), Enable: in.Enable, Sub: in.SubOf != 0})
		if in.Enable && isInstanceStopped(st.Name) {
			st.State = Stop
		}
	}
	running := map[string]*xray.Process{}
	for _, p := range snapshotProcs() {
		st := add(p.Name())
		running[p.Name()] = p
		switch {
		case p.IsRunning():
			st.State = Running
		case p.GetErr() != nil:
			st.State = Error
			st.ErrorMsg = p.GetResult()
			st.RetryIn = int(retryIn(p.Name(), p).Seconds() + 0.5)
		default:
			st.State = Stop
		}
		if p.IsRunning() {
			st.Pid = p.Pid()
			st.Cpus = p.CPUs()
			st.Uptime = p.GetUptime()
		}
	}

	counts := s.instanceTCPCounts(inbounds)
	egress, _ := s.settingService.GetInstanceEgress()
	udp := currentUDPPortUse()
	var hostIPs map[string]bool
	if len(egress) > 0 {
		hostIPs = hostAddressSet()
	}
	for name, st := range byName {
		st.Egress = egress[name]
		if st.Egress != "" && !hostIPs[st.Egress] {
			st.EgressGone = true
		}
		st.UdpPorts = -1
		if udp != nil {
			from := st.Egress
			if st.EgressGone {
				from = ""
			}
			st.UdpPorts = udp.used(from)
			st.UdpPool = udp.pool
		}
	}
	now := time.Now()
	statMu.Lock()
	seen := map[int]bool{}
	for _, st := range byName {
		if st.Pid == 0 {
			continue
		}
		seen[st.Pid] = true
		ticks, threads, ok := readProcStat(st.Pid)
		if ok {
			st.Threads = threads
			if last, had := lastTicks[st.Pid]; had && now.After(last.at) && ticks >= last.ticks {
				busy := float64(ticks-last.ticks) / clockTicks / now.Sub(last.at).Seconds()
				st.CpuBusy = busy
				n := len(st.Cpus)
				if n == 0 {
					n = len(xray.AvailableCPUs())
				}
				st.CpuUsage = 100 * busy / float64(n)
				if st.CpuUsage > 100 {
					st.CpuUsage = 100
				}
			}
			lastTicks[st.Pid] = cpuSample{ticks: ticks, at: now}
		}
		st.Mem = readRSS(st.Pid)
		if counts != nil {
			st.TcpCount = counts[st.Name]
		}
	}
	for pid := range lastTicks {
		if !seen[pid] {
			delete(lastTicks, pid)
		}
	}
	statMu.Unlock()

	sortNames(names)
	out := make([]XrayInstanceStatus, 0, len(names))
	for _, n := range names {
		out = append(out, *byName[n])
	}

	sum := XrayCpuSummary{Total: len(xray.AvailableCPUs())}
	for _, n := range cores {
		if n > 0 {
			sum.Reserved += n
		}
	}
	sum.Available = sum.Total - sum.Reserved
	if sum.Available < 0 {
		sum.Available = 0
	}
	return out, sum
}

func sortNames(names []string) {
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && model.LessInstanceName(names[j], names[j-1]); j-- {
			names[j], names[j-1] = names[j-1], names[j]
		}
	}
}

// instanceTCPCounts returns the established connections on each instance's
// inbound ports, refreshed at most every tcpCountEvery. An inbound listening
// on one address gets the connections to that address; one listening on all
// addresses gets the rest on its port.
func (s *XrayService) instanceTCPCounts(inbounds []*model.Inbound) map[string]int {
	statMu.Lock()
	if time.Since(tcpAt) < tcpCountEvery {
		c, failed := tcpCounts, tcpErr
		statMu.Unlock()
		if failed {
			return nil
		}
		return c
	}
	tcpAt = time.Now()
	statMu.Unlock()

	type owner struct{ instance, ip string }
	byPort := map[int][]owner{}
	var ports []int
	for _, in := range inbounds {
		if !in.Enable || in.Port <= 0 || strings.HasPrefix(in.Listen, "/") || strings.HasPrefix(in.Listen, "@") {
			continue
		}
		ip := in.Listen
		if ip == "0.0.0.0" || ip == "::" || ip == "::0" {
			ip = ""
		}
		if len(byPort[in.Port]) == 0 {
			ports = append(ports, in.Port)
		}
		byPort[in.Port] = append(byPort[in.Port], owner{instanceName(in), ip})
	}
	counts := map[string]int{}
	eps, err := sys.CountEstablishedTCP(ports)
	statMu.Lock()
	defer statMu.Unlock()
	if err != nil {
		logger.Debug("count xray instance connections:", err)
		tcpCounts, tcpErr = nil, true
		return nil
	}
	for ep, n := range eps {
		var wildcard string
		matched := false
		for _, o := range byPort[ep.Port] {
			if o.ip == "" {
				wildcard = o.instance
			} else if o.ip == ep.IP {
				counts[o.instance] += n
				matched = true
				break
			}
		}
		if !matched && wildcard != "" {
			counts[wildcard] += n
		}
	}
	tcpCounts, tcpErr = counts, false
	return counts
}

// clockTicks is USER_HZ, the unit of the times in /proc/<pid>/stat. It is 100
// on every Linux architecture the panel ships for.
const clockTicks = 100.0

// readProcStat returns utime+stime and the thread count of pid.
func readProcStat(pid int) (uint64, int, bool) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, 0, false
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0, 0, false
	}
	f := strings.Fields(s[i+1:])
	// f[0] is field 3 (state); utime and stime are fields 14 and 15,
	// num_threads is field 20.
	if len(f) < 18 {
		return 0, 0, false
	}
	ut, err1 := strconv.ParseUint(f[11], 10, 64)
	st, err2 := strconv.ParseUint(f[12], 10, 64)
	th, err3 := strconv.Atoi(f[17])
	if err1 != nil || err2 != nil || err3 != nil {
		return 0, 0, false
	}
	return ut + st, th, true
}

// readRSS returns the resident memory of pid in bytes.
func readRSS(pid int) uint64 {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/statm")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) < 2 {
		return 0
	}
	pages, err := strconv.ParseUint(f[1], 10, 64)
	if err != nil {
		return 0
	}
	return pages * uint64(os.Getpagesize())
}
