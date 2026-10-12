package service

// Several Xray cores.
//
// One xray process carrying hundreds of thousands of connections saturates
// its Go runtime long before the machine runs out of CPU. So every inbound
// names the core instance it runs in (model.Inbound.XrayInstance) and the
// panel runs one xray process per name. Each process gets the template --
// routing, outbounds, DNS, policy -- plus its own inbounds and its own API
// port, and is pinned to its own share of the CPUs.
//
// Changes still reach the cores without restarting them: inbound and client
// edits go through the API of the core that runs the inbound, an inbound
// moving to a new instance only starts that instance, and a change of cores
// re-pins running processes in place. A core is restarted only when its own
// config changed in a way the API could not apply.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/json_util"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

const defaultAPIPort = 62789

var (
	// instMu guards the maps below. It is held only for short reads and
	// writes, never while a core starts or stops; lock serialises those.
	instMu   sync.RWMutex
	procs    = map[string]*xray.Process{} // running (or crashed) cores by instance
	tagOwner = map[string]string{}        // inbound tag -> instance whose core runs it
	// touched records the inbounds whose live state was changed through a
	// core's API since that core last had its config recorded. Their
	// difference from the recorded config is expected, not a reason to
	// restart. The value is the touch sequence number.
	touched  = map[string]map[string]uint64{}
	touchSeq uint64
	// dirty marks a core whose API change failed: only a restart brings it
	// back in line with the database.
	dirty = map[string]bool{}
	// stoppedInst holds the instances stopped from the overview. They stay
	// stopped through inbound changes and crash checks until started again,
	// a full Xray restart, or a panel restart.
	stoppedInst = map[string]bool{}
	// crashFails counts the quick failures in a row of each instance, for
	// the back-off between its restarts.
	crashFails = map[string]int{}

	onlineMu      sync.RWMutex
	onlineClients []string
)

// ------------------------------------------------------------ API routing

var errInboundNotRunning = errors.New("no running xray core serves this inbound")

// coreAPI sends API calls to the core that runs the inbound concerned. It
// keeps one connection per core for the life of the batch.
type coreAPI struct {
	conns map[string]*xray.XrayAPI
}

func newCoreAPI() *coreAPI { return &coreAPI{conns: map[string]*xray.XrayAPI{}} }

// Close closes every connection the batch opened.
func (c *coreAPI) Close() {
	for _, a := range c.conns {
		a.Close()
	}
	c.conns = map[string]*xray.XrayAPI{}
}

func (c *coreAPI) conn(instance string) (*xray.XrayAPI, error) {
	if a, ok := c.conns[instance]; ok {
		return a, nil
	}
	instMu.RLock()
	p := procs[instance]
	instMu.RUnlock()
	if p == nil || !p.IsRunning() {
		return nil, errInboundNotRunning
	}
	a := &xray.XrayAPI{}
	if err := a.Init(p.GetAPIPort()); err != nil {
		return nil, err
	}
	c.conns[instance] = a
	return a, nil
}

func ownerOf(tag string) string {
	instMu.RLock()
	defer instMu.RUnlock()
	return tagOwner[tag]
}

func markTouched(instance, tag string) {
	if instance == "" {
		return
	}
	instMu.Lock()
	defer instMu.Unlock()
	touchSeq++
	if touched[instance] == nil {
		touched[instance] = map[string]uint64{}
	}
	touched[instance][tag] = touchSeq
}

// markDirtyTag records that the core running tag no longer matches the
// database, so the next apply restarts it.
func markDirtyTag(tag string) {
	instMu.Lock()
	defer instMu.Unlock()
	if owner := tagOwner[tag]; owner != "" {
		dirty[owner] = true
	}
}

// markDirtyInstance records that instance's core no longer matches the
// database, so the next apply restarts it.
func markDirtyInstance(instance string) {
	if instance == "" {
		return
	}
	instMu.Lock()
	dirty[instance] = true
	instMu.Unlock()
}

// corePortUser returns the instance whose core uses port for its API or
// metrics listener, or "".
func corePortUser(port int) string {
	instMu.RLock()
	defer instMu.RUnlock()
	for name, p := range procs {
		if !p.IsRunning() {
			continue
		}
		if p.GetAPIPort() == port {
			return name
		}
		if _, m := metricsListen(p.GetConfig().Metrics); m == port {
			return name
		}
	}
	return ""
}

// AddInbound adds an inbound to the running core of instance.
func (c *coreAPI) AddInbound(instance, tag string, inboundJSON []byte) error {
	a, err := c.conn(instance)
	if err != nil {
		return err
	}
	markTouched(instance, tag)
	if err := a.AddInbound(inboundJSON); err != nil {
		instMu.Lock()
		dirty[instance] = true
		instMu.Unlock()
		return err
	}
	instMu.Lock()
	tagOwner[tag] = instance
	instMu.Unlock()
	return nil
}

// DelInbound removes an inbound from whichever core runs it. An inbound no
// core runs is already gone.
func (c *coreAPI) DelInbound(tag string) error {
	owner := ownerOf(tag)
	if owner == "" {
		return nil
	}
	a, err := c.conn(owner)
	if err != nil {
		return nil
	}
	markTouched(owner, tag)
	if err := a.DelInbound(tag); err != nil {
		return err
	}
	instMu.Lock()
	if tagOwner[tag] == owner {
		delete(tagOwner, tag)
	}
	instMu.Unlock()
	return nil
}

// AddUser adds a client to the core running tag.
func (c *coreAPI) AddUser(protocol, tag string, user map[string]any) error {
	owner := ownerOf(tag)
	if owner == "" {
		return errInboundNotRunning
	}
	a, err := c.conn(owner)
	if err != nil {
		return err
	}
	markTouched(owner, tag)
	if err := a.AddUser(protocol, tag, user); err != nil {
		markDirtyTag(tag)
		return err
	}
	return nil
}

// RemoveUser removes a client from the core running tag. "User not found"
// is left to the caller, which treats it as already done.
func (c *coreAPI) RemoveUser(tag, email string) error {
	owner := ownerOf(tag)
	if owner == "" {
		return errInboundNotRunning
	}
	a, err := c.conn(owner)
	if err != nil {
		return err
	}
	markTouched(owner, tag)
	return a.RemoveUser(tag, email)
}

// XrayAPIPortForTag returns the API port of the core that runs tag, or 0.
func XrayAPIPortForTag(tag string) int {
	instMu.RLock()
	defer instMu.RUnlock()
	if p := procs[tagOwner[tag]]; p != nil && p.IsRunning() {
		return p.GetAPIPort()
	}
	return 0
}

// ------------------------------------------------------------ online clients

func setOnlineClients(c []string) {
	onlineMu.Lock()
	onlineClients = c
	onlineMu.Unlock()
}

func getOnlineClients() []string {
	onlineMu.RLock()
	defer onlineMu.RUnlock()
	return onlineClients
}

// ------------------------------------------------------------ CPU allocation

type coreRequest struct {
	Name  string
	Cores int // 0 = automatic share
}

// allocateCPUs gives every instance its CPUs. Instances with a fixed number
// get that many CPUs of their own, in name order; the instances on auto
// split what is left evenly. When there are more auto instances than CPUs
// left they share them, one CPU each, round-robin.
func allocateCPUs(cpus []int, reqs []coreRequest) map[string][]int {
	out := map[string][]int{}
	if len(cpus) == 0 {
		return out
	}
	sorted := append([]coreRequest(nil), reqs...)
	sort.SliceStable(sorted, func(i, j int) bool { return model.LessInstanceName(sorted[i].Name, sorted[j].Name) })
	next := 0
	var autos []string
	for _, r := range sorted {
		if r.Cores <= 0 {
			autos = append(autos, r.Name)
			continue
		}
		n := r.Cores
		if next+n > len(cpus) {
			n = len(cpus) - next
		}
		if n <= 0 {
			// More cores were promised than this machine has (it lost
			// CPUs since): run unpinned rather than not at all.
			out[r.Name] = append([]int(nil), cpus...)
			continue
		}
		out[r.Name] = append([]int(nil), cpus[next:next+n]...)
		next += n
	}
	rest := cpus[next:]
	if len(autos) == 0 {
		return out
	}
	if len(rest) == 0 {
		rest = cpus
	}
	if len(autos) > len(rest) {
		for i, name := range autos {
			out[name] = []int{rest[i%len(rest)]}
		}
		return out
	}
	base, extra := len(rest)/len(autos), len(rest)%len(autos)
	at := 0
	for i, name := range autos {
		n := base
		if i < extra {
			n++
		}
		out[name] = append([]int(nil), rest[at:at+n]...)
		at += n
	}
	return out
}

// availableCores is how many cores instance could be given, next to the
// others: total minus what fixed instances reserve, keeping one core for the
// auto instances if there are any.
func availableCores(total int, cores map[string]int, instance string) int {
	reserved, autos := 0, 0
	for name, n := range cores {
		if name == instance {
			continue
		}
		if n > 0 {
			reserved += n
		} else {
			autos++
		}
	}
	avail := total - reserved
	if autos > 0 {
		avail--
	}
	return avail
}

// checkCoreRequest validates the cores of instance against the others.
func checkCoreRequest(total int, cores map[string]int, instance string) error {
	n := cores[instance]
	if n < 0 {
		return fmt.Errorf("CPU cores of %s cannot be negative", instance)
	}
	avail := availableCores(total, cores, instance)
	if n > 0 && n > avail {
		if avail < 0 {
			avail = 0
		}
		return fmt.Errorf("%s cannot have %d CPU cores: this server has %d and only %d are available", instance, n, total, avail)
	}
	if n == 0 {
		// Auto instances share what the fixed ones leave; there just has
		// to be something left.
		reserved := 0
		for name, c := range cores {
			if name != instance && c > 0 {
				reserved += c
			}
		}
		if total-reserved < 1 {
			return fmt.Errorf("%s is set to auto, but the other instances reserve all %d CPU cores", instance, total)
		}
	}
	return nil
}

// instanceCores returns every instance named by an inbound with its cores.
// All inbounds of an instance carry the same value; if they ever disagree
// the oldest inbound wins.
func instanceCores(inbounds []*model.Inbound) map[string]int {
	out := map[string]int{}
	for _, in := range inbounds {
		name := instanceName(in)
		if _, ok := out[name]; !ok {
			out[name] = in.XrayCores
		}
	}
	return out
}

func instanceName(in *model.Inbound) string {
	if in.XrayInstance == "" {
		return model.XrayInstancePrefix + "1"
	}
	return in.XrayInstance
}

func sortedNames(m map[string]int) []string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool { return model.LessInstanceName(names[i], names[j]) })
	return names
}

// ------------------------------------------------------------ planning

// instancePlan is the set of cores the database asks for.
type instancePlan struct {
	order   []string // natural name order; the first is the primary
	configs map[string]*xray.Config
	cores   map[string]int // configured cores of every running instance
}

type runningPorts struct{ api, metrics int }

// buildPlan splits the full config (template plus every enabled inbound)
// into one config per instance. ports holds the API and metrics ports of
// cores already running, which they keep; new cores get free ports.
func buildPlan(full *xray.Config, inbounds []*model.Inbound, ports map[string]runningPorts) (*instancePlan, error) {
	allCores := instanceCores(inbounds)

	// Which instance runs each enabled inbound's tag.
	tagInst := map[string]string{}
	usedPorts := map[int]bool{}
	for _, in := range inbounds {
		usedPorts[in.Port] = true
		if in.Enable {
			tagInst[in.Tag] = instanceName(in)
		}
	}

	var apiInbound *xray.InboundConfig
	var templateInbounds []xray.InboundConfig
	groups := map[string][]xray.InboundConfig{}
	for _, ic := range full.InboundConfigs {
		if ic.Tag == "api" {
			c := ic
			apiInbound = &c
			continue
		}
		if name, ok := tagInst[ic.Tag]; ok {
			groups[name] = append(groups[name], ic)
			continue
		}
		templateInbounds = append(templateInbounds, ic)
	}

	if len(groups) == 0 {
		// No enabled inbound: keep one core up, as a single-core panel
		// would, under the first instance name.
		name := model.XrayInstancePrefix + "1"
		if names := sortedNames(allCores); len(names) > 0 {
			name = names[0]
		}
		groups[name] = nil
	}
	plan := &instancePlan{configs: map[string]*xray.Config{}, cores: map[string]int{}}
	for name := range groups {
		plan.order = append(plan.order, name)
		plan.cores[name] = allCores[name]
	}
	sort.Slice(plan.order, func(i, j int) bool { return model.LessInstanceName(plan.order[i], plan.order[j]) })

	apiBase := defaultAPIPort
	if apiInbound != nil && apiInbound.Port > 0 {
		apiBase = apiInbound.Port
	}
	metricsHost, metricsBase := metricsListen(full.Metrics)
	for _, p := range ports {
		usedPorts[p.api] = true
		usedPorts[p.metrics] = true
	}

	for i, name := range plan.order {
		cfg := *full
		p, running := ports[name]
		if !running {
			p.api = pickFreePort(apiBase, usedPorts)
			if metricsBase > 0 {
				p.metrics = pickFreePort(metricsBase, usedPorts)
			}
			if p.api == 0 {
				return nil, fmt.Errorf("no free local port for the API of %s", name)
			}
		}
		var ics []xray.InboundConfig
		if apiInbound != nil {
			api := *apiInbound
			api.Port = p.api
			ics = append(ics, api)
		}
		if i == 0 {
			ics = append(ics, templateInbounds...)
		}
		ics = append(ics, groups[name]...)
		cfg.InboundConfigs = ics
		if metricsBase > 0 && p.metrics > 0 {
			cfg.Metrics = withMetricsListen(full.Metrics, net.JoinHostPort(metricsHost, strconv.Itoa(p.metrics)))
		}
		plan.configs[name] = &cfg
	}
	return plan, nil
}

// metricsListen returns the host and port of the template's metrics
// listener, or port 0 when it has none.
func metricsListen(raw json_util.RawMessage) (string, int) {
	if len(raw) == 0 {
		return "", 0
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return "", 0
	}
	listen, _ := m["listen"].(string)
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", 0
	}
	n, _ := strconv.Atoi(port)
	return host, n
}

func withMetricsListen(raw json_util.RawMessage, listen string) json_util.RawMessage {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return raw
	}
	m["listen"] = listen
	b, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return b
}

// pickFreePort returns the first port from start on that nothing uses and
// that can be bound on loopback, and marks it used.
func pickFreePort(start int, used map[int]bool) int {
	for port := start; port < 65536; port++ {
		if used[port] {
			continue
		}
		l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			continue
		}
		l.Close()
		used[port] = true
		return port
	}
	return 0
}

// sameRunning reports whether a core started with have already runs want,
// apart from the inbounds in skip, whose live state was changed through the
// API.
func sameRunning(have, want *xray.Config, skip map[string]uint64) bool {
	h, w := *have, *want
	h.InboundConfigs, w.InboundConfigs = nil, nil
	if !h.Equals(&w) || string(h.Observatory) != string(w.Observatory) || string(h.BurstObservatory) != string(w.BurstObservatory) {
		return false
	}
	hm := map[string]*xray.InboundConfig{}
	for i := range have.InboundConfigs {
		hm[have.InboundConfigs[i].Tag] = &have.InboundConfigs[i]
	}
	wm := map[string]*xray.InboundConfig{}
	for i := range want.InboundConfigs {
		wm[want.InboundConfigs[i].Tag] = &want.InboundConfigs[i]
	}
	for tag, a := range hm {
		if _, ok := skip[tag]; ok {
			continue
		}
		b, ok := wm[tag]
		if !ok || !a.Equals(b) {
			return false
		}
	}
	for tag := range wm {
		if _, ok := skip[tag]; ok {
			continue
		}
		if _, ok := hm[tag]; !ok {
			return false
		}
	}
	return true
}

var unsafeFileChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// instanceConfigPath is where an instance's config is written: a readable
// form of the name, with a hash when that form is not the name itself.
func instanceConfigPath(name string) string {
	slug := unsafeFileChars.ReplaceAllString(name, "_")
	if len(slug) > 40 {
		slug = slug[:40]
	}
	if slug != name {
		h := uint32(2166136261)
		for i := 0; i < len(name); i++ {
			h = (h ^ uint32(name[i])) * 16777619
		}
		slug = fmt.Sprintf("%s-%08x", slug, h)
	}
	return filepath.Join(config.GetBinFolderPath(), "config-"+slug+".json")
}

// ------------------------------------------------------------ apply

// applyInstances brings the running cores in line with the database. With
// force every core restarts. Otherwise a core restarts only when its config
// changed in a way its API did not apply; cores no longer named by an
// enabled inbound stop, new ones start, and every running core is moved onto
// its current share of the CPUs. The caller holds lock.
func (s *XrayService) applyInstances(force bool) error {
	if force {
		// Stop everything first so the cores come back on the ports they
		// had, rather than on new ones picked while the old still held them.
		if err := stopAllInstances(); err != nil {
			logger.Warning("stop xray cores:", err)
		}
	}
	instMu.RLock()
	ports := map[string]runningPorts{}
	for name, p := range procs {
		if p.IsRunning() && !force {
			_, m := metricsListen(p.GetConfig().Metrics)
			ports[name] = runningPorts{api: p.GetAPIPort(), metrics: m}
		}
	}
	seq := touchSeq
	instMu.RUnlock()

	template, err := s.settingService.GetXrayConfigTemplate()
	if err != nil {
		return err
	}
	full, inbounds, err := s.buildXrayConfigAndInbounds(template)
	if err != nil {
		return err
	}
	plan, err := buildPlan(full, inbounds, ports)
	if err != nil {
		return err
	}
	instMu.Lock()
	for name := range stoppedInst {
		if _, ok := plan.configs[name]; !ok {
			delete(stoppedInst, name) // the instance is gone
		}
	}
	// Stopped instances get no CPUs: the auto ones share theirs.
	var reqs []coreRequest
	for _, name := range plan.order {
		if !stoppedInst[name] {
			reqs = append(reqs, coreRequest{Name: name, Cores: plan.cores[name]})
		}
	}
	instMu.Unlock()
	alloc := allocateCPUs(xray.AvailableCPUs(), reqs)

	// Decide.
	var stop []*xray.Process
	var start []string
	instMu.Lock()
	for name, p := range procs {
		if _, ok := plan.configs[name]; !ok || stoppedInst[name] {
			stop = append(stop, p)
			delete(procs, name)
		}
	}
	for _, name := range plan.order {
		if stoppedInst[name] {
			continue
		}
		p := procs[name]
		switch {
		case p == nil || !p.IsRunning():
			if p != nil && !force && !dirty[name] {
				failedFast := p.Crashed() && p.ExitTime().Sub(p.StartTime()) < crashQuietPeriod
				sameConfig := sameRunning(p.GetConfig(), plan.configs[name], nil)
				if failedFast && sameConfig && !restartDueLocked(name, p) {
					// A core that keeps failing on the same config waits
					// before its next try instead of being rebuilt every
					// two seconds. A changed config is tried at once.
					continue
				}
				if failedFast && sameConfig {
					crashFails[name]++
				} else {
					delete(crashFails, name)
				}
			} else {
				delete(crashFails, name)
			}
			start = append(start, name)
		case force || dirty[name] || !sameRunning(p.GetConfig(), plan.configs[name], touched[name]):
			stop = append(stop, p)
			start = append(start, name)
		default:
			// Already in line: record what it runs now and forget the
			// touches this plan accounts for.
			p.SetConfig(plan.configs[name])
			for tag, n := range touched[name] {
				if n <= seq {
					delete(touched[name], tag)
				}
			}
			s.recordTagsLocked(name, plan.configs[name])
		}
	}
	instMu.Unlock()

	// Stop first, all at once, so ports an inbound is moving with are free
	// before the core it moves to starts.
	var wg sync.WaitGroup
	for _, p := range stop {
		if !p.IsRunning() {
			continue
		}
		wg.Add(1)
		go func(p *xray.Process) {
			defer wg.Done()
			if err := p.Stop(); err != nil {
				logger.Warning("stop xray core", p.Name(), ":", err)
			}
		}(p)
	}
	wg.Wait()
	instMu.Lock()
	for _, p := range stop {
		s.forgetTagsLocked(p.Name(), p)
	}
	instMu.Unlock()

	var errs []string
	parentLimit := goMemLimit()
	// The limit is shared by the cores that run, by their CPUs: a lone
	// core keeps all of it, eight equal ones get an eighth each.
	allocated := 0
	for _, r := range reqs {
		allocated += len(alloc[r.Name])
	}
	for _, name := range start {
		p := xray.NewInstanceProcess(name, plan.configs[name], instanceConfigPath(name), alloc[name])
		if parentLimit > 0 {
			p.SetMemoryLimit(shareMemLimit(parentLimit, len(alloc[name]), allocated))
		}
		err := p.Start()
		instMu.Lock()
		procs[name] = p
		delete(touched, name)
		delete(dirty, name)
		s.recordTagsLocked(name, plan.configs[name])
		instMu.Unlock()
		if err != nil {
			errs = append(errs, name+": "+err.Error())
		}
	}

	// Re-pin the cores that kept running.
	instMu.RLock()
	for name, p := range procs {
		if !p.IsRunning() || sameInts(p.CPUs(), alloc[name]) {
			continue
		}
		if err := p.SetCPUs(alloc[name]); err != nil {
			logger.Warning("move xray core", name, "to its CPUs:", err)
		}
	}
	instMu.RUnlock()

	writeReferenceConfig(full)
	removeStaleInstanceConfigs(plan)
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// Restart back-off for a core that fails soon after starting: 2s, 4s, 8s,
// ... up to a minute. A core that ran crashQuietPeriod is restarted at once.
const (
	crashQuietPeriod = 30 * time.Second
	crashMaxBackoff  = time.Minute
)

func crashBackoff(fails int) time.Duration {
	if fails > 5 {
		return crashMaxBackoff
	}
	d := 2 * time.Second << fails
	if d > crashMaxBackoff {
		d = crashMaxBackoff
	}
	return d
}

// restartDueLocked reports whether the exited core of name may be started
// again now. The caller holds instMu.
func restartDueLocked(name string, p *xray.Process) bool {
	exit := p.ExitTime()
	if !p.Crashed() || exit.IsZero() || exit.Sub(p.StartTime()) >= crashQuietPeriod {
		return true
	}
	return time.Since(exit) >= crashBackoff(crashFails[name])
}

// retryIn returns how long until a failed core is tried again, or 0.
func retryIn(name string, p *xray.Process) time.Duration {
	instMu.RLock()
	defer instMu.RUnlock()
	exit := p.ExitTime()
	if exit.IsZero() || exit.Sub(p.StartTime()) >= crashQuietPeriod {
		return 0
	}
	left := crashBackoff(crashFails[name]) - time.Since(exit)
	if left < 0 {
		return 0
	}
	return left
}

// goMemLimit returns the panel's GOMEMLIMIT in bytes, or 0 when unset.
// The cores inherit the panel's environment, so a limit meant for one core
// would let every core grow to it.
func goMemLimit() int64 {
	return parseGoMemLimit(os.Getenv("GOMEMLIMIT"))
}

// parseGoMemLimit parses GOMEMLIMIT: bytes with an optional B, KiB, MiB,
// GiB or TiB suffix; "off" or anything unparsable is 0.
func parseGoMemLimit(v string) int64 {
	v = strings.TrimSpace(v)
	mult := int64(1)
	for _, u := range []struct {
		suffix string
		mult   int64
	}{{"TiB", 1 << 40}, {"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}, {"B", 1}} {
		if strings.HasSuffix(v, u.suffix) {
			v, mult = strings.TrimSuffix(v, u.suffix), u.mult
			break
		}
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		return 0
	}
	return n * mult
}

// shareMemLimit is a core's part of the panel's memory limit: its CPUs out
// of all the CPUs given to running cores, and never below 256 MiB.
func shareMemLimit(total int64, cpus, allCPUs int) int64 {
	if allCPUs <= 0 || cpus <= 0 {
		return total
	}
	share := total * int64(cpus) / int64(allCPUs)
	if share < 256<<20 {
		share = 256 << 20
	}
	return share
}

// recordTagsLocked notes which core runs each inbound of cfg.
func (s *XrayService) recordTagsLocked(name string, cfg *xray.Config) {
	for tag, owner := range tagOwner {
		if owner == name {
			delete(tagOwner, tag)
		}
	}
	for _, ic := range cfg.InboundConfigs {
		if ic.Tag != "api" {
			tagOwner[ic.Tag] = name
		}
	}
}

func (s *XrayService) forgetTagsLocked(name string, p *xray.Process) {
	if procs[name] != nil && procs[name] != p {
		return // a new core of this name already took over
	}
	for tag, owner := range tagOwner {
		if owner == name {
			delete(tagOwner, tag)
		}
	}
}

func sameInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// writeReferenceConfig keeps bin/config.json as the whole config -- the
// template with every enabled inbound -- for anyone who reads it. The cores
// run their own config-<instance>.json files.
func writeReferenceConfig(full *xray.Config) {
	data, err := json.MarshalIndent(full, "", "  ")
	if err != nil {
		return
	}
	if err := os.WriteFile(xray.GetConfigPath(), data, 0o644); err != nil {
		logger.Warning("write", xray.GetConfigPath(), ":", err)
	}
}

func removeStaleInstanceConfigs(plan *instancePlan) {
	keep := map[string]bool{}
	for _, name := range plan.order {
		keep[instanceConfigPath(name)] = true
	}
	matches, _ := filepath.Glob(filepath.Join(config.GetBinFolderPath(), "config-*.json"))
	for _, m := range matches {
		if !keep[m] {
			os.Remove(m)
		}
	}
}

// stopAllInstances stops every core. The caller holds lock.
func stopAllInstances() error {
	instMu.Lock()
	list := make([]*xray.Process, 0, len(procs))
	for _, p := range procs {
		list = append(list, p)
	}
	instMu.Unlock()
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []string
	for _, p := range list {
		if !p.IsRunning() {
			continue
		}
		wg.Add(1)
		go func(p *xray.Process) {
			defer wg.Done()
			if err := p.Stop(); err != nil {
				mu.Lock()
				errs = append(errs, p.Name()+": "+err.Error())
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()
	instMu.Lock()
	tagOwner = map[string]string{}
	touched = map[string]map[string]uint64{}
	dirty = map[string]bool{}
	instMu.Unlock()
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// StopInstance stops one core; the others keep running and the auto ones
// take over its CPUs. It stays stopped until StartInstance.
func (s *XrayService) StopInstance(name string) error {
	lock.Lock()
	defer lock.Unlock()
	instMu.Lock()
	_, running := procs[name]
	if !running && !stoppedInst[name] {
		instMu.Unlock()
		return fmt.Errorf("no xray core named %s is running", name)
	}
	stoppedInst[name] = true
	instMu.Unlock()
	if isManuallyStopped.Load() {
		return nil // everything is stopped already
	}
	return s.applyInstances(false)
}

// StartInstance starts a core stopped with StopInstance. After a full stop
// it starts this core alone; the others stay stopped.
func (s *XrayService) StartInstance(name string) error {
	lock.Lock()
	defer lock.Unlock()
	names, err := enabledInstanceNames()
	if err != nil {
		return err
	}
	if !names[name] {
		return fmt.Errorf("%s has no enabled inbound to run", name)
	}
	instMu.Lock()
	if isManuallyStopped.Load() {
		for n := range names {
			if n != name {
				stoppedInst[n] = true
			}
		}
	}
	delete(stoppedInst, name)
	dirty[name] = true // start it now, whatever its restart back-off says
	instMu.Unlock()
	isManuallyStopped.Store(false)
	return s.applyInstances(false)
}

// enabledInstanceNames returns the instances that have an enabled inbound.
func enabledInstanceNames() (map[string]bool, error) {
	var inbounds []*model.Inbound
	if err := database.GetDB().Model(model.Inbound{}).Select("id", "xray_instance").
		Where("enable = ?", true).Find(&inbounds).Error; err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, in := range inbounds {
		out[instanceName(in)] = true
	}
	return out, nil
}

// isInstanceStopped reports whether name was stopped from the overview.
func isInstanceStopped(name string) bool {
	instMu.RLock()
	defer instMu.RUnlock()
	return stoppedInst[name]
}

// RestartInstance restarts one core with the current config.
func (s *XrayService) RestartInstance(name string) error {
	lock.Lock()
	defer lock.Unlock()
	instMu.Lock()
	if stoppedInst[name] {
		instMu.Unlock()
		return fmt.Errorf("%s is stopped; start it instead", name)
	}
	if _, ok := procs[name]; !ok {
		instMu.Unlock()
		return fmt.Errorf("no xray core named %s is running", name)
	}
	dirty[name] = true
	instMu.Unlock()
	isManuallyStopped.Store(false)
	return s.applyInstances(false)
}

// ApplyInboundChanges brings the cores in line after inbounds were added,
// edited or deleted: a new instance starts, an emptied one stops, cores are
// re-pinned. Cores whose inbounds were already updated through the API keep
// running.
func (s *XrayService) ApplyInboundChanges() error {
	lock.Lock()
	defer lock.Unlock()
	if isManuallyStopped.Load() {
		return nil
	}
	return s.applyInstances(false)
}

// snapshotProcs returns the cores in name order.
func snapshotProcs() []*xray.Process {
	instMu.RLock()
	list := make([]*xray.Process, 0, len(procs))
	for _, p := range procs {
		list = append(list, p)
	}
	instMu.RUnlock()
	sort.Slice(list, func(i, j int) bool { return model.LessInstanceName(list[i].Name(), list[j].Name()) })
	return list
}

// ------------------------------------------------------------ inbound side

// prepareXrayInstance fills in the instance of an inbound being saved and
// checks its cores against the other instances. An update that names no
// instance keeps the inbound where it is.
func (s *InboundService) prepareXrayInstance(inbound *model.Inbound, old *model.Inbound) error {
	inbound.XrayInstance = strings.TrimSpace(inbound.XrayInstance)
	if inbound.XrayInstance == "" && old != nil {
		inbound.XrayInstance = old.XrayInstance
		inbound.XrayCores = old.XrayCores
	}
	var others []*model.Inbound
	q := database.GetDB().Model(model.Inbound{}).Select("id", "xray_instance", "xray_cores").Order("id")
	if inbound.Id > 0 {
		q = q.Where("id <> ?", inbound.Id)
	}
	if err := q.Find(&others).Error; err != nil {
		return err
	}
	if inbound.XrayInstance == "" {
		used := map[string]bool{}
		for _, o := range others {
			used[o.XrayInstance] = true
		}
		inbound.XrayInstance = model.NextXrayInstanceName(used)
	}
	cores := instanceCores(others)
	cores[inbound.XrayInstance] = inbound.XrayCores
	return checkCoreRequest(len(xray.AvailableCPUs()), cores, inbound.XrayInstance)
}

// XrayInstanceInbound is one inbound as the instance list shows it.
type XrayInstanceInbound struct {
	Id       int    `json:"id"`
	Remark   string `json:"remark"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Enable   bool   `json:"enable"`
}

// XrayInstanceInfo is an instance as the inbound form needs it.
type XrayInstanceInfo struct {
	Name     string                `json:"name"`
	Cores    int                   `json:"cores"`
	Inbounds []XrayInstanceInbound `json:"inbounds"`
}

// XrayInstancesInfo is what the inbound form needs to offer instances and
// cores.
type XrayInstancesInfo struct {
	TotalCores int                `json:"totalCores"`
	NextName   string             `json:"nextName"`
	Instances  []XrayInstanceInfo `json:"instances"`
}

// GetXrayInstancesInfo lists the instances inbounds name, with their cores.
func (s *InboundService) GetXrayInstancesInfo() (*XrayInstancesInfo, error) {
	var inbounds []*model.Inbound
	err := database.GetDB().Model(model.Inbound{}).
		Select("id", "remark", "port", "protocol", "enable", "xray_instance", "xray_cores").
		Order("id").Find(&inbounds).Error
	if err != nil {
		return nil, err
	}
	info := &XrayInstancesInfo{TotalCores: len(xray.AvailableCPUs())}
	cores := instanceCores(inbounds)
	used := map[string]bool{}
	byName := map[string]*XrayInstanceInfo{}
	for _, name := range sortedNames(cores) {
		info.Instances = append(info.Instances, XrayInstanceInfo{Name: name, Cores: cores[name], Inbounds: []XrayInstanceInbound{}})
		used[name] = true
	}
	for i := range info.Instances {
		byName[info.Instances[i].Name] = &info.Instances[i]
	}
	for _, in := range inbounds {
		it := byName[instanceName(in)]
		it.Inbounds = append(it.Inbounds, XrayInstanceInbound{Id: in.Id, Remark: in.Remark, Port: in.Port, Protocol: string(in.Protocol), Enable: in.Enable})
	}
	info.NextName = model.NextXrayInstanceName(used)
	return info, nil
}
