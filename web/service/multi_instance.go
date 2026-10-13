package service

// Multi Instance: sub-inbounds.
//
// An inbound can have sub-inbounds: the same inbound -- protocol, settings,
// clients, transport, sniffing -- on other ports, each in an xray instance of
// its own. A sub-inbound has four settings of its own and nothing else: its
// port, its instance, that instance's cores and whether it is enabled. Its
// clients are the inbound's clients (one traffic account each across every
// port), and its traffic counts on the inbound.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/common"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

// SubPlanItem is one sub-inbound to be added.
type SubPlanItem struct {
	Port     int    `json:"port"`
	Instance string `json:"instance"`
	Conflict string `json:"conflict"` // why this port cannot be used; "" if it can
}

// SubPlan is what adding sub-inbounds would do.
type SubPlan struct {
	SourcePort int           `json:"sourcePort"`
	TotalCores int           `json:"totalCores"`
	Available  int           `json:"available"` // cores new fixed instances can have between them
	Max        int           `json:"max"`       // sub-inbounds that fit with these cores
	Count      int           `json:"count"`
	Cores      int           `json:"cores"` // per sub-inbound; 0 = auto
	Clients    int           `json:"clients"`
	Items      []SubPlanItem `json:"items"`
	Error      string        `json:"error"` // why they cannot be added; "" if they can
}

// subPlanMax caps one request.
const subPlanMax = 1024

// othersExpanded returns every inbound but id, with their sub-inbounds.
func othersExpanded(id int) ([]*model.Inbound, error) {
	var all []*model.Inbound
	err := database.GetDB().Model(model.Inbound{}).
		Select("id", "remark", "port", "listen", "protocol", "enable", "tag", "xray_instance", "xray_cores", "sub_inbounds").
		Where("id <> ?", id).Order("id").Find(&all).Error
	if err != nil {
		return nil, err
	}
	return model.ExpandSubInbounds(all), nil
}

// familyCores returns the cores of every instance named by the other
// inbounds, by the inbound itself and by subs.
func familyCores(others []*model.Inbound, src *model.Inbound, subs []model.SubInbound) map[string]int {
	cores := instanceCores(others)
	if _, ok := cores[instanceName(src)]; !ok {
		cores[instanceName(src)] = src.XrayCores
	}
	for _, sub := range subs {
		if _, ok := cores[sub.Instance]; !ok {
			cores[sub.Instance] = sub.Cores
		}
	}
	return cores
}

// PlanSubInbounds proposes count new sub-inbounds for inbound id, on the
// ports after the highest one the inbound and current already use, each in
// a new instance with cores CPU cores (0 = auto). current is the list being
// edited, which may not be saved yet. With useMax, as many as the free CPU
// cores allow: fixed ones take every free core between them, auto ones add
// one instance per core no instance has yet.
func (s *InboundService) PlanSubInbounds(id int, current []model.SubInbound, count, cores int, useMax bool) (*SubPlan, error) {
	src, err := s.GetInbound(id)
	if err != nil {
		return nil, err
	}
	others, err := othersExpanded(id)
	if err != nil {
		return nil, err
	}
	if cores < 0 {
		cores = 0
	}
	all := familyCores(others, src, current)
	total := len(xray.AvailableCPUs())
	reserved, autos := 0, 0
	for _, n := range all {
		if n > 0 {
			reserved += n
		} else {
			autos++
		}
	}
	plan := &SubPlan{SourcePort: src.Port, TotalCores: total, Cores: cores}
	plan.Available = total - reserved
	if autos > 0 {
		plan.Available-- // the auto instances keep at least one core
	}
	if plan.Available < 0 {
		plan.Available = 0
	}
	if cores > 0 {
		plan.Max = plan.Available / cores
	} else if plan.Max = total - reserved - autos; plan.Max < 0 {
		plan.Max = 0
	}
	if clients, err := s.GetClients(src); err == nil {
		plan.Clients = len(clients)
	}
	if useMax {
		count = plan.Max
	}
	if count > subPlanMax {
		count = subPlanMax
	}
	plan.Count = count
	switch {
	case count < 1 && useMax:
		plan.Error = fmt.Sprintf("no CPU cores are left for new instances (%d in total, %d reserved)", total, reserved)
	case count < 1:
		plan.Error = "choose at least one instance"
	case cores > 0 && count*cores > plan.Available:
		plan.Error = fmt.Sprintf("%d instances × %d cores need %d CPU cores, but only %d are available", count, cores, count*cores, plan.Available)
	case cores == 0 && total-reserved < 1:
		plan.Error = fmt.Sprintf("auto instances need a free CPU core, but all %d are reserved", total)
	}

	if unixSocketListen(src.Listen) {
		plan.Error = errSubOnUnixSocket.Error()
		return plan, nil
	}

	used := map[string]bool{}
	for name := range all {
		used[name] = true
	}
	start := src.Port
	taken := map[int]bool{src.Port: true}
	for _, sub := range current {
		taken[sub.Port] = true
		if sub.Port > start {
			start = sub.Port
		}
	}
	// The ports after the highest one in use, skipping the ones that are
	// taken.
	running := ownPorts(src)
	for port := start + 1; len(plan.Items) < count && port <= 65535; port++ {
		if taken[port] || portConflict(src, port, others, running) != "" {
			continue
		}
		item := SubPlanItem{Port: port, Instance: model.NextXrayInstanceName(used)}
		used[item.Instance] = true
		plan.Items = append(plan.Items, item)
	}
	if len(plan.Items) < count && plan.Error == "" {
		plan.Error = fmt.Sprintf("only %d free ports are left after %d", len(plan.Items), start)
	}
	return plan, nil
}

var errSubOnUnixSocket = errors.New("an inbound that listens on a Unix socket cannot have sub-inbounds")

// unixSocketListen reports whether listen is a Unix socket: a path, or an
// abstract name.
func unixSocketListen(listen string) bool {
	return strings.HasPrefix(listen, "/") || strings.HasPrefix(listen, "@")
}

// ownPorts returns the ports the inbound's cores hold now: its own and its
// enabled sub-inbounds', while it is enabled. They are no conflict; any
// other port, a disabled sub-inbound's included, must be free.
func ownPorts(src *model.Inbound) map[int]bool {
	out := map[int]bool{}
	if !src.Enable {
		return out
	}
	out[src.Port] = true
	for _, sub := range src.Subs() {
		if sub.Enable {
			out[sub.Port] = true
		}
	}
	return out
}

func wildcardListen(l string) bool { return l == "" || l == "0.0.0.0" || l == "::" || l == "::0" }

// portConflict says why src cannot also listen on port, or "". others are
// the other inbounds with their sub-inbounds; ports in own are the
// inbound's own and are not tried.
func portConflict(src *model.Inbound, port int, others []*model.Inbound, own map[int]bool) string {
	if port < 1 || port > 65535 {
		return "not a port number"
	}
	for _, in := range others {
		if in.Port == port && (wildcardListen(src.Listen) || wildcardListen(in.Listen) || in.Listen == src.Listen) {
			name := in.Remark
			if name == "" {
				name = "#" + strconv.Itoa(in.Id)
			}
			if in.SubOf != 0 {
				return "used by a sub-inbound of " + name
			}
			return "used by inbound " + name
		}
	}
	if name := corePortUser(port); name != "" {
		return "used by the API of " + name
	}
	if own[port] {
		return ""
	}
	host := src.Listen
	if wildcardListen(host) || strings.HasPrefix(host, "/") || strings.HasPrefix(host, "@") {
		host = ""
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	if usesUDP(src) {
		c, err := net.ListenPacket("udp", addr)
		if err != nil {
			return "in use by another program"
		}
		c.Close()
		return ""
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return "in use by another program"
	}
	l.Close()
	return ""
}

// usesUDP reports whether an inbound listens on UDP rather than TCP.
func usesUDP(in *model.Inbound) bool {
	switch in.Protocol {
	case model.Hysteria, model.WireGuard:
		return true
	}
	var stream struct {
		Network string `json:"network"`
	}
	_ = json.Unmarshal([]byte(in.StreamSettings), &stream)
	return stream.Network == "kcp"
}

// SaveSubInbounds makes subs the sub-inbounds of inbound id. Ports must be
// free and distinct; an empty instance name gets the next default one; an
// instance may be shared by the inbound's own sub-inbounds (and the inbound
// itself), never with other inbounds, and its cores must fit next to every
// other instance. Changes go to the running cores through their API: the
// cores of other sub-inbounds keep running.
func (s *InboundService) SaveSubInbounds(id int, subs []model.SubInbound) (*model.Inbound, bool, error) {
	editMu.RLock()
	defer editMu.RUnlock()
	src, err := s.GetInbound(id)
	if err != nil {
		return nil, false, err
	}
	if len(subs) > 0 && unixSocketListen(src.Listen) {
		return nil, false, errSubOnUnixSocket
	}
	others, err := othersExpanded(id)
	if err != nil {
		return nil, false, err
	}
	otherNames := instanceCores(others)
	used := map[string]bool{instanceName(src): true}
	for n := range otherNames {
		used[n] = true
	}
	for _, sub := range subs {
		if n := strings.TrimSpace(sub.Instance); n != "" {
			used[n] = true
		}
	}
	own := ownPorts(src)
	seen := map[int]bool{src.Port: true}
	family := map[string]int{instanceName(src): src.XrayCores}
	for i := range subs {
		sub := &subs[i]
		if sub.Port < 1 || sub.Port > 65535 {
			return nil, false, common.NewErrorf("%d is not a port number", sub.Port)
		}
		if seen[sub.Port] {
			return nil, false, common.NewErrorf("port %d is used twice by this inbound", sub.Port)
		}
		seen[sub.Port] = true
		if c := portConflict(src, sub.Port, others, own); c != "" {
			return nil, false, common.NewErrorf("port %d is %s", sub.Port, c)
		}
		sub.Instance = strings.TrimSpace(sub.Instance)
		if sub.Instance == "" {
			sub.Instance = model.NextXrayInstanceName(used)
			used[sub.Instance] = true
		}
		if _, other := otherNames[sub.Instance]; other {
			return nil, false, common.NewErrorf("instance %s belongs to another inbound", sub.Instance)
		}
		if sub.Instance == instanceName(src) {
			sub.Cores = src.XrayCores // it shares the inbound's own core
		}
		if sub.Cores < 0 {
			return nil, false, common.NewErrorf("CPU cores of %s cannot be negative", sub.Instance)
		}
		if prev, ok := family[sub.Instance]; ok && prev != sub.Cores {
			return nil, false, common.NewErrorf("instance %s is given %d CPU cores in one sub-inbound and %d in another", sub.Instance, prev, sub.Cores)
		}
		family[sub.Instance] = sub.Cores
	}
	all := instanceCores(others)
	for name, n := range family {
		all[name] = n
	}
	total := len(xray.AvailableCPUs())
	for name := range family {
		if err := checkCoreRequest(total, all, name); err != nil {
			return nil, false, err
		}
	}

	sort.SliceStable(subs, func(i, j int) bool { return subs[i].Port < subs[j].Port })
	old := src.Subs()
	src.SetSubs(subs)
	if err := database.GetDB().Model(model.Inbound{}).Where("id = ?", id).Update("sub_inbounds", src.SubInbounds).Error; err != nil {
		return nil, false, err
	}
	return src, s.applySubChanges(src, old, subs), nil
}

// applySubChanges updates the running cores for a changed sub-inbound list:
// sub-inbounds removed, moved to another instance or disabled leave their
// core; new or re-enabled ones are added to theirs. It reports whether any
// change has to wait for a restart.
func (s *InboundService) applySubChanges(src *model.Inbound, old, subs []model.SubInbound) bool {
	oldBy := map[int]model.SubInbound{}
	for _, o := range old {
		oldBy[o.Port] = o
	}
	newBy := map[int]model.SubInbound{}
	for _, n := range subs {
		newBy[n.Port] = n
	}
	api := newCoreAPI()
	defer api.Close()
	needRestart := false
	for port, o := range oldBy {
		n, kept := newBy[port]
		if o.Enable && (!kept || !n.Enable || n.Instance != o.Instance) {
			if err := api.DelInbound(model.SubTag(src.Tag, port)); err != nil {
				logger.Debug("Unable to remove sub-inbound by api:", err)
				needRestart = true
			}
		}
	}
	if !src.Enable {
		return needRestart
	}
	var base *xray.InboundConfig
	for port, n := range newBy {
		o, had := oldBy[port]
		if !n.Enable || (had && o.Enable && o.Instance == n.Instance) {
			continue
		}
		if base == nil {
			rt, err := s.buildRuntimeInboundForAPI(database.GetDB(), src)
			if err != nil {
				return true
			}
			base = rt.GenXrayInboundConfig()
		}
		c := *base
		c.Port = port
		c.Tag = model.SubTag(src.Tag, port)
		b, err := json.Marshal(c)
		if err == nil {
			err = api.AddInbound(n.Instance, c.Tag, b)
		}
		if err != nil {
			// A new instance has no core yet: applying starts it.
			logger.Debug("Unable to add sub-inbound by api:", err)
			needRestart = true
		}
	}
	return needRestart
}

// addSubInboundsByAPI adds the enabled sub-inbounds of in to their cores,
// after the inbound itself was (re)added. It reports whether any has to
// wait for a restart.
func addSubInboundsByAPI(api *coreAPI, in *model.Inbound, base *xray.InboundConfig) bool {
	needRestart := false
	for _, sub := range in.Subs() {
		if !sub.Enable {
			continue
		}
		c := *base
		c.Port = sub.Port
		c.Tag = model.SubTag(in.Tag, sub.Port)
		b, err := json.Marshal(c)
		if err == nil {
			err = api.AddInbound(sub.Instance, c.Tag, b)
		}
		if err != nil {
			needRestart = true
		}
	}
	return needRestart
}

// subPortUser returns a description of the inbound or sub-inbound other than
// ignoreId that uses port on an address overlapping listen, or "".
func subPortUser(listen string, port int, ignoreId int) (string, error) {
	others, err := othersExpanded(ignoreId)
	if err != nil {
		return "", err
	}
	src := &model.Inbound{Listen: listen}
	for _, in := range others {
		if in.SubOf != 0 && in.Port == port && (wildcardListen(listen) || wildcardListen(in.Listen) || in.Listen == src.Listen) {
			name := in.Remark
			if name == "" {
				name = "#" + strconv.Itoa(in.SubOf)
			}
			return name, nil
		}
	}
	return "", nil
}
