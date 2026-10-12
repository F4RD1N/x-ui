package service

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/common"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

// Multi Instance: copies of one inbound, with all its clients, each in a new
// xray instance of its own, on the ports right after the inbound's.

// MultiInstanceItem is one copy to be made.
type MultiInstanceItem struct {
	Port     int    `json:"port"`
	Instance string `json:"instance"`
	Conflict string `json:"conflict"` // why this port cannot be used; "" if it can
}

// MultiInstancePlan is what a Multi Instance request would do.
type MultiInstancePlan struct {
	SourcePort int                 `json:"sourcePort"`
	TotalCores int                 `json:"totalCores"`
	Available  int                 `json:"available"` // cores new fixed instances can have between them
	Max        int                 `json:"max"`       // copies that fit with these cores
	Count      int                 `json:"count"`
	Cores      int                 `json:"cores"` // per copy; 0 = auto
	Clients    int                 `json:"clients"`
	Items      []MultiInstanceItem `json:"items"`
	Error      string              `json:"error"` // why it cannot be made; "" if it can
}

// multiInstanceMaxCopies caps one request; a port range this long is far
// beyond any CPU count anyway.
const multiInstanceMaxCopies = 1024

// PlanMultiInstance works out the copies of inbound id: count copies (or as
// many as the CPUs allow when useMax), each with cores CPU cores (0 = auto).
// With max, fixed copies take every free core between them and auto copies
// add one instance per core that no instance has yet.
func (s *InboundService) PlanMultiInstance(id, count, cores int, useMax bool) (*MultiInstancePlan, *model.Inbound, error) {
	src, err := s.GetInbound(id)
	if err != nil {
		return nil, nil, err
	}
	if cores < 0 {
		cores = 0
	}
	var all []*model.Inbound
	if err := database.GetDB().Model(model.Inbound{}).
		Select("id", "remark", "port", "listen", "xray_instance", "xray_cores").
		Order("id").Find(&all).Error; err != nil {
		return nil, nil, err
	}
	instCores := instanceCores(all)
	total := len(xray.AvailableCPUs())
	reserved, autos := 0, 0
	for _, n := range instCores {
		if n > 0 {
			reserved += n
		} else {
			autos++
		}
	}
	plan := &MultiInstancePlan{SourcePort: src.Port, TotalCores: total, Cores: cores}
	plan.Available = total - reserved
	if autos > 0 {
		plan.Available-- // the auto instances keep at least one core
	}
	if plan.Available < 0 {
		plan.Available = 0
	}
	if cores > 0 {
		plan.Max = plan.Available / cores
	} else {
		plan.Max = total - reserved - autos
		if plan.Max < 0 {
			plan.Max = 0
		}
	}
	if clients, err := s.GetClients(src); err == nil {
		plan.Clients = len(clients)
	}

	if useMax {
		count = plan.Max
	}
	if count > multiInstanceMaxCopies {
		count = multiInstanceMaxCopies
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

	used := map[string]bool{}
	for _, in := range all {
		used[instanceName(in)] = true
	}
	conflicts := 0
	for i := 1; i <= count; i++ {
		item := MultiInstanceItem{Port: src.Port + i, Instance: model.NextXrayInstanceName(used)}
		used[item.Instance] = true
		item.Conflict = s.portConflict(src, item.Port, all)
		if item.Conflict != "" {
			conflicts++
		}
		plan.Items = append(plan.Items, item)
	}
	if conflicts > 0 && plan.Error == "" {
		plan.Error = fmt.Sprintf("%d of the ports are taken", conflicts)
	}
	return plan, src, nil
}

// portConflict says why a copy of src cannot listen on port, or "".
func (s *InboundService) portConflict(src *model.Inbound, port int, all []*model.Inbound) string {
	if port > 65535 {
		return "beyond port 65535"
	}
	wildcard := func(l string) bool { return l == "" || l == "0.0.0.0" || l == "::" || l == "::0" }
	for _, in := range all {
		if in.Port == port && (wildcard(src.Listen) || wildcard(in.Listen) || in.Listen == src.Listen) {
			name := in.Remark
			if name == "" {
				name = "#" + strconv.Itoa(in.Id)
			}
			return "used by inbound " + name
		}
	}
	if name := corePortUser(port); name != "" {
		return "used by the API of " + name
	}
	host := src.Listen
	if wildcard(host) || strings.HasPrefix(host, "/") || strings.HasPrefix(host, "@") {
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

// MultiInstance makes the copies PlanMultiInstance describes: every setting
// of the inbound and every client is copied, each copy goes on the next
// port in a new instance. Client emails, which the panel needs unique, get
// the copy's port appended; ids, passwords, flows, limits, expiry and
// subscription ids stay the same, so a client's config works on every copy
// by changing the port. If any copy fails, the ones made are removed.
func (s *InboundService) MultiInstance(id, count, cores int, useMax bool) (*MultiInstancePlan, []*model.Inbound, error) {
	plan, src, err := s.PlanMultiInstance(id, count, cores, useMax)
	if err != nil {
		return nil, nil, err
	}
	if plan.Error != "" {
		return plan, nil, common.NewError(plan.Error)
	}
	taken := map[string]bool{}
	if emails, err := s.getAllEmails(); err == nil {
		for _, e := range emails {
			taken[strings.ToLower(e)] = true
		}
	}
	var created []*model.Inbound
	for _, item := range plan.Items {
		clone, err := cloneForPort(src, item, plan.Cores, taken)
		if err == nil {
			clone, _, err = s.AddInbound(clone)
		}
		if err != nil {
			for _, c := range created {
				if _, derr := s.DelInbound(c.Id); derr != nil {
					logger.Warning("multi instance: remove copy", c.Id, ":", derr)
				}
			}
			return plan, nil, fmt.Errorf("copy on port %d: %w", item.Port, err)
		}
		created = append(created, clone)
	}
	return plan, created, nil
}

// cloneForPort copies src for one Multi Instance item.
func cloneForPort(src *model.Inbound, item MultiInstanceItem, cores int, taken map[string]bool) (*model.Inbound, error) {
	settings := map[string]any{}
	if err := json.Unmarshal([]byte(src.Settings), &settings); err != nil {
		return nil, err
	}
	if clients, ok := settings["clients"].([]any); ok {
		for _, c := range clients {
			cm, ok := c.(map[string]any)
			if !ok {
				continue
			}
			email, _ := cm["email"].(string)
			if email == "" {
				continue
			}
			cm["email"] = uniqueEmail(email, item.Port, taken)
			delete(cm, "created_at")
			delete(cm, "updated_at")
		}
	}
	b, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return nil, err
	}
	remark := src.Remark
	if remark == "" {
		remark = "inbound"
	}
	clone := &model.Inbound{
		UserId:       src.UserId,
		Remark:       fmt.Sprintf("%s-%d", remark, item.Port),
		Enable:       src.Enable,
		Total:        src.Total,
		ExpiryTime:   src.ExpiryTime,
		TrafficReset: src.TrafficReset,
		Listen:       src.Listen,
		Port:         item.Port,
		Protocol:     src.Protocol,
		Settings:     string(b),
		// tlsSettings/realitySettings, transports and sniffing are kept as
		// they are: the copy answers exactly like the original.
		StreamSettings: src.StreamSettings,
		Sniffing:       src.Sniffing,
		XrayInstance:   item.Instance,
		XrayCores:      cores,
	}
	if clone.Listen == "" || clone.Listen == "0.0.0.0" || clone.Listen == "::" || clone.Listen == "::0" {
		clone.Tag = fmt.Sprintf("inbound-%v", clone.Port)
	} else {
		clone.Tag = fmt.Sprintf("inbound-%v:%v", clone.Listen, clone.Port)
	}
	return clone, nil
}

// uniqueEmail is email with the port appended, made unique among taken
// (compared without case), which it is added to.
func uniqueEmail(email string, port int, taken map[string]bool) string {
	cand := fmt.Sprintf("%s-%d", email, port)
	for n := 2; taken[strings.ToLower(cand)]; n++ {
		cand = fmt.Sprintf("%s-%d-%d", email, port, n)
	}
	taken[strings.ToLower(cand)] = true
	return cand
}
