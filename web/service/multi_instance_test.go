package service

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

func TestUniqueEmail(t *testing.T) {
	taken := map[string]bool{"a@x-444": true, "b-445": true}
	if got := uniqueEmail("A@x", 444, taken); got != "A@x-444-2" {
		t.Fatalf("taken without case: %s", got)
	}
	if got := uniqueEmail("c", 444, taken); got != "c-444" || !taken["c-444"] {
		t.Fatalf("plain: %s", got)
	}
}

func TestCloneForPort(t *testing.T) {
	src := &model.Inbound{
		UserId: 1, Remark: "edge", Enable: true, Total: 5, ExpiryTime: 9, TrafficReset: "monthly",
		Listen: "", Port: 443, Protocol: model.VLESS,
		Settings:       `{"clients":[{"id":"u1","email":"a","flow":"xtls-rprx-vision","limitIp":2,"totalGB":7,"subId":"s1","created_at":1},{"id":"u2","email":"b"}],"decryption":"none"}`,
		StreamSettings: `{"network":"tcp","security":"reality","realitySettings":{"privateKey":"k"}}`,
		Sniffing:       `{"enabled":true}`, XrayInstance: "xray-1",
	}
	c, err := cloneForPort(src, MultiInstanceItem{Port: 444, Instance: "xray-7"}, 2, map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if c.Port != 444 || c.Tag != "inbound-444" || c.XrayInstance != "xray-7" || c.XrayCores != 2 || c.Remark != "edge-444" {
		t.Fatalf("clone: %+v", c)
	}
	if c.StreamSettings != src.StreamSettings || c.Sniffing != src.Sniffing || c.Total != 5 || c.ExpiryTime != 9 || c.TrafficReset != "monthly" || !c.Enable {
		t.Fatalf("settings not copied: %+v", c)
	}
	var s struct {
		Clients    []map[string]any `json:"clients"`
		Decryption string           `json:"decryption"`
	}
	json.Unmarshal([]byte(c.Settings), &s)
	if len(s.Clients) != 2 || s.Decryption != "none" {
		t.Fatalf("settings: %s", c.Settings)
	}
	a := s.Clients[0]
	if a["id"] != "u1" || a["email"] != "a-444" || a["flow"] != "xtls-rprx-vision" || a["subId"] != "s1" || a["limitIp"].(float64) != 2 || a["totalGB"].(float64) != 7 {
		t.Fatalf("client: %v", a)
	}
	if _, ok := a["created_at"]; ok {
		t.Fatal("timestamps copied")
	}
	if !strings.Contains(src.Settings, `"email":"a"`) {
		t.Fatal("source changed")
	}
	if c2, _ := cloneForPort(&model.Inbound{Listen: "1.2.3.4", Port: 1, Settings: "{}"}, MultiInstanceItem{Port: 2}, 0, nil); c2.Tag != "inbound-1.2.3.4:2" {
		t.Fatalf("tag with listen: %s", c2.Tag)
	}
}

// freeRun returns a port p such that p..p+n-1 can all be bound.
func freeRun(t *testing.T, n int) int {
	t.Helper()
	for try := 0; try < 50; try++ {
		base := freeTCPPort(t)
		ok := true
		for i := 0; i < n && ok; i++ {
			l, err := net.Listen("tcp", fmt.Sprintf(":%d", base+i))
			if err != nil {
				ok = false
				continue
			}
			l.Close()
		}
		if ok && base+n < 65535 {
			return base
		}
	}
	t.Fatal("no free port run")
	return 0
}

func TestMultiInstanceIntegration(t *testing.T) {
	integrationCore(t)
	var xs XrayService
	var is InboundService
	total := len(xray.AvailableCPUs())
	if err := xs.RestartXray(true); err != nil {
		t.Fatal(err)
	}
	base := freeRun(t, 6)
	src := vlessInbound(t, "", 0)
	src.Port, src.Tag = base, fmt.Sprintf("inbound-%d", base)
	src.Settings = `{"clients":[{"id":"6b0e9c1c-2d6f-4c6e-9b8a-000000000001","email":"alice","enable":true,"flow":"","subId":"sa","totalGB":1073741824},{"id":"6b0e9c1c-2d6f-4c6e-9b8a-000000000002","email":"bob","enable":true,"flow":"","subId":"sb"}],"decryption":"none","fallbacks":[]}`
	src, _, err := is.AddInbound(src)
	if err != nil {
		t.Fatal(err)
	}
	xs.ApplyInboundChanges()

	t.Run("plan and max", func(t *testing.T) {
		// xray-1 (auto) keeps a core: fixed copies of 1 core fit total-1 times.
		plan, _, err := is.PlanMultiInstance(src.Id, 0, 1, true)
		if err != nil || plan.Error != "" {
			t.Fatalf("plan: %+v %v", plan, err)
		}
		if plan.Max != total-1 || plan.Count != total-1 || plan.Available != total-1 || plan.Clients != 2 {
			t.Fatalf("max: %+v", plan)
		}
		if plan.Items[0].Port != base+1 || plan.Items[0].Instance != "xray-2" || plan.Items[1].Instance != "xray-3" {
			t.Fatalf("items: %+v", plan.Items)
		}
		// Auto copies: one per core no instance has yet.
		plan, _, _ = is.PlanMultiInstance(src.Id, 0, 0, true)
		if plan.Max != total-1 {
			t.Fatalf("auto max: %+v", plan)
		}
		plan, _, _ = is.PlanMultiInstance(src.Id, total, 1, false)
		if plan.Error == "" || !strings.Contains(plan.Error, "available") {
			t.Fatalf("too many: %+v", plan)
		}
	})

	t.Run("a taken port is reported", func(t *testing.T) {
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", base+2))
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		plan, _, _ := is.PlanMultiInstance(src.Id, 3, 0, false)
		if plan.Items[1].Conflict == "" || plan.Items[0].Conflict != "" || plan.Error == "" {
			t.Fatalf("conflict: %+v", plan)
		}
		_, created, err := is.MultiInstance(src.Id, 3, 0, false)
		for _, c := range created {
			is.DelInbound(c.Id)
		}
		if err == nil || len(created) != 0 {
			t.Fatal("made copies onto a taken port")
		}
		var n int64
		database.GetDB().Model(model.Inbound{}).Count(&n)
		if n != 1 {
			t.Fatalf("inbounds after the refusal: %d", n)
		}
	})

	t.Run("a copy failing removes the ones made", func(t *testing.T) {
		// A row that takes the second copy's tag but not its port: the plan
		// passes, the second insert fails.
		blocker := &model.Inbound{UserId: 1, Port: base + 100, Tag: fmt.Sprintf("inbound-%d", base+2), Protocol: model.VLESS, Settings: `{"clients":[]}`, XrayInstance: "blocker"}
		if err := database.GetDB().Create(blocker).Error; err != nil {
			t.Fatal(err)
		}
		defer database.GetDB().Delete(&model.Inbound{}, blocker.Id)
		_, created, err := is.MultiInstance(src.Id, 2, 0, false)
		if err == nil || len(created) != 0 {
			t.Fatalf("expected a failure: %v %d", err, len(created))
		}
		var n int64
		database.GetDB().Model(model.Inbound{}).Where("port = ?", base+1).Count(&n)
		var stats int64
		database.GetDB().Model(xray.ClientTraffic{}).Where("email LIKE ?", fmt.Sprintf("%%-%d", base+1)).Count(&stats)
		if n != 0 || stats != 0 {
			t.Fatalf("first copy left behind: %d inbounds, %d client stats", n, stats)
		}
	})

	t.Run("generate", func(t *testing.T) {
		_, created, err := is.MultiInstance(src.Id, 2, 1, false)
		if err != nil {
			t.Fatal(err)
		}
		if err := xs.ApplyInboundChanges(); err != nil {
			t.Fatal(err)
		}
		if len(created) != 2 {
			t.Fatalf("created %d", len(created))
		}
		for i, c := range created {
			port := base + 1 + i
			if c.Port != port || c.XrayCores != 1 || c.Protocol != src.Protocol || c.StreamSettings != src.StreamSettings {
				t.Fatalf("copy %d: %+v", i, c)
			}
			if !listening(port) {
				t.Fatalf("port %d not listening", port)
			}
			p := procOf(c.XrayInstance)
			if p == nil || len(xray.ProcessCPUs(p.Pid())) != 1 {
				t.Fatalf("%s not on one CPU", c.XrayInstance)
			}
			clients, _ := is.GetClients(c)
			if len(clients) != 2 || clients[0].ID != "6b0e9c1c-2d6f-4c6e-9b8a-000000000001" || clients[0].Email != fmt.Sprintf("alice-%d", port) || clients[0].SubID != "sa" || clients[0].TotalGB != 1073741824 {
				t.Fatalf("copy clients: %+v", clients)
			}
			var stats int64
			database.GetDB().Model(xray.ClientTraffic{}).Where("inbound_id = ?", c.Id).Count(&stats)
			if stats != 2 {
				t.Fatalf("client stats of the copy: %d", stats)
			}
		}
		if created[0].XrayInstance == created[1].XrayInstance || created[0].XrayInstance == src.XrayInstance {
			t.Fatal("copies share an instance")
		}
		// The source keeps its own core.
		if got, _ := is.GetInbound(src.Id); got.XrayInstance != src.XrayInstance || !listening(src.Port) {
			t.Fatal("source changed")
		}
		for _, c := range created {
			is.DelInbound(c.Id)
		}
		xs.ApplyInboundChanges()
	})
}
