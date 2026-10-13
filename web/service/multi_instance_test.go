package service

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

func TestSubInboundTrafficCountsOnInbound(t *testing.T) {
	out := mergeTraffic([]*xray.Traffic{
		{IsInbound: true, Tag: "inbound-443", Up: 1, Down: 2},
		{IsInbound: true, Tag: "inbound-443~sub444", Up: 10, Down: 20},
		{IsInbound: true, Tag: "inbound-443~sub445", Up: 100, Down: 200},
		{IsOutbound: true, Tag: "direct", Up: 5, Down: 5},
	})
	if len(out) != 2 || out[0].Tag != "inbound-443" || out[0].Up != 111 || out[0].Down != 222 {
		t.Fatalf("merged: %+v", out[0])
	}
}

// freeRun returns a port p such that p..p+n-1 can all be bound.
func freeRun(t *testing.T, n int) int {
	t.Helper()
	for try := 0; try < 50; try++ {
		base := 20000 + (freeTCPPort(t) % 10000)
		ok := true
		for i := 0; i < n && ok; i++ {
			l, err := net.Listen("tcp", fmt.Sprintf(":%d", base+i))
			if err != nil {
				ok = false
				continue
			}
			l.Close()
		}
		if ok {
			return base
		}
	}
	t.Fatal("no free port run")
	return 0
}

func TestSubInboundsIntegration(t *testing.T) {
	integrationCore(t)
	var xs XrayService
	var is InboundService
	total := len(xray.AvailableCPUs())
	if err := xs.RestartXray(true); err != nil {
		t.Fatal(err)
	}
	base := freeRun(t, 8)
	src := vlessInbound(t, "", 0)
	src.Port, src.Tag = base, fmt.Sprintf("inbound-%d", base)
	src.Settings = `{"clients":[{"id":"6b0e9c1c-2d6f-4c6e-9b8a-000000000001","email":"alice","enable":true,"flow":""}],"decryption":"none","fallbacks":[]}`
	src, _, err := is.AddInbound(src)
	if err != nil {
		t.Fatal(err)
	}
	xs.ApplyInboundChanges()
	pSrc := pidOf(t, src.XrayInstance)

	t.Run("plan", func(t *testing.T) {
		plan, err := is.PlanSubInbounds(src.Id, nil, 0, 1, true)
		if err != nil || plan.Error != "" {
			t.Fatalf("plan: %+v %v", plan, err)
		}
		// The inbound's own instance is auto and keeps a core.
		if plan.Max != total-1 || plan.Count != total-1 || plan.Clients != 1 {
			t.Fatalf("max: %+v", plan)
		}
		if plan.Items[0].Port != base+1 || plan.Items[0].Instance != "xray-2" {
			t.Fatalf("first item: %+v", plan.Items[0])
		}
		// With an unsaved list, new ones go after it.
		plan, _ = is.PlanSubInbounds(src.Id, []model.SubInbound{{Port: base + 3, Instance: "xray-2", Enable: true}}, 2, 0, false)
		if plan.Items[0].Port != base+4 || plan.Items[1].Port != base+5 || plan.Items[0].Instance != "xray-3" {
			t.Fatalf("after current: %+v", plan.Items)
		}
		plan, _ = is.PlanSubInbounds(src.Id, nil, total, 1, false)
		if plan.Error == "" {
			t.Fatal("too many cores accepted")
		}
	})

	subs := []model.SubInbound{
		{Port: base + 1, Cores: 1, Enable: true},
		{Port: base + 2, Cores: 1, Enable: true},
	}
	t.Run("save", func(t *testing.T) {
		got, _, err := is.SaveSubInbounds(src.Id, subs)
		if err != nil {
			t.Fatal(err)
		}
		if err := xs.ApplyInboundChanges(); err != nil {
			t.Fatal(err)
		}
		saved := got.Subs()
		if len(saved) != 2 || saved[0].Instance != "xray-2" || saved[1].Instance != "xray-3" {
			t.Fatalf("saved: %+v", saved)
		}
		subs = saved
		for _, sub := range saved {
			if !listening(sub.Port) {
				t.Fatalf("sub-inbound %d not listening", sub.Port)
			}
			if got := xray.ProcessCPUs(pidOf(t, sub.Instance)); len(got) != 1 {
				t.Fatalf("%s on %v", sub.Instance, got)
			}
		}
		if pidOf(t, src.XrayInstance) != pSrc {
			t.Fatal("the inbound's own core restarted")
		}
		// Still one inbound.
		var n int64
		database.GetDB().Model(model.Inbound{}).Count(&n)
		if n != 1 {
			t.Fatalf("%d inbounds", n)
		}
		// The overview lists them under their instances.
		st, _ := xs.XrayInstancesStatus()
		var seen int
		for _, s := range st {
			for _, ib := range s.Inbounds {
				if ib.Id == src.Id && ib.Sub {
					seen++
				}
			}
		}
		if seen != 2 {
			t.Fatalf("status shows %d sub-inbounds", seen)
		}
	})

	t.Run("clients reach every port", func(t *testing.T) {
		p2, p3 := pidOf(t, "xray-2"), pidOf(t, "xray-3")
		data := &model.Inbound{Id: src.Id, Settings: `{"clients":[{"id":"6b0e9c1c-2d6f-4c6e-9b8a-000000000002","email":"bob","enable":true,"flow":""}]}`}
		needRestart, err := is.AddInboundClient(data)
		if err != nil || needRestart {
			t.Fatalf("add client: restart=%v err=%v", needRestart, err)
		}
		if err := xs.ApplyInboundChanges(); err != nil {
			t.Fatal(err)
		}
		if pidOf(t, "xray-2") != p2 || pidOf(t, "xray-3") != p3 || pidOf(t, src.XrayInstance) != pSrc {
			t.Fatal("a core restarted for a new client")
		}
		// bob is in every core's config now: they are recorded as touched,
		// and a rebuild would give the same inbound.
		instMu.RLock()
		_, t2 := touched["xray-2"][model.SubTag(src.Tag, subs[0].Port)]
		_, t3 := touched["xray-3"][model.SubTag(src.Tag, subs[1].Port)]
		instMu.RUnlock()
		if !t2 && !t3 {
			// ApplyInboundChanges may have adopted the new config already;
			// then the cores' configs carry bob.
			for _, name := range []string{"xray-2", "xray-3"} {
				cfg := procOf(name).GetConfig()
				found := false
				for _, ic := range cfg.InboundConfigs {
					if strings.Contains(string(ic.Settings), "bob") {
						found = true
					}
				}
				if !found {
					t.Fatalf("%s does not carry the new client", name)
				}
			}
		}
		// Removing it goes to every port too.
		if _, err := is.DelInboundClientByEmail(src.Id, "bob"); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("disable one, change cores of another", func(t *testing.T) {
		p3 := pidOf(t, "xray-3")
		edited := []model.SubInbound{
			{Port: subs[0].Port, Instance: subs[0].Instance, Cores: 1, Enable: false},
			{Port: subs[1].Port, Instance: subs[1].Instance, Cores: 2, Enable: true},
		}
		if _, _, err := is.SaveSubInbounds(src.Id, edited); err != nil {
			t.Fatal(err)
		}
		if err := xs.ApplyInboundChanges(); err != nil {
			t.Fatal(err)
		}
		if procOf("xray-2") != nil || listening(subs[0].Port) {
			t.Fatal("disabled sub-inbound still runs")
		}
		if pidOf(t, "xray-3") != p3 || len(xray.ProcessCPUs(p3)) != 2 {
			t.Fatalf("xray-3 should keep running on 2 CPUs: %v", xray.ProcessCPUs(p3))
		}
		subs = edited
	})

	t.Run("checks", func(t *testing.T) {
		other := vlessInbound(t, "", 0)
		other, _, err := is.AddInbound(other)
		if err != nil {
			t.Fatal(err)
		}
		bad := append(append([]model.SubInbound(nil), subs...), model.SubInbound{Port: other.Port, Enable: true})
		if _, _, err := is.SaveSubInbounds(src.Id, bad); err == nil || !strings.Contains(err.Error(), "used by inbound") {
			t.Fatalf("port of another inbound accepted: %v", err)
		}
		bad = append(append([]model.SubInbound(nil), subs...), model.SubInbound{Port: subs[1].Port, Enable: true})
		if _, _, err := is.SaveSubInbounds(src.Id, bad); err == nil || !strings.Contains(err.Error(), "twice") {
			t.Fatalf("duplicate port accepted: %v", err)
		}
		bad = append(append([]model.SubInbound(nil), subs...), model.SubInbound{Port: base + 5, Instance: other.XrayInstance, Enable: true})
		if _, _, err := is.SaveSubInbounds(src.Id, bad); err == nil || !strings.Contains(err.Error(), "another inbound") {
			t.Fatalf("other inbound's instance accepted: %v", err)
		}
		bad = append(append([]model.SubInbound(nil), subs...), model.SubInbound{Port: base + 5, Cores: total, Enable: true})
		if _, _, err := is.SaveSubInbounds(src.Id, bad); err == nil {
			t.Fatal("too many cores accepted")
		}
		// Another inbound cannot take a sub-inbound's port.
		clash := vlessInbound(t, "", 0)
		clash.Port, clash.Tag = subs[1].Port, fmt.Sprintf("inbound-%d", subs[1].Port)
		if _, _, err := is.AddInbound(clash); err == nil || !strings.Contains(err.Error(), "sub-inbound") {
			t.Fatalf("inbound on a sub-inbound's port accepted: %v", err)
		}
		is.DelInbound(other.Id)
		xs.ApplyInboundChanges()
	})

	t.Run("editing the inbound keeps its sub-inbounds", func(t *testing.T) {
		p3 := pidOf(t, "xray-3")
		cur, _ := is.GetInbound(src.Id)
		cur.Remark = "renamed"
		cur.SubInbounds = "" // the form never sends them
		if _, _, err := is.UpdateInbound(cur); err != nil {
			t.Fatal(err)
		}
		if err := xs.ApplyInboundChanges(); err != nil {
			t.Fatal(err)
		}
		got, _ := is.GetInbound(src.Id)
		if len(got.Subs()) != 2 {
			t.Fatalf("sub-inbounds lost: %q", got.SubInbounds)
		}
		if pidOf(t, "xray-3") != p3 || !listening(subs[1].Port) {
			t.Fatal("the sub-inbound's core restarted")
		}
	})

	t.Run("deleting the inbound stops its sub-inbounds", func(t *testing.T) {
		if _, err := is.DelInbound(src.Id); err != nil {
			t.Fatal(err)
		}
		if err := xs.ApplyInboundChanges(); err != nil {
			t.Fatal(err)
		}
		if procOf("xray-3") != nil || listening(subs[1].Port) {
			t.Fatal("sub-inbound outlived its inbound")
		}
	})
}

// The checks on sub-inbounds that need only the database.
func TestSubInboundChecks(t *testing.T) {
	dir := t.TempDir()
	if err := database.InitDB(filepath.Join(dir, "x-ui.db")); err != nil {
		t.Fatal(err)
	}
	defer database.CloseDB()
	// No core runs: changes wait for the next start.
	isManuallyStopped.Store(true)
	defer isManuallyStopped.Store(false)
	var is InboundService
	add := func(in *model.Inbound, port int) *model.Inbound {
		t.Helper()
		in.Port, in.Tag = port, fmt.Sprintf("inbound-%d", port)
		in, _, err := is.AddInbound(in)
		if err != nil {
			t.Fatal(err)
		}
		return in
	}
	base := freeRun(t, 8)
	a := add(vlessInbound(t, "", 0), base)
	add(vlessInbound(t, "", 0), base+1)

	t.Run("taken ports are skipped", func(t *testing.T) {
		// The port right after the inbound's is another inbound's.
		plan, err := is.PlanSubInbounds(a.Id, nil, 2, 0, false)
		if err != nil || plan.Error != "" {
			t.Fatalf("plan: %+v %v", plan, err)
		}
		if len(plan.Items) != 2 || plan.Items[0].Port != base+2 || plan.Items[1].Port != base+3 {
			t.Fatalf("items: %+v", plan.Items)
		}
	})

	t.Run("a re-enabled sub-inbound's port is checked", func(t *testing.T) {
		if _, _, err := is.SaveSubInbounds(a.Id, []model.SubInbound{{Port: base + 2, Enable: false}}); err != nil {
			t.Fatal(err)
		}
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", base+2))
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		a, _ = is.GetInbound(a.Id)
		subs := a.Subs()
		subs[0].Enable = true
		if _, _, err := is.SaveSubInbounds(a.Id, subs); err == nil || !strings.Contains(err.Error(), "another program") {
			t.Fatalf("re-enabled on a busy port: %v", err)
		}
	})

	t.Run("another inbound cannot join a sub-inbound's instance", func(t *testing.T) {
		if _, _, err := is.SaveSubInbounds(a.Id, []model.SubInbound{{Port: base + 3, Instance: "subs", Enable: true}}); err != nil {
			t.Fatal(err)
		}
		in := vlessInbound(t, "subs", 0)
		if _, _, err := is.AddInbound(in); err == nil || !strings.Contains(err.Error(), "sub-inbounds of another inbound") {
			t.Fatalf("inbound added into a sub-inbound's instance: %v", err)
		}
	})

	t.Run("no sub-inbounds on a Unix socket", func(t *testing.T) {
		uds := vlessInbound(t, "", 0)
		uds.Listen = filepath.Join(dir, "in.sock")
		uds = add(uds, base+5)
		if plan, _ := is.PlanSubInbounds(uds.Id, nil, 1, 0, false); plan == nil || !strings.Contains(plan.Error, "Unix socket") || len(plan.Items) != 0 {
			t.Fatalf("plan for a Unix socket: %+v", plan)
		}
		if _, _, err := is.SaveSubInbounds(uds.Id, []model.SubInbound{{Port: base + 6, Enable: true}}); err == nil {
			t.Fatal("sub-inbound saved on a Unix socket inbound")
		}
		// An inbound with sub-inbounds cannot move onto one either.
		a, _ = is.GetInbound(a.Id)
		a.Listen = "@abstract"
		if _, _, err := is.UpdateInbound(a); err == nil || !strings.Contains(err.Error(), "Unix socket") {
			t.Fatalf("inbound with sub-inbounds moved to a Unix socket: %v", err)
		}
	})
}
