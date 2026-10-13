package service

import (
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/util/json_util"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

func seq(from, n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = from + i
	}
	return out
}

func TestAllocateCPUsExamples(t *testing.T) {
	cpus := seq(0, 28)
	// Two auto instances on 28 cores: 14 each.
	a := allocateCPUs(cpus, []coreRequest{{"xray-1", 0}, {"xray-2", 0}})
	if !reflect.DeepEqual(a["xray-1"], seq(0, 14)) || !reflect.DeepEqual(a["xray-2"], seq(14, 14)) {
		t.Fatalf("2 auto: %v", a)
	}
	// One with 10, one auto: 10 and 18.
	a = allocateCPUs(cpus, []coreRequest{{"xray-1", 10}, {"xray-2", 0}})
	if len(a["xray-1"]) != 10 || len(a["xray-2"]) != 18 || a["xray-2"][0] != 10 {
		t.Fatalf("10 + auto: %v", a)
	}
	// The fixed one is placed first whatever its name.
	a = allocateCPUs(cpus, []coreRequest{{"xray-1", 0}, {"xray-2", 10}})
	if !reflect.DeepEqual(a["xray-2"], seq(0, 10)) || !reflect.DeepEqual(a["xray-1"], seq(10, 18)) {
		t.Fatalf("auto + 10: %v", a)
	}
	// Uneven split: 28 over 3 autos is 10, 9, 9, in name order.
	a = allocateCPUs(cpus, []coreRequest{{"xray-10", 0}, {"xray-2", 0}, {"xray-1", 0}})
	if len(a["xray-1"]) != 10 || len(a["xray-2"]) != 9 || len(a["xray-10"]) != 9 {
		t.Fatalf("3 autos: %v", a)
	}
	// Every CPU is used exactly once.
	seen := map[int]int{}
	for _, c := range a {
		for _, x := range c {
			seen[x]++
		}
	}
	if len(seen) != 28 {
		t.Fatalf("coverage: %v", seen)
	}
	for x, n := range seen {
		if n != 1 {
			t.Fatalf("cpu %d given %d times", x, n)
		}
	}
	// Only fixed instances: the rest of the CPUs stay free.
	a = allocateCPUs(cpus, []coreRequest{{"xray-1", 4}})
	if len(a) != 1 || len(a["xray-1"]) != 4 {
		t.Fatalf("fixed only: %v", a)
	}
}

func TestAllocateCPUsMoreInstancesThanCPUs(t *testing.T) {
	a := allocateCPUs(seq(0, 4), []coreRequest{{"xray-1", 2}, {"xray-2", 0}, {"xray-3", 0}, {"xray-4", 0}})
	if !reflect.DeepEqual(a["xray-1"], []int{0, 1}) {
		t.Fatalf("fixed: %v", a)
	}
	// Three autos share the two CPUs left, one each, round-robin.
	if !reflect.DeepEqual(a["xray-2"], []int{2}) || !reflect.DeepEqual(a["xray-3"], []int{3}) || !reflect.DeepEqual(a["xray-4"], []int{2}) {
		t.Fatalf("shared: %v", a)
	}
	// A machine that lost CPUs: the instance that no longer fits runs
	// unpinned, and the autos share everything.
	a = allocateCPUs(seq(0, 4), []coreRequest{{"xray-1", 4}, {"xray-2", 2}, {"xray-3", 0}})
	if len(a["xray-1"]) != 4 || len(a["xray-2"]) != 4 || len(a["xray-3"]) != 4 {
		t.Fatalf("over-committed: %v", a)
	}
	if len(allocateCPUs(nil, []coreRequest{{"xray-1", 0}})) != 0 {
		t.Fatal("no cpus")
	}
}

func TestAvailableCoresAndCheck(t *testing.T) {
	cores := map[string]int{"xray-1": 10, "xray-2": 0, "xray-3": 0}
	// For xray-3: 28 - 10 fixed - 1 kept for xray-2 (auto).
	if n := availableCores(28, cores, "xray-3"); n != 17 {
		t.Fatalf("available for xray-3: %d", n)
	}
	// For xray-1: 28 - 1 kept for the autos.
	if n := availableCores(28, cores, "xray-1"); n != 27 {
		t.Fatalf("available for xray-1: %d", n)
	}
	if err := checkCoreRequest(28, map[string]int{"xray-1": 27, "xray-2": 0}, "xray-1"); err != nil {
		t.Fatalf("27 + auto: %v", err)
	}
	if err := checkCoreRequest(28, map[string]int{"xray-1": 28, "xray-2": 0}, "xray-1"); err == nil || !strings.Contains(err.Error(), "only 27") {
		t.Fatalf("28 + auto must fail: %v", err)
	}
	if err := checkCoreRequest(28, map[string]int{"xray-1": 28}, "xray-1"); err != nil {
		t.Fatalf("all cores to the only instance: %v", err)
	}
	if err := checkCoreRequest(28, map[string]int{"xray-1": 29}, "xray-1"); err == nil {
		t.Fatal("more than the machine has must fail")
	}
	if err := checkCoreRequest(28, map[string]int{"xray-1": 28, "xray-2": 0}, "xray-2"); err == nil || !strings.Contains(err.Error(), "auto") {
		t.Fatalf("auto with nothing left must fail: %v", err)
	}
	if err := checkCoreRequest(28, map[string]int{"xray-1": -1}, "xray-1"); err == nil {
		t.Fatal("negative must fail")
	}
	// Two auto instances on one core share it.
	if err := checkCoreRequest(1, map[string]int{"xray-1": 0, "xray-2": 0}, "xray-2"); err != nil {
		t.Fatalf("2 autos on 1 core: %v", err)
	}
	// Many auto instances on few cores are fine: they share.
	many := map[string]int{}
	for i := 1; i <= 40; i++ {
		many[fmt.Sprintf("xray-%d", i)] = 0
	}
	if err := checkCoreRequest(8, many, "xray-40"); err != nil {
		t.Fatalf("40 autos on 8 cores: %v", err)
	}
}

const testTemplate = `{
  "log": {"access": "none", "loglevel": "warning"},
  "api": {"tag": "api", "services": ["HandlerService", "StatsService"]},
  "inbounds": [
    {"listen": "127.0.0.1", "port": 62789, "protocol": "tunnel", "settings": {"address": "127.0.0.1"}, "tag": "api"},
    {"listen": "127.0.0.1", "port": 1080, "protocol": "socks", "settings": {}, "tag": "template-socks"}
  ],
  "outbounds": [{"protocol": "freedom", "tag": "direct"}],
  "routing": {"rules": [{"inboundTag": ["api"], "outboundTag": "api"}]},
  "metrics": {"tag": "metrics_out", "listen": "127.0.0.1:11111"}
}`

func testInbound(id int, instance string, cores int, port int, enable bool) *model.Inbound {
	return &model.Inbound{
		Id: id, Port: port, Protocol: model.VLESS, Enable: enable,
		Tag: "inbound-" + strconv.Itoa(port), XrayInstance: instance, XrayCores: cores,
		Settings: `{"clients":[]}`, StreamSettings: `{"network":"tcp"}`, Sniffing: `{}`,
	}
}

// fullConfig builds what buildXrayConfig would: the template plus every
// enabled inbound.
func fullConfig(t *testing.T, inbounds []*model.Inbound) *xray.Config {
	t.Helper()
	c := &xray.Config{}
	if err := json.Unmarshal([]byte(testTemplate), c); err != nil {
		t.Fatal(err)
	}
	for _, in := range inbounds {
		if in.Enable {
			c.InboundConfigs = append(c.InboundConfigs, *in.GenXrayInboundConfig())
		}
	}
	return c
}

func tags(c *xray.Config) []string {
	var out []string
	for _, ic := range c.InboundConfigs {
		out = append(out, ic.Tag)
	}
	return out
}

func TestBuildPlanSplitsInbounds(t *testing.T) {
	inbounds := []*model.Inbound{
		testInbound(1, "xray-1", 0, 41001, true),
		testInbound(2, "xray-2", 6, 41002, true),
		testInbound(3, "xray-2", 6, 41003, true),
		testInbound(4, "xray-3", 0, 41004, false), // disabled: no core
	}
	plan, err := buildPlan(fullConfig(t, inbounds), inbounds, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plan.order, []string{"xray-1", "xray-2"}) {
		t.Fatalf("order: %v", plan.order)
	}
	if plan.cores["xray-2"] != 6 || plan.cores["xray-1"] != 0 {
		t.Fatalf("cores: %v", plan.cores)
	}
	// The primary carries the template's own inbounds; every core has the
	// API inbound.
	if got := tags(plan.configs["xray-1"]); !reflect.DeepEqual(got, []string{"api", "template-socks", "inbound-41001"}) {
		t.Fatalf("xray-1 inbounds: %v", got)
	}
	if got := tags(plan.configs["xray-2"]); !reflect.DeepEqual(got, []string{"api", "inbound-41002", "inbound-41003"}) {
		t.Fatalf("xray-2 inbounds: %v", got)
	}
	// Each core has its own API and metrics port.
	api1, api2 := plan.configs["xray-1"].InboundConfigs[0].Port, plan.configs["xray-2"].InboundConfigs[0].Port
	if api1 == api2 || api1 == 0 || api2 == 0 {
		t.Fatalf("api ports: %d %d", api1, api2)
	}
	_, m1 := metricsListen(plan.configs["xray-1"].Metrics)
	_, m2 := metricsListen(plan.configs["xray-2"].Metrics)
	if m1 == m2 || m1 == 0 || m1 == api1 || m1 == api2 {
		t.Fatalf("metrics ports: %d %d (api %d %d)", m1, m2, api1, api2)
	}
	// Outbounds and routing are the template's, in every core.
	for _, name := range plan.order {
		c := plan.configs[name]
		if string(c.OutboundConfigs) != string(plan.configs["xray-1"].OutboundConfigs) || len(c.RouterConfig) == 0 {
			t.Fatalf("%s lost the template", name)
		}
	}
}

func TestBuildPlanKeepsRunningPorts(t *testing.T) {
	inbounds := []*model.Inbound{testInbound(1, "xray-1", 0, 41001, true), testInbound(2, "xray-2", 0, 41002, true)}
	ports := map[string]runningPorts{"xray-2": {api: 50123, metrics: 50124}}
	plan, err := buildPlan(fullConfig(t, inbounds), inbounds, ports, "")
	if err != nil {
		t.Fatal(err)
	}
	if p := plan.configs["xray-2"].InboundConfigs[0].Port; p != 50123 {
		t.Fatalf("running core lost its API port: %d", p)
	}
	if _, m := metricsListen(plan.configs["xray-2"].Metrics); m != 50124 {
		t.Fatalf("running core lost its metrics port: %d", m)
	}
	if p := plan.configs["xray-1"].InboundConfigs[0].Port; p == 50123 || p == 50124 {
		t.Fatalf("new core took a running core's port: %d", p)
	}
}

func TestBuildPlanAvoidsBusyAndInboundPorts(t *testing.T) {
	// Hold the template's API port, and give an inbound the next one.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	busy := l.Addr().(*net.TCPAddr).Port
	tpl := strings.Replace(testTemplate, "62789", strconv.Itoa(busy), 1)
	c := &xray.Config{}
	json.Unmarshal([]byte(tpl), c)
	in := testInbound(1, "xray-1", 0, busy+1, true)
	c.InboundConfigs = append(c.InboundConfigs, *in.GenXrayInboundConfig())
	plan, err := buildPlan(c, []*model.Inbound{in}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if p := plan.configs["xray-1"].InboundConfigs[0].Port; p == busy || p == busy+1 {
		t.Fatalf("api port %d is taken", p)
	}
}

func TestBuildPlanWithoutEnabledInbounds(t *testing.T) {
	inbounds := []*model.Inbound{testInbound(1, "edge-b", 0, 41001, false), testInbound(2, "edge-a", 0, 41002, false)}
	plan, err := buildPlan(fullConfig(t, inbounds), inbounds, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	// One core keeps running, as with a single core, under the first name.
	if !reflect.DeepEqual(plan.order, []string{"edge-a"}) {
		t.Fatalf("order: %v", plan.order)
	}
	plan, _ = buildPlan(fullConfig(t, nil), nil, nil, "")
	if !reflect.DeepEqual(plan.order, []string{"xray-1"}) {
		t.Fatalf("no inbounds: %v", plan.order)
	}
}

func TestSameRunning(t *testing.T) {
	inbounds := []*model.Inbound{testInbound(1, "xray-1", 0, 41001, true), testInbound(2, "xray-1", 0, 41002, true)}
	have, _ := buildPlan(fullConfig(t, inbounds), inbounds, map[string]runningPorts{"xray-1": {api: 50001, metrics: 50002}}, "")
	cfg := have.configs["xray-1"]
	if !sameRunning(cfg, cfg, nil) {
		t.Fatal("identical configs differ")
	}

	// An inbound edited in the database...
	edited := []*model.Inbound{testInbound(1, "xray-1", 0, 41001, true), testInbound(2, "xray-1", 0, 41002, true)}
	edited[1].Settings = `{"clients":[{"id":"x","email":"a"}]}`
	want, _ := buildPlan(fullConfig(t, edited), edited, map[string]runningPorts{"xray-1": {api: 50001, metrics: 50002}}, "")
	if sameRunning(cfg, want.configs["xray-1"], nil) {
		t.Fatal("changed inbound not noticed")
	}
	// ...that was already applied through the API is not a reason to restart.
	if !sameRunning(cfg, want.configs["xray-1"], map[string]uint64{"inbound-41002": 1}) {
		t.Fatal("API-applied change treated as a difference")
	}
	// An inbound added or removed through the API, likewise.
	added := append(inbounds, testInbound(3, "xray-1", 0, 41003, true))
	want, _ = buildPlan(fullConfig(t, added), added, map[string]runningPorts{"xray-1": {api: 50001, metrics: 50002}}, "")
	if sameRunning(cfg, want.configs["xray-1"], nil) {
		t.Fatal("added inbound not noticed")
	}
	if !sameRunning(cfg, want.configs["xray-1"], map[string]uint64{"inbound-41003": 1}) {
		t.Fatal("API-added inbound treated as a difference")
	}
	// A template change always restarts, touched or not.
	other := *cfg
	other.RouterConfig = json_util.RawMessage(`{"rules":[]}`)
	if sameRunning(cfg, &other, map[string]uint64{"inbound-41001": 1, "inbound-41002": 1}) {
		t.Fatal("template change not noticed")
	}
	obs := *cfg
	obs.Observatory = json_util.RawMessage(`{"subjectSelector":["x"]}`)
	if sameRunning(cfg, &obs, nil) {
		t.Fatal("observatory change not noticed")
	}
}

func TestMergeTraffic(t *testing.T) {
	in := []*xray.Traffic{
		{IsOutbound: true, Tag: "direct", Up: 1, Down: 2},
		{IsInbound: true, Tag: "inbound-1", Up: 5, Down: 6},
		{IsOutbound: true, Tag: "direct", Up: 10, Down: 20},
		{IsInbound: true, Tag: "direct", Up: 100, Down: 100}, // an inbound tag that matches an outbound's
	}
	out := mergeTraffic(in)
	if len(out) != 3 || out[0].Up != 11 || out[0].Down != 22 || out[2].Up != 100 {
		t.Fatalf("merged: %+v %+v %+v", out[0], out[1], out[2])
	}
	if in[0].Up != 1 {
		t.Fatal("input modified")
	}
	cl := mergeClientTraffic([]*xray.ClientTraffic{{Email: "a", Up: 1}, {Email: "b", Up: 2}, {Email: "a", Down: 3}})
	if len(cl) != 2 || cl[0].Up != 1 || cl[0].Down != 3 || cl[1].Up != 2 {
		t.Fatalf("clients: %+v", cl)
	}
}

func TestInstanceConfigPath(t *testing.T) {
	if got := filepath.Base(instanceConfigPath("xray-2")); got != "config-xray-2.json" {
		t.Fatalf("plain name: %s", got)
	}
	a := filepath.Base(instanceConfigPath("edge 1"))
	b := filepath.Base(instanceConfigPath("edge_1"))
	if a == b || !strings.HasPrefix(a, "config-edge_1-") || strings.ContainsAny(a, " /") {
		t.Fatalf("unsafe names: %s %s", a, b)
	}
	if got := filepath.Base(instanceConfigPath("../../etc/passwd")); strings.Contains(got, "/") || strings.HasPrefix(got, "config-..") && strings.Contains(got, "..json") {
		t.Fatalf("path name: %s", got)
	}
}

func TestInstanceCores(t *testing.T) {
	got := instanceCores([]*model.Inbound{
		{Id: 1, XrayInstance: "xray-1", XrayCores: 4},
		{Id: 2, XrayInstance: "xray-1", XrayCores: 9}, // disagrees: the oldest wins
		{Id: 3, XrayInstance: "", XrayCores: 0},       // unnamed counts as xray-1
		{Id: 4, XrayInstance: "big", XrayCores: 0},
	})
	if !reflect.DeepEqual(got, map[string]int{"xray-1": 4, "big": 0}) {
		t.Fatalf("cores: %v", got)
	}
}

func TestParseGoMemLimit(t *testing.T) {
	for in, want := range map[string]int64{
		"72GiB": 72 << 30, "512MiB": 512 << 20, "1024": 1024, "2048B": 2048, "1TiB": 1 << 40,
		"": 0, "off": 0, "-5": 0, "12XB": 0,
	} {
		if got := parseGoMemLimit(in); got != want {
			t.Errorf("%q: %d, want %d", in, got, want)
		}
	}
	// 72 GiB over 56 CPUs: a 2-CPU core gets 2/56 of it.
	if got := shareMemLimit(72<<30, 2, 56); got != (72<<30)*2/56 {
		t.Fatalf("share: %d", got)
	}
	if got := shareMemLimit(1<<30, 1, 56); got != 256<<20 {
		t.Fatalf("floor: %d", got)
	}
	if got := shareMemLimit(1<<30, 56, 56); got != 1<<30 {
		t.Fatalf("all CPUs: %d", got)
	}
}

func TestCrashBackoff(t *testing.T) {
	want := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second, time.Minute, time.Minute, time.Minute}
	for i, w := range want {
		if got := crashBackoff(i); got != w {
			t.Fatalf("fails %d: %v", i, got)
		}
	}
	if crashBackoff(1000) != time.Minute {
		t.Fatal("cap")
	}
}

func TestFillShadowsocksClientMethod(t *testing.T) {
	settings := map[string]any{"method": "chacha20-ietf-poly1305"}
	c := map[string]any{"password": "x", "method": ""}
	fillShadowsocksClientMethod(model.Shadowsocks, settings, c)
	if c["method"] != "chacha20-ietf-poly1305" {
		t.Fatalf("empty method not filled: %v", c)
	}
	c = map[string]any{"password": "x", "method": "aes-128-gcm"}
	fillShadowsocksClientMethod(model.Shadowsocks, settings, c)
	if c["method"] != "aes-128-gcm" {
		t.Fatal("a client's own method was replaced")
	}
	c = map[string]any{"password": "x"}
	fillShadowsocksClientMethod(model.Shadowsocks, map[string]any{"method": "2022-blake3-aes-128-gcm"}, c)
	if _, ok := c["method"]; ok {
		t.Fatal("2022 clients take no method")
	}
	c = map[string]any{"id": "x"}
	fillShadowsocksClientMethod(model.VLESS, settings, c)
	if _, ok := c["method"]; ok {
		t.Fatal("vless client touched")
	}
}

func TestBuildPlanTemplateInboundsStay(t *testing.T) {
	inbounds := []*model.Inbound{testInbound(1, "xray-1", 0, 41001, true), testInbound(2, "xray-2", 0, 41002, true)}
	has := func(plan *instancePlan, name string) bool {
		for _, tag := range tags(plan.configs[name]) {
			if tag == "template-socks" {
				return true
			}
		}
		return false
	}
	plan, _ := buildPlan(fullConfig(t, inbounds), inbounds, nil, "")
	if plan.templateHost != "xray-1" || !has(plan, "xray-1") || has(plan, "xray-2") {
		t.Fatalf("first plan: host %q", plan.templateHost)
	}
	// A new instance that sorts first does not take them over.
	added := append(inbounds, testInbound(3, "edge", 0, 41003, true))
	plan, _ = buildPlan(fullConfig(t, added), added, nil, "xray-1")
	if plan.templateHost != "xray-1" || !has(plan, "xray-1") || has(plan, "edge") {
		t.Fatalf("after adding edge: host %q", plan.templateHost)
	}
	// Disabling the host's only inbound keeps them, and its core, where
	// they are; the other cores' configs do not change.
	inbounds[0].Enable = false
	plan, _ = buildPlan(fullConfig(t, inbounds), inbounds, nil, "xray-1")
	if got := tags(plan.configs["xray-1"]); !reflect.DeepEqual(got, []string{"api", "template-socks"}) {
		t.Fatalf("disabled host runs %v", got)
	}
	if has(plan, "xray-2") {
		t.Fatal("the template's inbounds moved into xray-2")
	}
	// Once no inbound names the host, the first instance takes them.
	plan, _ = buildPlan(fullConfig(t, added[1:]), added[1:], nil, "xray-1")
	if plan.templateHost != "edge" || !has(plan, "edge") || plan.configs["xray-1"] != nil {
		t.Fatalf("host gone: host %q, order %v", plan.templateHost, plan.order)
	}
	// Without inbounds of its own the template has no host.
	c := fullConfig(t, inbounds)
	c.InboundConfigs = c.InboundConfigs[:1]
	inbounds[0].Enable = true
	c.InboundConfigs = append(c.InboundConfigs, *inbounds[0].GenXrayInboundConfig(), *inbounds[1].GenXrayInboundConfig())
	if plan, _ = buildPlan(c, inbounds, nil, "xray-1"); plan.templateHost != "" {
		t.Fatalf("host without template inbounds: %q", plan.templateHost)
	}
}

func TestBuildPlanGivesRunningCoresMetricsPorts(t *testing.T) {
	// Two cores started from a template without metrics; the template now
	// has them.
	inbounds := []*model.Inbound{testInbound(1, "xray-1", 0, 41001, true), testInbound(2, "xray-2", 0, 41002, true)}
	ports := map[string]runningPorts{"xray-1": {api: 50001}, "xray-2": {api: 50002}}
	plan, err := buildPlan(fullConfig(t, inbounds), inbounds, ports, "")
	if err != nil {
		t.Fatal(err)
	}
	_, m1 := metricsListen(plan.configs["xray-1"].Metrics)
	_, m2 := metricsListen(plan.configs["xray-2"].Metrics)
	if m1 == 0 || m2 == 0 || m1 == m2 {
		t.Fatalf("metrics ports %d and %d", m1, m2)
	}
}

func TestBuildPlanExitedCoreKeepsItsPorts(t *testing.T) {
	inbounds := []*model.Inbound{testInbound(1, "xray-1", 0, 41001, true)}
	api, metrics := freeTCPPort(t), freeTCPPort(t)
	ports := map[string]runningPorts{"xray-1": {api: api, metrics: metrics, exited: true}}
	plan, err := buildPlan(fullConfig(t, inbounds), inbounds, ports, "")
	if err != nil {
		t.Fatal(err)
	}
	if p := plan.configs["xray-1"].InboundConfigs[0].Port; p != api {
		t.Fatalf("exited core's API moved from %d to %d", api, p)
	}
	if _, m := metricsListen(plan.configs["xray-1"].Metrics); m != metrics {
		t.Fatalf("exited core's metrics moved from %d to %d", metrics, m)
	}
	// One that another program took meanwhile is not reused.
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", api))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	plan, err = buildPlan(fullConfig(t, inbounds), inbounds, ports, "")
	if err != nil {
		t.Fatal(err)
	}
	if p := plan.configs["xray-1"].InboundConfigs[0].Port; p == api || p == 0 {
		t.Fatalf("API port %d is taken", p)
	}
}
