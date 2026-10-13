package service

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/xray"

	"github.com/xtls/xray-core/app/proxyman/command"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// coreUsers lists the clients the core of instance name serves on tag.
func coreUsers(t *testing.T, name, tag string) []string {
	t.Helper()
	p := procOf(name)
	if p == nil || !p.IsRunning() {
		return []string{"<core not running>"}
	}
	conn, err := grpc.NewClient(fmt.Sprintf("127.0.0.1:%d", p.GetAPIPort()), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	c := command.NewHandlerServiceClient(conn)
	var r *command.GetInboundUserResponse
	for i := 0; i < 50; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		r, err = c.GetInboundUsers(ctx, &command.GetInboundUserRequest{Tag: tag})
		cancel()
		if status.Code(err) != codes.Unavailable {
			break // answered; only a core not listening yet is waited for
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		return []string{"<" + err.Error() + ">"}
	}
	var out []string
	for _, u := range r.Users {
		out = append(out, u.Email)
	}
	sort.Strings(out)
	return out
}

// waitAPI waits until the API of every running core answers: a core that
// has just started refuses API calls for a moment.
func waitAPI(t *testing.T) {
	t.Helper()
	for _, name := range running() {
		coreUsers(t, name, "api")
	}
}

func hasUser(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// subInboundSetup runs an inbound with two clients in xray-1 and a
// sub-inbound of it in xray-2.
func subInboundSetup(t *testing.T, n int) (*model.Inbound, string) {
	t.Helper()
	integrationCore(t)
	var xs XrayService
	var is InboundService
	if err := xs.RestartXray(true); err != nil {
		t.Fatal(err)
	}
	waitAPI(t)
	in := vlessInbound(t, "xray-1", 0)
	in.Settings = fmt.Sprintf(`{"clients":[{"id":"7b0e9c1c-2d6f-4c6e-9b8a-0000000%03d01","email":"keep%d@v","enable":true,"flow":""},{"id":"7b0e9c1c-2d6f-4c6e-9b8a-0000000%03d02","email":"gone%d@v","enable":true,"flow":""}],"decryption":"none","fallbacks":[]}`, n, n, n, n)
	in, _, err := is.AddInbound(in)
	if err != nil {
		t.Fatal(err)
	}
	if err := xs.ApplyInboundChanges(); err != nil {
		t.Fatal(err)
	}
	waitAPI(t)
	subPort := freeTCPPort(t)
	if _, _, err := is.SaveSubInbounds(in.Id, []model.SubInbound{{Port: subPort, Instance: "xray-2", Enable: true}}); err != nil {
		t.Fatal(err)
	}
	if err := xs.ApplyInboundChanges(); err != nil {
		t.Fatal(err)
	}
	waitAPI(t)
	return in, model.SubTag(in.Tag, subPort)
}

// Auto-renewing a depleted client puts it back in the core: a shadowsocks
// client (no "cipher" in its settings) and a VLESS client saved without
// "flow" used to crash the panel here. A client the admin switched off
// stays out.
func TestAutoRenewAddsClientBack(t *testing.T) {
	integrationCore(t)
	var xs XrayService
	var is InboundService
	if err := xs.RestartXray(true); err != nil {
		t.Fatal(err)
	}
	waitAPI(t)
	future := time.Now().Add(24 * time.Hour).UnixMilli()
	ss := &model.Inbound{
		UserId: 1, Enable: true, Remark: "ss", Port: freeTCPPort(t), Protocol: model.Shadowsocks, XrayInstance: "xray-1",
		Settings: fmt.Sprintf(`{"method":"aes-256-gcm","network":"tcp,udp","clients":[
{"method":"","password":"pwss1","email":"ss1@v","enable":true,"reset":30,"expiryTime":%d,"totalGB":1},
{"method":"","password":"pwss2","email":"ss2@v","enable":true,"reset":30,"expiryTime":%d,"totalGB":1}]}`, future, future),
		StreamSettings: `{"network":"tcp","security":"none","tcpSettings":{"header":{"type":"none"}}}`,
		Sniffing:       `{"enabled":false}`,
	}
	ss.Tag = fmt.Sprintf("inbound-%d", ss.Port)
	vl := vlessInbound(t, "xray-1", 0)
	// AddInbound stores clients without "flow" when it is empty.
	vl.Settings = fmt.Sprintf(`{"clients":[{"id":"7b0e9c1c-2d6f-4c6e-9b8a-000000000301","email":"vl1@v","enable":true,"reset":30,"expiryTime":%d,"totalGB":1}],"decryption":"none","fallbacks":[]}`, future)
	for _, in := range []*model.Inbound{ss, vl} {
		if _, _, err := is.AddInbound(in); err != nil {
			t.Fatal(err)
		}
	}
	xs.ApplyInboundChanges()
	waitAPI(t)
	emails := []string{"ss1@v", "ss2@v", "vl1@v"}
	database.GetDB().Model(xray.ClientTraffic{}).Where("email IN ?", emails).Updates(map[string]any{"up": 5})
	is.AddTraffic(nil, nil)
	if u := coreUsers(t, "xray-1", ss.Tag); len(u) != 0 {
		t.Fatalf("depleted clients still served: %v", u)
	}
	// The admin switches ss2 off meanwhile.
	settings := `{"method":"aes-256-gcm","network":"tcp,udp","clients":[
{"method":"","password":"pwss1","email":"ss1@v","enable":true,"reset":30,"expiryTime":%d,"totalGB":1},
{"method":"","password":"pwss2","email":"ss2@v","enable":false,"reset":30,"expiryTime":%d,"totalGB":1}]}`
	database.GetDB().Model(model.Inbound{}).Where("id = ?", ss.Id).Update("settings", fmt.Sprintf(settings, future, future))
	database.GetDB().Model(xray.ClientTraffic{}).Where("email IN ?", emails).Updates(map[string]any{"expiry_time": time.Now().UnixMilli() - 1000})

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("renewal panicked: %v", r)
			}
		}()
		is.AddTraffic(nil, nil)
	}()
	if u := coreUsers(t, "xray-1", ss.Tag); fmt.Sprint(u) != "[ss1@v]" {
		t.Errorf("shadowsocks inbound serves %v, want [ss1@v]", u)
	}
	if u := coreUsers(t, "xray-1", vl.Tag); fmt.Sprint(u) != "[vl1@v]" {
		t.Errorf("vless inbound serves %v, want [vl1@v]", u)
	}
}

// Deleting the depleted clients of every inbound deletes an inbound left
// with none -- with its stats -- and takes it out of its core, at once.
func TestDelDepletedClientsAllInbounds(t *testing.T) {
	integrationCore(t)
	var xs XrayService
	var is InboundService
	if err := xs.RestartXray(true); err != nil {
		t.Fatal(err)
	}
	waitAPI(t)
	a := vlessInbound(t, "xray-1", 0)
	a.Settings = `{"clients":[{"id":"7b0e9c1c-2d6f-4c6e-9b8a-000000000021","email":"a1@v","enable":true,"flow":""},{"id":"7b0e9c1c-2d6f-4c6e-9b8a-000000000022","email":"a2@v","enable":true,"flow":""}],"decryption":"none","fallbacks":[]}`
	a, _, err := is.AddInbound(a)
	if err != nil {
		t.Fatal(err)
	}
	b := vlessInbound(t, "xray-1", 0)
	b.Settings = `{"clients":[{"id":"7b0e9c1c-2d6f-4c6e-9b8a-000000000023","email":"b1@v","enable":true,"flow":""}],"decryption":"none","fallbacks":[]}`
	b, _, err = is.AddInbound(b)
	if err != nil {
		t.Fatal(err)
	}
	xs.ApplyInboundChanges()
	waitAPI(t)
	database.GetDB().Model(xray.ClientTraffic{}).Where("email IN ?", []string{"a2@v", "b1@v"}).Updates(map[string]any{"total": 1, "up": 10})
	is.AddTraffic(nil, nil)

	start := time.Now()
	if _, err := is.DelDepletedClients(-1); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("took %v: the deletes waited on each other", d)
	}
	var n int64
	database.GetDB().Model(model.Inbound{}).Where("id = ?", b.Id).Count(&n)
	if n != 0 {
		t.Error("the inbound left with no client is still in the database")
	}
	database.GetDB().Model(xray.ClientTraffic{}).Where("email IN ?", []string{"a2@v", "b1@v"}).Count(&n)
	if n != 0 {
		t.Errorf("%d stats rows of deleted clients left", n)
	}
	if u := coreUsers(t, "xray-1", b.Tag); len(u) == 1 && u[0] == "b1@v" {
		t.Error("the deleted inbound is still served")
	}
	ain, _ := is.GetInbound(a.Id)
	clients, _ := is.GetClients(ain)
	if len(clients) != 1 || clients[0].Email != "a1@v" {
		t.Errorf("inbound a keeps %v", clients)
	}
	xs.RestartXray(true)
	if u := coreUsers(t, "xray-1", a.Tag); fmt.Sprint(u) != "[a1@v]" {
		t.Errorf("after a restart inbound a serves %v", u)
	}
}

// Resetting the traffic of every client puts the depleted ones back in the
// core, without restarting it.
func TestResetAllClientTrafficsAddsClientsBack(t *testing.T) {
	in, subTag := subInboundSetup(t, 4)
	var xs XrayService
	var is InboundService
	p1, p2 := pidOf(t, "xray-1"), pidOf(t, "xray-2")
	database.GetDB().Model(xray.ClientTraffic{}).Where("email = ?", "gone4@v").Updates(map[string]any{"total": 1, "up": 10})
	is.AddTraffic(nil, nil)
	if hasUser(coreUsers(t, "xray-1", in.Tag), "gone4@v") {
		t.Fatal("the depleted client is still served")
	}
	needRestart, err := is.ResetAllClientTraffics(in.Id)
	if err != nil || needRestart {
		t.Fatalf("ResetAllClientTraffics: needRestart=%v err=%v", needRestart, err)
	}
	xs.RestartXray(false)
	if pidOf(t, "xray-1") != p1 || pidOf(t, "xray-2") != p2 {
		t.Error("a core restarted")
	}
	if !hasUser(coreUsers(t, "xray-1", in.Tag), "gone4@v") || !hasUser(coreUsers(t, "xray-2", subTag), "gone4@v") {
		t.Errorf("the client is not back: %v / %v", coreUsers(t, "xray-1", in.Tag), coreUsers(t, "xray-2", subTag))
	}
}
