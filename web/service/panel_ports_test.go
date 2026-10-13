package service

import (
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
)

// An inbound cannot take the panel's or the subscription server's port, and
// those servers cannot move to a port an inbound or another program holds.
func TestPanelPortsAreKeptApart(t *testing.T) {
	if err := database.InitDB(filepath.Join(t.TempDir(), "x-ui.db")); err != nil {
		t.Fatal(err)
	}
	defer database.CloseDB()
	var ss SettingService
	webPort, subPort := freeTCPPort(t), freeTCPPort(t)
	if err := ss.setInt("webPort", webPort); err != nil {
		t.Fatal(err)
	}
	if err := ss.setInt("subPort", subPort); err != nil {
		t.Fatal(err)
	}

	var is InboundService
	for port, want := range map[int]string{webPort: "panel", subPort: "subscription"} {
		in := vlessInbound(t, "", 0)
		in.Port = port
		if _, _, err := is.AddInbound(in); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("inbound on the %s port: %v", want, err)
		}
	}

	in := vlessInbound(t, "", 0)
	if err := database.GetDB().Create(in).Error; err != nil {
		t.Fatal(err)
	}
	src := vlessInbound(t, "", 0)
	src.SetSubs([]model.SubInbound{{Port: freeTCPPort(t), Instance: "xray-2", Enable: true}})
	if err := database.GetDB().Create(src).Error; err != nil {
		t.Fatal(err)
	}
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	heldPort := held.Addr().(*net.TCPAddr).Port

	if err := ss.checkServerPorts("", webPort, true, "", subPort); err != nil {
		t.Errorf("unchanged ports: %v", err)
	}
	for name, port := range map[string]int{"an inbound": in.Port, "a sub-inbound": src.Subs()[0].Port, "another program": heldPort} {
		if err := ss.checkServerPorts("", webPort, true, "", port); err == nil {
			t.Errorf("sub port taken by %s (%d) accepted", name, port)
		}
		if err := ss.checkServerPorts("", port, true, "", subPort); err == nil {
			t.Errorf("web port taken by %s (%d) accepted", name, port)
		}
	}
	if free := freeTCPPort(t); ss.checkServerPorts("", webPort, true, "", free) != nil {
		t.Errorf("free sub port %s refused", strconv.Itoa(free))
	}
	// A subscription server that stays off is not checked.
	if err := ss.checkServerPorts("", webPort, false, "", in.Port); err != nil {
		t.Errorf("disabled sub server: %v", err)
	}
}

// Moving a running server to another address on the same port is allowed:
// the probe would only find the server's own socket. Each server here is a
// real listener, as the running panel is.
func TestServerMovesAddressOnSamePort(t *testing.T) {
	if err := database.InitDB(filepath.Join(t.TempDir(), "x-ui.db")); err != nil {
		t.Fatal(err)
	}
	defer database.CloseDB()
	var ss SettingService
	listen := func(addr string) (net.Listener, int) {
		t.Helper()
		l, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		return l, l.Addr().(*net.TCPAddr).Port
	}
	set := func(kv map[string]string) {
		t.Helper()
		for k, v := range kv {
			if err := ss.saveSetting(k, v); err != nil {
				t.Fatal(err)
			}
		}
	}

	// The panel on all addresses, then on 127.0.0.1, same port.
	_, web := listen(":0")
	set(map[string]string{"webListen": "", "webPort": strconv.Itoa(web), "subEnable": "false"})
	if err := ss.checkServerPorts("127.0.0.1", web, false, "", 0); err != nil {
		t.Errorf("panel '' -> 127.0.0.1 on its own port: %v", err)
	}

	// And back: the panel on 127.0.0.1, moving to all addresses.
	web1, webPort1 := listen("127.0.0.1:0")
	set(map[string]string{"webListen": "127.0.0.1", "webPort": strconv.Itoa(webPort1)})
	if err := ss.checkServerPorts("", webPort1, false, "", 0); err != nil {
		t.Errorf("panel 127.0.0.1 -> '' on its own port: %v", err)
	}
	// Two addresses that do not overlap are still probed: another program
	// on 127.0.0.2 with that port is found.
	if other, err := net.Listen("tcp", "127.0.0.2:"+strconv.Itoa(webPort1)); err == nil {
		if err := ss.checkServerPorts("127.0.0.2", webPort1, false, "", 0); err == nil {
			t.Error("panel moved onto a port another program holds at 127.0.0.2")
		}
		other.Close()
		if err := ss.checkServerPorts("127.0.0.2", webPort1, false, "", 0); err != nil {
			t.Errorf("panel 127.0.0.1 -> 127.0.0.2, port free there: %v", err)
		}
	}
	web1.Close()

	// The subscription server, on, changes only its address.
	_, sub := listen(":0")
	_, web2 := listen(":0")
	set(map[string]string{"webListen": "", "webPort": strconv.Itoa(web2), "subEnable": "true", "subListen": "", "subPort": strconv.Itoa(sub)})
	if err := ss.checkServerPorts("", web2, true, "127.0.0.1", sub); err != nil {
		t.Errorf("subscription '' -> 127.0.0.1 on its own port: %v", err)
	}
	// Turned on now, its port held by something else: refused as before.
	set(map[string]string{"subEnable": "false"})
	if err := ss.checkServerPorts("", web2, true, "127.0.0.1", sub); err == nil {
		t.Error("subscription turned on at a port another program holds")
	}
	// An inbound on the port is refused even when the server keeps it.
	set(map[string]string{"subEnable": "true"})
	in := vlessInbound(t, "", 0)
	in.Port = sub
	if err := database.GetDB().Create(in).Error; err != nil {
		t.Fatal(err)
	}
	if err := ss.checkServerPorts("", web2, true, "127.0.0.1", sub); err == nil {
		t.Error("subscription moved onto an inbound's port")
	}
}

// The panel's web port, and the subscription port while that server is on,
// are reserved along with the inbound ports.
func TestAddPanelPorts(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XUI_DB_FOLDER", dir)
	if err := database.InitDB(filepath.Join(dir, "x-ui.db")); err != nil {
		t.Fatal(err)
	}
	defer database.CloseDB()
	s := &XrayService{}
	if err := s.settingService.SetPort(60000); err != nil {
		t.Fatal(err)
	}
	s.settingService.saveSetting("subPort", "2096")
	s.settingService.saveSetting("subEnable", "false")
	got := map[int]bool{443: true}
	s.addPanelPorts(got)
	if !got[443] || !got[60000] || got[2096] {
		t.Fatalf("sub off: %v", got)
	}
	s.settingService.saveSetting("subEnable", "true")
	s.addPanelPorts(got)
	if !got[2096] {
		t.Fatalf("sub on: %v", got)
	}
}
