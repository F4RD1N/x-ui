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
