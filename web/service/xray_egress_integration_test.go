package service

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database/model"
)

// sourceEcho answers every TCP connection and UDP datagram on a loopback
// port with the address it came from.
func sourceEcho(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	u, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close(); u.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			c.Write([]byte(host))
			c.Close()
		}
	}()
	go func() {
		buf := make([]byte, 1500)
		for {
			_, from, err := u.ReadFrom(buf)
			if err != nil {
				return
			}
			host, _, _ := net.SplitHostPort(from.String())
			u.WriteTo([]byte(host), from)
		}
	}()
	return port
}

func sourceSeenTCP(port int) string {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		return "error: " + err.Error()
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err != nil {
		return "error: " + err.Error()
	}
	return string(buf[:n])
}

func sourceSeenUDP(port int) string {
	c, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return "error: " + err.Error()
	}
	defer c.Close()
	buf := make([]byte, 64)
	for try := 0; try < 5; try++ {
		c.Write([]byte("who"))
		c.SetReadDeadline(time.Now().Add(time.Second))
		if n, err := c.Read(buf); err == nil {
			return string(buf[:n])
		}
	}
	return "error: no answer"
}

// An instance's outgoing IP is where its TCP connections and UDP flows
// leave from; the default address is used again once it is cleared.
func TestInstanceEgressIntegration(t *testing.T) {
	integrationCore(t)
	// 127.0.0.2 stands in for a second address of the server.
	stubHostAddresses(t, "127.0.0.2")
	stubProbe(t, nil)
	var xs XrayService
	var is InboundService
	var ss SettingService
	// The default template blocks private addresses; the echo is on one.
	tmpl := map[string]any{}
	json.Unmarshal([]byte(xrayTemplateConfig), &tmpl)
	routing := tmpl["routing"].(map[string]any)
	var rules []any
	for _, r := range routing["rules"].([]any) {
		if !strings.Contains(fmt.Sprint(r), "geoip:private") {
			rules = append(rules, r)
		}
	}
	routing["rules"] = rules
	b, _ := json.Marshal(tmpl)
	if err := ss.setString("xrayTemplateConfig", string(b)); err != nil {
		t.Fatal(err)
	}
	if err := xs.RestartXray(true); err != nil {
		t.Fatal(err)
	}

	echo := sourceEcho(t)
	port := freeTCPPort(t)
	in := &model.Inbound{
		UserId: 1, Enable: true, Port: port, Protocol: model.Tunnel, Tag: fmt.Sprintf("inbound-%d", port),
		XrayInstance:   "xray-1",
		Settings:       fmt.Sprintf(`{"address":"127.0.0.1","port":%d,"network":"tcp,udp","followRedirect":false}`, echo),
		StreamSettings: `{}`,
		Sniffing:       `{"enabled":false}`,
	}
	if _, _, err := is.AddInbound(in); err != nil {
		t.Fatal(err)
	}
	if err := xs.ApplyInboundChanges(); err != nil {
		t.Fatal(err)
	}
	if !listening(port) {
		t.Fatalf("core not up: %v", procOf("xray-1").GetResult())
	}
	if got := sourceSeenTCP(port); got != "127.0.0.1" {
		t.Fatalf("before: TCP from %q, want 127.0.0.1", got)
	}

	pid := pidOf(t, "xray-1")
	if err := xs.SetInstanceEgress("xray-1", "127.0.0.2"); err != nil {
		t.Fatal(err)
	}
	if pidOf(t, "xray-1") == pid {
		t.Fatal("the core did not restart to take its outgoing IP")
	}
	if !listening(port) {
		t.Fatal("core not back up")
	}
	if got := sourceSeenTCP(port); got != "127.0.0.2" {
		t.Errorf("TCP from %q, want the outgoing IP 127.0.0.2", got)
	}
	if got := sourceSeenUDP(port); got != "127.0.0.2" {
		t.Errorf("UDP from %q, want the outgoing IP 127.0.0.2", got)
	}
	cfg := string(procOf("xray-1").GetConfig().OutboundConfigs)
	if !strings.Contains(cfg, `"sendThrough":"127.0.0.2"`) {
		t.Errorf("outbounds %s", cfg)
	}

	st, _ := xs.XrayInstancesStatus()
	for _, s := range st {
		if s.Name == "xray-1" && (s.Egress != "127.0.0.2" || s.EgressGone) {
			t.Errorf("status egress %q gone=%v", s.Egress, s.EgressGone)
		}
	}

	if err := xs.SetInstanceEgress("xray-1", ""); err != nil {
		t.Fatal(err)
	}
	if !listening(port) {
		t.Fatal("core not back up after clearing")
	}
	if got := sourceSeenTCP(port); got != "127.0.0.1" {
		t.Errorf("after clearing: TCP from %q, want 127.0.0.1", got)
	}
}
