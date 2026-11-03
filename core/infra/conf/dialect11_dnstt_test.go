package conf_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	confserial "github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/proxy/dns"
	"github.com/xtls/xray-core/proxy/dnstt"
	_ "github.com/xtls/xray-core/proxy/dokodemo"
	_ "github.com/xtls/xray-core/proxy/freedom"
	"golang.org/x/net/proxy"
	"google.golang.org/protobuf/proto"
	"www.bamsoftware.com/git/dnstt.git/noise"
)

func dnsttLoad(t *testing.T, obj any) *core.Config {
	t.Helper()
	raw, e := json.Marshal(obj)
	if e != nil {
		t.Fatal(e)
	}
	c, e := confserial.LoadJSONConfig(bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func dnsttStart(t *testing.T, obj any) *core.Instance {
	t.Helper()
	c, e := core.New(dnsttLoad(t, obj))
	if e != nil {
		t.Fatal(e)
	}
	if e = c.Start(); e != nil {
		c.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	return c
}
func dnsttPort(t *testing.T, udp bool) int {
	t.Helper()
	if udp {
		c, e := net.ListenPacket("udp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		return c.LocalAddr().(*net.UDPAddr).Port
	}
	c, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	return c.Addr().(*net.TCPAddr).Port
}

func TestDNSTTConfigOrdinaryDNSUnchanged(t *testing.T) {
	for _, raw := range []string{`{}`, `{"network":"udp","address":"127.0.0.1","port":5353,"userLevel":1,"nonIPQuery":"skip","blockTypes":[28]}`} {
		var old conf.DNSOutboundConfig
		if e := json.Unmarshal([]byte(raw), &old); e != nil {
			t.Fatal(e)
		}
		want, e := old.Build()
		if e != nil {
			t.Fatal(e)
		}
		full := dnsttLoad(t, map[string]any{"outbounds": []any{map[string]any{"protocol": "dns", "settings": json.RawMessage(raw)}}})
		got, e := full.Outbound[0].ProxySettings.GetInstance()
		if e != nil {
			t.Fatal(e)
		}
		if _, ok := got.(*dns.Config); !ok || !proto.Equal(want, got) {
			t.Fatal("ordinary DNS changed after tunnel registration")
		}
	}
}

func TestDNSTTConfigOrdinaryDNSRuntime(t *testing.T) {
	packet, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	authority := &mdns.Server{PacketConn: packet, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, q *mdns.Msg) {
		a := new(mdns.Msg)
		a.SetReply(q)
		a.Answer = []mdns.RR{&mdns.TXT{Hdr: mdns.RR_Header{Name: q.Question[0].Name, Rrtype: mdns.TypeTXT, Class: mdns.ClassINET}, Txt: []string{"stock-dns-ok"}}}
		_ = w.WriteMsg(a)
	})}
	go authority.ActivateAndServe()
	defer authority.Shutdown()
	inboundPort := dnsttPort(t, true)
	dnsttStart(t, map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": inboundPort, "protocol": "dokodemo-door", "settings": map[string]any{"address": "127.0.0.1", "port": 53, "network": "udp"}}}, "outbounds": []any{map[string]any{"protocol": "dns", "settings": map[string]any{"network": "udp", "address": "127.0.0.1", "port": packet.LocalAddr().(*net.UDPAddr).Port, "nonIPQuery": "skip"}}}})
	q := new(mdns.Msg)
	q.SetQuestion("local.invalid.", mdns.TypeTXT)
	a, _, e := (&mdns.Client{Timeout: 3 * time.Second}).Exchange(q, net.JoinHostPort("127.0.0.1", strconv.Itoa(inboundPort)))
	if e != nil || len(a.Answer) != 1 {
		t.Fatalf("ordinary DNS runtime failed: %v", e)
	}
	if got := a.Answer[0].(*mdns.TXT).Txt[0]; got != "stock-dns-ok" {
		t.Fatal("stock DNS result changed")
	}
}

func TestDNSTTConfigFullCoreTunnelAndAlias(t *testing.T) {
	key, e := noise.GeneratePrivkey()
	if e != nil {
		t.Fatal(e)
	}
	serverPort := dnsttPort(t, true)
	id := "00112233-4455-0677-8899-aabbccddeeff"
	settings := map[string]any{"domain": "tunnel.test", "privateKey": hex.EncodeToString(key), "inner": map[string]any{"protocol": "vless"}, "clients": []any{map[string]any{"id": id, "email": "config-test"}}}
	dnsttStart(t, map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": []any{map[string]any{"tag": "dns-tunnel", "listen": "127.0.0.1", "port": serverPort, "protocol": "dnstt", "settings": settings}}, "outbounds": []any{map[string]any{"protocol": "freedom"}}})
	echo, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer echo.Close()
	go func() {
		for {
			c, e := echo.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	tunnel := map[string]any{"domain": "tunnel.test", "publicKey": hex.EncodeToString(noise.PubkeyFromPrivkey(key)), "resolvers": []any{map[string]any{"transport": "udp", "address": net.JoinHostPort("127.0.0.1", strconv.Itoa(serverPort))}}, "inner": map[string]any{"protocol": "vless", "uuid": id}}
	for _, name := range []string{"dns", "dnstt"} {
		t.Run(name, func(t *testing.T) {
			clientPort := dnsttPort(t, false)
			outSettings := any(tunnel)
			if name == "dns" {
				outSettings = map[string]any{"tunnel": tunnel}
			}
			config := map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": clientPort, "protocol": "socks", "settings": map[string]any{"auth": "noauth"}}}, "outbounds": []any{map[string]any{"protocol": name, "settings": outSettings}}}
			built := dnsttLoad(t, config)
			value, e := built.Outbound[0].ProxySettings.GetInstance()
			if e != nil {
				t.Fatal(e)
			}
			if _, ok := value.(*dnstt.Config); !ok {
				t.Fatal("tunnel config loaded wrong handler")
			}
			dnsttStart(t, config)
			dialer, e := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(clientPort)), nil, &net.Dialer{Timeout: 3 * time.Second})
			if e != nil {
				t.Fatal(e)
			}
			conn, e := dialer.Dial("tcp", echo.Addr().String())
			if e != nil {
				t.Fatal(e)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(10 * time.Second))
			want := bytes.Repeat([]byte("full-json-client"), 256)
			if _, e = conn.Write(want); e != nil {
				t.Fatal(e)
			}
			got := make([]byte, len(want))
			if _, e = io.ReadFull(conn, got); e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(want, got) {
				t.Fatal("full JSON core transfer mismatch")
			}
		})
	}
}

func TestDNSTTConfigRejectsMalformedTunnel(t *testing.T) {
	for _, settings := range []string{`{"tunnel":null}`, `{"tunnel":[]}`, `{"tunnel":{}}`, `{"tunnel":{"surprise":true}}`, `{"port":53,"tunnel":{}}`, `{"address":"127.0.0.1","tunnel":{}}`, `{"tunnel":{"inner":null}}`} {
		raw := []byte(`{"outbounds":[{"protocol":"dns","settings":` + settings + `}]}`)
		if _, e := confserial.LoadJSONConfig(bytes.NewReader(raw)); e == nil {
			t.Fatalf("invalid explicit tunnel accepted: %s", settings)
		}
	}
}

func TestDNSTTConfigInboundAliases(t *testing.T) {
	key, e := noise.GeneratePrivkey()
	if e != nil {
		t.Fatal(e)
	}
	settings := map[string]any{"domain": "tunnel.test", "privateKey": hex.EncodeToString(key), "clients": []any{map[string]any{"id": "00112233-4455-0677-8899-aabbccddeeff"}}}
	var previous proto.Message
	for _, name := range []string{"dnstt", "dns"} {
		cfg := dnsttLoad(t, map[string]any{"inbounds": []any{map[string]any{"protocol": name, "listen": "127.0.0.1", "port": 15353, "settings": settings}}, "outbounds": []any{map[string]any{"protocol": "freedom"}}})
		value, e := cfg.Inbound[0].ProxySettings.GetInstance()
		if e != nil {
			t.Fatal(e)
		}
		server, ok := value.(*dnstt.ServerConfig)
		if !ok {
			t.Fatal("inbound alias loaded a different protocol")
		}
		if previous != nil && !proto.Equal(previous, value) {
			t.Fatal("inbound alias changes server settings")
		}
		if server.PrivateKey != settings["privateKey"] {
			t.Fatal("loading inbound regenerated its private key")
		}
		previous = value
	}
}
