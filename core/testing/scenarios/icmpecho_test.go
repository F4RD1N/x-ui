package scenarios

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	gonet "net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/icmpecho"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	jsonconf "github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/testing/servers/tcp"
)

// TestICMPEchoThroughServer drives pings the way hev-socks5-tunnel does on
// a handset -- a SOCKS5 UDP ASSOCIATE datagram to port 0 carrying an ICMP
// echo request -- through a client core and each protocol to a server core,
// whose freedom outbound sends the ping for real. It checks that port 0
// survives every hop (SOCKS UDP, sniffing and routing, each protocol's
// encoding, XUDP, Mux) and that the reply comes back from the pinged address.
//
// It needs root (or a namespace whose net.ipv4.ping_group_range admits root)
// for freedom's ICMP socket. ICMPECHO_TEST_PEER4 and ICMPECHO_TEST_PEER6 ping
// a host on another namespace in place of the loopback addresses.
// ICMPECHO_TEST_LONG=1 also waits out the client's UDP link (over a minute
// per XUDP case) before reusing a source port, so that XUDP resumes the
// server's flow.
func TestICMPEchoThroughServer(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("freedom needs an ICMP socket: run as root")
	}
	peer4 := envOr("ICMPECHO_TEST_PEER4", "127.0.0.1")
	peer6 := envOr("ICMPECHO_TEST_PEER6", "::1")
	if c, err := gonet.ListenPacket("udp6", "[::1]:0"); err == nil {
		c.Close()
	} else {
		peer6 = ""
	}

	uid := uuid.New()
	id := uid.String()
	ct, ctHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	certPEM, keyPEM := ct.ToPEM()
	ss2022Key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 16))

	tlsServer := fmt.Sprintf(`{"security": "tls", "tlsSettings": {"certificates": [{"certificate": %s, "key": %s}]}}`,
		pemLines(certPEM), pemLines(keyPEM))
	tlsClient := fmt.Sprintf(`{"security": "tls", "tlsSettings": {"serverName": "localhost", "pinnedPeerCertSha256": %q}}`,
		hex.EncodeToString(ctHash[:]))

	cases := []struct {
		name string
		// server inbound settings and stream settings; client outbound
		// settings, stream settings and mux. %d is the server port.
		protocol       string
		inbound        string
		inboundStream  string
		outbound       string
		outboundStream string
		mux            string
		coneDisabled   bool
	}{
		{
			name:     "vless dialect, XUDP",
			protocol: "vless",
			inbound:  fmt.Sprintf(`{"clients": [{"id": %q}], "decryption": "none", "dialects": [7]}`, id),
			outbound: fmt.Sprintf(`{"address": "127.0.0.1", "port": %%d, "id": %q, "encryption": "none", "dialect": 7}`, id),
		},
		{
			name:         "vless dialect, plain UDP (cone disabled)",
			protocol:     "vless",
			inbound:      fmt.Sprintf(`{"clients": [{"id": %q}], "decryption": "none", "dialects": [7]}`, id),
			outbound:     fmt.Sprintf(`{"address": "127.0.0.1", "port": %%d, "id": %q, "encryption": "none", "dialect": 7}`, id),
			coneDisabled: true,
		},
		{
			name:     "vless, Mux with XUDP",
			protocol: "vless",
			inbound:  fmt.Sprintf(`{"clients": [{"id": %q}], "decryption": "none"}`, id),
			outbound: fmt.Sprintf(`{"address": "127.0.0.1", "port": %%d, "id": %q, "encryption": "none"}`, id),
			mux:      `{"enabled": true, "concurrency": 8, "xudpConcurrency": 8}`,
		},
		{
			name:           "vless vision over tls",
			protocol:       "vless",
			inbound:        fmt.Sprintf(`{"clients": [{"id": %q, "flow": "xtls-rprx-vision"}], "decryption": "none", "dialects": [7]}`, id),
			inboundStream:  tlsServer,
			outbound:       fmt.Sprintf(`{"address": "127.0.0.1", "port": %%d, "id": %q, "encryption": "none", "flow": "xtls-rprx-vision", "dialect": 7}`, id),
			outboundStream: tlsClient,
		},
		{
			name:     "vmess, XUDP",
			protocol: "vmess",
			inbound:  fmt.Sprintf(`{"clients": [{"id": %q}]}`, id),
			outbound: fmt.Sprintf(`{"vnext": [{"address": "127.0.0.1", "port": %%d, "users": [{"id": %q, "security": "aes-128-gcm"}]}]}`, id),
		},
		{
			name:         "vmess, plain UDP (cone disabled)",
			protocol:     "vmess",
			inbound:      fmt.Sprintf(`{"clients": [{"id": %q}]}`, id),
			outbound:     fmt.Sprintf(`{"vnext": [{"address": "127.0.0.1", "port": %%d, "users": [{"id": %q, "security": "aes-128-gcm"}]}]}`, id),
			coneDisabled: true,
		},
		{
			name:     "trojan",
			protocol: "trojan",
			inbound:  `{"clients": [{"password": "icmp-test"}]}`,
			outbound: `{"servers": [{"address": "127.0.0.1", "port": %d, "password": "icmp-test"}]}`,
		},
		{
			name:     "shadowsocks aead",
			protocol: "shadowsocks",
			inbound:  `{"method": "aes-128-gcm", "password": "icmp-test", "network": "tcp,udp"}`,
			outbound: `{"servers": [{"address": "127.0.0.1", "port": %d, "method": "aes-128-gcm", "password": "icmp-test"}]}`,
		},
		{
			name:     "shadowsocks 2022",
			protocol: "shadowsocks",
			inbound:  fmt.Sprintf(`{"method": "2022-blake3-aes-128-gcm", "password": %q, "network": "tcp,udp"}`, ss2022Key),
			outbound: fmt.Sprintf(`{"servers": [{"address": "127.0.0.1", "port": %%d, "method": "2022-blake3-aes-128-gcm", "password": %q}]}`, ss2022Key),
		},
	}

	udpEcho := startUDPEchoServer(t)
	longWait := os.Getenv("ICMPECHO_TEST_LONG") != ""

	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			serverPort := int(tcp.PickPort())
			clientPort := int(tcp.PickPort())
			stream := func(s string) string {
				if s == "" {
					return `{}`
				}
				return s
			}
			mux := c.mux
			if mux == "" {
				mux = `{"enabled": false}`
			}
			// The server is set up as the panel sets one up: sniffing on, and
			// routing that sends UDP to a freedom outbound but blocks some
			// addresses (127.0.0.2 standing for geoip:private).
			server := startCore(t, fmt.Sprintf(`{
				"log": {"loglevel": "warning"},
				"inbounds": [{
					"listen": "127.0.0.1", "port": %d, "protocol": %q,
					"settings": %s, "streamSettings": %s,
					"sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"]}
				}],
				"outbounds": [
					{"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "AsIs"}},
					{"tag": "blocked", "protocol": "blackhole"}
				],
				"routing": {"rules": [
					{"type": "field", "protocol": ["bittorrent"], "outboundTag": "blocked"},
					{"type": "field", "ip": ["127.0.0.2/32"], "outboundTag": "blocked"},
					{"type": "field", "network": "udp", "outboundTag": "direct"}
				]}
			}`, serverPort, c.protocol, c.inbound, stream(c.inboundStream)), false)
			defer server.Close()

			client := startCore(t, fmt.Sprintf(`{
				"log": {"loglevel": "warning"},
				"inbounds": [{
					"listen": "127.0.0.1", "port": %d, "protocol": "socks",
					"settings": {"auth": "noauth", "udp": true, "ip": "127.0.0.1"},
					"sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"]}
				}],
				"outbounds": [{"protocol": %q, "settings": %s, "streamSettings": %s, "mux": %s}]
			}`, clientPort, c.protocol, fmt.Sprintf(c.outbound, serverPort), stream(c.outboundStream), mux), c.coneDisabled)
			defer client.Close()

			echoID := uint16(0x5100 + i)
			targets := []echoTarget{{1, peer4, false}, {3, "localhost", false}}
			if peer6 != "" {
				targets = append(targets, echoTarget{4, peer6, true})
			}

			// One association per target, as hev-socks5-tunnel keeps one per
			// pinged address.
			for _, tg := range targets {
				ctrl, relay := socksUDPAssociate(t, clientPort, nil)
				pingThroughSocks(t, relay, tg, echoID, c.name)
				relay.Close()
				ctrl.Close()
			}

			// Routing blocks 127.0.0.2.
			blocked := echoTarget{1, "127.0.0.2", false}
			ctrl, relay := socksUDPAssociate(t, clientPort, nil)
			for seq := uint16(1); seq <= 2; seq++ {
				if pingAnswered(t, relay, blocked, echoID, seq, 700*time.Millisecond) {
					t.Fatalf("%s: a ping to a blocked address was answered", c.name)
				}
			}
			relay.Close()
			ctrl.Close()

			// Without cone UDP, Xray sends all of an association's datagrams
			// to its first destination, pings or not. With it (the default),
			// an association's datagrams travel in one flow, which routing saw
			// only the first destination of, so the server pings no other
			// address in it: it ends the flow instead, and the next one is
			// routed afresh -- to the association's first destination (the
			// SOCKS inbound dispatches each of its flows there), or to the
			// packet's (Shadowsocks 2022's server). A blocked address is never
			// answered, and the first destination keeps working. (hev keeps
			// an association per pinged address.)
			if !c.coneDisabled {
				ctrl, relay := socksUDPAssociate(t, clientPort, nil)
				pingThroughSocks(t, relay, targets[0], echoID+0x80, c.name+", shared")
				for seq := uint16(1); seq <= 3; seq++ {
					if pingAnswered(t, relay, blocked, echoID+0x80, seq, 700*time.Millisecond) {
						t.Fatalf("%s: a ping to a blocked address in a flow routed to %s was answered", c.name, targets[0].addr)
					}
				}
				pingUntilAnswered(t, relay, targets[0], echoID+0x81, 10*time.Second, c.name+", shared after a blocked ping")
				if pingAnswered(t, relay, targets[1], echoID+0x82, 1, 700*time.Millisecond) {
					t.Fatalf("%s: a ping to %s in a flow routed to %s was answered", c.name, targets[1].addr, targets[0].addr)
				}
				pingUntilAnswered(t, relay, targets[0], echoID+0x83, 10*time.Second, c.name+", shared after a ping elsewhere")
				relay.Close()
				ctrl.Close()

				// A new association from the source port of one that pinged
				// inherits its flow (the client's link for the port, an XUDP
				// session resumed): its UDP goes through all the same.
				ctrl1, relay1 := socksUDPAssociate(t, clientPort, nil)
				pingThroughSocks(t, relay1, targets[0], echoID+0x90, c.name+", before reuse")
				local := relay1.LocalAddr().(*gonet.UDPAddr)
				relay1.Close()
				ctrl1.Close()
				if longWait && strings.Contains(c.name, "XUDP") {
					time.Sleep(75 * time.Second)
				}
				ctrl2, relay2 := socksUDPAssociate(t, clientPort, local)
				udpUntilAnswered(t, relay2, udpEcho, 10*time.Second, c.name+", UDP from a reused port")
				pingUntilAnswered(t, relay2, targets[0], echoID+0x91, 10*time.Second, c.name+", ping from a reused port")
				relay2.Close()
				ctrl2.Close()
			}

			ctrl, relay = socksUDPAssociate(t, clientPort, nil)
			defer ctrl.Close()
			defer relay.Close()
			pingThroughSocks(t, relay, targets[0], echoID+0xa0, c.name+", fresh")

			// A ping to a port-0 address of the wrong family is dropped,
			// and the association keeps working.
			bad := icmpecho.AppendRequest(nil, icmpecho.Echo{IPv6: true, ID: echoID, Seq: 99})
			relay.Write(socksDatagram(1, peer4, 0, bad))
			good := icmpecho.AppendRequest(nil, icmpecho.Echo{ID: echoID, Seq: 100, Data: []byte("after")})
			relay.Write(socksDatagram(1, peer4, 0, good))
			relay.SetReadDeadline(time.Now().Add(5 * time.Second))
			b := make([]byte, 65536)
			n, err := relay.Read(b)
			if err != nil {
				t.Fatalf("no reply after a dropped ping: %v", err)
			}
			_, _, payload, _ := parseSocksDatagram(b[:n])
			if rep, ok := icmpecho.ParseReply(payload, false); !ok || rep.Seq != 100 {
				t.Fatalf("expected the reply to seq 100, got %x", payload)
			}
		})
	}
}

type echoTarget struct {
	atyp byte
	addr string
	ipv6 bool
}

// pingThroughSocks sends two pings to tg through a SOCKS5 UDP association and
// checks each reply: from tg, port 0, carrying the request's identifier,
// sequence number and data.
func pingThroughSocks(t *testing.T, relay *gonet.UDPConn, tg echoTarget, id uint16, label string) {
	t.Helper()
	for seq := uint16(1); seq <= 2; seq++ {
		data := []byte(fmt.Sprintf("%s -> %s #%d", label, tg.addr, seq))
		req := icmpecho.AppendRequest(nil, icmpecho.Echo{IPv6: tg.ipv6, ID: id, Seq: seq, Data: data})
		if _, err := relay.Write(socksDatagram(tg.atyp, tg.addr, 0, req)); err != nil {
			t.Fatal(err)
		}
		relay.SetReadDeadline(time.Now().Add(5 * time.Second))
		b := make([]byte, 65536)
		n, err := relay.Read(b)
		if err != nil {
			t.Fatalf("%s: ping %s seq %d: no reply: %v", label, tg.addr, seq, err)
		}
		from, port, payload, err := parseSocksDatagram(b[:n])
		if err != nil {
			t.Fatal(err)
		}
		if port != 0 || !sameAddr(from, tg.addr) {
			t.Fatalf("%s: reply from %s:%d, want %s:0", label, from, port, tg.addr)
		}
		rep, ok := icmpecho.ParseReply(payload, tg.ipv6)
		if !ok || rep.ID != id || rep.Seq != seq || !bytes.Equal(rep.Data, data) {
			t.Fatalf("%s: bad reply %x (ok=%v)", label, payload, ok)
		}
	}
}

// pingAnswered sends one ping to tg and reports whether it was answered
// within wait. Datagrams that are not its reply are skipped.
func pingAnswered(t *testing.T, relay *gonet.UDPConn, tg echoTarget, id, seq uint16, wait time.Duration) bool {
	t.Helper()
	data := []byte(fmt.Sprintf("to %s #%d", tg.addr, seq))
	req := icmpecho.AppendRequest(nil, icmpecho.Echo{IPv6: tg.ipv6, ID: id, Seq: seq, Data: data})
	if _, err := relay.Write(socksDatagram(tg.atyp, tg.addr, 0, req)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(wait)
	b := make([]byte, 65536)
	for {
		relay.SetReadDeadline(deadline)
		n, err := relay.Read(b)
		if err != nil {
			return false
		}
		from, port, payload, err := parseSocksDatagram(b[:n])
		if err != nil || port != 0 || !sameAddr(from, tg.addr) {
			continue
		}
		if rep, ok := icmpecho.ParseReply(payload, tg.ipv6); ok && rep.ID == id && rep.Seq == seq && bytes.Equal(rep.Data, data) {
			return true
		}
	}
}

// pingUntilAnswered pings tg until a ping is answered, for at most d.
func pingUntilAnswered(t *testing.T, relay *gonet.UDPConn, tg echoTarget, id uint16, d time.Duration, label string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for seq := uint16(1); time.Now().Before(deadline); seq++ {
		if pingAnswered(t, relay, tg, id, seq, 500*time.Millisecond) {
			return
		}
	}
	t.Fatalf("%s: no ping to %s answered in %v", label, tg.addr, d)
}

// startUDPEchoServer runs a UDP server on 127.0.0.1 that answers each
// datagram with "echo:" and the datagram, and returns its port.
func startUDPEchoServer(t *testing.T) uint16 {
	t.Helper()
	srv, err := gonet.ListenUDP("udp4", &gonet.UDPAddr{IP: gonet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	go func() {
		b := make([]byte, 2048)
		for {
			n, from, err := srv.ReadFromUDP(b)
			if err != nil {
				return
			}
			srv.WriteToUDP(append([]byte("echo:"), b[:n]...), from)
		}
	}()
	return uint16(srv.LocalAddr().(*gonet.UDPAddr).Port)
}

// udpUntilAnswered sends datagrams to 127.0.0.1:port until one is echoed
// back, for at most d.
func udpUntilAnswered(t *testing.T, relay *gonet.UDPConn, port uint16, d time.Duration, label string) {
	t.Helper()
	deadline := time.Now().Add(d)
	b := make([]byte, 65536)
	for i := 0; time.Now().Before(deadline); i++ {
		probe := fmt.Sprintf("probe %d", i)
		if _, err := relay.Write(socksDatagram(1, "127.0.0.1", port, []byte(probe))); err != nil {
			t.Fatal(err)
		}
		wait := time.Now().Add(500 * time.Millisecond)
		for {
			relay.SetReadDeadline(wait)
			n, err := relay.Read(b)
			if err != nil {
				break
			}
			from, fromPort, payload, err := parseSocksDatagram(b[:n])
			if err == nil && from == "127.0.0.1" && fromPort == port && string(payload) == "echo:"+probe {
				return
			}
		}
	}
	t.Fatalf("%s: no UDP answered in %v", label, d)
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func pemLines(b []byte) string {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	quoted := make([]string, len(lines))
	for i, l := range lines {
		quoted[i] = fmt.Sprintf("%q", l)
	}
	return "[" + strings.Join(quoted, ",") + "]"
}

func startCore(t *testing.T, jsonConfig string, coneDisabled bool) *core.Instance {
	t.Helper()
	if coneDisabled {
		t.Setenv("XRAY_CONE_DISABLED", "true")
	} else {
		t.Setenv("XRAY_CONE_DISABLED", "")
	}
	config, err := jsonconf.LoadJSONConfig(strings.NewReader(jsonConfig))
	if err != nil {
		t.Fatalf("config: %v\n%s", err, jsonConfig)
	}
	instance, err := core.New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	return instance
}

// socksUDPAssociate opens a UDP association with the SOCKS server on port,
// sending from local (an ephemeral port when nil).
func socksUDPAssociate(t *testing.T, port int, local *gonet.UDPAddr) (gonet.Conn, *gonet.UDPConn) {
	t.Helper()
	var ctrl gonet.Conn
	var err error
	for i := 0; i < 50; i++ {
		if ctrl, err = gonet.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	ctrl.SetDeadline(time.Now().Add(5 * time.Second))
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err = ctrl.Write([]byte{5, 1, 0})
	must(err)
	hello := make([]byte, 2)
	_, err = io.ReadFull(ctrl, hello)
	must(err)
	_, err = ctrl.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	must(err)
	head := make([]byte, 4)
	_, err = io.ReadFull(ctrl, head)
	must(err)
	if head[1] != 0 {
		t.Fatalf("UDP ASSOCIATE refused: %v", head)
	}
	var ip gonet.IP
	switch head[3] {
	case 1:
		ip = make([]byte, 4)
	case 4:
		ip = make([]byte, 16)
	default:
		t.Fatalf("unexpected BND.ADDR type %d", head[3])
	}
	_, err = io.ReadFull(ctrl, ip)
	must(err)
	pb := make([]byte, 2)
	_, err = io.ReadFull(ctrl, pb)
	must(err)
	ctrl.SetDeadline(time.Time{})
	relay, err := gonet.DialUDP("udp", local, &gonet.UDPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(pb))})
	must(err)
	return ctrl, relay
}

func socksDatagram(atyp byte, addr string, port uint16, payload []byte) []byte {
	b := []byte{0, 0, 0, atyp}
	switch atyp {
	case 1:
		b = append(b, gonet.ParseIP(addr).To4()...)
	case 4:
		b = append(b, gonet.ParseIP(addr).To16()...)
	case 3:
		b = append(b, byte(len(addr)))
		b = append(b, addr...)
	}
	b = binary.BigEndian.AppendUint16(b, port)
	return append(b, payload...)
}

func parseSocksDatagram(b []byte) (addr string, port uint16, payload []byte, err error) {
	if len(b) < 4 {
		return "", 0, nil, fmt.Errorf("short datagram")
	}
	rest := b[4:]
	switch b[3] {
	case 1:
		if len(rest) < 6 {
			return "", 0, nil, fmt.Errorf("short IPv4 datagram")
		}
		addr, rest = gonet.IP(rest[:4]).String(), rest[4:]
	case 4:
		if len(rest) < 18 {
			return "", 0, nil, fmt.Errorf("short IPv6 datagram")
		}
		addr, rest = gonet.IP(rest[:16]).String(), rest[16:]
	case 3:
		if len(rest) < 1 || len(rest) < 1+int(rest[0])+2 {
			return "", 0, nil, fmt.Errorf("short domain datagram")
		}
		addr, rest = string(rest[1:1+int(rest[0])]), rest[1+int(rest[0]):]
	default:
		return "", 0, nil, fmt.Errorf("address type %d", b[3])
	}
	return addr, binary.BigEndian.Uint16(rest[:2]), rest[2:], nil
}

func sameAddr(a, b string) bool {
	if ia, ib := gonet.ParseIP(a), gonet.ParseIP(b); ia != nil && ib != nil {
		return ia.Equal(ib)
	}
	return a == b
}
