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
			// routing that sends UDP to a freedom outbound.
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

			// One association per target, as a client that keeps one per
			// destination does.
			for _, tg := range targets {
				ctrl, relay := socksUDPAssociate(t, clientPort)
				pingThroughSocks(t, relay, tg, echoID, c.name)
				relay.Close()
				ctrl.Close()
			}

			ctrl, relay := socksUDPAssociate(t, clientPort)
			defer ctrl.Close()
			defer relay.Close()
			// With cone UDP (the default) one association reaches every
			// target. Without it, Xray sends all of an association's datagrams
			// to its first destination, pings or not.
			if !c.coneDisabled {
				for _, tg := range targets {
					pingThroughSocks(t, relay, tg, echoID+0x80, c.name+", shared")
				}
			}

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

func socksUDPAssociate(t *testing.T, port int) (gonet.Conn, *gonet.UDPConn) {
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
	relay, err := gonet.DialUDP("udp", nil, &gonet.UDPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(pb))})
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
