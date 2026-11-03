package client

// These acceptance tests use freshly generated credentials and a stock OpenVPN
// daemon. Run the compiled test in an unnamed network namespace; no production
// server, public VPN configuration, or existing test namespace is touched.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/clientproof"
	xproxy "golang.org/x/net/proxy"
)

type proofOracle struct {
	dir, text, logPath, tunnelIP string
}

func proofLog(path string) string {
	b, _ := os.ReadFile(path)
	return string(b)
}

func proofWait(t *testing.T, description string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out: %s", description)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func proofFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func proofStart(t *testing.T, index int, tcp, protected bool, cn, extraServer, extraClient string, omitExporter ...bool) *proofOracle {
	t.Helper()
	dir := t.TempDir()
	pki := getPKI(t)
	ca := proofFile(t, dir, "ca.crt", pki.caPEM)
	cert := proofFile(t, dir, "server.crt", pki.serverCertPEM)
	key := proofFile(t, dir, "server.key", pki.serverKeyPEM)
	proto, clientProto := "udp4", "udp"
	if tcp {
		proto, clientProto = "tcp4-server", "tcp"
	}
	port := 25194 + index
	protection := ""
	if protected {
		keys := proofFile(t, dir, "proof.keys", []byte("interop\t"+hex.EncodeToString(bytes.Repeat([]byte{0x43}, 32))+"\t"+cn+"\n"))
		plugin := os.Getenv("OVPN_CLIENT_PROOF_PLUGIN")
		if !filepath.IsAbs(plugin) {
			t.Fatal("OVPN_CLIENT_PROOF_PLUGIN must be an absolute plugin path")
		}
		protection = fmt.Sprintf("plugin %s %s\nkeying-material-exporter %s %d\n", plugin, keys, clientproof.ExporterLabel, clientproof.ExporterLength)
		if len(omitExporter) != 0 && omitExporter[0] {
			protection = fmt.Sprintf("plugin %s %s\n", plugin, keys)
		}
	}
	ip := fmt.Sprintf("10.109.%d.1", index+1)
	conf := fmt.Sprintf("local 127.0.0.1\nport %d\nproto %s\ndev tun\ntopology subnet\nserver 10.109.%d.0 255.255.255.0\nca %s\ncert %s\nkey %s\ndh none\nkeepalive 2 15\ntls-version-min 1.2\ndata-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305\ndisable-dco\nverb 2\n%s%s", port, proto, index+1, ca, cert, key, protection, extraServer)
	confPath := proofFile(t, dir, "server.conf", []byte(conf))
	logPath := filepath.Join(dir, "server.log")
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/usr/sbin/openvpn", "--config", confPath)
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		log.Close()
		if t.Failed() {
			// The plugin emits fixed diagnostics; use low stock-daemon verbosity.
			t.Logf("stock server diagnostics:\n%s", proofLog(logPath))
		}
	})
	proofWait(t, "stock server ready", func() bool { return strings.Contains(proofLog(logPath), "Initialization Sequence Completed") })
	text := ovpnText(t, fmt.Sprintf("remote 127.0.0.1 %d %s\n", port, clientProto)+extraClient)
	return &proofOracle{dir: dir, text: text, logPath: logPath, tunnelIP: ip}
}

func proofStock(t *testing.T, srv *proofOracle, marker string, wantSuccess bool) {
	t.Helper()
	profile := proofFile(t, srv.dir, "stock-client.ovpn", []byte(srv.text))
	args := []string{"--config", profile, "--dev", "null", "--ifconfig-noexec", "--route-noexec", "--connect-retry-max", "1", "--connect-retry", "1", "--hand-window", "5", "--tls-timeout", "1", "--tls-exit", "--auth-retry", "none", "--disable-dco", "--verb", "3"}
	if marker != "" {
		args = append(args, "--setenv", clientproof.PeerInfoKey, marker, "--push-peer-info")
	}
	path := filepath.Join(srv.dir, "stock-client.log")
	log, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/sbin/openvpn", args...)
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait(); log.Close() }()
	proofWait(t, "stock client admission decision", func() bool {
		return strings.Contains(proofLog(path), "Initialization Sequence Completed") ||
			strings.Contains(proofLog(srv.logPath), "[openvpn-client-proof] authentication rejected")
	})
	connected := strings.Contains(proofLog(path), "Initialization Sequence Completed")
	if connected != wantSuccess {
		t.Fatalf("stock admission success=%v, want %v", connected, wantSuccess)
	}
}

func proofKey(t *testing.T, id string, value byte) *clientproof.Key {
	t.Helper()
	k, err := clientproof.New(id, bytes.Repeat([]byte{value}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func proofDial(t *testing.T, srv *proofOracle, k *clientproof.Key, user, pass string) (*Client, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	c, err := Dial(ctx, Config{Options: parseOpts(t, srv.text), Dial: netDial, ClientProof: k, Username: user, Password: pass, HandshakeTimeout: 6 * time.Second})
	if c != nil {
		t.Cleanup(func() { c.Close() })
	}
	return c, err
}

func proofPing(t *testing.T, c *Client) {
	t.Helper()
	packets := packetReader(c)
	for i := uint16(1); i <= 3; i++ {
		if !pingThrough(c, packets, i, []byte("authenticated OpenVPN data"), time.Second) {
			t.Fatal("OpenVPN data-channel echo failed")
		}
	}
}

func TestClientProofStockServer(t *testing.T) {
	if os.Getenv("OVPN_CLIENT_PROOF_REALSERVER") != "1" {
		t.Skip("set OVPN_CLIENT_PROOF_REALSERVER=1 inside an unnamed private network namespace")
	}
	if os.Geteuid() != 0 || !inPrivateNetns() {
		t.Fatal("real proof tests require root in a private network namespace")
	}
	index := 0
	start := func(t *testing.T, tcp, protected bool, cn, server, client string) *proofOracle {
		index++
		return proofStart(t, index, tcp, protected, cn, server, client)
	}
	// First establish unmodified stock client/server interoperability.
	for _, tcp := range []bool{false, true} {
		t.Run(fmt.Sprintf("stock-baseline-tcp-%v", tcp), func(t *testing.T) {
			proofStock(t, start(t, tcp, false, "client", "", ""), "", true)
		})
	}
	for _, tcp := range []bool{false, true} {
		t.Run(fmt.Sprintf("normal-core-tcp-%v", tcp), func(t *testing.T) {
			c, err := proofDial(t, start(t, tcp, false, "client", "", ""), nil, "", "")
			if err != nil {
				t.Fatal(err)
			}
			proofPing(t, c)
		})
	}
	for _, tcp := range []bool{false, true} {
		t.Run(fmt.Sprintf("protected-core-tcp-%v", tcp), func(t *testing.T) {
			c, err := proofDial(t, start(t, tcp, true, "client", "", ""), proofKey(t, "interop", 0x43), "", "")
			if err != nil {
				t.Fatal(err)
			}
			proofPing(t, c)
		})
		t.Run(fmt.Sprintf("stock-denied-tcp-%v", tcp), func(t *testing.T) {
			proofStock(t, start(t, tcp, true, "client", "", ""), "", false)
		})
	}
	t.Run("stock-static-marker-denied", func(t *testing.T) {
		proofStock(t, start(t, false, true, "client", "", ""), "1:interop:"+strings.Repeat("A", 43), false)
	})
	for _, tc := range []struct {
		name, id, cn string
		key          byte
	}{
		{"wrong-key", "interop", "client", 0x44},
		{"unknown-key-id", "unknown", "client", 0x43},
		{"wrong-certificate-binding", "interop", "another-client", 0x43},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := start(t, true, true, tc.cn, "", "")
			c, err := proofDial(t, srv, proofKey(t, tc.id, tc.key), "", "")
			if c != nil || err == nil {
				t.Fatal("invalid proof was admitted")
			}
			if !strings.Contains(proofLog(srv.logPath), "[openvpn-client-proof] authentication rejected") {
				t.Fatal("no server proof rejection")
			}
		})
	}
	t.Run("tls12-proof", func(t *testing.T) {
		c, err := proofDial(t, start(t, true, true, "client", "tls-version-max 1.2\n", "tls-version-max 1.2\n"), proofKey(t, "interop", 0x43), "", "")
		if err != nil {
			t.Fatal(err)
		}
		if c.Info().TLSVersion != "TLS 1.2" {
			t.Fatal("TLS 1.2 was not negotiated")
		}
		proofPing(t, c)
	})
	for _, tcp := range []bool{false, true} {
		for _, mode := range []string{"tls-auth", "tls-crypt", "tls-crypt-v2"} {
			t.Run(fmt.Sprintf("protected-%s-tcp-%v", mode, tcp), func(t *testing.T) {
				dir := t.TempDir()
				text := staticKeyText(newStaticKey(t))
				path := proofFile(t, dir, "control.key", []byte(text))
				server := mode + " " + path + "\n"
				client := "<" + mode + ">\n" + text + "</" + mode + ">\n"
				if mode == "tls-auth" {
					server = mode + " " + path + " 0\nauth SHA256\n"
					client = "key-direction 1\nauth SHA256\n" + client
				}
				if mode == "tls-crypt-v2" {
					path = filepath.Join(dir, "server-v2.key")
					clientPath := filepath.Join(dir, "client-v2.key")
					for _, args := range [][]string{{"--genkey", mode + "-server", path}, {"--tls-crypt-v2", path, "--genkey", mode + "-client", clientPath}} {
						if out, err := exec.Command("/usr/sbin/openvpn", args...).CombinedOutput(); err != nil {
							t.Fatalf("ephemeral control-key generation failed: %v (%d diagnostic bytes)", err, len(out))
						}
					}
					key, err := os.ReadFile(clientPath)
					if err != nil {
						t.Fatal(err)
					}
					server = mode + " " + path + "\n"
					client = "<" + mode + ">\n" + string(key) + "</" + mode + ">\n"
				}
				srv := start(t, tcp, true, "client", server, client)
				c, err := proofDial(t, srv, proofKey(t, "interop", 0x43), "", "")
				if err != nil {
					t.Fatal(err)
				}
				proofPing(t, c)
				c.Close()
				if mode == "tls-crypt" {
					// The stock client also has the correct outer control key;
					// rejection must come from the proof plugin, not that wrapper.
					proofStock(t, srv, "", false)
				}
			})
		}
	}
	t.Run("replayed-proof-denied", func(t *testing.T) {
		// Capture a genuine proof from a different, valid TLS connection.
		fake := startServer(t, srvConfig{cipher: "AES-256-GCM", ekm: true})
		c := mustDial(t, fake, sessionOpts{cfg: func(cfg *Config) { cfg.ClientProof = proofKey(t, "interop", 0x43) }})
		var marker string
		for _, line := range strings.Split(fake.snapshot().peerInfo, "\n") {
			if value, ok := strings.CutPrefix(line, clientproof.PeerInfoKey+"="); ok {
				marker = value
			}
		}
		c.Close()
		if marker == "" {
			t.Fatal("no proof captured from the initial TLS session")
		}
		proofStock(t, start(t, true, true, "client", "", ""), marker, false)
	})
	t.Run("renegotiation", func(t *testing.T) {
		srv := start(t, false, true, "client", "reneg-sec 3\nhand-window 2\n", "")
		c, err := proofDial(t, srv, proofKey(t, "interop", 0x43), "", "")
		if err != nil {
			t.Fatal(err)
		}
		packets := packetReader(c)
		deadline := time.Now().Add(9 * time.Second)
		for seq := uint16(100); time.Now().Before(deadline); seq++ {
			if !pingThrough(c, packets, seq, []byte("rekey proof"), time.Second) {
				t.Fatal("traffic failed across rekey")
			}
			time.Sleep(100 * time.Millisecond)
		}
		if strings.Count(proofLog(srv.logPath), "[openvpn-client-proof] authentication accepted") < 3 {
			t.Fatal("proof was not checked on at least three TLS generations")
		}
	})
	t.Run("ordinary-password-still-required", func(t *testing.T) {
		checkDir := t.TempDir()
		check := proofFile(t, checkDir, "check.sh", []byte("#!/bin/sh\n[ \"$(sed -n 1p \"$1\")\" = alice ] && [ \"$(sed -n 2p \"$1\")\" = s3cret ]\n"))
		if err := os.Chmod(check, 0700); err != nil {
			t.Fatal(err)
		}
		server := "script-security 2\nauth-user-pass-verify " + check + " via-file\n"
		srv := start(t, true, true, "client", server, "auth-user-pass\n")
		c, err := proofDial(t, srv, proofKey(t, "interop", 0x43), "alice", "s3cret")
		if err != nil {
			t.Fatal(err)
		}
		proofPing(t, c)
		c.Close()
		if bad, err := proofDial(t, srv, proofKey(t, "interop", 0x43), "alice", "wrong"); bad != nil || err == nil {
			t.Fatal("proof bypassed the ordinary password check")
		}
	})
	t.Run("auth-token-renegotiation-still-requires-proof", func(t *testing.T) {
		checkDir := t.TempDir()
		count := filepath.Join(checkDir, "password-calls")
		check := proofFile(t, checkDir, "check.sh", []byte("#!/bin/sh\nprintf '.\\n' >> "+count+"\n[ \"$(sed -n 1p \"$1\")\" = alice ] && [ \"$(sed -n 2p \"$1\")\" = s3cret ]\n"))
		if err := os.Chmod(check, 0700); err != nil {
			t.Fatal(err)
		}
		server := "script-security 2\nauth-user-pass-verify " + check + " via-file\nauth-gen-token\nreneg-sec 5\nhand-window 2\n"
		srv := start(t, true, true, "client", server, "auth-user-pass\n")
		c, err := proofDial(t, srv, proofKey(t, "interop", 0x43), "alice", "s3cret")
		if err != nil {
			t.Fatal(err)
		}
		packets := packetReader(c)
		deadline := time.Now().Add(12 * time.Second)
		for seq := uint16(200); time.Now().Before(deadline); seq++ {
			if !pingThrough(c, packets, seq, []byte("auth-token and independent proof"), time.Second) {
				t.Fatal("traffic failed across auth-token rekey")
			}
			time.Sleep(100 * time.Millisecond)
		}
		if strings.Count(proofLog(srv.logPath), "[openvpn-client-proof] authentication accepted") < 3 {
			t.Fatal("proof was not checked across auth-token renegotiation")
		}
		if calls := strings.Count(proofLog(count), "."); calls != 1 {
			t.Fatalf("password callback ran %d times; expected token-authenticated rekeys", calls)
		}
	})
	t.Run("wrong-exporter-label-denied", func(t *testing.T) {
		srv := start(t, true, true, "client", "keying-material-exporter EXPORTER-Wrong-Proof-Label 32\n", "")
		if c, err := proofDial(t, srv, proofKey(t, "interop", 0x43), "", ""); c != nil || err == nil {
			t.Fatal("a mismatched exporter label was admitted")
		}
		if !strings.Contains(proofLog(srv.logPath), "[openvpn-client-proof] authentication rejected") {
			t.Fatal("no server rejection for mismatched exporter")
		}
	})
	t.Run("missing-exporter-denied", func(t *testing.T) {
		index++
		srv := proofStart(t, index, true, true, "client", "", "", true)
		if c, err := proofDial(t, srv, proofKey(t, "interop", 0x43), "", ""); c != nil || err == nil {
			t.Fatal("missing server exporter configuration admitted a connection")
		}
		if !strings.Contains(proofLog(srv.logPath), "[openvpn-client-proof] authentication rejected") {
			t.Fatal("no server rejection for missing exporter")
		}
	})
	if path := os.Getenv("OVPN_CLIENT_PROOF_XRAY"); path != "" {
		for _, protected := range []bool{false, true} {
			t.Run(fmt.Sprintf("full-xray-http-and-udp-protected-%v", protected), func(t *testing.T) {
				srv := start(t, true, protected, "client", "", "")
				proofFullCore(t, path, srv, protected)
			})
		}
		t.Run("full-xray-protected-base64", func(t *testing.T) {
			srv := start(t, false, true, "client", "", "")
			proofFullCore(t, path, srv, true, "base64")
		})
	}
}

func proofFullCore(t *testing.T, bin string, srv *proofOracle, protected bool, format ...string) {
	t.Helper()
	ln, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("OpenVPN ordinary framing and authenticated admission\n"), 1024)
	httpServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(payload) }), ReadHeaderTimeout: time.Second}
	go httpServer.Serve(ln)
	t.Cleanup(func() { httpServer.Close() })
	udp, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	go func() {
		b := make([]byte, 2048)
		for {
			n, a, e := udp.ReadFrom(b)
			if e != nil {
				return
			}
			udp.WriteTo(b[:n], a)
		}
	}()
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	socksPort := probe.Addr().(*net.TCPAddr).Port
	probe.Close()
	settings := map[string]any{"ovpn": srv.text}
	protocol := "ov"
	if protected {
		if len(format) > 0 && format[0] == "base64" {
			settings = map[string]any{"ovpnBase64": base64.StdEncoding.EncodeToString([]byte(srv.text))}
			settings["clientProof"] = map[string]any{"keyId": "interop", "key": hex.EncodeToString(bytes.Repeat([]byte{0x43}, 32))}
		} else {
			remote := parseOpts(t, srv.text).Remotes[0]
			pki := getPKI(t)
			settings = map[string]any{
				"server":       map[string]any{"address": remote.Host, "port": remote.Port, "network": remote.Network},
				"crypto":       map[string]any{"cipher": "AES-256-GCM", "dataCiphers": []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"}, "authHash": "SHA256"},
				"certificates": map[string]any{"ca": string(pki.caPEM), "cert": string(pki.clientCertPEM), "key": string(pki.clientKeyPEM)},
				"advanced":     map[string]any{"dev": "tun", "nobind": true, "remoteCertTls": "server", "mtu": 1400},
			}
			keyFile := proofFile(t, srv.dir, "client-proof.key", []byte(hex.EncodeToString(bytes.Repeat([]byte{0x43}, 32))+"\n"))
			settings["clientProof"] = map[string]any{"keyId": "interop", "keyFile": keyFile}
			protocol = "openvpn" // Exercise the existing alias with structured settings.
		}
	}
	cfg := map[string]any{"log": map[string]any{"loglevel": "warning"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": socksPort, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": true}}}, "outbounds": []any{map[string]any{"protocol": protocol, "settings": settings}}}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := proofFile(t, srv.dir, "xray.json", b)
	log, err := os.OpenFile(filepath.Join(srv.dir, "xray.log"), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "run", "-config", path)
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait(); log.Close() })
	socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)
	proofWait(t, "SOCKS listener", func() bool {
		c, e := net.DialTimeout("tcp", socksAddr, 100*time.Millisecond)
		if c != nil {
			c.Close()
		}
		return e == nil
	})
	d, err := xproxy.SOCKS5("tcp", socksAddr, nil, xproxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{DialContext: d.(xproxy.ContextDialer).DialContext}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	url := fmt.Sprintf("http://%s:%d/blob", srv.tunnelIP, ln.Addr().(*net.TCPAddr).Port)
	res, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(io.LimitReader(res.Body, int64(len(payload)+1)))
	res.Body.Close()
	if err != nil || res.StatusCode != 200 || !bytes.Equal(got, payload) {
		t.Fatal("full-core HTTP payload mismatch")
	}
	proofSOCKSUDP(t, socksAddr, srv.tunnelIP, udp.LocalAddr().(*net.UDPAddr).Port)
}

func proofSOCKSUDP(t *testing.T, socksAddr, targetIP string, targetPort int) {
	t.Helper()
	ctl, err := net.DialTimeout("tcp", socksAddr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer ctl.Close()
	ctl.SetDeadline(time.Now().Add(8 * time.Second))
	ctl.Write([]byte{5, 1, 0})
	hello := make([]byte, 2)
	if _, err = io.ReadFull(ctl, hello); err != nil || !bytes.Equal(hello, []byte{5, 0}) {
		t.Fatal("SOCKS authentication failed")
	}
	ctl.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	reply := make([]byte, 10)
	if _, err = io.ReadFull(ctl, reply); err != nil || reply[1] != 0 || reply[3] != 1 {
		t.Fatal("SOCKS UDP association failed")
	}
	ip := net.IP(reply[4:8])
	if ip.IsUnspecified() {
		ip = net.IPv4(127, 0, 0, 1)
	}
	dst := &net.UDPAddr{IP: ip, Port: int(reply[8])<<8 | int(reply[9])}
	c, err := net.DialUDP("udp4", nil, dst)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(8 * time.Second))
	payload := []byte("actual application UDP through OpenVPN")
	packet := append([]byte{0, 0, 0, 1}, net.ParseIP(targetIP).To4()...)
	packet = append(packet, byte(targetPort>>8), byte(targetPort))
	packet = append(packet, payload...)
	if _, err = c.Write(packet); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 2048)
	n, err := c.Read(b)
	if err != nil || n < 10 || b[3] != 1 || !bytes.Equal(b[10:n], payload) {
		t.Fatal("full-core UDP echo failed")
	}
}
