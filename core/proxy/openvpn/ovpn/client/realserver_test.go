package client

// TestRealServer runs the client against the real OpenVPN 2.6 binary: one
// server per case on 127.0.0.1, an ICMP echo to the server's tunnel address
// through the tunnel. The servers create tun devices, so it runs only as
// root inside a private network namespace, e.g.
//
//	go test -c -o client.test ./proxy/openvpn/ovpn/client/
//	unshare -n sh -c 'ip link set lo up; OVPN_REALSERVER=1 ./client.test -test.run TestRealServer -test.v'

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type captureLogger struct {
	*testLogger
	mu    sync.Mutex
	lines []string
}

func (l *captureLogger) Infof(format string, args ...any) {
	l.mu.Lock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
	l.mu.Unlock()
	l.testLogger.Infof(format, args...)
}

func (l *captureLogger) has(sub string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, s := range l.lines {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func csum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

func icmpEcho(src, dst netip.Addr, id, seq uint16, payload []byte) []byte {
	icmp := make([]byte, 8+len(payload))
	icmp[0] = 8
	binary.BigEndian.PutUint16(icmp[4:], id)
	binary.BigEndian.PutUint16(icmp[6:], seq)
	copy(icmp[8:], payload)
	binary.BigEndian.PutUint16(icmp[2:], csum(icmp))
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(icmp)))
	ip[8], ip[9] = 64, 1
	s4, d4 := src.As4(), dst.As4()
	copy(ip[12:16], s4[:])
	copy(ip[16:20], d4[:])
	binary.BigEndian.PutUint16(ip[10:], csum(ip))
	return append(ip, icmp...)
}

func isEchoReply(p []byte, id, seq uint16, payload []byte) bool {
	if len(p) < 28 || p[0]>>4 != 4 || p[9] != 1 {
		return false
	}
	ihl := int(p[0]&15) * 4
	if len(p) < ihl+8 {
		return false
	}
	icmp := p[ihl:]
	return icmp[0] == 0 && binary.BigEndian.Uint16(icmp[4:]) == id && binary.BigEndian.Uint16(icmp[6:]) == seq &&
		string(icmp[8:]) == string(payload)
}

// pingThrough sends an ICMP echo to the server's tunnel address and waits
// for the reply.
func pingThrough(c *Client, in <-chan []byte, seq uint16, payload []byte, wait time.Duration) bool {
	info := c.Info()
	src := info.IPv4.Addr()
	dst := netip.AddrFrom4([4]byte{src.As4()[0], src.As4()[1], src.As4()[2], 1})
	if c.WritePacket(icmpEcho(src, dst, 0x4242, seq, payload)) != nil {
		return false
	}
	timeout := time.After(wait)
	for {
		select {
		case p, ok := <-in:
			if !ok {
				return false
			}
			if isEchoReply(p, 0x4242, seq, payload) {
				return true
			}
		case <-timeout:
			return false
		}
	}
}

// inPrivateNetns reports whether this process runs in a network namespace
// other than init's.
func inPrivateNetns() bool {
	self, err1 := os.Readlink("/proc/self/ns/net")
	initNS, err2 := os.Readlink("/proc/1/ns/net")
	return err1 == nil && err2 == nil && self != initNS
}

func TestRealServer(t *testing.T) {
	if os.Getenv("OVPN_REALSERVER") == "" {
		t.Skip("set OVPN_REALSERVER=1 (as root, in a private network namespace)")
	}
	if os.Geteuid() != 0 || !inPrivateNetns() {
		t.Skip("needs root in a private network namespace (unshare -n)")
	}
	bin := "/usr/sbin/openvpn"
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("no OpenVPN binary: %v", err)
	}
	dir := t.TempDir()
	p := getPKI(t)
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	write("ca.crt", p.caPEM)
	write("server.crt", p.serverCertPEM)
	write("server.key", p.serverKeyPEM)
	ta := newStaticKey(t)
	write("ta.key", []byte(staticKeyText(ta)))
	write("check.sh", []byte("#!/bin/sh\n[ \"$(sed -n 1p \"$1\")\" = alice ] && [ \"$(sed -n 2p \"$1\")\" = s3cret ]\n"))
	os.Chmod(filepath.Join(dir, "check.sh"), 0o755)
	if out, err := exec.Command(bin, "--genkey", "tls-crypt-v2-server", filepath.Join(dir, "v2srv.key")).CombinedOutput(); err != nil {
		t.Fatalf("genkey: %v %s", err, out)
	}
	if out, err := exec.Command(bin, "--tls-crypt-v2", filepath.Join(dir, "v2srv.key"), "--genkey", "tls-crypt-v2-client", filepath.Join(dir, "v2cli.key")).CombinedOutput(); err != nil {
		t.Fatalf("genkey: %v %s", err, out)
	}
	v2cli, _ := os.ReadFile(filepath.Join(dir, "v2cli.key"))
	taText := staticKeyText(ta)

	userpassServer := "verify-client-cert none\nauth-user-pass-verify " + filepath.Join(dir, "check.sh") + " via-file\nscript-security 2\nusername-as-common-name\n"
	cases := []struct {
		name     string
		tcp      bool
		server   string
		client   string
		cfg      func(*Config)
		wantErr  error
		duration time.Duration
		check    func(t *testing.T, c *Client, l *captureLogger)
		payload  int
		lossSeed uint64
	}{
		{name: "udp-lossy-tlscrypt-1", server: "tls-crypt " + filepath.Join(dir, "ta.key") + "\n", client: "<tls-crypt>\n" + taText + "</tls-crypt>\n", lossSeed: 1},
		{name: "udp-lossy-tlscrypt-2", server: "tls-crypt " + filepath.Join(dir, "ta.key") + "\n", client: "<tls-crypt>\n" + taText + "</tls-crypt>\n", lossSeed: 2},
		{name: "udp-lossy-tlsauth-3", server: "tls-auth " + filepath.Join(dir, "ta.key") + " 0\n", client: "key-direction 1\n<tls-auth>\n" + taText + "</tls-auth>\n", lossSeed: 3},
		{name: "udp-lossy-plain-4", lossSeed: 4},
		{name: "udp-lossy-v2-5", server: "tls-crypt-v2 " + filepath.Join(dir, "v2srv.key") + "\n", client: "<tls-crypt-v2>\n" + string(v2cli) + "</tls-crypt-v2>\n", lossSeed: 5},
		{name: "udp-tlscrypt-gcm", server: "tls-crypt " + filepath.Join(dir, "ta.key") + "\n", client: "<tls-crypt>\n" + taText + "</tls-crypt>\n",
			check: func(t *testing.T, c *Client, l *captureLogger) {
				i := c.Info()
				if i.Cipher != "AES-256-GCM" || i.KeyDerivation != "tls-ekm" || i.TLSVersion != "TLS 1.3" {
					t.Errorf("info %+v", i)
				}
			}},
		{name: "tcp-tlsauth-sha256", tcp: true, server: "tls-auth " + filepath.Join(dir, "ta.key") + " 0\nauth SHA256\n", client: "key-direction 1\n<tls-auth>\n" + taText + "</tls-auth>\nauth SHA256\n"},
		{name: "udp-plain-prf-datav1", cfg: func(c *Config) { c.DisableEKM, c.DisableDataV2 = true, true },
			check: func(t *testing.T, c *Client, l *captureLogger) {
				if c.Info().KeyDerivation != "prf" {
					t.Errorf("info %+v", c.Info())
				}
			}},
		{name: "udp-tlsauth-cbc-sha1", server: "tls-auth " + filepath.Join(dir, "ta.key") + " 0\ndata-ciphers AES-256-CBC\nauth SHA1\n",
			client: "key-direction 1\n<tls-auth>\n" + taText + "</tls-auth>\ndata-ciphers AES-256-GCM:AES-256-CBC\n",
			check: func(t *testing.T, c *Client, l *captureLogger) {
				if c.Info().Cipher != "AES-256-CBC" {
					t.Errorf("info %+v", c.Info())
				}
			}},
		{name: "udp-chacha-userpass", server: userpassServer + "data-ciphers CHACHA20-POLY1305\n", client: "auth-user-pass\n",
			cfg: func(c *Config) { c.Username, c.Password = "alice", "s3cret" }},
		{name: "udp-authfail", server: userpassServer, client: "auth-user-pass\n",
			cfg: func(c *Config) { c.Username, c.Password = "alice", "wrong" }, wantErr: ErrAuthFailed},
		{name: "udp-tlscrypt-v2", server: "tls-crypt-v2 " + filepath.Join(dir, "v2srv.key") + "\n", client: "<tls-crypt-v2>\n" + string(v2cli) + "</tls-crypt-v2>\n"},
		{name: "tcp-tlscrypt-v2", tcp: true, server: "tls-crypt-v2 " + filepath.Join(dir, "v2srv.key") + "\n", client: "<tls-crypt-v2>\n" + string(v2cli) + "</tls-crypt-v2>\n"},
		{name: "tcp-tls12-cbc-sha512", tcp: true, server: "tls-version-max 1.2\ndata-ciphers AES-128-CBC\nauth SHA512\n", client: "data-ciphers AES-256-GCM:AES-128-CBC\nauth SHA512\n",
			check: func(t *testing.T, c *Client, l *captureLogger) {
				i := c.Info()
				if i.Cipher != "AES-128-CBC" || i.TLSVersion != "TLS 1.2" {
					t.Errorf("info %+v", i)
				}
			}},
		{name: "udp-lz4v2", server: "allow-compression yes\ncompress lz4-v2\npush \"compress lz4-v2\"\n", payload: 1000},
		{name: "udp-complzo", server: "allow-compression yes\ncomp-lzo yes\npush \"comp-lzo yes\"\n", payload: 1000},
		{name: "udp-compress-stub", server: "compress\npush \"compress\"\n", payload: 1000},
		{name: "udp-reneg", server: "tls-crypt " + filepath.Join(dir, "ta.key") + "\nreneg-sec 3\n", client: "<tls-crypt>\n" + taText + "</tls-crypt>\n", duration: 8 * time.Second,
			check: func(t *testing.T, c *Client, l *captureLogger) {
				if !l.has("key 2 active") {
					t.Errorf("no second renegotiation")
				}
			}},
		{name: "tcp-reneg-userpass-token", tcp: true, server: userpassServer + "reneg-sec 4\nhand-window 2\nauth-gen-token\n", client: "auth-user-pass\n",
			cfg: func(c *Config) { c.Username, c.Password = "alice", "s3cret" }, duration: 8 * time.Second,
			check: func(t *testing.T, c *Client, l *captureLogger) {
				if !l.has("key 2 active") {
					t.Errorf("no second renegotiation")
				}
			}},
		{name: "udp-client-reneg", server: "tls-crypt " + filepath.Join(dir, "ta.key") + "\n", client: "<tls-crypt>\n" + taText + "</tls-crypt>\nreneg-sec 2\n", duration: 7 * time.Second,
			check: func(t *testing.T, c *Client, l *captureLogger) {
				if !l.has("key 2 active") {
					t.Errorf("no second renegotiation")
				}
			}},
		// The auth-token outlives its 5s lifetime at the second
		// renegotiation: the server refuses it, the session ends with
		// ErrAuthTokenRejected, and a new session with the username and
		// password works, as OpenVPN's own client restarts there.
		{name: "tcp-reneg-token-expired", tcp: true, server: userpassServer + "reneg-sec 3\nhand-window 2\nauth-gen-token 5 4\n", client: "auth-user-pass\n",
			cfg: func(c *Config) { c.Username, c.Password = "alice", "s3cret" },
			check: func(t *testing.T, c *Client, l *captureLogger) {
				select {
				case <-c.Done():
				case <-time.After(20 * time.Second):
					t.Fatal("the session outlived its auth-token")
				}
				if err := c.Err(); !errors.Is(err, ErrAuthFailed) || !errors.Is(err, ErrAuthTokenRejected) {
					t.Fatalf("session ended with %v, want ErrAuthFailed and ErrAuthTokenRejected", err)
				}
				again, err := Dial(context.Background(), c.d.cfg)
				if err != nil {
					t.Fatalf("logging in again with the username and password: %v", err)
				}
				again.Close()
			}},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			port := 21194 + i
			proto := "udp4"
			if tc.tcp {
				proto = "tcp4-server"
			}
			conf := fmt.Sprintf("local 127.0.0.1\nport %d\nproto %s\ndev tun\ntopology subnet\nserver 10.99.%d.0 255.255.255.0\n"+
				"ca %s\ncert %s\nkey %s\ndh none\nkeepalive 10 60\nverb 4\n%s",
				port, proto, i+1, filepath.Join(dir, "ca.crt"), filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"), tc.server)
			confPath := write(tc.name+".conf", []byte(conf))
			logPath := filepath.Join(dir, tc.name+".log")
			logf, _ := os.Create(logPath)
			cmd := exec.Command(bin, "--config", confPath)
			cmd.Stdout, cmd.Stderr = logf, logf
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				cmd.Process.Kill()
				cmd.Wait()
				logf.Close()
				if t.Failed() || testing.Verbose() {
					b, _ := os.ReadFile(logPath)
					t.Logf("server log:\n%s", b)
				}
			}()
			deadline := time.Now().Add(10 * time.Second)
			for {
				b, _ := os.ReadFile(logPath)
				if strings.Contains(string(b), "Initialization Sequence Completed") {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("server did not start")
				}
				time.Sleep(50 * time.Millisecond)
			}
			netw := "udp"
			if tc.tcp {
				netw = "tcp"
			}
			remotePort := port
			var relay *lossyRelay
			if tc.lossSeed != 0 {
				relay = startRelayTo(t, port, tc.lossSeed)
				relay.loss.Store(20)
				relay.jitter.Store(int64(15 * time.Millisecond))
				remotePort = relay.port()
			}
			o := parseOpts(t, ovpnText(t, fmt.Sprintf("remote 127.0.0.1 %d %s\n", remotePort, netw)+tc.client))
			l := &captureLogger{testLogger: newTestLogger(t)}
			cfg := Config{Options: o, Dial: netDial, Logger: l, HandshakeTimeout: 50 * time.Second}
			if tc.cfg != nil {
				tc.cfg(&cfg)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 55*time.Second)
			defer cancel()
			start := time.Now()
			c, err := Dial(ctx, cfg)
			if relay != nil {
				t.Logf("lossy handshake took %v, relay dropped %d", time.Since(start), relay.lost.Load())
				relay.loss.Store(0)
				relay.jitter.Store(0)
			}
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				t.Logf("got expected error: %v", err)
				return
			}
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer c.Close()
			t.Logf("info: %+v", c.Info())
			in := packetReader(c)
			payload := []byte("hello through the tunnel")
			if tc.payload > 0 {
				payload = make([]byte, tc.payload) // compressible
			}
			ok := 0
			for seq := uint16(1); seq <= 5; seq++ {
				if pingThrough(c, in, seq, payload, 2*time.Second) {
					ok++
				}
			}
			if ok < 5 {
				t.Fatalf("%d of 5 pings answered", ok)
			}
			if tc.duration > 0 {
				end := time.Now().Add(tc.duration)
				sent, got := 0, 0
				lastOK := time.Time{}
				for seq := uint16(100); time.Now().Before(end); seq++ {
					sent++
					if pingThrough(c, in, seq, payload, 500*time.Millisecond) {
						got++
						lastOK = time.Now()
					}
					time.Sleep(50 * time.Millisecond)
				}
				t.Logf("long run: %d/%d pings answered", got, sent)
				if time.Since(lastOK) > time.Second || got < sent*8/10 {
					t.Errorf("traffic did not keep flowing: %d/%d, last reply %v ago", got, sent, time.Since(lastOK))
				}
				if c.Err() != nil {
					t.Fatalf("session ended: %v", c.Err())
				}
			}
			if tc.check != nil {
				tc.check(t, c, l)
			}
			c.Close()
			time.Sleep(300 * time.Millisecond)
		})
	}
}
