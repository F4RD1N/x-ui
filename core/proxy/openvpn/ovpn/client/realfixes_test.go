package client

// TestRealServerFixes runs the liveness, negotiation and diagnosis fixes
// against the real OpenVPN 2.6 binary, like TestRealServer (root, a private
// network namespace, OVPN_REALSERVER=1):
//
//	go test -c -o client.test ./proxy/openvpn/ovpn/client/
//	unshare -n sh -c 'ip link set lo up; OVPN_REALSERVER=1 ./client.test -test.run TestRealServerFixes -test.v'

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type realServer struct {
	t    *testing.T
	cmd  *exec.Cmd
	conf string
	log  string
}

// startReal starts an OpenVPN server with conf and waits until it is up.
func startReal(t *testing.T, dir, name, conf string) *realServer {
	t.Helper()
	s := &realServer{t: t, conf: filepath.Join(dir, name+".conf"), log: filepath.Join(dir, name+".log")}
	if err := os.WriteFile(s.conf, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	s.start()
	t.Cleanup(func() {
		s.kill()
		if t.Failed() || testing.Verbose() {
			b, _ := os.ReadFile(s.log)
			t.Logf("server log %s:\n%s", name, b)
		}
	})
	return s
}

func (s *realServer) start() {
	s.t.Helper()
	logf, err := os.OpenFile(s.log, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		s.t.Fatal(err)
	}
	before, _ := os.ReadFile(s.log)
	s.cmd = exec.Command("/usr/sbin/openvpn", "--config", s.conf)
	s.cmd.Stdout, s.cmd.Stderr = logf, logf
	if err := s.cmd.Start(); err != nil {
		s.t.Fatal(err)
	}
	logf.Close()
	deadline := time.Now().Add(10 * time.Second)
	for {
		b, _ := os.ReadFile(s.log)
		if strings.Contains(string(b[len(before):]), "Initialization Sequence Completed") {
			return
		}
		if time.Now().After(deadline) {
			s.t.Fatalf("server did not start:\n%s", b)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (s *realServer) kill() {
	if s.cmd != nil && s.cmd.Process != nil {
		s.cmd.Process.Kill()
		s.cmd.Wait()
		s.cmd = nil
	}
}

func (s *realServer) logHas(sub string) bool {
	b, _ := os.ReadFile(s.log)
	return strings.Contains(string(b), sub)
}

// unconnectedUDP is a UDP transport like Xray's PacketConnWrapper: an
// unconnected socket that writes to one destination.
type unconnectedUDP struct {
	*net.UDPConn
	dst *net.UDPAddr
}

func (u *unconnectedUDP) Write(b []byte) (int, error) { return u.WriteToUDP(b, u.dst) }
func (u *unconnectedUDP) Read(b []byte) (int, error) {
	n, _, err := u.ReadFromUDP(b)
	return n, err
}
func (u *unconnectedUDP) RemoteAddr() net.Addr { return u.dst }

func dialUnconnected(ctx context.Context, network, address string) (net.Conn, error) {
	if !strings.HasPrefix(network, "udp") {
		return netDial(ctx, network, address)
	}
	dst, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		return nil, err
	}
	c, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, err
	}
	return &unconnectedUDP{UDPConn: c, dst: dst}, nil
}

// rsaPKI is a CA, an RSA server certificate and a client certificate, for
// servers that need an RSA key (DHE-RSA suites).
type rsaPKI struct {
	caPEM, serverCert, serverKey, clientCert, clientKey []byte
}

func makeRSAPKI(t *testing.T) *rsaPKI {
	t.Helper()
	now := time.Now()
	key := func() *rsa.PrivateKey {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	caKey := key()
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "RSA Test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leaf := func(serial int64, cn string, eku x509.ExtKeyUsage) (certPEM, keyPEM []byte) {
		k := key()
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{eku}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &k.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	}
	p := &rsaPKI{caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})}
	p.serverCert, p.serverKey = leaf(2, "server", x509.ExtKeyUsageServerAuth)
	p.clientCert, p.clientKey = leaf(3, "client", x509.ExtKeyUsageClientAuth)
	return p
}

func TestRealServerFixes(t *testing.T) {
	if os.Getenv("OVPN_REALSERVER") == "" {
		t.Skip("set OVPN_REALSERVER=1 (as root, in a private network namespace)")
	}
	if os.Geteuid() != 0 || !inPrivateNetns() {
		t.Skip("needs root in a private network namespace (unshare -n)")
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
	ca, crt, key := write("ca.crt", p.caPEM), write("server.crt", p.serverCertPEM), write("server.key", p.serverKeyPEM)
	nextNet := 0
	serverConf := func(port int, tcp bool, extra string) string {
		nextNet++
		proto := "udp4"
		if tcp {
			proto = "tcp4-server"
		}
		return fmt.Sprintf("local 127.0.0.1\nport %d\nproto %s\ndev tun\ntopology subnet\nserver 10.97.%d.0 255.255.255.0\nca %s\ncert %s\nkey %s\nverb 4\n%s",
			port, proto, nextNet, ca, crt, key, extra)
	}
	dial := func(t *testing.T, port int, tcp bool, client string, cfg func(*Config)) (*Client, error) {
		netw := "udp"
		if tcp {
			netw = "tcp"
		}
		o := parseOpts(t, ovpnText(t, fmt.Sprintf("remote 127.0.0.1 %d %s\n", port, netw)+client))
		c := Config{Options: o, Dial: dialUnconnected, Logger: &captureLogger{testLogger: newTestLogger(t)}, HandshakeTimeout: 20 * time.Second}
		if cfg != nil {
			cfg(&c)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cl, err := Dial(ctx, c)
		if cl != nil {
			t.Cleanup(func() { cl.Close() })
		}
		return cl, err
	}
	pings := func(t *testing.T, c *Client, in <-chan []byte, n int) int {
		ok := 0
		for seq := uint16(1); seq <= uint16(n); seq++ {
			if pingThrough(c, in, seq, []byte("hello through the tunnel"), 2*time.Second) {
				ok++
			}
		}
		return ok
	}

	// hostile-1 / concurrency-1: a TCP server that stops (SIGSTOP) while
	// the client uploads; ping-restart must still end the session.
	for i, uplink := range []bool{false, true} {
		t.Run(fmt.Sprintf("tcp-stopped-server/uplink=%v", uplink), func(t *testing.T) {
			port := 31400 + i
			srv := startReal(t, dir, fmt.Sprintf("stall-%d", i), serverConf(port, true, "dh none\nkeepalive 1 3\n"))
			c, err := dial(t, port, true, "", nil)
			if err != nil {
				t.Fatal(err)
			}
			in := packetReader(c)
			if n := pings(t, c, in, 2); n != 2 {
				t.Fatalf("%d of 2 pings answered", n)
			}
			var writes atomic.Int64
			var lastReturn atomic.Int64
			start := time.Now()
			upDone := make(chan struct{})
			if uplink {
				info := c.Info()
				src := info.IPv4.Addr()
				dst := src.Prev()
				pkt := icmpEcho(src, dst, 7, 7, make([]byte, 1372))
				go func() {
					defer close(upDone)
					for c.Err() == nil {
						c.WritePacket(pkt)
						lastReturn.Store(int64(time.Since(start)))
						writes.Add(1)
					}
				}()
				time.Sleep(200 * time.Millisecond) // fill the buffers
			} else {
				close(upDone)
			}
			stopped := time.Now()
			if err := syscall.Kill(srv.cmd.Process.Pid, syscall.SIGSTOP); err != nil {
				t.Fatal(err)
			}
			select {
			case <-c.Done():
			case <-time.After(10 * time.Second):
				t.Fatalf("pushed ping-restart 3s, but the session is still up %v after the server stopped (%d writes)", time.Since(stopped).Round(time.Millisecond), writes.Load())
			}
			ended := time.Since(stopped)
			t.Logf("session ended %v after the server stopped: %v (%d writes)", ended.Round(time.Millisecond), c.Err(), writes.Load())
			if !errors.Is(c.Err(), ErrPingTimeout) || ended > 4500*time.Millisecond {
				t.Errorf("Err = %v after %v, want ErrPingTimeout within ping-restart 3s + 1.5s", c.Err(), ended)
			}
			select {
			case <-upDone:
				if d := time.Duration(lastReturn.Load()) - stopped.Sub(start) - ended; uplink && d > time.Second {
					t.Errorf("the uploader returned %v after the session ended", d)
				}
			case <-time.After(2 * time.Second):
				t.Errorf("the uploader is still blocked 2s after the session ended")
			}
		})
	}

	// liveness-1 / concurrency-2: no keepalive anywhere. The client-mode
	// default (shortened here) ends the session once the server is gone,
	// and OCC probes keep it up while the server lives.
	t.Run("udp-no-keepalive", func(t *testing.T) {
		port := 31410
		srv := startReal(t, dir, "nokeepalive", serverConf(port, false, "dh none\n"))
		const def = 4 * time.Second
		c, err := dial(t, port, false, "", func(c *Config) { c.hooks = &testHooks{defaultPingRestart: def} })
		if err != nil {
			t.Fatal(err)
		}
		in := packetReader(c)
		if n := pings(t, c, in, 2); n != 2 {
			t.Fatalf("%d of 2 pings answered", n)
		}
		time.Sleep(def + 2*time.Second) // idle
		if err := c.Err(); err != nil {
			t.Fatalf("an idle session to a live server without keepalive ended: %v", err)
		}
		if n := pings(t, c, in, 2); n != 2 {
			t.Fatalf("after idling, %d of 2 pings answered", n)
		}
		srv.kill()
		killed := time.Now()
		srv.start() // a fresh server on the same port knows nothing of the session
		go func() {
			for seq := uint16(100); c.Err() == nil; seq++ {
				pingThrough(c, in, seq, []byte("x"), 500*time.Millisecond)
			}
		}()
		select {
		case <-c.Done():
		case <-time.After(def + 6*time.Second):
			t.Fatalf("no ping-restart %v after the server was restarted", time.Since(killed).Round(time.Millisecond))
		}
		t.Logf("session ended %v after the server restart: %v", time.Since(killed).Round(time.Millisecond), c.Err())
		if !errors.Is(c.Err(), ErrPingTimeout) {
			t.Errorf("Err = %v, want ErrPingTimeout", c.Err())
		}
	})

	// liveness-2: EPERM on sendto (a firewall rule, as during a network
	// change) for 2 s must not end a UDP session.
	t.Run("udp-eperm-blip", func(t *testing.T) {
		port := 31411
		startReal(t, dir, "eperm", serverConf(port, false, "dh none\nkeepalive 10 60\n"))
		c, err := dial(t, port, false, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		in := packetReader(c)
		if n := pings(t, c, in, 2); n != 2 {
			t.Fatalf("%d of 2 pings answered", n)
		}
		rule := []string{"OUTPUT", "-p", "udp", "--dport", fmt.Sprint(port), "-j", "DROP"}
		if out, err := exec.Command("iptables", append([]string{"-I"}, rule...)...).CombinedOutput(); err != nil {
			t.Skipf("iptables: %v %s", err, out)
		}
		var werr error
		end := time.Now().Add(2 * time.Second)
		for time.Now().Before(end) {
			if err := c.WritePacket(testPacket(1, 100)); err != nil {
				werr = err
			}
			time.Sleep(50 * time.Millisecond)
		}
		exec.Command("iptables", append([]string{"-D"}, rule...)...).Run()
		t.Logf("write error during the block: %v", werr)
		if !errors.Is(werr, syscall.EPERM) {
			t.Errorf("no EPERM while the rule was in place (%v)", werr)
		}
		if err := c.Err(); err != nil {
			t.Fatalf("the session ended: %v", err)
		}
		if n := pings(t, c, in, 5); n != 5 {
			t.Fatalf("after the block, %d of 5 pings answered", n)
		}
	})

	// crypto-3: a server that pushes "auth SHA256" but runs auth SHA1.
	t.Run("udp-pushed-auth-ignored", func(t *testing.T) {
		port := 31412
		startReal(t, dir, "pushauth", serverConf(port, false, "dh none\nkeepalive 10 60\ndata-ciphers AES-256-CBC\nauth SHA1\npush \"auth SHA256\"\n"))
		c, err := dial(t, port, false, "data-ciphers AES-256-GCM:AES-256-CBC\n", nil)
		if err != nil {
			t.Fatal(err)
		}
		if c.Info().Cipher != "AES-256-CBC" {
			t.Fatalf("cipher %q", c.Info().Cipher)
		}
		if n := pings(t, c, packetReader(c), 5); n != 5 {
			t.Fatalf("%d of 5 pings answered", n)
		}
	})

	// crypto-2 / legacy-3: nothing pushed (filtered); the server's options
	// string names AES-256-CBC, which data-ciphers allows.
	t.Run("udp-no-pushed-cipher", func(t *testing.T) {
		port := 31413
		startReal(t, dir, "nopushcipher", serverConf(port, false, "dh none\nkeepalive 10 60\ndata-ciphers AES-256-CBC\ndata-ciphers-fallback AES-256-CBC\n"))
		c, err := dial(t, port, false, "data-ciphers AES-256-GCM:AES-256-CBC\npull-filter ignore \"cipher\"\n", nil)
		if err != nil {
			t.Fatal(err)
		}
		if c.Info().Cipher != "AES-256-CBC" {
			t.Fatalf("cipher %q, want the server's AES-256-CBC", c.Info().Cipher)
		}
		if n := pings(t, c, packetReader(c), 5); n != 5 {
			t.Fatalf("%d of 5 pings answered", n)
		}
	})

	// legacy-1: a server limited to TLS 1.0 fails at once, saying why.
	for i, tcp := range []bool{false, true} {
		t.Run(fmt.Sprintf("tls-1.0/tcp=%v", tcp), func(t *testing.T) {
			port := 31414 + i
			startReal(t, dir, fmt.Sprintf("tls10-%d", i), serverConf(port, tcp, "dh none\nkeepalive 10 60\ntls-version-min 1.0\ntls-version-max 1.0\ntls-cipher DEFAULT:@SECLEVEL=0\n"))
			start := time.Now()
			_, err := dial(t, port, tcp, "", nil)
			t.Logf("after %v: %v", time.Since(start).Round(time.Millisecond), err)
			if err == nil || !strings.Contains(err.Error(), "TLS 1.0") {
				t.Fatalf("err = %v, want one that names TLS 1.0", err)
			}
			if d := time.Since(start); d > 3*time.Second {
				t.Errorf("failed after %v", d)
			}
		})
	}

	// legacy-2: a DHE-only server (TLS 1.2 max) shares no cipher suite
	// with crypto/tls; the error says so instead of a bare timeout.
	rp := makeRSAPKI(t)
	dh := filepath.Join(dir, "dh.pem")
	if out, err := exec.Command("openssl", "genpkey", "-genparam", "-algorithm", "DH", "-pkeyopt", "group:ffdhe2048", "-out", dh).CombinedOutput(); err != nil {
		t.Fatalf("openssl: %v %s", err, out)
	}
	rca, rcrt, rkey := write("rsa-ca.crt", rp.caPEM), write("rsa-server.crt", rp.serverCert), write("rsa-server.key", rp.serverKey)
	for i, tcp := range []bool{false, true} {
		t.Run(fmt.Sprintf("dhe-only/tcp=%v", tcp), func(t *testing.T) {
			port := 31416 + i
			proto := "udp4"
			if tcp {
				proto = "tcp4-server"
			}
			conf := fmt.Sprintf("local 127.0.0.1\nport %d\nproto %s\ndev tun\ntopology subnet\nserver 10.97.%d.0 255.255.255.0\nca %s\ncert %s\nkey %s\ndh %s\nverb 4\nkeepalive 10 60\n"+
				"tls-version-max 1.2\ntls-cipher TLS-DHE-RSA-WITH-AES-256-GCM-SHA384:TLS-DHE-RSA-WITH-AES-256-CBC-SHA\n", port, proto, 200+i, rca, rcrt, rkey, dh)
			srv := startReal(t, dir, fmt.Sprintf("dhe-%d", i), conf)
			netw := "udp"
			if tcp {
				netw = "tcp"
			}
			text := fmt.Sprintf("client\ndev tun\nnobind\nremote-cert-tls server\nremote 127.0.0.1 %d %s\n<ca>\n%s</ca>\n<cert>\n%s</cert>\n<key>\n%s</key>\n",
				port, netw, rp.caPEM, rp.clientCert, rp.clientKey)
			o := parseOpts(t, text)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			_, err := Dial(ctx, Config{Options: o, Dial: dialUnconnected, Logger: newTestLogger(t), HandshakeTimeout: 4 * time.Second})
			t.Logf("err: %v", err)
			if err == nil || !strings.Contains(err.Error(), "no TLS reply") {
				t.Errorf("err = %v, want the no-TLS-reply hint", err)
			}
			if !srv.logHas("no shared cipher") {
				t.Errorf("the server did not report 'no shared cipher'")
			}
		})
	}
	// Control: the same RSA server with default suites works.
	t.Run("rsa-default-control", func(t *testing.T) {
		port := 31418
		conf := fmt.Sprintf("local 127.0.0.1\nport %d\nproto udp4\ndev tun\ntopology subnet\nserver 10.97.210.0 255.255.255.0\nca %s\ncert %s\nkey %s\ndh none\nverb 4\nkeepalive 10 60\ntls-version-max 1.2\n", port, rca, rcrt, rkey)
		startReal(t, dir, "rsa-control", conf)
		text := fmt.Sprintf("client\ndev tun\nnobind\nremote-cert-tls server\nremote 127.0.0.1 %d udp\n<ca>\n%s</ca>\n<cert>\n%s</cert>\n<key>\n%s</key>\n", port, rp.caPEM, rp.clientCert, rp.clientKey)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		c, err := Dial(ctx, Config{Options: parseOpts(t, text), Dial: dialUnconnected, Logger: newTestLogger(t), HandshakeTimeout: 10 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if n := pings(t, c, packetReader(c), 3); n != 3 {
			t.Fatalf("%d of 3 pings answered", n)
		}
	})

	// concurrency-4: deferred authentication through the management
	// interface (client-pending-auth with a timeout) longer than the
	// client's handshake window.
	t.Run("auth-pending-timeout", func(t *testing.T) {
		port, mport := 31419, 31420
		startReal(t, dir, "pending", serverConf(port, false, fmt.Sprintf("dh none\nkeepalive 10 60\nmanagement 127.0.0.1 %d\nmanagement-client-auth\nauth-user-pass-optional\n", mport)))
		mc, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", mport))
		if err != nil {
			t.Fatal(err)
		}
		defer mc.Close()
		const approveAfter = 7 * time.Second
		mgmtDone := make(chan error, 1)
		go func() {
			r := bufio.NewReader(mc)
			var cid, kid string
			for {
				line, err := r.ReadString('\n')
				if err != nil {
					mgmtDone <- err
					return
				}
				line = strings.TrimSpace(line)
				if rest, ok := strings.CutPrefix(line, ">CLIENT:CONNECT,"); ok {
					f := strings.Split(rest, ",")
					cid, kid = f[0], f[1]
				}
				if line == ">CLIENT:ENV,END" && cid != "" {
					fmt.Fprintf(mc, "client-pending-auth %s %s WEB_AUTH::http://127.0.0.1/approve 30\n", cid, kid)
					time.Sleep(approveAfter)
					fmt.Fprintf(mc, "client-auth-nt %s %s\n", cid, kid)
					mgmtDone <- nil
					return
				}
			}
		}()
		start := time.Now()
		c, err := dial(t, port, false, "", func(c *Config) { c.HandshakeTimeout = 4 * time.Second })
		t.Logf("after %v: %v", time.Since(start).Round(time.Millisecond), err)
		if err != nil {
			t.Fatalf("Dial with a pending authentication approved after %v (hand-window 4s): %v", approveAfter, err)
		}
		if n := pings(t, c, packetReader(c), 2); n != 2 {
			t.Fatalf("%d of 2 pings answered", n)
		}
		select {
		case err := <-mgmtDone:
			if err != nil {
				t.Errorf("management: %v", err)
			}
		case <-time.After(time.Second):
		}
	})
}
