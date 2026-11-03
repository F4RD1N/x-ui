package ctlwrap

// Tests that use the real OpenVPN binary as the oracle: keys it generates
// must parse, and an OpenVPN 2.6 server must accept what Wrap produces and
// answer with packets Unwrap accepts. They skip when the binary is missing
// or with -short.

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/wire"
)

const openvpnBin = "/usr/sbin/openvpn"

func needOpenVPN(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping OpenVPN oracle test in -short mode")
	}
	if _, err := os.Stat(openvpnBin); err != nil {
		t.Skipf("no %s: %v", openvpnBin, err)
	}
}

// genkey runs "openvpn --genkey args..." in dir.
func genkey(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command(openvpnBin, append([]string{"--genkey"}, args...)...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("openvpn --genkey %v: %v\n%s", args, err, out)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// oracleKeys is a set of keys made by the real binary.
type oracleKeys struct {
	dir      string
	static   *StaticKey
	v2Kc     *StaticKey
	v2WKc    []byte
	v2Server []byte // the 128-byte tls-crypt-v2 server key
}

func makeOracleKeys(t *testing.T) *oracleKeys {
	t.Helper()
	dir := t.TempDir()
	genkey(t, dir, "secret", "ta.key")
	genkey(t, dir, "tls-crypt-v2-server", "v2s.key")
	genkey(t, dir, "tls-crypt-v2-client", "v2c.key", "--tls-crypt-v2", "v2s.key")
	k := &oracleKeys{dir: dir}
	var err error
	if k.static, err = ParseStaticKey(readFile(t, filepath.Join(dir, "ta.key"))); err != nil {
		t.Fatalf("ParseStaticKey(openvpn --genkey secret): %v", err)
	}
	if k.v2Kc, k.v2WKc, err = ParseTLSCryptV2ClientKey(readFile(t, filepath.Join(dir, "v2c.key"))); err != nil {
		t.Fatalf("ParseTLSCryptV2ClientKey(openvpn --genkey tls-crypt-v2-client): %v", err)
	}
	blk, _ := pem.Decode(readFile(t, filepath.Join(dir, "v2s.key")))
	if blk == nil || blk.Type != "OpenVPN tls-crypt-v2 server key" {
		t.Fatalf("tls-crypt-v2 server key is not the expected PEM block")
	}
	k.v2Server = blk.Bytes
	return k
}

// TestOpenVPNGeneratedKeys parses keys made by the real binary and checks
// the WKc against the server key: WKc = T || AES-256-CTR(Ke, T[:16],
// Kc || metadata) || len with T = HMAC-SHA256(Ka, len || Kc || metadata).
// The server key is 128 bytes: a 64-byte cipher part, then a 64-byte hmac
// part.
func TestOpenVPNGeneratedKeys(t *testing.T) {
	needOpenVPN(t)
	k := makeOracleKeys(t)
	if len(k.v2Server) != 128 {
		t.Fatalf("tls-crypt-v2 server key is %d bytes, want 128", len(k.v2Server))
	}
	wkc := k.v2WKc
	if n := int(binary.BigEndian.Uint16(wkc[len(wkc)-2:])); n != len(wkc) {
		t.Fatalf("WKc trailer says %d, WKc is %d bytes", n, len(wkc))
	}
	block, err := aes.NewCipher(k.v2Server[:32])
	if err != nil {
		t.Fatal(err)
	}
	tg, ct, lenField := wkc[:32], wkc[32:len(wkc)-2], wkc[len(wkc)-2:]
	pt := make([]byte, len(ct))
	cipher.NewCTR(block, tg[:16]).XORKeyStream(pt, ct)
	m := hmac.New(sha256.New, k.v2Server[64:96])
	m.Write(lenField)
	m.Write(pt)
	if !hmac.Equal(m.Sum(nil), tg) {
		t.Fatalf("WKc tag does not verify with the server key")
	}
	if !bytes.Equal(pt[:256], k.v2Kc[:]) {
		t.Fatalf("WKc does not wrap the Kc that precedes it")
	}
	t.Logf("WKc: %d bytes, metadata %d bytes (type %d)", len(wkc), len(pt)-256, pt[256])
}

// oracleServer is a running OpenVPN server on 127.0.0.1.
type oracleServer struct {
	addr *net.UDPAddr
	mu   sync.Mutex
	log  bytes.Buffer
}

func (s *oracleServer) logText() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.log.String()
}

// writeCert writes a throwaway self-signed CA certificate and key for the
// server's --ca/--cert/--key.
func writeCert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ctlwrap-oracle"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// startServer runs an OpenVPN tls-server on --dev null with the given extra
// options (p2p unless they say --mode server) and waits until it is bound.
func startServer(t *testing.T, dir string, extra ...string) *oracleServer {
	t.Helper()
	certPath, keyPath := writeCert(t, dir)
	l, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	addr := l.LocalAddr().(*net.UDPAddr)
	l.Close()
	args := []string{
		"--dev", "null", "--proto", "udp4", "--local", "127.0.0.1", "--lport", strconv.Itoa(addr.Port),
		"--tls-server", "--ca", certPath, "--cert", certPath, "--key", keyPath, "--dh", "none",
		"--verb", "3",
	}
	cmd := exec.Command(openvpnBin, append(args, extra...)...)
	cmd.Dir = dir
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	s := &oracleServer{addr: addr}
	ready := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(out)
		once := sync.Once{}
		for sc.Scan() {
			line := sc.Text()
			s.mu.Lock()
			s.log.WriteString(line + "\n")
			s.mu.Unlock()
			if strings.Contains(line, "link local (bound)") {
				once.Do(func() { close(ready) })
			}
		}
	}()
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		if t.Failed() {
			t.Logf("openvpn %s log:\n%s", strings.Join(extra, " "), s.logText())
		}
	})
	select {
	case <-ready:
	case <-time.After(15 * time.Second):
		t.Fatalf("openvpn did not bind within 15s")
	}
	return s
}

// rawPID returns the (time, pid) a wrapped packet carries, for logs.
func rawPID(w Wrapper, b []byte) (uint32, uint32) {
	off := headLen
	if a, ok := w.(*tlsAuth); ok {
		off += a.digest.size
	}
	if len(b) < off+pidLen {
		return 0, 0
	}
	return binary.BigEndian.Uint32(b[off+4:]), binary.BigEndian.Uint32(b[off:])
}

// oracleClient talks to an oracleServer through one Wrapper.
type oracleClient struct {
	t    *testing.T
	conn *net.UDPConn
	w    Wrapper
	sid  wire.SessionID
}

func newOracleClient(t *testing.T, s *oracleServer, w Wrapper) *oracleClient {
	t.Helper()
	conn, err := net.DialUDP("udp4", nil, s.addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	c := &oracleClient{t: t, conn: conn, w: w}
	rand.Read(c.sid[:])
	return c
}

func (c *oracleClient) send(p *wire.ControlPacket) {
	c.t.Helper()
	p.SessionID = c.sid
	b, err := c.w.Wrap(p)
	if err != nil {
		c.t.Fatalf("Wrap(%v): %v", p.Opcode, err)
	}
	if _, err := c.conn.Write(b); err != nil {
		c.t.Fatal(err)
	}
}

// recv returns the next packet within d, nil on timeout. Every packet must
// unwrap: an authentic packet the replay window rejects is a failure.
func (c *oracleClient) recv(d time.Duration) *wire.ControlPacket {
	c.t.Helper()
	buf := make([]byte, 4096)
	c.conn.SetReadDeadline(time.Now().Add(d))
	n, err := c.conn.Read(buf)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return nil
		}
		c.t.Fatal(err)
	}
	tm, pid := rawPID(c.w, buf[:n])
	p, err := c.w.Unwrap(buf[:n])
	if err != nil {
		c.t.Fatalf("Unwrap(server packet of %d bytes, time %d pid %d): %v", n, tm, pid, err)
	}
	c.t.Logf("server sent %v key %d acks %v msg %d (%d payload bytes), wrap time %d pid %d",
		p.Opcode, p.KeyID, p.Acks, p.PacketID, len(p.Payload), tm, pid)
	return p
}

func TestOpenVPNOracle(t *testing.T) {
	needOpenVPN(t)
	k := makeOracleKeys(t)
	ta := filepath.Join(k.dir, "ta.key")
	v2s := filepath.Join(k.dir, "v2s.key")
	mustAuth := func(dir Direction, digest string) Wrapper {
		w, err := NewTLSAuth(k.static, dir, digest)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	mustCrypt := func() Wrapper {
		w, err := NewTLSCrypt(k.static, true)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	mustV2 := func() Wrapper {
		w, err := NewTLSCryptV2Client(k.v2Kc, k.v2WKc)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	serverMode := []string{"--mode", "server", "--dev-type", "tun", "--topology", "subnet",
		"--ifconfig", "10.213.99.1", "255.255.255.0", "--ifconfig-noexec"}
	tests := []struct {
		name   string
		server []string
		client func() Wrapper
		reset  wire.Opcode
		accept bool
	}{
		{"tls-auth-sha1-dir01", []string{"--tls-auth", ta, "0"}, func() Wrapper { return mustAuth(Inverse, "") }, wire.ControlHardResetClientV2, true},
		{"tls-auth-sha256-dir10", []string{"--tls-auth", ta, "1", "--auth", "SHA256"}, func() Wrapper { return mustAuth(Normal, "sha-256") }, wire.ControlHardResetClientV2, true},
		{"tls-auth-sha512-bidir", []string{"--tls-auth", ta, "--auth", "SHA512"}, func() Wrapper { return mustAuth(Bidirectional, "SHA512") }, wire.ControlHardResetClientV2, true},
		{"tls-auth-md5-dir01", []string{"--tls-auth", ta, "0", "--auth", "MD5"}, func() Wrapper { return mustAuth(Inverse, "MD5") }, wire.ControlHardResetClientV2, true},
		{"tls-auth-sha384-dir01", []string{"--tls-auth", ta, "0", "--auth", "SHA384"}, func() Wrapper { return mustAuth(Inverse, "SHA384") }, wire.ControlHardResetClientV2, true},
		{"tls-auth-sha224-dir01", []string{"--tls-auth", ta, "0", "--auth", "SHA224"}, func() Wrapper { return mustAuth(Inverse, "SHA224") }, wire.ControlHardResetClientV2, true},
		{"tls-auth-wrong-direction", []string{"--tls-auth", ta, "0"}, func() Wrapper { return mustAuth(Normal, "") }, wire.ControlHardResetClientV2, false},
		{"tls-auth-wrong-digest", []string{"--tls-auth", ta, "0", "--auth", "SHA256"}, func() Wrapper { return mustAuth(Inverse, "SHA1") }, wire.ControlHardResetClientV2, false},
		{"tls-crypt", []string{"--tls-crypt", ta}, mustCrypt, wire.ControlHardResetClientV2, true},
		{"tls-crypt-v2", []string{"--tls-crypt-v2", v2s}, mustV2, wire.ControlHardResetClientV3, true},
		{"server-tls-auth", append([]string{"--tls-auth", ta, "0"}, serverMode...), func() Wrapper { return mustAuth(Inverse, "") }, wire.ControlHardResetClientV2, true},
		{"server-tls-crypt", append([]string{"--tls-crypt", ta}, serverMode...), mustCrypt, wire.ControlHardResetClientV2, true},
		{"server-tls-crypt-v2", append([]string{"--tls-crypt-v2", v2s}, serverMode...), mustV2, wire.ControlHardResetClientV3, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := startServer(t, t.TempDir(), tc.server...)
			c := newOracleClient(t, s, tc.client())
			c.send(&wire.ControlPacket{Opcode: tc.reset})
			wait := 5 * time.Second
			if !tc.accept {
				wait = 1500 * time.Millisecond
			}
			p := c.recv(wait)
			if !tc.accept {
				if p != nil {
					t.Fatalf("server answered a packet it should have rejected: %v", p.Opcode)
				}
				return
			}
			if p == nil {
				t.Fatalf("no answer to %v within %v", tc.reset, wait)
			}
			if p.Opcode != wire.ControlHardResetServerV2 || p.KeyID != 0 || p.PacketID != 0 ||
				len(p.Acks) != 1 || p.Acks[0] != 0 || p.RemoteSessionID != c.sid {
				t.Fatalf("unexpected reset reply: %+v", p)
			}
			// Continue the session: ack the server's reset and send the
			// first TLS record. A server-mode 2.6 server answers its
			// stateless reset from one context and the rest from the
			// session's own, so this checks that the replay window takes
			// the second context's packets.
			serverSID := p.SessionID
			c.send(&wire.ControlPacket{Opcode: wire.ControlV1, Acks: []wire.PacketID{0}, RemoteSessionID: serverSID,
				PacketID: 1, Payload: []byte{0x16, 0x03, 0x01, 0x01, 0x00}}) // a record header; OpenSSL waits for the rest
			got := false
			for end := time.Now().Add(3 * time.Second); time.Now().Before(end); {
				q := c.recv(time.Until(end))
				if q == nil {
					break
				}
				if q.SessionID != serverSID {
					t.Fatalf("second packet from a different server session")
				}
				for _, a := range q.Acks {
					if a == 1 {
						got = true
					}
				}
				if got {
					break
				}
			}
			if !got {
				t.Fatalf("server never acked message 1")
			}
		})
	}
}
