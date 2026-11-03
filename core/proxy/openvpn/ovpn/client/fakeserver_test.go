package client

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/compress"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/ctlwrap"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/datachan"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/handshake"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/reliable"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/wire"
)

// ---------------------------------------------------------------------------
// Test PKI

type testPKI struct {
	caPEM         []byte
	clientCertPEM []byte
	clientKeyPEM  []byte
	serverCertPEM []byte
	serverKeyPEM  []byte
	serverCert    tls.Certificate
	pool          *x509.CertPool
}

var (
	pkiOnce sync.Once
	pkiVal  *testPKI
	pkiErr  error
)

func getPKI(t testing.TB) *testPKI {
	t.Helper()
	pkiOnce.Do(func() { pkiVal, pkiErr = makePKI() })
	if pkiErr != nil {
		t.Fatalf("making the test PKI: %v", pkiErr)
	}
	return pkiVal
}

func makePKI() (*testPKI, error) {
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	leaf := func(serial int64, cn string, eku x509.ExtKeyUsage) (certPEM, keyPEM []byte, err error) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    now.Add(-time.Hour),
			NotAfter:     now.Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{eku},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &k.PublicKey, caKey)
		if err != nil {
			return nil, nil, err
		}
		kder, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), nil
	}
	p := &testPKI{caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})}
	srvCert, srvKey, err := leaf(2, "server", x509.ExtKeyUsageServerAuth)
	if err != nil {
		return nil, err
	}
	if p.clientCertPEM, p.clientKeyPEM, err = leaf(3, "client", x509.ExtKeyUsageClientAuth); err != nil {
		return nil, err
	}
	p.serverCertPEM, p.serverKeyPEM = srvCert, srvKey
	if p.serverCert, err = tls.X509KeyPair(srvCert, srvKey); err != nil {
		return nil, err
	}
	p.pool = x509.NewCertPool()
	p.pool.AddCert(ca)
	return p, nil
}

func newStaticKey(t testing.TB) *ctlwrap.StaticKey {
	t.Helper()
	var k ctlwrap.StaticKey
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	return &k
}

func staticKeyText(k *ctlwrap.StaticKey) string {
	var b strings.Builder
	b.WriteString("#\n# 2048 bit OpenVPN static key\n#\n-----BEGIN OpenVPN Static key V1-----\n")
	for i := 0; i < len(k); i += 16 {
		b.WriteString(hex.EncodeToString(k[i : i+16]))
		b.WriteByte('\n')
	}
	b.WriteString("-----END OpenVPN Static key V1-----\n")
	return b.String()
}

// ---------------------------------------------------------------------------
// Fake OpenVPN server, built from the leaf packages in server direction.

type srvConfig struct {
	// observePeerInfo observes decrypted metadata and its matching TLS state.
	observePeerInfo func(string, tls.ConnectionState)
	tcp             bool
	wrap            string // "", "tls-auth", "tls-crypt", "tls-crypt-v2"
	key             *ctlwrap.StaticKey
	wkc             []byte // tls-crypt-v2: the client's wrapped key, as the client appends it

	cipher string // pushed cipher ("" pushes none)
	// occCipher is the cipher a server that pushes none runs and names in
	// its options string (default BF-CBC, as an old server).
	occCipher string
	// auth is the server's --auth (the CBC data digest, default SHA1);
	// pushAuth is an "auth" option it pushes, which a real server does
	// not apply to itself.
	auth, pushAuth string
	noPeerID       bool   // never push a peer-id
	ekm            bool   // push key-derivation tls-ekm when the client can export
	compress       string // "", "stub-v2", "lzo-no"
	ccExit         bool
	authToken      string
	extraPush      []string
	split          bool          // push-continuation
	pushEarly      bool          // push right after the key exchange when asked
	authFail       string        // answer PUSH_REQUEST with AUTH_FAILED,<reason>
	hangUp         bool          // TCP: close the connection right after AUTH_FAILED
	renegAuthFail  string        // answer each later key exchange with AUTH_FAILED,<reason>
	authPending    time.Duration // AUTH_PENDING, then push this much later
	// authPendingMsg replaces the "AUTH_PENDING" message.
	authPendingMsg string
	renegAfter     time.Duration // server-initiated renegotiation interval
	tlsMin, tlsMax uint16
	// noTLSReply acknowledges the client's TLS records but never answers
	// them (a server with no TLS version or cipher suite in common, over
	// UDP); noKeyMethod finishes TLS but never sends key-method 2.
	noTLSReply, noKeyMethod bool
	reliable                reliable.Options
}

type srvStats struct {
	sessions     int
	exchanges    int
	usernames    []string
	passwords    []string
	ivProto      uint32
	peerInfo     string
	options      string
	pushRequests int
	echoed       int
	pings        int
	exitMsgs     int
	occExits     int
	occRequests  int
	badData      int
	dataOps      map[wire.Opcode]int
	dataKeys     map[uint8]int
	clientResets int
	serverResets int
	lastKeyAt    time.Time
	ctlPackets   int
	maxCtl       int // largest control packet received, wrapped
	v3Resets     int // P_CONTROL_HARD_RESET_CLIENT_V3 with the right WKc
}

type srvPacket struct {
	b    []byte
	from *net.UDPAddr
	conn net.Conn
}

const (
	srvEvClientMsg = iota
	srvEvMessage
	srvEvError
)

type srvEvent struct {
	sess *srvSession
	key  *srvKey
	kind int
	cm   *handshake.ClientMessage
	cs   tls.ConnectionState
	msg  string
	err  error
}

type srvKey struct {
	id          uint8
	layer       *reliable.Layer
	adapter     *tlsAdapter
	tls         *tls.Conn
	exchanged   bool
	established time.Time
}

type srvSession struct {
	clientSID, serverSID wire.SessionID
	peer                 *net.UDPAddr
	conn                 net.Conn
	wrapper              ctlwrap.Wrapper
	keys                 map[uint8]*srvKey
	primary, lame        *srvKey
	negotiating          *srvKey
	lastKeyID            uint8
	data                 *datachan.Channel
	useEKM               bool
	peerID               uint32
	cipher, digest       string
	comp                 compress.Mode
	pushed               bool
	pendingUntil         time.Time
	hangUp               bool // close the TCP connection after the next flush
}

type fakeServer struct {
	t       testing.TB
	cfg     srvConfig
	tlsConf *tls.Config
	udp     *net.UDPConn
	ln      net.Listener
	port    int

	in     chan srvPacket
	events chan srvEvent
	wake   chan struct{}
	cmds   chan func()
	quit   chan struct{}
	wg     sync.WaitGroup
	silent atomic.Bool
	once   sync.Once

	tcpMu    sync.Mutex
	tcpConns []net.Conn

	mu    sync.Mutex
	stats srvStats

	sess *srvSession // owned by the loop
}

func startServer(t testing.TB, cfg srvConfig) *fakeServer {
	t.Helper()
	p := getPKI(t)
	s := &fakeServer{
		t:      t,
		cfg:    cfg,
		in:     make(chan srvPacket, 1024),
		events: make(chan srvEvent, 64),
		wake:   make(chan struct{}, 1),
		cmds:   make(chan func()),
		quit:   make(chan struct{}),
	}
	s.stats.dataOps = map[wire.Opcode]int{}
	s.stats.dataKeys = map[uint8]int{}
	s.tlsConf = &tls.Config{
		Certificates: []tls.Certificate{p.serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    p.pool,
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   cfg.tlsMax,
	}
	if cfg.tlsMin != 0 {
		s.tlsConf.MinVersion = cfg.tlsMin
	}
	if cfg.tlsMax != 0 && cfg.tlsMax < tls.VersionTLS12 {
		s.tlsConf.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA}
	}
	if cfg.tcp {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		s.ln = ln
		s.port = ln.Addr().(*net.TCPAddr).Port
		s.wg.Add(1)
		go s.acceptLoop()
	} else {
		u, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		s.udp = u
		s.port = u.LocalAddr().(*net.UDPAddr).Port
		s.wg.Add(1)
		go s.udpLoop()
	}
	s.wg.Add(1)
	go s.loop()
	t.Cleanup(s.Close)
	return s
}

// remoteLine is the client config line that reaches this server.
func (s *fakeServer) remoteLine() string {
	proto := "udp"
	if s.cfg.tcp {
		proto = "tcp"
	}
	return fmt.Sprintf("remote 127.0.0.1 %d %s\n", s.port, proto)
}

func (s *fakeServer) Close() {
	s.once.Do(func() {
		close(s.quit)
		if s.udp != nil {
			s.udp.Close()
		}
		if s.ln != nil {
			s.ln.Close()
		}
		s.tcpMu.Lock()
		for _, c := range s.tcpConns {
			c.Close()
		}
		s.tcpMu.Unlock()
		s.wg.Wait()
	})
}

func (s *fakeServer) snapshot() srvStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stats
	st.dataOps = map[wire.Opcode]int{}
	for k, v := range s.stats.dataOps {
		st.dataOps[k] = v
	}
	st.dataKeys = map[uint8]int{}
	for k, v := range s.stats.dataKeys {
		st.dataKeys[k] = v
	}
	st.usernames = append([]string(nil), s.stats.usernames...)
	st.passwords = append([]string(nil), s.stats.passwords...)
	return st
}

func (s *fakeServer) stat(f func(*srvStats)) {
	s.mu.Lock()
	f(&s.stats)
	s.mu.Unlock()
}

// do runs f on the server loop.
func (s *fakeServer) do(f func()) {
	done := make(chan struct{})
	select {
	case s.cmds <- func() { f(); close(done) }:
		<-done
	case <-s.quit:
	}
}

// sendControl sends a control message on the session's primary key.
func (s *fakeServer) sendControl(msg string) {
	s.do(func() {
		if s.sess != nil && s.sess.primary != nil {
			s.writeMsg(s.sess.primary, msg)
		}
	})
}

func (s *fakeServer) udpLoop() {
	defer s.wg.Done()
	buf := make([]byte, 65536)
	for {
		n, from, err := s.udp.ReadFromUDP(buf)
		if err != nil {
			return
		}
		select {
		case s.in <- srvPacket{b: append([]byte(nil), buf[:n]...), from: from}:
		case <-s.quit:
			return
		}
	}
}

func (s *fakeServer) acceptLoop() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.tcpMu.Lock()
		s.tcpConns = append(s.tcpConns, c)
		s.tcpMu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer c.Close()
			fr := wire.NewFrameReader(c)
			buf := make([]byte, 65536)
			for {
				n, err := fr.ReadPacket(buf)
				if err != nil {
					return
				}
				select {
				case s.in <- srvPacket{b: append([]byte(nil), buf[:n]...), conn: c}:
				case <-s.quit:
					return
				}
			}
		}()
	}
}

func (s *fakeServer) signalWake() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *fakeServer) loop() {
	defer s.wg.Done()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	defer s.endSession()
	for {
		select {
		case <-s.quit:
			return
		case p := <-s.in:
			s.handlePacket(p)
		case ev := <-s.events:
			s.handleEvent(ev)
		case f := <-s.cmds:
			f()
		case <-s.wake:
		case <-tick.C:
			s.timers()
		}
		s.flush()
		if sess := s.sess; sess != nil && sess.hangUp && sess.conn != nil {
			sess.conn.Close()
			s.endSession()
		}
	}
}

func (s *fakeServer) endSession() {
	if s.sess == nil {
		return
	}
	for _, k := range s.sess.keys {
		k.adapter.Close()
	}
	s.sess = nil
}

func (s *fakeServer) newWrapper() ctlwrap.Wrapper {
	var (
		w   ctlwrap.Wrapper
		err error
	)
	switch s.cfg.wrap {
	case "tls-auth":
		// --auth is also tls-auth's HMAC digest.
		w, err = ctlwrap.NewTLSAuth(s.cfg.key, ctlwrap.Normal, s.cfg.auth)
	case "tls-crypt", "tls-crypt-v2":
		w, err = ctlwrap.NewTLSCrypt(s.cfg.key, false)
	default:
		w = ctlwrap.NewPlain()
	}
	if err != nil {
		panic(err)
	}
	return w
}

func (s *fakeServer) relOptions() reliable.Options {
	o := s.cfg.reliable
	if s.cfg.tcp {
		o.InitialTimeout = -1
	}
	return o
}

func (s *fakeServer) handlePacket(p srvPacket) {
	if s.silent.Load() || len(p.b) == 0 {
		return
	}
	now := time.Now()
	op, keyID := wire.SplitHeader(p.b[0])
	sess := s.sess
	if op.IsData() {
		if sess == nil || sess.data == nil {
			return
		}
		out, kind, err := sess.data.Open(nil, p.b)
		if err != nil {
			s.stat(func(st *srvStats) { st.badData++ })
			return
		}
		s.stat(func(st *srvStats) { st.dataOps[op]++; st.dataKeys[keyID]++ })
		switch kind {
		case datachan.KindPacket:
			pkt, err := sess.data.Seal(nil, out)
			if err == nil {
				s.write(sess, pkt)
				s.stat(func(st *srvStats) { st.echoed++ })
			}
		case datachan.KindPing:
			s.stat(func(st *srvStats) { st.pings++ })
			if pkt, err := sess.data.SealPing(nil); err == nil {
				s.write(sess, pkt)
			}
		case datachan.KindOCC:
			if len(out) > 0 && out[0] == datachan.OCCExit {
				s.stat(func(st *srvStats) { st.occExits++ })
			}
			if len(out) > 0 && out[0] == 0 { // OCC_REQUEST: answer OCC_REPLY
				s.stat(func(st *srvStats) { st.occRequests++ })
				if pkt, err := sess.data.SealOCC(nil, 1); err == nil {
					s.write(sess, pkt)
				}
			}
		}
		return
	}
	if !op.IsControl() || len(p.b) < 9 {
		return
	}
	s.stat(func(st *srvStats) { st.ctlPackets++; st.maxCtl = max(st.maxCtl, len(p.b)) })
	if s.cfg.wrap == "tls-crypt-v2" && (op == wire.ControlHardResetClientV3 || op == wire.ControlWKCV1) {
		// The server knows Kc already; it only checks and strips WKc.
		if !bytes.HasSuffix(p.b, s.cfg.wkc) {
			return
		}
		p.b = p.b[:len(p.b)-len(s.cfg.wkc)]
		s.stat(func(st *srvStats) { st.v3Resets++ })
	}
	var w ctlwrap.Wrapper
	isNew := false
	if (op == wire.ControlHardResetClientV2 || op == wire.ControlHardResetClientV3) && keyID == 0 {
		var sid wire.SessionID
		copy(sid[:], p.b[1:9])
		if sess == nil || sess.clientSID != sid {
			w, isNew = s.newWrapper(), true
		}
	}
	if !isNew {
		if sess == nil {
			return
		}
		w = sess.wrapper
	}
	cp, err := w.Unwrap(p.b)
	if err != nil {
		return
	}
	if isNew {
		s.endSession()
		sess = &srvSession{clientSID: cp.SessionID, peer: p.from, conn: p.conn, wrapper: w, keys: map[uint8]*srvKey{}, peerID: wire.NoPeerID}
		rand.Read(sess.serverSID[:])
		s.sess = sess
		s.stat(func(st *srvStats) { st.sessions++ })
		k := s.newKey(sess, 0, wire.ControlHardResetServerV2)
		sess.primary = k
		s.startTLS(sess, k)
	}
	if cp.SessionID != sess.clientSID {
		return
	}
	if len(cp.Acks) > 0 && cp.RemoteSessionID != sess.serverSID {
		return
	}
	k := sess.keys[cp.KeyID]
	if k == nil {
		if cp.Opcode != wire.ControlSoftResetV1 || sess.data == nil {
			return
		}
		if sess.negotiating != nil {
			s.dropKey(sess, sess.negotiating)
		}
		k = s.newKey(sess, cp.KeyID, wire.ControlSoftResetV1)
		sess.negotiating = k
		s.startTLS(sess, k)
		s.stat(func(st *srvStats) { st.clientResets++ })
	}
	for _, m := range k.layer.Receive(cp, now) {
		switch {
		case m.Opcode != wire.ControlV1:
		case s.cfg.noTLSReply:
			// Over TCP, OpenVPN closes the connection on a TLS failure.
			sess.hangUp = sess.conn != nil
		default:
			k.adapter.deliver(m.Payload)
		}
	}
}

// sendDataPing sends the server's keepalive ping, unasked.
func (s *fakeServer) sendDataPing() {
	s.do(func() {
		if sess := s.sess; sess != nil && sess.data != nil {
			if pkt, err := sess.data.SealPing(nil); err == nil {
				s.write(sess, pkt)
			}
		}
	})
}

func (s *fakeServer) newKey(sess *srvSession, id uint8, op wire.Opcode) *srvKey {
	k := &srvKey{
		id:      id,
		layer:   reliable.New(s.relOptions()),
		adapter: newTLSAdapter(1000, s.signalWake, nil, nil),
	}
	k.layer.Send(op, nil)
	sess.keys[id] = k
	sess.lastKeyID = id
	return k
}

func (s *fakeServer) dropKey(sess *srvSession, k *srvKey) {
	k.adapter.Close()
	delete(sess.keys, k.id)
	if sess.data != nil && k.exchanged {
		sess.data.DropKey(k.id)
	}
	if sess.negotiating == k {
		sess.negotiating = nil
	}
	if sess.lame == k {
		sess.lame = nil
	}
}

func (s *fakeServer) startTLS(sess *srvSession, k *srvKey) {
	k.tls = tls.Server(k.adapter, s.tlsConf)
	s.wg.Add(1)
	go s.runKey(sess, k)
}

func (s *fakeServer) runKey(sess *srvSession, k *srvKey) {
	defer s.wg.Done()
	report := func(ev srvEvent) bool {
		ev.sess, ev.key = sess, k
		select {
		case s.events <- ev:
			return true
		case <-s.quit:
			return false
		}
	}
	tc := k.tls
	if err := tc.Handshake(); err != nil {
		report(srvEvent{kind: srvEvError, err: err})
		return
	}
	var buf []byte
	tmp := make([]byte, 16<<10)
	var cm *handshake.ClientMessage
	for cm == nil {
		n, err := tc.Read(tmp)
		buf = append(buf, tmp[:n]...)
		m, used, perr := handshake.ParseClientMessage(buf)
		if perr == nil {
			cm, buf = m, buf[used:]
			break
		}
		if !errors.Is(perr, handshake.ErrShort) {
			report(srvEvent{kind: srvEvError, err: perr})
			return
		}
		if err != nil {
			report(srvEvent{kind: srvEvError, err: err})
			return
		}
	}
	if !report(srvEvent{kind: srvEvClientMsg, cm: cm, cs: tc.ConnectionState()}) {
		return
	}
	pending := buf
	for {
		var msgs []string
		msgs, pending = splitControlMessages(pending)
		for _, m := range msgs {
			if !report(srvEvent{kind: srvEvMessage, msg: m}) {
				return
			}
		}
		n, err := tc.Read(tmp)
		pending = append(pending, tmp[:n]...)
		if err != nil {
			return
		}
	}
}

func ivProto(peerInfo string) uint32 {
	for _, line := range strings.Split(peerInfo, "\n") {
		if v, ok := strings.CutPrefix(line, "IV_PROTO="); ok {
			var n uint32
			fmt.Sscan(v, &n)
			return n
		}
	}
	return 0
}

func (s *fakeServer) handleEvent(ev srvEvent) {
	sess, k := ev.sess, ev.key
	if sess != s.sess || sess.keys[k.id] != k {
		return
	}
	switch ev.kind {
	case srvEvError:
		return
	case srvEvClientMsg:
		s.keyExchange(sess, k, ev.cm, ev.cs)
	case srvEvMessage:
		s.controlMessage(sess, k, ev.msg)
	}
}

// keyExchange installs the key's data keys and answers the client's
// key-method 2 message.
func (s *fakeServer) keyExchange(sess *srvSession, k *srvKey, cm *handshake.ClientMessage, cs tls.ConnectionState) {
	proto := ivProto(cm.PeerInfo)
	s.stat(func(st *srvStats) {
		st.exchanges++
		st.usernames = append(st.usernames, cm.Username)
		st.passwords = append(st.passwords, cm.Password)
		st.ivProto = proto
		st.peerInfo = cm.PeerInfo
		st.options = cm.Options
		st.lastKeyAt = time.Now()
	})
	if s.cfg.observePeerInfo != nil {
		s.cfg.observePeerInfo(cm.PeerInfo, cs)
	}

	first := sess.data == nil
	if first {
		sess.useEKM = s.cfg.ekm && proto&handshake.IVProtoTLSKeyExport != 0
		if proto&handshake.IVProtoDataV2 != 0 && !s.cfg.noPeerID {
			sess.peerID = 7
		}
		sess.cipher = s.cfg.cipher
		if sess.cipher == "" {
			sess.cipher = s.cfg.occCipher
		}
		if sess.cipher == "" {
			sess.cipher = "BF-CBC"
		}
		sess.digest = s.cfg.auth
		if sess.digest == "" {
			sess.digest = "SHA1"
		}
		switch s.cfg.compress {
		case "stub-v2":
			sess.comp = compress.V2
		case "lzo-no":
			sess.comp = compress.LZO
		}
	}
	var src handshake.ServerKeySource
	rand.Read(src.Random1[:])
	rand.Read(src.Random2[:])
	var k2 *handshake.Key2
	if sess.useEKM {
		ekm, err := cs.ExportKeyingMaterial(handshake.EKMLabel, nil, handshake.EKMLength)
		if err != nil {
			s.t.Errorf("fake server: EKM: %v", err)
			return
		}
		if k2, err = handshake.Key2FromEKM(ekm); err != nil {
			s.t.Errorf("fake server: Key2FromEKM: %v", err)
			return
		}
	} else {
		k2 = handshake.DeriveKey2PRF(&cm.Source, &src, sess.clientSID, sess.serverSID)
	}
	dk, err := datachan.NewKeyState(k.id, sess.cipher, sess.digest, k2.ServerSend(), k2.ServerRecv())
	if err != nil {
		s.t.Errorf("fake server: NewKeyState(%s, %s): %v", sess.cipher, sess.digest, err)
		return
	}
	if first {
		sess.data = datachan.New(datachan.Options{PeerID: sess.peerID, Compression: sess.comp})
	}
	sess.data.SetPrimary(dk)
	k.exchanged = true
	k.established = time.Now()
	if !first {
		if sess.lame != nil {
			s.dropKey(sess, sess.lame)
		}
		sess.lame = sess.primary
		sess.primary = k
		sess.negotiating = nil
	}
	if s.cfg.noKeyMethod {
		return
	}
	occAuth := sess.digest
	if datachan.IsAEAD(sess.cipher) {
		occAuth = "[null-digest]"
	}
	sm := handshake.ServerMessage{Source: src, Options: fmt.Sprintf("V4,dev-type tun,link-mtu 1549,tun-mtu 1500,proto UDPv4,cipher %s,auth %s,keysize 256,key-method 2,tls-server", sess.cipher, occAuth)}
	if _, err := k.tls.Write(sm.Marshal()); err != nil {
		return
	}
	if first && s.cfg.pushEarly && proto&handshake.IVProtoRequestPush != 0 {
		s.push(sess, k)
	}
	if !first && s.cfg.renegAuthFail != "" {
		s.writeMsg(k, "AUTH_FAILED,"+s.cfg.renegAuthFail)
	}
}

func (s *fakeServer) controlMessage(sess *srvSession, k *srvKey, msg string) {
	switch {
	case msg == "PUSH_REQUEST":
		s.stat(func(st *srvStats) { st.pushRequests++ })
		switch {
		case s.cfg.authFail != "":
			s.writeMsg(k, "AUTH_FAILED,"+s.cfg.authFail)
			sess.hangUp = s.cfg.hangUp
		case s.cfg.authPending > 0 && sess.pendingUntil.IsZero():
			msg := "AUTH_PENDING"
			if s.cfg.authPendingMsg != "" {
				msg = s.cfg.authPendingMsg
			}
			s.writeMsg(k, msg)
			s.writeMsg(k, "INFO_PRE,waiting for approval")
			sess.pendingUntil = time.Now().Add(s.cfg.authPending)
		case s.cfg.authPending > 0 && time.Now().Before(sess.pendingUntil):
		default:
			s.push(sess, k)
		}
	case msg == "EXIT":
		s.stat(func(st *srvStats) { st.exitMsgs++ })
	}
}

func (s *fakeServer) pushOptions(sess *srvSession) []string {
	opts := []string{"route-gateway 10.8.0.1", "topology subnet", "ping 10", "ping-restart 60",
		"ifconfig 10.8.0.2 255.255.255.0", "ifconfig-ipv6 fd00::2/64 fd00::1", "dhcp-option DNS 10.8.0.1"}
	if sess.peerID != wire.NoPeerID {
		opts = append(opts, fmt.Sprintf("peer-id %d", sess.peerID))
	}
	if s.cfg.cipher != "" {
		opts = append(opts, "cipher "+s.cfg.cipher)
	}
	if s.cfg.pushAuth != "" {
		opts = append(opts, "auth "+s.cfg.pushAuth)
	}
	if sess.useEKM {
		opts = append(opts, "key-derivation tls-ekm")
	}
	if s.cfg.ccExit {
		opts = append(opts, "protocol-flags cc-exit")
	}
	switch s.cfg.compress {
	case "stub-v2":
		opts = append(opts, "compress stub-v2")
	case "lzo-no":
		opts = append(opts, "comp-lzo no")
	}
	if s.cfg.authToken != "" {
		opts = append(opts, "auth-token "+s.cfg.authToken)
	}
	return append(opts, s.cfg.extraPush...)
}

func (s *fakeServer) push(sess *srvSession, k *srvKey) {
	opts := s.pushOptions(sess)
	if s.cfg.split {
		h := len(opts) / 2
		s.writeMsg(k, "PUSH_REPLY,"+strings.Join(opts[:h], ",")+",push-continuation 2")
		s.writeMsg(k, "PUSH_REPLY,"+strings.Join(opts[h:], ",")+",push-continuation 1")
	} else {
		s.writeMsg(k, "PUSH_REPLY,"+strings.Join(opts, ","))
	}
	sess.pushed = true
}

func (s *fakeServer) writeMsg(k *srvKey, msg string) {
	if k.tls == nil || !k.exchanged {
		return
	}
	k.tls.Write(append([]byte(msg), 0))
}

func (s *fakeServer) timers() {
	sess := s.sess
	if sess == nil || sess.data == nil || s.silent.Load() {
		return
	}
	now := time.Now()
	if s.cfg.authPending > 0 && !sess.pushed && !sess.pendingUntil.IsZero() && now.After(sess.pendingUntil) {
		s.push(sess, sess.primary)
	}
	if s.cfg.renegAfter > 0 && sess.pushed && sess.negotiating == nil && now.Sub(sess.primary.established) >= s.cfg.renegAfter {
		id := sess.lastKeyID + 1
		if id&wire.KeyIDMask == 0 {
			id = 1
		}
		id &= wire.KeyIDMask
		if old := sess.keys[id]; old != nil {
			s.dropKey(sess, old)
		}
		k := s.newKey(sess, id, wire.ControlSoftResetV1)
		sess.negotiating = k
		s.startTLS(sess, k)
		s.stat(func(st *srvStats) { st.serverResets++ })
	}
}

func (s *fakeServer) flush() {
	sess := s.sess
	if sess == nil || s.silent.Load() {
		return
	}
	now := time.Now()
	for _, k := range sess.keys {
		for _, chunk := range k.adapter.takeOut() {
			k.layer.Send(wire.ControlV1, chunk)
		}
		for _, p := range k.layer.Poll(now) {
			p.KeyID = k.id
			p.SessionID = sess.serverSID
			p.RemoteSessionID = sess.clientSID
			b, err := sess.wrapper.Wrap(p)
			if err != nil {
				s.t.Errorf("fake server: wrap: %v", err)
				continue
			}
			s.write(sess, b)
		}
	}
}

func (s *fakeServer) write(sess *srvSession, b []byte) {
	if s.silent.Load() {
		return
	}
	if sess.conn != nil {
		f, _ := wire.AppendFrame(nil, b)
		sess.conn.Write(f)
		return
	}
	s.udp.WriteToUDP(b, sess.peer)
}

// ---------------------------------------------------------------------------
// Lossy, reordering UDP relay.

type lossyRelay struct {
	front  *net.UDPConn // the client talks to this
	back   *net.UDPConn // connected to the server
	loss   atomic.Int32 // percent
	jitter atomic.Int64 // max extra delay, reorders packets
	client atomic.Pointer[net.UDPAddr]
	mu     sync.Mutex
	seed   uint64
	quit   chan struct{}
	wg     sync.WaitGroup
	lost   atomic.Int64
}

func startRelay(t testing.TB, server *fakeServer, seed uint64) *lossyRelay {
	return startRelayTo(t, server.port, seed)
}

// startRelayTo relays between a client and the UDP server on 127.0.0.1:port.
func startRelayTo(t testing.TB, port int, seed uint64) *lossyRelay {
	t.Helper()
	front, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	back, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	r := &lossyRelay{front: front, back: back, seed: seed | 1, quit: make(chan struct{})}
	r.wg.Add(2)
	go r.run(true)
	go r.run(false)
	t.Cleanup(func() {
		close(r.quit)
		front.Close()
		back.Close()
		r.wg.Wait()
	})
	return r
}

func (r *lossyRelay) port() int { return r.front.LocalAddr().(*net.UDPAddr).Port }

// rnd is xorshift64, deterministic per seed.
func (r *lossyRelay) rnd() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	x := r.seed
	x ^= x << 13
	x ^= x >> 7
	x ^= x << 17
	r.seed = x
	return x
}

func (r *lossyRelay) run(fromClient bool) {
	defer r.wg.Done()
	buf := make([]byte, 65536)
	for {
		var (
			n   int
			err error
		)
		if fromClient {
			var from *net.UDPAddr
			n, from, err = r.front.ReadFromUDP(buf)
			if err == nil {
				r.client.Store(from)
			}
		} else {
			n, err = r.back.Read(buf)
		}
		if err != nil {
			return
		}
		if l := r.loss.Load(); l > 0 && int32(r.rnd()%100) < l {
			r.lost.Add(1)
			continue
		}
		pkt := append([]byte(nil), buf[:n]...)
		send := func() {
			select {
			case <-r.quit:
				return
			default:
			}
			if fromClient {
				r.back.Write(pkt)
			} else if c := r.client.Load(); c != nil {
				r.front.WriteToUDP(pkt, c)
			}
		}
		if j := r.jitter.Load(); j > 0 {
			d := time.Duration(r.rnd() % uint64(j))
			r.wg.Add(1)
			time.AfterFunc(d, func() { defer r.wg.Done(); send() })
			continue
		}
		send()
	}
}

// ---------------------------------------------------------------------------
// Helpers

type testLogger struct {
	t    testing.TB
	mu   sync.Mutex
	done bool
}

func newTestLogger(t testing.TB) *testLogger {
	l := &testLogger{t: t}
	t.Cleanup(func() { l.mu.Lock(); l.done = true; l.mu.Unlock() })
	return l
}

func (l *testLogger) logf(level, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.done {
		l.t.Logf("%s %s %s", time.Now().Format("15:04:05.000"), level, fmt.Sprintf(format, args...))
	}
}

func (l *testLogger) Debugf(format string, args ...any) { l.logf("D", format, args...) }
func (l *testLogger) Infof(format string, args ...any)  { l.logf("I", format, args...) }
func (l *testLogger) Warnf(format string, args ...any)  { l.logf("W", format, args...) }

// ovpnText is a client config for the test PKI; body adds lines (remotes,
// keys, ...).
func ovpnText(t testing.TB, body string) string {
	p := getPKI(t)
	var b bytes.Buffer
	b.WriteString("client\ndev tun\nnobind\nremote-cert-tls server\n")
	b.WriteString(body)
	fmt.Fprintf(&b, "<ca>\n%s</ca>\n<cert>\n%s</cert>\n<key>\n%s</key>\n", p.caPEM, p.clientCertPEM, p.clientKeyPEM)
	return b.String()
}

// wrapLines is the client config for a server's control channel protection.
func wrapLines(cfg srvConfig) string {
	switch cfg.wrap {
	case "tls-auth":
		return "key-direction 1\n<tls-auth>\n" + staticKeyText(cfg.key) + "</tls-auth>\n"
	case "tls-crypt":
		return "<tls-crypt>\n" + staticKeyText(cfg.key) + "</tls-crypt>\n"
	case "tls-crypt-v2":
		blob := append(append([]byte(nil), cfg.key[:]...), cfg.wkc...)
		return "<tls-crypt-v2>\n" + string(pem.EncodeToMemory(&pem.Block{Type: "OpenVPN tls-crypt-v2 client key", Bytes: blob})) + "</tls-crypt-v2>\n"
	}
	return ""
}

// newV2Config fills in a tls-crypt-v2 client key Kc and a made-up WKc (the
// fake server never unwraps it).
func newV2Config(t testing.TB, cfg srvConfig) srvConfig {
	cfg.wrap = "tls-crypt-v2"
	cfg.key = newStaticKey(t)
	cfg.wkc = make([]byte, 300)
	rand.Read(cfg.wkc)
	cfg.wkc[298], cfg.wkc[299] = byte(len(cfg.wkc)>>8), byte(len(cfg.wkc))
	return cfg
}

func netDial(ctx context.Context, network, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

// packetReader collects what ReadPacket returns.
func packetReader(c *Client) <-chan []byte {
	ch := make(chan []byte, 4096)
	go func() {
		defer close(ch)
		buf := make([]byte, 65536)
		for {
			n, err := c.ReadPacket(buf)
			if err != nil {
				return
			}
			ch <- append([]byte(nil), buf[:n]...)
		}
	}()
	return ch
}

// testPacket is an IPv4-looking packet carrying seq.
func testPacket(seq uint32, size int) []byte {
	p := make([]byte, max(size, 24))
	p[0] = 0x45
	p[20], p[21], p[22], p[23] = byte(seq>>24), byte(seq>>16), byte(seq>>8), byte(seq)
	for i := 24; i < len(p); i++ {
		p[i] = byte(i + int(seq))
	}
	return p
}

// echo sends packets and waits for each echo, retrying a few times.
func echo(t testing.TB, c *Client, in <-chan []byte, count, size int) {
	t.Helper()
	for i := 0; i < count; i++ {
		want := testPacket(uint32(i)+1000, size)
		ok := false
		for try := 0; try < 10 && !ok; try++ {
			if err := c.WritePacket(want); err != nil {
				t.Fatalf("WritePacket: %v", err)
			}
			deadline := time.After(300 * time.Millisecond)
		wait:
			for {
				select {
				case got, open := <-in:
					if !open {
						t.Fatalf("session ended: %v", c.Err())
					}
					if bytes.Equal(got, want) {
						ok = true
						break wait
					}
				case <-deadline:
					break wait
				}
			}
		}
		if !ok {
			t.Fatalf("packet %d was not echoed", i)
		}
	}
}

func waitFor(t testing.TB, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
