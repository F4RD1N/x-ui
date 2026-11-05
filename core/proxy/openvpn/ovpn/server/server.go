// Package server implements one native OpenVPN control/data session. The caller
// owns accepting TCP or demultiplexing UDP, address allocation, identity policy,
// and routing decrypted IP packets. No process or kernel tunnel is started.
package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/ctlwrap"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/datachan"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/handshake"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/reliable"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/wire"
)

var (
	ErrAuthentication   = errors.New("openvpn server: authentication failed")
	ErrHandshakeTimeout = errors.New("openvpn server: handshake timed out")
	ErrIdleTimeout      = errors.New("openvpn server: idle timeout")
	ErrBacklog          = errors.New("openvpn server: bounded queue exhausted")
	ErrInternal         = errors.New("openvpn server: internal session failure")
)

// PacketConn carries complete OpenVPN wire packets; TCP framing is supplied by
// the caller. Close must interrupt both ReadPacket and WritePacket promptly.
type PacketConn interface {
	ReadPacket([]byte) (int, error)
	WritePacket([]byte) error
	Close() error
}

// Admission describes an authenticated identity and caller-allocated tunnel
// settings. Push must contain individual comma-free OpenVPN push directives.
// Identity is stable across all TLS key generations of one session.
type Admission struct {
	Identity string
	Push     []string
}

type Config struct {
	// PeerID is the caller-assigned 24-bit DATA_V2 identifier (zero is valid).
	PeerID uint32

	TLSConfig     *tls.Config
	Ciphers       []string
	Auth          string
	Wrapper       string // empty, tls-auth, tls-crypt, tls-crypt-v2
	StaticKey     *ctlwrap.StaticKey
	KeyDirection  ctlwrap.Direction
	TLSCryptV2Key *ctlwrap.TLSCryptV2ServerKey
	// Authenticate must enforce ordinary credentials and optional clientProof.
	// It runs after a verified TLS handshake on EVERY key exchange, before keys
	// are installed, and must honor context cancellation. Return generic errors.
	Authenticate                               func(context.Context, *handshake.ClientMessage, tls.ConnectionState) (Admission, error)
	Renegotiate, HandshakeTimeout, IdleTimeout time.Duration
	TCP                                        bool
}

type keyState struct {
	dataKey              *datachan.KeyState
	controlEnded         bool
	id                   uint8
	layer                *reliable.Layer
	adapter              *tlsAdapter
	tls                  *tls.Conn
	created, established time.Time
	exchanged            bool
}
type event struct {
	key       *keyState
	cm        *handshake.ClientMessage
	state     tls.ConnectionState
	admission Admission
	msg       string
	err       error
}
type writeRequest struct {
	packet []byte
	result chan error
}

// Session owns one peer. Public methods are safe for concurrent use.
type Session struct {
	cfg         Config
	conn        PacketConn
	ctx         context.Context
	cancel      context.CancelFunc
	done, ready chan struct{}
	once        sync.Once
	wg          sync.WaitGroup
	mu          sync.Mutex
	err         error
	identity    string
	incoming    chan []byte
	outgoing    chan []byte
	received    chan []byte
	writes      chan writeRequest
	events      chan event
	ioErrors    chan error
	wake        chan struct{}
	// Below is owned exclusively by loop.
	wrapper                                      ctlwrap.Wrapper
	clientSID, serverSID                         wire.SessionID
	started                                      bool
	keys                                         map[uint8]*keyState
	primary, old, negotiating                    *keyState
	sendKey                                      *keyState
	data                                         *datachan.Channel
	admission                                    Admission
	cipher                                       string
	ekm                                          bool
	peerID                                       uint32
	began, lastAuthenticated, lastPing, lastPush time.Time
}

// Serve waits for the first successful admission. It owns and closes conn on
// both success and failure. No data is made available before authentication.
func Serve(ctx context.Context, conn PacketConn, cfg Config) (*Session, error) {
	if conn == nil {
		return nil, errors.New("openvpn server: missing transport")
	}
	if err := ctx.Err(); err != nil {
		conn.Close()
		return nil, err
	}
	if err := validate(&cfg); err != nil {
		conn.Close()
		return nil, err
	}
	wrapper, err := makeWrapper(cfg)
	if err != nil {
		conn.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	s := &Session{cfg: cfg, conn: conn, ctx: ctx, cancel: cancel, done: make(chan struct{}), ready: make(chan struct{}), incoming: make(chan []byte, 64), outgoing: make(chan []byte, 256), received: make(chan []byte, 256), writes: make(chan writeRequest), events: make(chan event, 16), ioErrors: make(chan error, 2), wake: make(chan struct{}, 1), wrapper: wrapper, keys: make(map[uint8]*keyState), peerID: wire.NoPeerID, began: time.Now(), lastAuthenticated: time.Now(), lastPing: time.Now()}
	s.wg.Add(2)
	go s.reader()
	go s.writer()
	go s.loop()
	select {
	case <-s.ready:
		return s, nil
	case <-s.done:
		return nil, s.Err()
	case <-ctx.Done():
		s.Close()
		return nil, s.Err()
	}
}

func validate(c *Config) error {
	if c.PeerID >= wire.NoPeerID {
		return errors.New("openvpn server: peer ID exceeds 24-bit usable range")
	}
	if c.TLSConfig == nil || len(c.TLSConfig.Certificates) == 0 && c.TLSConfig.GetCertificate == nil {
		return errors.New("openvpn server: TLS server certificate required")
	}
	if c.Authenticate == nil {
		return errors.New("openvpn server: explicit admission policy required")
	}
	c.TLSConfig = c.TLSConfig.Clone()
	if c.TLSConfig.MinVersion < tls.VersionTLS12 {
		c.TLSConfig.MinVersion = tls.VersionTLS12
	}
	if c.TLSConfig.MaxVersion != 0 && c.TLSConfig.MaxVersion < tls.VersionTLS12 {
		return errors.New("openvpn server: TLS 1.2 or newer required")
	}
	// OpenVPN generates fresh TLS sessions per rekey; resumption could omit the
	// certificate identity or unexpectedly share TLS exporter state.
	c.TLSConfig.SessionTicketsDisabled = true
	if len(c.Ciphers) == 0 {
		c.Ciphers = []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"}
	} else {
		c.Ciphers = append([]string(nil), c.Ciphers...)
	}
	if c.Auth == "" {
		c.Auth = "SHA256"
	}
	var k handshake.Key
	seen := map[string]bool{}
	for i, cipher := range c.Ciphers {
		canonical, ok := datachan.CanonicalCipher(cipher)
		if !ok {
			return errors.New("openvpn server: unsupported data cipher")
		}
		cipher = canonical
		c.Ciphers[i] = canonical
		if seen[cipher] {
			return errors.New("openvpn server: duplicate data cipher")
		}
		seen[cipher] = true
		if _, err := datachan.NewKeyState(0, cipher, c.Auth, &k, &k); err != nil {
			return err
		}
	}
	if c.HandshakeTimeout == 0 {
		c.HandshakeTimeout = 30 * time.Second
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = 120 * time.Second
	}
	if c.Renegotiate == 0 {
		c.Renegotiate = time.Hour
	}
	if c.HandshakeTimeout < 0 || c.IdleTimeout < 0 || c.Renegotiate < 0 {
		return errors.New("openvpn server: negative timeout")
	}
	return nil
}
func makeWrapper(c Config) (ctlwrap.Wrapper, error) {
	switch c.Wrapper {
	case "":
		return ctlwrap.NewPlain(), nil
	case "tls-auth":
		return ctlwrap.NewTLSAuth(c.StaticKey, c.KeyDirection, c.Auth)
	case "tls-crypt":
		return ctlwrap.NewTLSCrypt(c.StaticKey, false)
	case "tls-crypt-v2":
		return ctlwrap.NewTLSCryptV2Server(c.TLSCryptV2Key)
	default:
		return nil, errors.New("openvpn server: unsupported control wrapper")
	}
}
func (s *Session) Identity() string      { s.mu.Lock(); defer s.mu.Unlock(); return s.identity }
func (s *Session) Err() error            { s.mu.Lock(); defer s.mu.Unlock(); return s.err }
func (s *Session) Done() <-chan struct{} { return s.done }
func (s *Session) Close() error          { s.cancel(); s.closeTransport(); <-s.done; return nil }
func (s *Session) ReadPacket(b []byte) (int, error) {
	select {
	case p := <-s.received:
		if len(b) < len(p) {
			return 0, io.ErrShortBuffer
		}
		return copy(b, p), nil
	case <-s.done:
		return 0, s.Err()
	}
}
func (s *Session) WritePacket(b []byte) error {
	if len(b) == 0 || len(b) > 65535 {
		return errors.New("openvpn server: invalid packet length")
	}
	r := writeRequest{packet: bytes.Clone(b), result: make(chan error, 1)}
	select {
	case s.writes <- r:
	case <-s.done:
		return s.Err()
	}
	select {
	case err := <-r.result:
		return err
	case <-s.done:
		return s.Err()
	}
}
func (s *Session) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// User-supplied transports and admission callbacks are contained to this
// session. Panic values can contain secrets and are deliberately discarded.
func (s *Session) recoverWorker() {
	if recover() != nil {
		s.stop(ErrInternal)
	}
}
func (s *Session) closeTransport() {
	defer func() {
		if recover() != nil {
			s.stop(ErrInternal)
		}
	}()
	_ = s.conn.Close()
}

func (s *Session) reader() {
	defer s.wg.Done()
	defer s.recoverWorker()
	b := make([]byte, 65536)
	for {
		n, err := s.conn.ReadPacket(b)
		if err != nil {
			s.ioError(err)
			return
		}
		if n <= 0 || n > 65535 {
			continue
		}
		select {
		case s.incoming <- bytes.Clone(b[:n]):
		case <-s.ctx.Done():
			return
		}
	}
}
func (s *Session) writer() {
	defer s.wg.Done()
	defer s.recoverWorker()
	for {
		select {
		case b := <-s.outgoing:
			// Let the control loop admit another application packet after a
			// queued packet moves to the transport writer. Writes remain bounded
			// by the queue and a single in-flight transport packet.
			s.signal()
			if err := s.conn.WritePacket(b); err != nil {
				s.ioError(err)
				return
			}
		case <-s.ctx.Done():
			return
		}
	}
}
func (s *Session) ioError(err error) {
	select {
	case s.ioErrors <- err:
	case <-s.ctx.Done():
	}
}
func (s *Session) stop(err error) {
	s.mu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.mu.Unlock()
	s.cancel()
}
func (s *Session) loop() {
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	defer func() {
		if recover() != nil {
			s.stop(ErrInternal)
		}
		s.cancel()
		s.closeTransport()
		for _, k := range s.keys {
			k.adapter.Close()
		}
		s.wg.Wait()
		s.mu.Lock()
		if s.err == nil {
			s.err = net.ErrClosed
		}
		s.mu.Unlock()
		close(s.done)
	}()
	for {
		// A slow TCP peer is ordinary backpressure, not a reason to terminate
		// an authenticated tunnel. Stop accepting application packets before
		// they fill the queue, while continuing to process input, TLS events,
		// cancellation and timers. Reserve half the queue for control traffic
		// so a rekey can progress during a sustained download.
		dataWrites := s.writes
		if len(s.outgoing) >= cap(s.outgoing)/2 {
			dataWrites = nil
		}
		select {
		case <-s.ctx.Done():
			s.stop(s.ctx.Err())
			return
		case err := <-s.ioErrors:
			s.stop(err)
			return
		case b := <-s.incoming:
			s.packet(b)
		case e := <-s.events:
			s.event(e)
		case r := <-dataWrites:
			if s.data == nil {
				r.result <- ErrAuthentication
				break
			}
			b, err := s.data.Seal(nil, r.packet)
			if err == nil {
				err = s.send(b)
			}
			r.result <- err
		case <-s.wake:
		case <-tick.C:
			s.timers()
		}
		if s.ctx.Err() != nil {
			return
		}
		s.flush()
	}
}
func (s *Session) send(b []byte) error {
	select {
	case s.outgoing <- b:
		return nil
	default:
		s.stop(ErrBacklog)
		return ErrBacklog
	}
}
func (s *Session) packet(b []byte) {
	if len(b) == 0 {
		return
	}
	op, id := wire.SplitHeader(b[0])
	now := time.Now()
	if op.IsData() {
		if s.data == nil {
			return
		}
		out, kind, err := s.data.Open(nil, b)
		if err != nil {
			return
		}
		s.lastAuthenticated = now
		if s.primary != nil && id == s.primary.id && s.sendKey != s.primary {
			s.promotePrimary()
		}
		switch kind {
		case datachan.KindPacket:
			select {
			case s.received <- out:
			default:
			} // bounded datagram loss under backpressure
		case datachan.KindOCC:
			if len(out) > 0 && out[0] == datachan.OCCExit {
				s.stop(io.EOF)
			}
			if len(out) > 0 && out[0] == 0 {
				if p, e := s.data.SealOCC(nil, 1); e == nil {
					s.send(p)
				}
			}
		}
		return
	}
	if !op.IsControl() || len(b) < 9 || len(b) > 16384 {
		return
	}
	if !s.started {
		expected := wire.ControlHardResetClientV2
		if s.cfg.Wrapper == "tls-crypt-v2" {
			expected = wire.ControlHardResetClientV3
		}
		if op != expected || id != 0 {
			return
		}
	} else if !bytes.Equal(b[1:9], s.clientSID[:]) {
		return
	}
	p, err := s.wrapper.Unwrap(b)
	if err != nil {
		return
	}
	if !s.started {
		if p.PacketID != 0 {
			return
		}
		if _, err := rand.Read(s.serverSID[:]); err != nil {
			s.stop(err)
			return
		}
		s.clientSID = p.SessionID
		s.started = true
		s.primary = s.newKey(0, wire.ControlHardResetServerV2)
	}
	if p.SessionID != s.clientSID || len(p.Acks) > 0 && p.RemoteSessionID != s.serverSID {
		return
	}
	k := s.keys[p.KeyID]
	if k == nil {
		if p.Opcode != wire.ControlSoftResetV1 || s.data == nil || s.negotiating != nil || s.sendKey != s.primary || p.KeyID != nextKey(s.primary.id) {
			return
		}
		k = s.newKey(p.KeyID, wire.ControlSoftResetV1)
		s.negotiating = k
	}
	for _, m := range k.layer.Receive(p, now) {
		if m.Opcode == wire.ControlV1 {
			k.adapter.deliver(m.Payload)
		}
	}
}
func nextKey(id uint8) uint8 {
	id = (id + 1) & wire.KeyIDMask
	if id == 0 {
		id = 1
	}
	return id
}
func (s *Session) newKey(id uint8, op wire.Opcode) *keyState {
	opt := reliable.Options{}
	if s.cfg.TCP {
		opt.InitialTimeout = -1
	}
	k := &keyState{id: id, layer: reliable.New(opt), adapter: newTLSAdapter(1000, s.signal, nil, nil), created: time.Now()}
	k.layer.Send(op, nil)
	s.keys[id] = k
	k.tls = tls.Server(k.adapter, s.cfg.TLSConfig)
	s.wg.Add(1)
	go s.keyWorker(k)
	return k
}
func (s *Session) report(e event) bool {
	select {
	case s.events <- e:
		return true
	case <-s.ctx.Done():
		return false
	}
}
func (s *Session) keyWorker(k *keyState) {
	defer s.wg.Done()
	defer s.recoverWorker()
	ctx, cancel := context.WithTimeout(s.ctx, s.cfg.HandshakeTimeout)
	defer cancel()
	fail := func(err error) { s.report(event{key: k, err: err}) }
	k.adapter.SetReadDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
	if err := k.tls.HandshakeContext(ctx); err != nil {
		// The TLS read deadline and the control-loop timer race to observe
		// the same timeout. Preserve the public cause whichever wins.
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
			fail(ErrHandshakeTimeout)
			return
		}
		fail(errors.New("openvpn server: TLS handshake failed"))
		return
	}
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 16384)
	var cm *handshake.ClientMessage
	for cm == nil {
		n, err := k.tls.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if len(buf) > handshake.MaxMessageLen+16384 {
			fail(errors.New("openvpn server: key exchange too large"))
			return
		}
		parsed, used, perr := handshake.ParseClientMessage(buf)
		if perr == nil {
			cm = parsed
			buf = buf[used:]
			break
		}
		if !errors.Is(perr, handshake.ErrShort) {
			fail(errors.New("openvpn server: invalid key exchange"))
			return
		}
		if err != nil {
			fail(err)
			return
		}
	}
	cs := k.tls.ConnectionState()
	admission, err := s.cfg.Authenticate(ctx, cm, cs)
	if err != nil || ctx.Err() != nil {
		fail(ErrAuthentication)
		return
	}
	if admission.Identity == "" || len(admission.Identity) > 256 {
		fail(ErrAuthentication)
		return
	}
	if err := validatePush(admission.Push); err != nil {
		fail(err)
		return
	}
	admission.Push = append([]string(nil), admission.Push...)
	if !s.report(event{key: k, cm: cm, state: cs, admission: admission}) {
		return
	}
	k.adapter.SetReadDeadline(time.Time{})
	for {
		for {
			i := bytes.IndexByte(buf, 0)
			if i < 0 {
				break
			}
			msg := string(buf[:i])
			buf = buf[i+1:]
			if !s.report(event{key: k, msg: msg}) {
				return
			}
		}
		if len(buf) > 16<<10 {
			fail(errors.New("openvpn server: control message too large"))
			return
		}
		n, err := k.tls.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			fail(errors.New("openvpn server: TLS control channel closed"))
			return
		}
	}
}
func validatePush(push []string) error {
	if len(push) > 64 {
		return errors.New("openvpn server: too many push options")
	}
	total := 0
	for _, p := range push {
		total += len(p)
		if len(p) > 1024 || strings.ContainsAny(p, ",\x00\r\n") {
			return errors.New("openvpn server: invalid push option")
		}
		key, _, _ := strings.Cut(p, " ")
		switch key {
		case "cipher", "key-derivation", "peer-id", "auth-token", "auth-token-user", "push-continuation", "compress", "comp-lzo":
			return errors.New("openvpn server: reserved push option")
		}
	}
	if total > 8192 {
		return errors.New("openvpn server: push options too large")
	}
	return nil
}
func (s *Session) event(e event) {
	k := e.key
	if s.keys[k.id] != k {
		return
	}
	if e.err != nil {
		if k == s.old {
			if s.sendKey == k {
				// A closed old TLS stream does not prove the new key-method
				// reply arrived. Retain only its data key until confirmation.
				k.controlEnded = true
				k.adapter.Close()
				return
			}
			s.dropKey(k)
			return
		}
		s.stop(e.err)
		return
	}
	if e.cm != nil {
		s.exchange(k, e.cm, e.state, e.admission)
		return
	}
	if !k.exchanged {
		return
	}
	switch e.msg {
	case "PUSH_REQUEST":
		if time.Since(s.lastPush) >= time.Second {
			s.push(k)
		}
	case "EXIT":
		s.stop(io.EOF)
	}
}
func peerFields(info string) (map[string]string, error) {
	m := map[string]string{}
	for _, line := range strings.Split(info, "\n") {
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if _, dup := m[k]; dup {
			return nil, ErrAuthentication
		}
		m[k] = v
	}
	return m, nil
}

// Compression capabilities in IV_* are harmless; only an enabled OCC
// compression directive requires unsupported framing and is rejected here.
func validateClientOCC(occ string) error {
	for _, option := range strings.Split(occ, ",") {
		fields := strings.Fields(option)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "comp-lzo", "compress":
			return errors.New("openvpn server: compression framing is disabled")
		}
	}
	return nil
}

func selectCipher(ciphers []string, cm *handshake.ClientMessage, fields map[string]string) (string, error) {
	offered := strings.Split(fields["IV_CIPHERS"], ":")
	if fields["IV_CIPHERS"] == "" {
		offered = nil
		for _, o := range strings.Split(cm.Options, ",") {
			if v, ok := strings.CutPrefix(o, "cipher "); ok {
				offered = append(offered, v)
			}
		}
		if fields["IV_NCP"] == "2" {
			offered = append(offered, "AES-256-GCM", "AES-128-GCM")
		}
	}
	for _, allowed := range ciphers {
		for _, v := range offered {
			if v == allowed {
				return allowed, nil
			}
		}
	}
	return "", errors.New("openvpn server: no shared data cipher")
}
func (s *Session) exchange(k *keyState, cm *handshake.ClientMessage, cs tls.ConnectionState, ad Admission) {
	if k.exchanged {
		s.stop(ErrAuthentication)
		return
	}
	if err := validateClientOCC(cm.Options); err != nil {
		s.stop(err)
		return
	}
	fields, err := peerFields(cm.PeerInfo)
	if err != nil {
		s.stop(err)
		return
	}
	pv, _ := strconv.ParseUint(fields["IV_PROTO"], 10, 32)
	proto := uint32(pv)
	first := s.data == nil
	chosen, err := selectCipher(s.cfg.Ciphers, cm, fields)
	if err != nil {
		s.stop(err)
		return
	}
	if first {
		s.cipher = chosen
		s.ekm = proto&handshake.IVProtoTLSKeyExport != 0
		if proto&handshake.IVProtoDataV2 != 0 {
			s.peerID = s.cfg.PeerID
		}
		s.admission = ad
	} else if ad.Identity != s.admission.Identity || chosen != s.cipher || s.ekm && proto&handshake.IVProtoTLSKeyExport == 0 {
		s.stop(ErrAuthentication)
		return
	}
	var source handshake.ServerKeySource
	if _, err = rand.Read(source.Random1[:]); err != nil {
		s.stop(err)
		return
	}
	if _, err = rand.Read(source.Random2[:]); err != nil {
		s.stop(err)
		return
	}
	var key2 *handshake.Key2
	if s.ekm {
		var material []byte
		material, err = cs.ExportKeyingMaterial(handshake.EKMLabel, nil, handshake.EKMLength)
		if err == nil {
			key2, err = handshake.Key2FromEKM(material)
			clear(material)
		}
	} else {
		key2 = handshake.DeriveKey2PRF(&cm.Source, &source, s.clientSID, s.serverSID)
	}
	if err != nil {
		s.stop(errors.New("openvpn server: key derivation failed"))
		return
	}
	dk, err := datachan.NewKeyState(k.id, s.cipher, s.cfg.Auth, key2.ServerSend(), key2.ServerRecv())
	if err != nil {
		s.stop(err)
		return
	}
	occAuth := s.cfg.Auth
	if datachan.IsAEAD(s.cipher) {
		occAuth = "[null-digest]"
	}
	protoName := "UDPv4"
	if s.cfg.TCP {
		protoName = "TCPv4_SERVER"
	}
	message := handshake.ServerMessage{Source: source, Options: fmt.Sprintf("V4,dev-type tun,link-mtu 1549,tun-mtu 1500,proto %s,cipher %s,auth %s,keysize %d,key-method 2,tls-server", protoName, s.cipher, occAuth, datachan.KeyBits(s.cipher))}
	if _, err = k.tls.Write(message.Marshal()); err != nil {
		s.stop(err)
		return
	}
	if first {
		s.data = datachan.New(datachan.Options{PeerID: s.peerID})
	}
	// Install the receiving key immediately, but do not transmit under it
	// until the peer proves it has received our key-method reply. A reordered
	// UDP data packet otherwise arrives before the peer can decrypt it.

	k.dataKey = dk
	s.data.SetPrimary(dk)
	if !first && s.sendKey != nil {
		s.data.SetPrimary(s.sendKey.dataKey)
	}
	k.exchanged = true
	k.established = time.Now()
	s.lastAuthenticated = k.established
	if !first {
		if s.old != nil {
			s.dropKey(s.old)
		}
		s.old = s.primary
		s.primary = k
		s.negotiating = nil
	} else {
		s.sendKey = k
		s.mu.Lock()
		s.identity = ad.Identity
		s.mu.Unlock()
		s.push(k)
		s.once.Do(func() { close(s.ready) })
	}
}

// promotePrimary changes only the sending generation; the prior receiving
// key remains valid during the ordinary overlap window. Successful new-key
// data authenticates peer readiness, including keepalive packets.
func (s *Session) promotePrimary() {
	if s.primary != nil && s.primary.dataKey != nil && s.data != nil {
		s.data.SetPrimary(s.primary.dataKey)
		s.sendKey = s.primary
	}
}

func (s *Session) push(k *keyState) {
	push := append([]string(nil), s.admission.Push...)
	push = append(push, "cipher "+s.cipher, "ping 10", "ping-restart "+strconv.Itoa(max(1, int(s.cfg.IdleTimeout/time.Second))))
	if s.peerID != wire.NoPeerID {
		push = append(push, fmt.Sprintf("peer-id %d", s.peerID))
	}
	if s.ekm {
		push = append(push, "key-derivation tls-ekm")
	}
	s.lastPush = time.Now()
	if _, err := k.tls.Write(append([]byte("PUSH_REPLY,"+strings.Join(push, ",")), 0)); err != nil {
		s.stop(err)
	}
}
func (s *Session) dropKey(k *keyState) {
	k.adapter.Close()
	delete(s.keys, k.id)
	if s.data != nil {
		s.data.DropKey(k.id)
	}
	if s.old == k {
		s.old = nil
	}
}
func (s *Session) timers() {
	now := time.Now()
	if s.data == nil && now.Sub(s.began) > s.cfg.HandshakeTimeout {
		s.stop(ErrHandshakeTimeout)
		return
	}
	if s.negotiating != nil && now.Sub(s.negotiating.created) > s.cfg.HandshakeTimeout {
		s.stop(ErrHandshakeTimeout)
		return
	}
	if s.data == nil {
		return
	}
	if now.Sub(s.lastAuthenticated) > s.cfg.IdleTimeout {
		s.stop(ErrIdleTimeout)
		return
	}
	if now.Sub(s.lastPing) >= 10*time.Second {
		if b, err := s.data.SealPing(nil); err == nil {
			s.send(b)
		}
		s.lastPing = now
	}
	if s.old != nil && now.Sub(s.primary.established) > 60*time.Second {
		if s.sendKey == s.old {
			s.stop(ErrHandshakeTimeout)
			return
		}
		s.dropKey(s.old)
	}
	if s.negotiating == nil && s.sendKey == s.primary && (now.Sub(s.primary.established) >= s.cfg.Renegotiate || s.data.NeedsRenegotiation()) {
		id := nextKey(s.primary.id)
		if prev := s.keys[id]; prev != nil {
			s.dropKey(prev)
		}
		s.negotiating = s.newKey(id, wire.ControlSoftResetV1)
	}
}
func (s *Session) flush() {
	now := time.Now()
	for _, k := range s.keys {
		if k.controlEnded {
			continue
		}
		for _, chunk := range k.adapter.takeOut() {
			if k.layer.Unacked() >= 256 {
				s.stop(ErrBacklog)
				return
			}
			k.layer.Send(wire.ControlV1, chunk)
		}
		for _, p := range k.layer.Poll(now) {
			p.KeyID = k.id
			p.SessionID = s.serverSID
			p.RemoteSessionID = s.clientSID
			b, err := s.wrapper.Wrap(p)
			if err != nil {
				s.stop(err)
				return
			}
			if s.send(b) != nil {
				return
			}
		}
	}
}
