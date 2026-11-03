// Package client is an OpenVPN 2.x client session: it dials a server, runs
// the control channel (reliability layer, tls-auth/tls-crypt, TLS, key-method
// 2, PUSH_REQUEST/PUSH_REPLY), installs data-channel keys and then carries IP
// packets until the session ends. It knows nothing about Xray; the caller
// supplies the dial function and moves packets between the session and a
// userspace network stack.
//
// One Client is one session to one server. It does not reconnect: when the
// session dies (ping-restart expiry, the server's RESTART or HALT, a
// transport error) Done is closed, Err says why, and the caller dials a new
// Client. Within a session it answers and initiates renegotiation (soft
// reset to the next key id, both key states alive for the transition
// window), sends keepalive pings and enforces ping-restart.
//
// Liveness, as in OpenVPN's client mode: ping-restart is the pushed value,
// else the profile's, else 120 s ("ping-restart 0" in the profile turns it
// off). Under that 120 s default the server sends no keepalive, so after a
// quarter of it without a word from the server the client asks for an OCC
// reply (OCC_REQUEST), which a live server answers: an idle tunnel stays up,
// a dead server is noticed. The keepalive timers count time the device spent
// suspended (see stamp), and ping-restart is enforced even while a
// transport write is blocked (a TCP server that stopped reading). A failed
// UDP send loses that datagram only; a failed TCP write ends the session.
//
// Flow of a session (per remote, until one succeeds or ctx ends):
//
//  1. Dial the remote (UDP datagrams, or TCP with wire framing).
//  2. Send P_CONTROL_HARD_RESET_CLIENT_V2 (V3 with tls-crypt-v2), key id 0,
//     a fresh random session id; take the server's reset and its session id.
//  3. Run crypto/tls (tlsconf.Build) over P_CONTROL_V1 messages: TLS writes
//     are cut into control payloads that fit the link (at most 1250 bytes of
//     wrapped packet), reads are the in-order payloads concatenated.
//  4. Write the key-method 2 client message (credentials when
//     auth-user-pass, peer info announcing DATA_V2, REQUEST_PUSH, TLS key
//     export only when the TLS connection can export keying material, the
//     cipher list); read the server's message.
//  5. Send "PUSH_REQUEST" (NUL-terminated) and resend it every few seconds
//     until a PUSH_REPLY; follow push-continuation; fail on AUTH_FAILED;
//     wait out AUTH_PENDING (bounded by HandshakeTimeout, which an
//     "AUTH_PENDING,timeout N" from the server extends to N seconds from
//     then, at most 10 minutes; the peer info announces the keyword).
//  6. Choose the data cipher as OpenVPN 2.6 does, only ever one of
//     IV_CIPHERS (data-ciphers, plus data-ciphers-fallback or --cipher): the
//     pushed cipher, which must be one of them; else the cipher the
//     server's options string names, if it is one of them; else
//     data-ciphers-fallback, else --cipher; else fail (no implicit BF-CBC).
//     The digest for CBC ciphers is --auth (default SHA1); "auth" is not a
//     push option, a pushed one is ignored. Derive key2 (tls-ekm when
//     pushed, else PRF), install the key; P_DATA_V2 when a peer-id was
//     pushed. A session whose server negotiated TLS 1.0 fails at once:
//     crypto/tls splits every TLS 1.0 record (1/n-1), which OpenVPN cannot
//     read the key-method 2 message from.
//  7. Carry packets; handle control messages (RESTART, HALT, EXIT,
//     AUTH_FAILED, INFO) and soft resets for the rest of the session.
package client

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/clientproof"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/ctlwrap"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/datachan"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/options"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/reliable"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/tlsconf"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/wire"
)

var (
	// ErrAuthFailed: the server answered AUTH_FAILED. The error text carries
	// the server's reason when it gave one.
	ErrAuthFailed = errors.New("openvpn: authentication failed")
	// ErrAuthTokenRejected comes with ErrAuthFailed when the AUTH_FAILED
	// ended a session that was up and logging in with a pushed auth-token:
	// the server refused the token, which says nothing about the username
	// and password, so a new session (which logs in with them) may work.
	ErrAuthTokenRejected = errors.New("openvpn: the server refused the auth-token")
	// ErrHandshakeTimeout: no working session within the handshake window.
	ErrHandshakeTimeout = errors.New("openvpn: handshake timed out")
	// ErrPingTimeout: nothing heard from the server for ping-restart.
	ErrPingTimeout = errors.New("openvpn: server stopped answering (ping-restart)")
	// ErrServerRestart / ErrServerHalt: the server's RESTART / HALT message.
	ErrServerRestart = errors.New("openvpn: server asked to restart")
	ErrServerHalt    = errors.New("openvpn: server asked to halt")
	// ErrClosed: Close was called.
	ErrClosed = errors.New("openvpn: session closed")
)

// DialFunc opens the transport to a remote. network is the Remote's Network
// ("udp", "udp4", "udp6", "tcp", "tcp4", "tcp6"); address is host:port with
// the host as written in the config (possibly a name). A UDP connection must
// preserve datagram boundaries (one Write = one datagram, one Read = one
// datagram), as a connected net.UDPConn does.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Logger receives the session's log lines. Nil discards them.
type Logger interface {
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
}

// Config describes a session.
type Config struct {
	// ClientProof is optional. Nil preserves ordinary OpenVPN behavior.
	// When set, every TLS key state must send a fresh session-bound proof.
	ClientProof *clientproof.Key
	// Options is the parsed configuration (required).
	Options *options.Options
	// Username/Password, when Username is not empty, replace the ones in
	// Options (and turn on auth-user-pass).
	Username string
	Password string
	// Dial opens the transport (required).
	Dial   DialFunc
	Logger Logger
	// Platform is IV_PLAT; default "linux".
	Platform string

	// HandshakeTimeout bounds steps 1-6 for one remote; default
	// Options.HandWindow (60s). An "AUTH_PENDING,timeout N" from the server
	// extends it (to at most 10 minutes from then). ctx bounds the whole
	// Dial.
	HandshakeTimeout time.Duration

	// Test knobs: announce no TLS key export (forces the PRF), announce no
	// DATA_V2 (forces P_DATA_V1).
	DisableEKM    bool
	DisableDataV2 bool
	// Rand replaces crypto/rand.Reader.
	Rand io.Reader

	// hooks shortens timers in this package's tests.
	hooks *testHooks
}

// testHooks are timer overrides for tests; zero fields keep the defaults.
type testHooks struct {
	reliable         reliable.Options
	pushInterval     time.Duration
	transitionWindow time.Duration
	// defaultPingRestart replaces the 120 s client default.
	defaultPingRestart time.Duration
	// maxSleep replaces maxLoopSleep.
	maxSleep time.Duration
	// wallSkew is added to the wall clock the liveness timers read, to
	// stand for time the device spent suspended.
	wallSkew func() time.Duration
}

// TunnelInfo is the tunnel the server assigned.
type TunnelInfo struct {
	IPv4 netip.Prefix // zero when the server pushed no IPv4 address
	IPv6 netip.Prefix // zero when none
	// MTU is the pushed tun-mtu, else Options.TunMTU (1500).
	MTU int
	DNS []netip.Addr
	// What was negotiated, for logs.
	Remote        options.Remote
	Cipher        string
	KeyDerivation string // "tls-ekm" or "prf"
	TLSVersion    string // e.g. "TLS 1.3"
}

// Session constants.
const (
	// maxControlPacket is the largest wrapped control packet sent (OpenVPN's
	// default --tls-mtu).
	maxControlPacket = 1250
	// maxAcksPerPacket bounds the ack array of an outgoing control packet.
	maxAcksPerPacket = 4
	// controlHeaderMax is the unwrapped control packet size besides the
	// payload: op/key, session id, ack count, acks, remote session id,
	// message id.
	controlHeaderMax = 1 + 8 + 1 + 4*maxAcksPerPacket + 8 + 4
	minControlChunk  = 256

	defaultHandshakeTimeout = 60 * time.Second
	defaultConnectTimeout   = 30 * time.Second
	defaultPushInterval     = 2 * time.Second
	defaultTransition       = 60 * time.Second
	closeGrace              = 200 * time.Millisecond
	maxLoopSleep            = 5 * time.Second
	// defaultPingRestart is OpenVPN's client-mode ping-restart when neither
	// the profile nor the server sets one.
	defaultPingRestart = 120 * time.Second
	// maxAuthPending caps the wait an "AUTH_PENDING,timeout N" asks for.
	maxAuthPending = 10 * time.Minute

	packetQueueLen  = 1024
	controlQueueLen = 256
	eventQueueLen   = 64
	// maxQueuedBytes bounds what the receive queue holds in bytes;
	// MTU-sized packets fill all packetQueueLen slots below it.
	maxQueuedBytes = 2 << 20
	// packetSlack is how much a received IP packet may exceed the tunnel
	// MTU before it is dropped.
	packetSlack = 256
	// rxBufSize is the size of the pooled receive buffers: an MTU-sized
	// packet decrypts in place in one.
	rxBufSize = 2048

	maxServerMessage  = 64 << 10
	maxControlMessage = 256 << 10
	maxExitNotify     = 10

	peerInfoVersion = "2.6.12"
	peerInfoMTU     = 1600
	defaultPlatform = "linux"
)

// Client is a running session. ReadPacket, WritePacket and Close are safe to
// call from different goroutines.
type Client struct {
	d      *dialer
	log    logger
	remote options.Remote
	tcp    bool
	conn   net.Conn

	writeMu sync.Mutex
	frame   []byte // TCP framing buffer, guarded by writeMu

	wrapper ctlwrap.Wrapper
	chunk   int    // largest P_CONTROL_V1 payload
	occ     string // OCC options string

	data atomic.Pointer[datachan.Channel]

	// When the transport last carried a packet each way, and when the
	// control loop last tried to ping (see stamp).
	epoch                         time.Time
	lastSend, lastRecv, pingTried atomicStamp
	dropLogAt                     atomic.Int64
	writeFailing                  atomic.Bool // a UDP send failed; logged once
	wallSkew                      func() time.Duration
	maxSleep                      time.Duration

	// Published by the control loop for the watchdog and the reader.
	established   atomic.Bool  // the session is up
	pingNs        atomic.Int64 // keepalive interval, 0 for none
	pingRestartNs atomic.Int64 // ping-restart, 0 for none
	hsDeadlineNs  atomic.Int64 // handshake deadline, ns since epoch

	packets   chan rxPacket
	queued    atomic.Int64 // bytes in packets
	maxPacket atomic.Int64 // largest IP packet accepted from the server
	dropped   atomic.Uint64

	ctlIn   chan *wire.ControlPacket
	events  chan keyEvent
	wake    chan struct{}
	kick    chan struct{} // wakes the watchdog
	readErr chan error    // the reader's last word

	ctx       context.Context // ends with the session
	cancel    context.CancelFunc
	ready     chan struct{}
	done      chan struct{}
	closing   chan struct{}
	closeOnce sync.Once
	failOnce  sync.Once
	errMu     sync.Mutex
	err       error
	wg        sync.WaitGroup

	info TunnelInfo // written by the control loop before ready closes

	loop loopState // owned by the control loop goroutine
}

// Dial connects, authenticates and returns a session that is ready to carry
// packets. It tries Options.Remotes in order (shuffled once with
// RemoteRandom) until one works, ctx ends or all failed; the error then
// wraps the last remote's failure. ErrAuthFailed stops the loop at once.
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	d, err := newDialer(cfg)
	if err != nil {
		return nil, err
	}
	remotes := append([]options.Remote(nil), d.opts.Remotes...)
	if d.opts.RemoteRandom {
		if err := shuffleRemotes(remotes, d.rand); err != nil {
			return nil, err
		}
	}
	var last error
	for _, r := range remotes {
		if err := ctx.Err(); err != nil {
			if last == nil {
				last = err
			}
			break
		}
		c, err := d.connect(ctx, r)
		if err == nil {
			return c, nil
		}
		err = fmt.Errorf("remote %s/%s: %w", hostPort(r), r.Network, err)
		if errors.Is(err, ErrAuthFailed) {
			return nil, err
		}
		d.log.Warnf("openvpn: %v", err)
		last = err
	}
	return nil, fmt.Errorf("openvpn: no remote worked: %w", last)
}

// Info returns the tunnel parameters.
func (c *Client) Info() TunnelInfo {
	info := c.info
	info.DNS = append([]netip.Addr(nil), c.info.DNS...)
	return info
}

// ReadPacket blocks for the next IP packet from the server and copies it to
// p. It returns the session's error once the session is over. A packet
// larger than p is truncated (io.ErrShortBuffer).
func (c *Client) ReadPacket(p []byte) (int, error) {
	select {
	case <-c.done:
		return 0, c.Err()
	default:
	}
	select {
	case pkt := <-c.packets:
		n := copy(p, pkt.data)
		short := n < len(pkt.data)
		c.queued.Add(-int64(len(pkt.data)))
		pkt.release()
		if short {
			return n, io.ErrShortBuffer
		}
		return n, nil
	case <-c.done:
		return 0, c.Err()
	}
}

// rxPacket is a received IP packet waiting for ReadPacket. data lives in
// buf, a pooled buffer, unless buf is nil.
type rxPacket struct {
	data []byte
	buf  *[]byte
}

func (p rxPacket) release() {
	if p.buf != nil {
		rxPool.Put(p.buf)
	}
}

var rxPool = sync.Pool{New: func() any {
	b := make([]byte, 0, rxBufSize)
	return &b
}}

var sealPool = sync.Pool{New: func() any {
	b := make([]byte, 0, 2048)
	return &b
}}

// WritePacket sends one IP packet. It does not block on a slow link beyond
// one transport write (a write stuck on a TCP server that stopped reading
// is released when ping-restart ends the session); it fails once the
// session is over. A failed UDP send returns its error and the session goes
// on; a failed TCP write ends the session.
func (c *Client) WritePacket(p []byte) error {
	select {
	case <-c.done:
		return c.Err()
	default:
	}
	ch := c.data.Load()
	if ch == nil {
		return errors.New("openvpn: no data channel key")
	}
	bp := sealPool.Get().(*[]byte)
	defer sealPool.Put(bp)
	pkt, err := ch.Seal((*bp)[:0], p)
	if err != nil {
		if errors.Is(err, datachan.ErrPacketIDExhausted) {
			c.signalWake() // the control loop renegotiates
		}
		return fmt.Errorf("openvpn: sealing a packet: %w", err)
	}
	err = c.writeRaw(pkt)
	if cap(pkt) <= 64<<10 {
		*bp = pkt[:0]
	}
	return err
}

// Done is closed when the session is over.
func (c *Client) Done() <-chan struct{} { return c.done }

// Err is why the session ended (nil while it runs).
func (c *Client) Err() error {
	c.errMu.Lock()
	defer c.errMu.Unlock()
	return c.err
}

// Close ends the session, telling the server first when it can (control
// channel "EXIT" when cc-exit was negotiated, else explicit-exit-notify OCC
// packets over UDP when configured).
func (c *Client) Close() error {
	c.closeOnce.Do(func() { close(c.closing) })
	t := time.NewTimer(closeGrace + 300*time.Millisecond)
	select {
	case <-c.done:
	case <-t.C:
		c.fail(ErrClosed)
	}
	t.Stop()
	c.wg.Wait()
	return nil
}

// DroppedPackets reports how many received IP packets were discarded
// because ReadPacket was not keeping up (the receive queue holds at most
// 1024 packets and 2 MiB), or because they were larger than the tunnel MTU
// allows.
func (c *Client) DroppedPackets() uint64 { return c.dropped.Load() }

// fail ends the session with err (the first error wins): Done closes, the
// transport closes, and every goroutine winds down.
func (c *Client) fail(err error) {
	c.failOnce.Do(func() {
		c.errMu.Lock()
		c.err = err
		c.errMu.Unlock()
		close(c.done)
		c.cancel()
		_ = c.conn.Close()
	})
}

func (c *Client) isDone() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

func (c *Client) signalWake() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *Client) mono(t time.Time) int64 { return int64(t.Sub(c.epoch)) }

// dialer is what Dial prepares once for all remotes.
type dialer struct {
	cfg  Config
	opts *options.Options
	log  logger
	rand io.Reader

	tlsConf   *tls.Config
	wrapKind  wrapKind
	staticKey *ctlwrap.StaticKey
	wkc       []byte
	resetOp   wire.Opcode

	ciphers      []string // IV_CIPHERS, canonical
	fallback     string   // data-ciphers-fallback, else --cipher, else ""
	authUserPass bool
	username     string
	password     string

	timeout            time.Duration
	connectTimeout     time.Duration
	pushInterval       time.Duration
	transition         time.Duration
	defaultPingRestart time.Duration
	maxSleep           time.Duration
	relUDP             reliable.Options
	relTCP             reliable.Options
}

type wrapKind int

const (
	wrapPlain wrapKind = iota
	wrapTLSAuth
	wrapTLSCrypt
	wrapTLSCryptV2
)

func newDialer(cfg Config) (*dialer, error) {
	if cfg.Options == nil {
		return nil, errors.New("openvpn: Config.Options is required")
	}
	if cfg.Dial == nil {
		return nil, errors.New("openvpn: Config.Dial is required")
	}
	o := cfg.Options
	if len(o.Remotes) == 0 {
		return nil, errors.New("openvpn: the configuration has no remote")
	}
	d := &dialer{cfg: cfg, opts: o, log: logger{cfg.Logger}, rand: rand.Reader}
	if cfg.Rand != nil {
		d.rand = &lockedReader{r: cfg.Rand}
	}

	tc, err := tlsconf.Build(o)
	if err != nil {
		return nil, fmt.Errorf("openvpn: TLS configuration: %w", err)
	}
	if cfg.Rand != nil {
		tc = tc.Clone()
		tc.Rand = d.rand
	}
	d.tlsConf = tc

	d.resetOp = wire.ControlHardResetClientV2
	switch {
	case len(o.TLSCryptV2) > 0:
		k, wkc, err := ctlwrap.ParseTLSCryptV2ClientKey(o.TLSCryptV2)
		if err != nil {
			return nil, fmt.Errorf("openvpn: tls-crypt-v2 key: %w", err)
		}
		d.wrapKind, d.staticKey, d.wkc = wrapTLSCryptV2, k, wkc
		d.resetOp = wire.ControlHardResetClientV3
	case len(o.TLSCrypt) > 0:
		k, err := ctlwrap.ParseStaticKey(o.TLSCrypt)
		if err != nil {
			return nil, fmt.Errorf("openvpn: tls-crypt key: %w", err)
		}
		d.wrapKind, d.staticKey = wrapTLSCrypt, k
	case len(o.TLSAuth) > 0:
		k, err := ctlwrap.ParseStaticKey(o.TLSAuth)
		if err != nil {
			return nil, fmt.Errorf("openvpn: tls-auth key: %w", err)
		}
		d.wrapKind, d.staticKey = wrapTLSAuth, k
	}
	if _, err := d.newWrapper(); err != nil {
		return nil, err
	}

	d.ciphers, d.fallback = d.cipherList()

	if cfg.Username != "" {
		d.authUserPass, d.username, d.password = true, cfg.Username, cfg.Password
	} else if o.AuthUserPass {
		d.authUserPass, d.username, d.password = true, o.Username, o.Password
	}

	d.timeout = cfg.HandshakeTimeout
	if d.timeout <= 0 {
		d.timeout = o.HandWindow
	}
	if d.timeout <= 0 {
		d.timeout = defaultHandshakeTimeout
	}
	d.connectTimeout = o.ConnectTimeout
	if d.connectTimeout <= 0 {
		d.connectTimeout = defaultConnectTimeout
	}
	d.connectTimeout = min(d.connectTimeout, d.timeout)
	d.pushInterval = defaultPushInterval
	d.transition = defaultTransition
	d.defaultPingRestart = defaultPingRestart
	d.maxSleep = maxLoopSleep
	d.relUDP = reliable.Options{MaxAcksPerPacket: maxAcksPerPacket}
	if h := cfg.hooks; h != nil {
		if h.pushInterval > 0 {
			d.pushInterval = h.pushInterval
		}
		if h.transitionWindow > 0 {
			d.transition = h.transitionWindow
		}
		if h.defaultPingRestart > 0 {
			d.defaultPingRestart = h.defaultPingRestart
		}
		if h.maxSleep > 0 {
			d.maxSleep = h.maxSleep
		}
		d.relUDP = h.reliable
		d.relUDP.MaxAcksPerPacket = maxAcksPerPacket
	}
	d.relTCP = d.relUDP
	d.relTCP.InitialTimeout = -1
	return d, nil
}

func (d *dialer) newWrapper() (ctlwrap.Wrapper, error) {
	var (
		w   ctlwrap.Wrapper
		err error
	)
	switch d.wrapKind {
	case wrapTLSCryptV2:
		w, err = ctlwrap.NewTLSCryptV2Client(d.staticKey, d.wkc)
	case wrapTLSCrypt:
		w, err = ctlwrap.NewTLSCrypt(d.staticKey, true)
	case wrapTLSAuth:
		w, err = ctlwrap.NewTLSAuth(d.staticKey, keyDirection(d.opts.KeyDirection), d.opts.Auth)
	default:
		w = ctlwrap.NewPlain()
	}
	if err != nil {
		return nil, fmt.Errorf("openvpn: control channel protection: %w", err)
	}
	return w, nil
}

func keyDirection(dir int) ctlwrap.Direction {
	switch dir {
	case 0:
		return ctlwrap.Normal
	case 1:
		return ctlwrap.Inverse
	}
	return ctlwrap.Bidirectional
}

// cipherList returns IV_CIPHERS (data-ciphers canonicalised, unsupported
// ones dropped, the fallback cipher appended when missing) and the
// configured fallback cipher (data-ciphers-fallback, else --cipher, else
// none: like OpenVPN 2.6, there is no implicit BF-CBC).
func (d *dialer) cipherList() (list []string, fallback string) {
	o := d.opts
	names := o.DataCiphers
	if len(names) == 0 {
		names = []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"}
	}
	add := func(name string) {
		cn, ok := datachan.CanonicalCipher(name)
		if !ok {
			d.log.Warnf("openvpn: data cipher %q is not supported; not offering it", name)
			return
		}
		for _, have := range list {
			if have == cn {
				return
			}
		}
		list = append(list, cn)
	}
	for _, n := range names {
		add(n)
	}
	switch {
	case o.DataCiphersFallback != "":
		fallback = o.DataCiphersFallback
	case o.Cipher != "":
		fallback = o.Cipher
	}
	if fallback != "" {
		add(fallback)
	}
	return list, fallback
}

// connect runs one remote: dial, handshake, push. On success the session
// keeps running after ctx ends. The handshake window (which AUTH_PENDING
// may extend) is the control loop's to enforce, with the watchdog behind
// it; ctx only cuts the attempt short.
func (d *dialer) connect(ctx context.Context, r options.Remote) (*Client, error) {
	start := time.Now()
	addr := hostPort(r)
	d.log.Infof("openvpn: connecting to %s over %s", addr, r.Network)

	dctx, dcancel := context.WithTimeout(ctx, d.connectTimeout)
	conn, err := d.cfg.Dial(dctx, r.Network, addr)
	dcancel()
	if err != nil {
		if ctx.Err() == nil && errors.Is(dctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("%w: dialing: %w", ErrHandshakeTimeout, err)
		}
		return nil, fmt.Errorf("dialing: %w", err)
	}
	if conn == nil {
		return nil, errors.New("dialing: no connection returned")
	}
	c, err := newClient(d, r, conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	c.setHandshakeDeadline(start.Add(d.timeout)) // the dial counts
	c.start()
	select {
	case <-c.ready:
		return c, nil
	case <-c.done:
	case <-ctx.Done():
		c.fail(ctx.Err())
	}
	c.wg.Wait()
	err = c.Err()
	if cerr := ctx.Err(); cerr != nil && !errors.Is(err, cerr) {
		err = fmt.Errorf("%w (%w)", cerr, err)
	}
	return nil, err
}

func newClient(d *dialer, r options.Remote, conn net.Conn) (*Client, error) {
	w, err := d.newWrapper()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	c := &Client{
		d:        d,
		log:      d.log,
		remote:   r,
		tcp:      isTCP(r.Network),
		conn:     conn,
		wrapper:  w,
		epoch:    now,
		maxSleep: d.maxSleep,
		packets:  make(chan rxPacket, packetQueueLen),
		ctlIn:    make(chan *wire.ControlPacket, controlQueueLen),
		events:   make(chan keyEvent, eventQueueLen),
		wake:     make(chan struct{}, 1),
		kick:     make(chan struct{}, 1),
		readErr:  make(chan error, 1),
		ready:    make(chan struct{}),
		done:     make(chan struct{}),
		closing:  make(chan struct{}),
	}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	if h := d.cfg.hooks; h != nil {
		c.wallSkew = h.wallSkew
	}
	c.setPacketCeiling(d.opts.TunMTU)
	overhead := w.Overhead()
	if d.wrapKind == wrapTLSCryptV2 {
		// Only the P_CONTROL_HARD_RESET_CLIENT_V3 carries WKc.
		overhead = max(overhead-len(d.wkc), 0)
	}
	c.chunk = max(maxControlPacket-overhead-controlHeaderMax, minControlChunk)
	c.occ = d.occString(r)

	s := &c.loop
	for s.ourSID == (wire.SessionID{}) {
		if _, err := io.ReadFull(d.rand, s.ourSID[:]); err != nil {
			c.cancel()
			return nil, fmt.Errorf("openvpn: random session id: %w", err)
		}
	}
	s.start = now
	c.setHandshakeDeadline(now.Add(d.timeout))
	s.connectDeadline = now.Add(d.connectTimeout)
	s.pushed = options.NewPushed()
	s.authUserPass, s.username, s.password = d.authUserPass, d.username, d.password
	ks, err := c.newKeyState(0, d.resetOp, now)
	if err != nil {
		c.cancel()
		return nil, err
	}
	s.primary = ks
	return c, nil
}

func (c *Client) start() {
	c.wg.Add(3)
	go c.readLoop()
	go c.controlLoop()
	go c.watchdog()
}

// setPacketCeiling sets the largest IP packet accepted from the server for
// a tunnel MTU of mtu (at least 1500).
func (c *Client) setPacketCeiling(mtu int) {
	c.maxPacket.Store(int64(max(mtu, 1500) + packetSlack))
}

func (c *Client) relOptions() reliable.Options {
	if c.tcp {
		return c.d.relTCP
	}
	return c.d.relUDP
}

func isTCP(network string) bool {
	switch network {
	case "tcp", "tcp4", "tcp6", "tcp-client", "tcp4-client", "tcp6-client":
		return true
	}
	return false
}

func hostPort(r options.Remote) string {
	return net.JoinHostPort(r.Host, strconv.Itoa(int(r.Port)))
}

// shuffleRemotes is a Fisher-Yates shuffle driven by r.
func shuffleRemotes(rs []options.Remote, r io.Reader) error {
	var b [8]byte
	for i := len(rs) - 1; i > 0; i-- {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return fmt.Errorf("openvpn: shuffling remotes: %w", err)
		}
		j := int(binary.BigEndian.Uint64(b[:]) % uint64(i+1))
		rs[i], rs[j] = rs[j], rs[i]
	}
	return nil
}

// lockedReader serialises reads from a caller-supplied random source, which
// several goroutines (the control loop, TLS) use.
type lockedReader struct {
	mu sync.Mutex
	r  io.Reader
}

func (l *lockedReader) Read(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.r.Read(p)
}

// logger tolerates a nil Logger.
type logger struct{ l Logger }

func (l logger) Debugf(format string, args ...any) {
	if l.l != nil {
		l.l.Debugf(format, args...)
	}
}

func (l logger) Infof(format string, args ...any) {
	if l.l != nil {
		l.l.Infof(format, args...)
	}
}

func (l logger) Warnf(format string, args ...any) {
	if l.l != nil {
		l.l.Warnf(format, args...)
	}
}
