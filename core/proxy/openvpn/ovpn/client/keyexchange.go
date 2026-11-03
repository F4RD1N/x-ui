package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/clientproof"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/compress"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/datachan"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/handshake"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/options"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/wire"
)

// runKeyTLS is a key state's TLS goroutine: the TLS handshake, the
// key-method 2 exchange, then every control message the server sends on
// this key until the key state or the session ends.
func (c *Client) runKeyTLS(ks *keyState, ctx context.Context, user, pass string) {
	defer c.wg.Done()
	report := func(ev keyEvent) bool {
		ev.ks = ks
		select {
		case c.events <- ev:
			return true
		case <-c.done:
		case <-ctx.Done():
		}
		return false
	}
	tc := ks.tls
	if err := tc.HandshakeContext(ctx); err != nil {
		report(keyEvent{kind: evError, err: fmt.Errorf("TLS handshake: %w", err)})
		return
	}
	ks.tlsDone.Store(true)
	cs := tc.ConnectionState()
	if cs.Version == tls.VersionTLS10 {
		report(keyEvent{kind: evError, err: errTLS10})
		return
	}
	canEKM := false
	if !c.d.cfg.DisableEKM {
		// Go refuses to export from TLS 1.2 without extended master secret.
		_, err := cs.ExportKeyingMaterial(handshake.EKMLabel, nil, handshake.EKMLength)
		canEKM = err == nil
	}

	peerInfo := c.peerInfo(canEKM)
	if proof := c.d.cfg.ClientProof; proof != nil {
		// A new exporter is required for each TLS connection, including
		// renegotiations. Never reuse an earlier proof or downgrade on error.
		if cs.Version < tls.VersionTLS12 {
			report(keyEvent{kind: evError, err: errors.New("client proof: TLS 1.2 or newer is required")})
			return
		}
		exporter, err := cs.ExportKeyingMaterial(clientproof.ExporterLabel, nil, clientproof.ExporterLength)
		if err != nil {
			report(keyEvent{kind: evError, err: errors.New("client proof: TLS keying material export failed")})
			return
		}
		value, err := proof.Generate(exporter)
		clear(exporter)
		if err != nil {
			report(keyEvent{kind: evError, err: errors.New("client proof: proof generation failed")})
			return
		}
		peerInfo += clientproof.PeerInfoKey + "=" + value + "\n"
	}

	msg := handshake.ClientMessage{
		Source:   *ks.source,
		Options:  c.occ,
		Username: user,
		Password: pass,
		PeerInfo: peerInfo,
	}
	b := msg.Marshal()
	_, err := tc.Write(b)
	clear(b)
	clear(msg.Source.PreMaster[:])
	if err != nil {
		report(keyEvent{kind: evError, err: fmt.Errorf("sending the key-method 2 message: %w", err)})
		return
	}

	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 16<<10)
	var server *handshake.ServerMessage
	for server == nil {
		n, rerr := tc.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if len(buf) > 0 {
			sm, used, perr := handshake.ParseServerMessage(buf)
			switch {
			case perr == nil:
				server = sm
				buf = append([]byte(nil), buf[used:]...)
				continue
			case !errors.Is(perr, handshake.ErrShort):
				report(keyEvent{kind: evError, err: fmt.Errorf("reading the key-method 2 message: %w", perr)})
				return
			}
		}
		if rerr != nil {
			report(keyEvent{kind: evError, err: fmt.Errorf("reading the key-method 2 message: %w", rerr)})
			return
		}
		if len(buf) > maxServerMessage {
			report(keyEvent{kind: evError, err: errors.New("key-method 2 message too long")})
			return
		}
	}
	if !report(keyEvent{kind: evExchanged, server: server, cs: cs, canEKM: canEKM}) {
		return
	}

	pending := buf
	for {
		var msgs []string
		msgs, pending = splitControlMessages(pending)
		for _, m := range msgs {
			if !report(keyEvent{kind: evMessage, msg: m}) {
				return
			}
		}
		if len(pending) > maxControlMessage {
			report(keyEvent{kind: evError, err: errors.New("control message too long")})
			return
		}
		n, rerr := tc.Read(tmp)
		pending = append(pending, tmp[:n]...)
		if rerr != nil {
			msgs, _ = splitControlMessages(pending)
			for _, m := range msgs {
				if !report(keyEvent{kind: evMessage, msg: m}) {
					return
				}
			}
			report(keyEvent{kind: evError, err: fmt.Errorf("control channel: %w", rerr)})
			return
		}
	}
}

// errTLS10 ends a session whose server negotiated TLS 1.0. Every TLS 1.0
// suite crypto/tls offers is CBC (RC4 is never offered), and on those it
// sends each write as a 1-byte record and the rest (the 1/n-1 split against
// BEAST, which cannot be turned off); OpenVPN reads the key-method 2 message
// with a single read, gets 1 byte and drops the session.
var errTLS10 = errors.New("the server negotiated TLS 1.0, which this client cannot use with OpenVPN (the server must allow TLS 1.1 or newer)")

// splitControlMessages cuts the NUL-terminated control messages off the
// front of b; rest is the unterminated tail. Empty messages are skipped.
func splitControlMessages(b []byte) (msgs []string, rest []byte) {
	for {
		i := bytes.IndexByte(b, 0)
		if i < 0 {
			break
		}
		if i > 0 {
			msgs = append(msgs, string(b[:i]))
		}
		b = b[i+1:]
	}
	if len(b) == 0 {
		return msgs, nil
	}
	return msgs, b
}

// peerInfo renders the IV_* block for one key state.
func (c *Client) peerInfo(canEKM bool) string {
	d := c.d
	proto := uint32(handshake.IVProtoRequestPush | handshake.IVProtoCCExitNotify | handshake.IVProtoDNSOption | handshake.IVProtoAuthPendingKW)
	if !d.cfg.DisableDataV2 {
		proto |= handshake.IVProtoDataV2
	}
	if canEKM {
		proto |= handshake.IVProtoTLSKeyExport
	}
	platform := d.cfg.Platform
	if platform == "" {
		platform = defaultPlatform
	}
	pi := handshake.PeerInfo{
		Version:    peerInfoVersion,
		Platform:   platform,
		Proto:      proto,
		Ciphers:    d.ciphers,
		MTU:        peerInfoMTU,
		Stubs:      true,
		Decompress: true,
	}
	return pi.String()
}

// occString renders the OCC options string for a remote. It names the
// configured fallback cipher, and no cipher without one (as OpenVPN 2.6
// does).
func (d *dialer) occString(r options.Remote) string {
	o := d.opts
	cipher, ok := datachan.CanonicalCipher(d.fallback)
	if !ok {
		cipher = d.fallback
	}
	auth := o.Auth
	if a, ok := datachan.CanonicalDigest(auth); ok {
		auth = a
	}
	if auth == "" {
		auth = "SHA1"
	}
	keySize := 0
	if ok {
		keySize = datachan.KeyBits(cipher)
		if datachan.IsAEAD(cipher) {
			auth = "[null-digest]"
		}
	}
	return handshake.OptionsString(handshake.OCCOptions{
		TCP:     isTCP(r.Network),
		IPv6:    strings.HasSuffix(r.Network, "6"),
		TunMTU:  o.TunMTU,
		Cipher:  cipher,
		Auth:    auth,
		KeySize: keySize,
		CompLZO: o.CompressionSet && o.Compression == compress.LZO,
		TLSAuth: len(o.TLSAuth) > 0,
	})
}

// handleControlMessage acts on one control message from the server.
func (c *Client) handleControlMessage(msg string, now time.Time) error {
	s := &c.loop
	msg = strings.TrimRight(msg, "\r\n\t ")
	cmd, arg, hasArg := strings.Cut(msg, ",")
	switch cmd {
	case "PUSH_REPLY":
		if s.up || !s.pushing {
			c.updateAuthToken(msg)
			return nil
		}
		c.log.Debugf("openvpn: %s", redactPush(msg))
		more, err := s.pushed.ApplyPushReply(msg, c.d.opts.PullFilters)
		if err != nil {
			return fmt.Errorf("openvpn: PUSH_REPLY: %w", err)
		}
		s.gotPush = true
		if more {
			return nil
		}
		return c.completeSetup(now)
	case "AUTH_FAILED":
		err := ErrAuthFailed
		if reason := printable(arg); hasArg && reason != "" {
			err = fmt.Errorf("%w: %s", ErrAuthFailed, reason)
		}
		// Once the session is up with a pushed auth-token, renegotiations
		// log in with the token, so an AUTH_FAILED then is most likely the
		// server turning the token down (it expired, or the server
		// restarted or failed over and no longer knows it), not the
		// credentials. OpenVPN 2.x drops the token and restarts with the
		// username and password there (ssl_clean_auth_token in
		// receive_auth_failed); the error says so, and the next session
		// starts without a token anyway. Before the session is up the
		// key-method 2 message always carried the password, so an
		// AUTH_FAILED there stays a plain one.
		if s.up && s.authToken != "" {
			s.authToken, s.authTokenUser = "", ""
			c.log.Infof("openvpn: AUTH_FAILED while logged in with the auth-token; it is dropped, the next session logs in with the username and password")
			return fmt.Errorf("%w (%w)", err, ErrAuthTokenRejected)
		}
		return err
	case "AUTH_PENDING":
		if !s.up {
			s.pending = true
			c.log.Infof("openvpn: authentication pending%s", suffix(arg))
			if d, ok := authPendingTimeout(arg); ok {
				if dl := now.Add(min(d, maxAuthPending)); dl.After(s.hsDeadline) {
					c.setHandshakeDeadline(dl)
					c.log.Infof("openvpn: waiting up to %v for the authentication", dl.Sub(now).Round(time.Second))
				}
			}
		}
		return nil
	case "INFO", "INFO_PRE":
		c.log.Infof("openvpn: server info: %s", printable(arg))
		return nil
	case "RESTART":
		c.log.Infof("openvpn: server asked to restart%s", suffix(arg))
		return ErrServerRestart
	case "HALT":
		c.log.Infof("openvpn: server asked to halt%s", suffix(arg))
		return ErrServerHalt
	case "EXIT":
		c.log.Infof("openvpn: server is exiting")
		return fmt.Errorf("%w (EXIT)", ErrServerRestart)
	}
	c.log.Debugf("openvpn: ignoring control message %q", printable(cmd))
	return nil
}

// authPendingTimeout reads the "timeout N" keyword (seconds) of an
// AUTH_PENDING message's arguments ("timeout 120,..."); ok is false when
// there is none or it is not a positive number.
func authPendingTimeout(arg string) (d time.Duration, ok bool) {
	for _, kw := range strings.Split(arg, ",") {
		k, v, found := strings.Cut(strings.TrimSpace(kw), " ")
		if !found {
			k, v, found = strings.Cut(strings.TrimSpace(kw), "=")
		}
		if !found || k != "timeout" {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 32)
		if err != nil || n == 0 {
			return 0, false
		}
		return time.Duration(n) * time.Second, true
	}
	return 0, false
}

// updateAuthToken takes a renewed auth-token from a PUSH_REPLY that comes
// after the tunnel is up; everything else in it is ignored.
func (c *Client) updateAuthToken(msg string) {
	s := &c.loop
	p := options.NewPushed()
	if _, err := p.ApplyPushReply(msg, c.d.opts.PullFilters); err != nil || p.AuthToken == "" {
		c.log.Debugf("openvpn: ignoring a later PUSH_REPLY")
		return
	}
	s.authToken = p.AuthToken
	if p.AuthTokenUser != "" {
		s.authTokenUser = p.AuthTokenUser
	}
	c.log.Debugf("openvpn: auth-token renewed")
}

// completeSetup installs the first data key from what was pushed and marks
// the session up.
func (c *Client) completeSetup(now time.Time) error {
	s := &c.loop
	o := c.d.opts
	p := s.pushed

	cipher, err := c.chooseCipher(p.Cipher, s.primary.server.Options)
	if err != nil {
		return err
	}
	// "auth" is not a push option: OpenVPN rejects it there and the server
	// keeps its own --auth, so applying it would only break the tunnel.
	digestName := o.Auth
	if digestName == "" {
		digestName = "SHA1"
	}
	if p.Auth != "" && !datachan.IsAEAD(cipher) && !sameDigest(p.Auth, digestName) {
		c.log.Infof("openvpn: ignoring the pushed auth %s (not a push option); the data digest is %s", printable(p.Auth), digestName)
	}
	digest, ok := datachan.CanonicalDigest(digestName)
	if !ok {
		if !datachan.IsAEAD(cipher) {
			return fmt.Errorf("openvpn: data digest %q: %w", digestName, datachan.ErrUnsupported)
		}
		digest = "SHA1" // unused with AEAD
	}
	s.cipher, s.digest = cipher, digest
	s.keyDerivation = "prf"
	if p.KeyDerivation == "tls-ekm" {
		s.keyDerivation = "tls-ekm"
	}

	ks := s.primary
	dk, err := c.dataKey(ks)
	if err != nil {
		return err
	}
	mtu := o.TunMTU
	if p.TunMTU > 0 {
		mtu = p.TunMTU
	}
	if mtu <= 0 {
		mtu = 1500
	}
	c.setPacketCeiling(max(mtu, o.TunMTU))
	peerID := p.PeerID
	if c.d.cfg.DisableDataV2 {
		peerID = wire.NoPeerID
	}
	comp := o.Compression
	if p.CompressionSet {
		comp = p.Compression
	}
	ch := datachan.New(datachan.Options{PeerID: peerID, Compression: comp})
	ch.SetPrimary(dk)
	c.data.Store(ch)

	s.ping, s.pingRestart = o.Ping, o.PingRestart
	if p.Ping > 0 {
		s.ping = p.Ping
	}
	switch {
	case p.PingRestart > 0:
		s.pingRestart = p.PingRestart
	case o.PingRestart == 0 && !o.PingRestartSet:
		// OpenVPN's client-mode default; "ping-restart 0" turns it off.
		s.pingRestart, s.probe = c.d.defaultPingRestart, true
	}
	s.exitNotify = o.ExplicitExitNotify
	if p.ExplicitExitNotify > 0 {
		s.exitNotify = p.ExplicitExitNotify
	}
	for _, f := range p.ProtocolFlags {
		if f == "cc-exit" {
			s.ccExit = true
		}
	}
	if p.AuthToken != "" {
		s.authToken, s.authTokenUser = p.AuthToken, p.AuthTokenUser
	}

	c.info = TunnelInfo{
		IPv4:          p.IPv4,
		IPv6:          p.IPv6,
		MTU:           mtu,
		DNS:           append([]netip.Addr(nil), p.DNS...),
		Remote:        c.remote,
		Cipher:        cipher,
		KeyDerivation: s.keyDerivation,
		TLSVersion:    tls.VersionName(ks.cs.Version),
	}

	s.up = true
	s.pushing = false
	ks.established = now
	c.markRecv(now)
	c.markSend(now)
	c.pingNs.Store(int64(s.ping))
	c.pingRestartNs.Store(int64(s.pingRestart))
	c.established.Store(true)
	c.kickWatchdog()
	var addrs []string
	for _, a := range []netip.Prefix{c.info.IPv4, c.info.IPv6} {
		if a.IsValid() {
			addrs = append(addrs, a.String())
		}
	}
	c.log.Infof("openvpn: tunnel up: %s, mtu %d, %s, %s keys, %s, peer-id %s, compression %v, ping %v, ping-restart %v",
		strings.Join(addrs, " "), mtu, cipher, s.keyDerivation, c.info.TLSVersion, peerIDString(peerID), comp, s.ping, s.pingRestart)
	close(c.ready)
	return nil
}

// chooseCipher picks the data cipher as OpenVPN 2.6 does, only ever one of
// IV_CIPHERS (data-ciphers plus the configured fallback): the pushed
// cipher; without one, the cipher the server's options string names (what
// a server without cipher negotiation runs); else the configured fallback.
// There is no implicit BF-CBC.
func (c *Client) chooseCipher(pushed, serverOptions string) (string, error) {
	d := c.d
	offered := strings.Join(d.ciphers, ":")
	if pushed != "" {
		cn, ok := datachan.CanonicalCipher(pushed)
		if !ok {
			return "", fmt.Errorf("openvpn: the server pushed data cipher %q: %w", printable(pushed), datachan.ErrUnsupported)
		}
		if !slices.Contains(d.ciphers, cn) {
			return "", fmt.Errorf("openvpn: the server pushed data cipher %s, which is not in data-ciphers (%s)", cn, offered)
		}
		return cn, nil
	}
	theirs := optionsCipher(serverOptions)
	if cn, ok := datachan.CanonicalCipher(theirs); ok && slices.Contains(d.ciphers, cn) {
		c.log.Infof("openvpn: the server pushed no cipher; using its cipher %s", cn)
		return cn, nil
	}
	if d.fallback != "" {
		cn, ok := datachan.CanonicalCipher(d.fallback)
		if !ok {
			return "", fmt.Errorf("openvpn: data-ciphers-fallback %q: %w", d.fallback, datachan.ErrUnsupported)
		}
		return cn, nil
	}
	if theirs != "" {
		return "", fmt.Errorf("openvpn: the server pushed no cipher and runs %s, which is not in data-ciphers (%s); add it there or set data-ciphers-fallback %s", printable(theirs), offered, printable(theirs))
	}
	return "", errors.New("openvpn: the server pushed no cipher and named none; set data-ciphers-fallback to the server's cipher")
}

// optionsCipher is the "cipher X" entry of an OCC options string, "" when
// it has none.
func optionsCipher(options string) string {
	for _, o := range strings.Split(options, ",") {
		if v, ok := strings.CutPrefix(o, "cipher "); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// sameDigest compares digest names as datachan reads them.
func sameDigest(a, b string) bool {
	ca, oka := datachan.CanonicalDigest(a)
	cb, okb := datachan.CanonicalDigest(b)
	return oka && okb && ca == cb
}

// dataKey derives a key state's data-channel keys with the negotiated
// cipher, digest and key derivation.
func (c *Client) dataKey(ks *keyState) (*datachan.KeyState, error) {
	s := &c.loop
	var (
		k2  *handshake.Key2
		err error
	)
	if s.keyDerivation == "tls-ekm" {
		if !ks.canEKM {
			return nil, fmt.Errorf("openvpn: server wants tls-ekm keys, but key %d's TLS session cannot export keying material", ks.id)
		}
		ekm, err := ks.cs.ExportKeyingMaterial(handshake.EKMLabel, nil, handshake.EKMLength)
		if err != nil {
			return nil, fmt.Errorf("openvpn: exporting keying material: %w", err)
		}
		k2, err = handshake.Key2FromEKM(ekm)
		clear(ekm)
		if err != nil {
			return nil, fmt.Errorf("openvpn: tls-ekm keys: %w", err)
		}
	} else {
		k2 = handshake.DeriveKey2PRF(ks.source, &ks.server.Source, s.ourSID, s.serverSID)
	}
	clear(ks.source.PreMaster[:])
	dk, err := datachan.NewKeyState(ks.id, s.cipher, s.digest, k2.ClientSend(), k2.ClientRecv())
	clear(k2[:])
	if err != nil {
		return nil, fmt.Errorf("openvpn: data key %d (%s/%s): %w", ks.id, s.cipher, s.digest, err)
	}
	return dk, nil
}

// redactPush hides the auth-token in a PUSH_REPLY before it is logged.
func redactPush(msg string) string {
	parts := strings.Split(msg, ",")
	for i, p := range parts {
		if f := strings.Fields(p); len(f) > 0 && (f[0] == "auth-token" || f[0] == "auth-token-user") {
			parts[i] = f[0] + " [redacted]"
		}
	}
	return strings.Join(parts, ",")
}

// printable trims a server-supplied text for a log line or error.
func printable(s string) string {
	const limit = 256
	if len(s) > limit {
		s = s[:limit]
	}
	return strings.Map(func(r rune) rune {
		if r == unicode.ReplacementChar || !unicode.IsPrint(r) {
			return '?'
		}
		return r
	}, s)
}

func suffix(arg string) string {
	if arg = printable(arg); arg != "" {
		return ": " + arg
	}
	return ""
}

func peerIDString(id uint32) string {
	if id == wire.NoPeerID {
		return "none"
	}
	return fmt.Sprint(id)
}
