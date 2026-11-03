package transport

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/hkdf"
)

// This is VPN-Core 0.12's client REALITY adapter (transport/reality.go,
// DialReality), the client half only. It speaks to an unmodified
// github.com/xtls/reality server -- VPN-Core's vpn-server uses 8cdf7bf9c7f0
// (testing/orbit runs against it; this module's go.mod has 20261014 since
// the upfix round, see reality_server_test.go) -- but it is not Xray's
// transport/internet/reality client: that one is wired to Xray's stream
// settings and, when the server does not prove the key, keeps the connection
// to the cover and starts a background HTTP "spider" against it. Here a failed
// proof closes the attempt and sends nothing more. The package imports
// nothing from xtls/reality or transport/internet/reality and shares no state
// with them.

// ErrRealityAuthentication means that the peer did not present REALITY's
// authenticated temporary certificate. A normal, even publicly trusted, cover
// certificate never authorizes sending the native protocol to that peer.
var ErrRealityAuthentication = errors.New("transport: REALITY server authentication failed")

// RealityClientOptions configures the outer TCP handshake. The returned stream
// carries the existing native HTTP/TLS2 protocol and its normal authentication.
type RealityClientOptions struct {
	ServerName  string
	PublicKey   string // Unpadded base64url X25519 public key, exactly 32 bytes.
	ShortID     string // Zero to eight bytes, encoded as an even number of hex digits.
	Fingerprint string // Empty means chrome.
	// now is the clock written into the session ID; nil is time.Now. Only
	// this package's tests set it (a client clock outside the window).
	now func() time.Time
	// proofKey, when set, sees the derived key after the session ID is
	// sealed and before the certificate proof is checked. Only this
	// package's tests set it, to make the proof itself fail.
	proofKey func([]byte)
}

// This private wrapper is issued only after REALITY authenticates successfully.
// Native framing may use it to recognize an already encrypted outer stream.
type authenticatedRealityConn struct{ net.Conn }

func (c *authenticatedRealityConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return errors.New("transport: REALITY connection cannot half-close")
}

// IsRealityConnection reports whether conn is a stream DialReality returned.
func IsRealityConnection(conn net.Conn) bool {
	_, ok := conn.(*authenticatedRealityConn)
	return ok
}

func realityKey(encoded string) ([]byte, error) {
	key, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(key) != 32 || len(encoded) != 43 {
		return nil, errors.New("transport: REALITY key must be an unpadded base64url 32-byte X25519 key")
	}
	return key, nil
}

func realityShortID(encoded string) ([8]byte, error) {
	var id [8]byte
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) > len(id) {
		return id, errors.New("transport: REALITY short ID must contain zero to sixteen even hex digits")
	}
	copy(id[:], decoded)
	return id, nil
}

func validRealityServerName(name string) bool {
	if name == "" || len(name) > 253 || net.ParseIP(name) != nil || strings.TrimSpace(name) != name {
		return false
	}
	for _, part := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if part == "" || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
		for _, c := range part {
			if c != '-' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
				return false
			}
		}
	}
	return true
}

// DialReality authenticates a REALITY server over an already connected TCP
// stream. Failure closes raw. It never sends a cover HTTP request or starts a
// background connection after authentication fails.
func DialReality(ctx context.Context, raw net.Conn, options RealityClientOptions) (_ net.Conn, err error) {
	if raw == nil {
		return nil, errors.New("transport: REALITY requires a connection")
	}
	defer func() {
		if err != nil {
			raw.Close()
		}
	}()
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if !validRealityServerName(options.ServerName) {
		return nil, errors.New("transport: REALITY requires a DNS server name")
	}
	keyBytes, err := realityKey(options.PublicKey)
	if err != nil {
		return nil, err
	}
	peerKey, err := ecdh.X25519().NewPublicKey(keyBytes)
	if err != nil {
		return nil, errors.New("transport: invalid REALITY public key")
	}
	shortID, err := realityShortID(options.ShortID)
	if err != nil {
		return nil, err
	}
	name := options.Fingerprint
	if name == "" {
		name = "chrome"
	}
	if name != "chrome" && name != "firefox" && name != "safari" {
		return nil, errors.New("transport: REALITY fingerprint must be chrome, firefox or safari")
	}
	id, err := fingerprintID(name)
	if err != nil {
		return nil, errors.New("transport: unsupported REALITY fingerprint")
	}
	now := options.now
	if now == nil {
		now = time.Now
	}
	var authKey []byte
	verified := false
	client := utls.UClient(raw, &utls.Config{
		ServerName: options.ServerName, MinVersion: utls.VersionTLS13,
		InsecureSkipVerify:     true, // The mandatory HMAC proof below replaces CA trust.
		SessionTicketsDisabled: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 || len(authKey) != 32 {
				return ErrRealityAuthentication
			}
			cert, parseErr := x509.ParseCertificate(rawCerts[0])
			if parseErr != nil {
				return ErrRealityAuthentication
			}
			public, ok := cert.PublicKey.(ed25519.PublicKey)
			if !ok {
				return ErrRealityAuthentication
			}
			proof := hmac.New(sha512.New, authKey)
			proof.Write(public)
			if !hmac.Equal(cert.Signature, proof.Sum(nil)) {
				return ErrRealityAuthentication
			}
			verified = true
			return nil
		},
	}, id)
	if err = client.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("transport: build REALITY ClientHello: %w", err)
	}
	hello := client.HandshakeState.Hello
	if hello == nil || len(hello.Raw) < 71 || len(hello.Random) != 32 || hello.Raw[38] != 32 || client.HandshakeState.State13.KeyShareKeys == nil {
		return nil, errors.New("transport: REALITY fingerprint lacks TLS 1.3 key material")
	}
	// The pinned REALITY server requires the current hybrid key share. Reject
	// older presets before writing any ClientHello instead of silently changing
	// their fingerprint. X25519, when additionally offered, supplies the auth key.
	hybrid := false
	for _, share := range hello.KeyShares {
		if share.Group == utls.X25519MLKEM768 {
			hybrid = true
			break
		}
	}
	if !hybrid {
		return nil, errors.New("transport: REALITY fingerprint must offer X25519MLKEM768")
	}
	keys := client.HandshakeState.State13.KeyShareKeys
	private := keys.Ecdhe
	if private == nil {
		private = keys.MlkemEcdhe
	}
	if private == nil {
		return nil, errors.New("transport: REALITY fingerprint lacks X25519 key material")
	}
	authKey, err = private.ECDH(peerKey)
	if err != nil {
		return nil, errors.New("transport: invalid REALITY public key")
	}
	if _, err = io.ReadFull(hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")), authKey); err != nil {
		return nil, errors.New("transport: REALITY key derivation failed")
	}
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, err
	}
	seal, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	hello.SessionId = make([]byte, 32)
	clear(hello.Raw[39:71])
	plain := make([]byte, 16)
	copy(plain, []byte{0, 12, 0}) // VPN-Core client version; byte three is reserved.
	binary.BigEndian.PutUint32(plain[4:], uint32(now().Unix()))
	copy(plain[8:], shortID[:])
	seal.Seal(hello.SessionId[:0], hello.Random[20:], plain, hello.Raw)
	copy(hello.Raw[39:71], hello.SessionId)
	if options.proofKey != nil {
		options.proofKey(authKey)
	}
	if err = client.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("transport: REALITY handshake: %w", err)
	}
	if !verified || client.ConnectionState().Version != utls.VersionTLS13 {
		return nil, ErrRealityAuthentication
	}
	return &authenticatedRealityConn{Conn: client}, nil
}
