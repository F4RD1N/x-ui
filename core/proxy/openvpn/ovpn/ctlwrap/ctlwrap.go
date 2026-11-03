// Package ctlwrap protects control-channel packets the way OpenVPN's
// --tls-auth, --tls-crypt and --tls-crypt-v2 do, or leaves them plain.
//
// Wire layouts (op = opcode/key byte, sid = sender session id, body =
// wire.AppendBody output, pid = 4-byte replay packet id, time = 4-byte
// unix time, both big-endian):
//
//	plain:      op sid body
//	tls-auth:   op sid hmac pid time body
//	            hmac = HMAC-<auth digest>(send hmac key, pid time op sid body)
//	tls-crypt:  op sid pid time tag AES-256-CTR(Ke, iv = tag[:16], body)
//	            tag  = HMAC-SHA256(Ka, op sid pid time body)
//	tls-crypt-v2 (client): exactly tls-crypt with the client key Kc, but the
//	            first packet is P_CONTROL_HARD_RESET_CLIENT_V3 and has WKc
//	            appended after the tls-crypt ciphertext.
//
// The replay pid starts at 1 and increases by one for every packet sent,
// retransmissions and acks included. time is fixed when the wrapper is made.
// Incoming packets are checked against a sliding replay window keyed on
// (time, pid).
//
// Key slots: a static key file is 256 bytes, four 64-byte parts:
// key[0].cipher, key[0].hmac, key[1].cipher, key[1].hmac. Key direction
// NORMAL (0) sends with key[0] and receives with key[1]; INVERSE (1) the
// reverse; BIDIRECTIONAL (no key-direction) uses key[0] both ways.
// tls-auth uses only the hmac parts, truncated to the digest size.
// tls-crypt uses cipher[:32] as the AES-256-CTR key and hmac[:32] as the
// HMAC-SHA256 key; its client always uses INVERSE and its server NORMAL.
package ctlwrap

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/wire"
)

// Errors. Unwrap returns ErrAuth or ErrReplay as they are; a packet too
// short for its protection or with a data opcode gives an error wrapping
// wire.ErrShort or wire.ErrBadOpcode, and an authentic packet whose body
// does not parse gives one wrapping the wire.ParseBody error. Key parsers
// and constructors wrap ErrKey.
var (
	ErrAuth   = errors.New("ctlwrap: packet failed authentication")
	ErrReplay = errors.New("ctlwrap: replayed packet")
	ErrKey    = errors.New("ctlwrap: malformed key")
)

// StaticKey is the 256-byte body of an "OpenVPN Static key V1" file.
type StaticKey [256]byte

// Direction selects which halves of a StaticKey are used for sending and
// receiving.
type Direction int

const (
	Bidirectional Direction = -1
	Normal        Direction = 0
	Inverse       Direction = 1
)

// String names the direction as the --key-direction argument would ("0",
// "1", or "bidirectional").
func (d Direction) String() string {
	switch d {
	case Bidirectional:
		return "bidirectional"
	case Normal:
		return "0"
	case Inverse:
		return "1"
	}
	return fmt.Sprintf("Direction(%d)", int(d))
}

const (
	staticKeyBegin = "-----BEGIN OpenVPN Static key V1-----"
	staticKeyEnd   = "-----END OpenVPN Static key V1-----"
	staticKeyHex   = 2 * len(StaticKey{})
)

// ParseStaticKey reads the text of an "OpenVPN Static key V1" file: the
// -----BEGIN/END OpenVPN Static key V1----- lines around 512 hex digits,
// with comments ('#'), blank lines and CRLF tolerated.
//
// Anything before the BEGIN line and after the END line is ignored. Inside
// the block, lines starting with '#' or ';' and blank lines are skipped and
// spaces or tabs between digits are allowed; any other character is an
// error. Errors wrap ErrKey and never quote key material.
func ParseStaticKey(text []byte) (*StaticKey, error) {
	var k StaticKey
	digits := 0
	inside, done := false, false
	lineNo := 0
	for len(text) > 0 && !done {
		var line []byte
		if i := bytes.IndexByte(text, '\n'); i >= 0 {
			line, text = text[:i], text[i+1:]
		} else {
			line, text = text, nil
		}
		lineNo++
		line = bytes.TrimSpace(line) // also strips the '\r' of CRLF
		if !inside {
			if string(line) == staticKeyBegin {
				inside = true
			}
			continue
		}
		if string(line) == staticKeyEnd {
			done = true
			continue
		}
		if len(line) == 0 || line[0] == '#' || line[0] == ';' {
			continue
		}
		for _, c := range line {
			if c == ' ' || c == '\t' {
				continue
			}
			v, ok := unhex(c)
			if !ok {
				return nil, fmt.Errorf("%w: static key line %d has a non-hex character", ErrKey, lineNo)
			}
			if digits >= staticKeyHex {
				return nil, fmt.Errorf("%w: static key has more than %d hex digits", ErrKey, staticKeyHex)
			}
			if digits%2 == 0 {
				k[digits/2] = v << 4
			} else {
				k[digits/2] |= v
			}
			digits++
		}
	}
	switch {
	case !inside:
		return nil, fmt.Errorf("%w: no %q line", ErrKey, staticKeyBegin)
	case !done:
		return nil, fmt.Errorf("%w: no %q line", ErrKey, staticKeyEnd)
	case digits != staticKeyHex:
		return nil, fmt.Errorf("%w: static key has %d hex digits, want %d", ErrKey, digits, staticKeyHex)
	}
	return &k, nil
}

func unhex(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// Parts returns the 64-byte cipher and hmac parts used to send and to
// receive in direction dir.
//
// The slices are copies. For a dir other than Bidirectional, Normal or
// Inverse all four are nil.
func (k *StaticKey) Parts(dir Direction) (sendCipher, sendHMAC, recvCipher, recvHMAC []byte) {
	var send, recv int
	switch dir {
	case Bidirectional:
		send, recv = 0, 0
	case Normal:
		send, recv = 0, 1
	case Inverse:
		send, recv = 1, 0
	default:
		return nil, nil, nil, nil
	}
	part := func(i int) []byte { return bytes.Clone(k[64*i : 64*(i+1)]) }
	return part(2 * send), part(2*send + 1), part(2 * recv), part(2*recv + 1)
}

// Wrapper adds and removes one control-channel protection. Implementations
// are safe for concurrent use.
type Wrapper interface {
	// Wrap encodes p for the wire with the protection applied.
	Wrap(p *wire.ControlPacket) ([]byte, error)
	// Unwrap authenticates (and decrypts) one received control packet. It
	// returns ErrAuth for a packet that fails authentication and ErrReplay
	// for one already seen. The returned payload may alias b.
	Unwrap(b []byte) (*wire.ControlPacket, error)
	// Overhead is the most bytes the protection adds to wire.Marshal's size.
	Overhead() int
}

// NewPlain returns the Wrapper for a session without tls-auth or tls-crypt.
//
// Its Unwrap is wire.Unmarshal: no authentication and no replay check (the
// reliability layer drops duplicate message ids).
func NewPlain() Wrapper { return plain{} }

// NewTLSAuth returns the --tls-auth Wrapper. digest is the --auth name
// (case-insensitive): MD5, SHA1 (OpenVPN's default), SHA224, SHA256,
// SHA384, SHA512; "" means SHA1.
//
// Dashes, underscores and OpenSSL 3's "SHA2-" spelling are accepted too
// ("SHA-256", "SHA2-256"). dir is the --key-direction (Bidirectional when
// the config has none).
func NewTLSAuth(key *StaticKey, dir Direction, digest string) (Wrapper, error) {
	if key == nil {
		return nil, fmt.Errorf("%w: no tls-auth key", ErrKey)
	}
	d, ok := lookupDigest(digest)
	if !ok {
		return nil, fmt.Errorf("ctlwrap: unsupported tls-auth digest %q", digest)
	}
	_, sendHMAC, _, recvHMAC := key.Parts(dir)
	if sendHMAC == nil {
		return nil, fmt.Errorf("ctlwrap: invalid key direction %v", dir)
	}
	return &tlsAuth{
		digest:  d,
		sendKey: sendHMAC[:d.size],
		recvKey: recvHMAC[:d.size],
		send:    newSender(),
	}, nil
}

// NewTLSCrypt returns the --tls-crypt Wrapper; client selects the
// direction (client: Inverse, server: Normal).
func NewTLSCrypt(key *StaticKey, client bool) (Wrapper, error) {
	return newTLSCrypt(key, client, nil)
}

const (
	v2ClientKeyType = "OpenVPN tls-crypt-v2 client key"
	// A WKc is tag(32) || AES-256-CTR(Kc(256) || metadata) || len(2); OpenVPN
	// caps the whole at 1024 bytes.
	minWKcLen = 32 + len(StaticKey{}) + 2
	maxWKcLen = 1024
)

// ParseTLSCryptV2ClientKey reads an "OpenVPN tls-crypt-v2 client key" PEM
// block: base64 of the 256-byte client key Kc followed by the wrapped key
// WKc (which ends with its own 16-bit big-endian length).
//
// Text around the block and other PEM blocks are ignored; CRLF is
// tolerated. The returned WKc is a fresh slice. Errors wrap ErrKey.
func ParseTLSCryptV2ClientKey(text []byte) (*StaticKey, []byte, error) {
	rest := text
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			return nil, nil, fmt.Errorf("%w: no valid -----BEGIN %s----- block", ErrKey, v2ClientKeyType)
		}
		if blk.Type != v2ClientKeyType {
			continue
		}
		data := blk.Bytes
		if len(data) < len(StaticKey{}) {
			return nil, nil, fmt.Errorf("%w: tls-crypt-v2 client key has %d bytes, too short", ErrKey, len(data))
		}
		var k StaticKey
		copy(k[:], data)
		wkc := bytes.Clone(data[len(k):])
		clear(data)
		if err := checkWKc(wkc); err != nil {
			clear(k[:])
			return nil, nil, err
		}
		return &k, wkc, nil
	}
}

func checkWKc(wkc []byte) error {
	if len(wkc) < minWKcLen || len(wkc) > maxWKcLen {
		return fmt.Errorf("%w: tls-crypt-v2 wrapped client key is %d bytes, want %d to %d", ErrKey, len(wkc), minWKcLen, maxWKcLen)
	}
	if n := int(binary.BigEndian.Uint16(wkc[len(wkc)-2:])); n != len(wkc) {
		return fmt.Errorf("%w: tls-crypt-v2 wrapped client key says it is %d bytes but is %d", ErrKey, n, len(wkc))
	}
	return nil
}

// NewTLSCryptV2Client returns the --tls-crypt-v2 client Wrapper: tls-crypt
// with key in the client direction, and wkc appended to every
// P_CONTROL_HARD_RESET_CLIENT_V3 it wraps (retransmissions included).
//
// wkc is also appended to P_CONTROL_WKC_V1, the opcode that exists to
// resend it. Unwrap is plain tls-crypt: servers never append anything.
func NewTLSCryptV2Client(key *StaticKey, wkc []byte) (Wrapper, error) {
	if err := checkWKc(wkc); err != nil {
		return nil, err
	}
	return newTLSCrypt(key, true, bytes.Clone(wkc))
}

func newTLSCrypt(key *StaticKey, client bool, wkc []byte) (*tlsCrypt, error) {
	if key == nil {
		return nil, fmt.Errorf("%w: no tls-crypt key", ErrKey)
	}
	dir := Normal
	if client {
		dir = Inverse
	}
	sendCipher, sendHMAC, recvCipher, recvHMAC := key.Parts(dir)
	sendBlock, err := aes.NewCipher(sendCipher[:32])
	if err != nil {
		return nil, fmt.Errorf("ctlwrap: tls-crypt cipher: %w", err)
	}
	recvBlock, err := aes.NewCipher(recvCipher[:32])
	if err != nil {
		return nil, fmt.Errorf("ctlwrap: tls-crypt cipher: %w", err)
	}
	return &tlsCrypt{
		sendBlock: sendBlock,
		recvBlock: recvBlock,
		sendMAC:   sendHMAC[:32],
		recvMAC:   recvHMAC[:32],
		send:      newSender(),
		wkc:       wkc,
	}, nil
}
