package ctlwrap

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"sync"
	"time"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/wire"
)

// TLSCryptV2ServerKey is the 128-byte OpenVPN server wrapping key.
type TLSCryptV2ServerKey [128]byte

// ParseTLSCryptV2ServerKey accepts a server PEM block, never a client key.
func ParseTLSCryptV2ServerKey(text []byte) (*TLSCryptV2ServerKey, error) {
	for len(text) > 0 {
		block, rest := pem.Decode(text)
		text = rest
		if block == nil {
			break
		}
		if block.Type != "OpenVPN tls-crypt-v2 server key" {
			continue
		}
		if len(block.Bytes) != 128 {
			return nil, fmt.Errorf("%w: tls-crypt-v2 server key length", ErrKey)
		}
		var k TLSCryptV2ServerKey
		copy(k[:], block.Bytes)
		clear(block.Bytes)
		return &k, nil
	}
	return nil, fmt.Errorf("%w: tls-crypt-v2 server PEM missing", ErrKey)
}

// UnwrapTLSCryptV2ClientKey authenticates WKc before exposing its client key
// or metadata. The bounded WKc trailer is itself part of the MAC input.
func UnwrapTLSCryptV2ClientKey(key *TLSCryptV2ServerKey, wkc []byte) (*StaticKey, []byte, error) {
	if key == nil {
		return nil, nil, ErrKey
	}
	if err := checkWKc(wkc); err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, nil, err
	}
	tag, ct, length := wkc[:32], wkc[32:len(wkc)-2], wkc[len(wkc)-2:]
	plain := make([]byte, len(ct))
	defer clear(plain)
	cipher.NewCTR(block, tag[:16]).XORKeyStream(plain, ct)
	mac := hmac.New(sha256.New, key[64:96])
	mac.Write(length)
	mac.Write(plain)
	if !hmac.Equal(mac.Sum(nil), tag) {
		return nil, nil, ErrAuth
	}
	var k StaticKey
	copy(k[:], plain[:256])
	return &k, bytes.Clone(plain[256:]), nil
}

// NewTLSCryptV2Server binds one transport session to the authenticated WKc
// in its first V3 reset. Repeated resets must carry that identical WKc.
func NewTLSCryptV2Server(key *TLSCryptV2ServerKey) (Wrapper, error) {
	if key == nil {
		return nil, ErrKey
	}
	return &tlsCryptV2ServerSession{key: *key}, nil
}

type tlsCryptV2ServerSession struct {
	mu    sync.Mutex
	key   TLSCryptV2ServerKey
	inner Wrapper
	wkc   []byte
}

func (v *tlsCryptV2ServerSession) Overhead() int { return 40 }
func (v *tlsCryptV2ServerSession) Wrap(p *wire.ControlPacket) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.inner == nil {
		return nil, ErrAuth
	}
	return v.inner.Wrap(p)
}
func (v *tlsCryptV2ServerSession) Unwrap(b []byte) (*wire.ControlPacket, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(b) < 9 {
		return nil, wire.ErrShort
	}
	op, kid := wire.SplitHeader(b[0])
	if op == wire.ControlHardResetClientV3 || op == wire.ControlWKCV1 {
		if len(b) < minWKcLen+9 {
			return nil, ErrAuth
		}
		n := int(binary.BigEndian.Uint16(b[len(b)-2:]))
		if n < minWKcLen || n > maxWKcLen || n > len(b)-9 {
			return nil, ErrAuth
		}
		wrapped := b[len(b)-n:]
		b = b[:len(b)-n]
		if v.inner == nil {
			if op != wire.ControlHardResetClientV3 || kid != 0 {
				return nil, ErrAuth
			}
			key, _, err := UnwrapTLSCryptV2ClientKey(&v.key, wrapped)
			if err != nil {
				return nil, err
			}
			defer clear(key[:])
			inner, err := NewTLSCrypt(key, false)
			if err != nil {
				return nil, err
			}
			packet, err := inner.Unwrap(b)
			if err != nil {
				return nil, err
			}
			v.inner = inner
			v.wkc = bytes.Clone(wrapped)
			return packet, nil
		}
		if !hmac.Equal(v.wkc, wrapped) {
			return nil, ErrAuth
		}
	}
	if v.inner == nil {
		return nil, ErrAuth
	}
	return v.inner.Unwrap(b)
}

// GenerateTLSCryptV2ServerKey creates an independent server wrapping key using
// the operating system's cryptographic random source.
func GenerateTLSCryptV2ServerKey() (*TLSCryptV2ServerKey, error) {
	var key TLSCryptV2ServerKey
	if _, err := rand.Read(key[:]); err != nil {
		clear(key[:])
		return nil, err
	}
	return &key, nil
}

// MarshalPEM exports the private server key in stock OpenVPN's server format.
// The caller must protect the returned material as a server credential.
func (k *TLSCryptV2ServerKey) MarshalPEM() []byte {
	if k == nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "OpenVPN tls-crypt-v2 server key", Bytes: k[:]})
}

// IssueTLSCryptV2ClientKey generates a fresh client Kc, wraps/authenticates it
// with the server key and returns a complete stock-compatible client PEM.
// Nil metadata uses OpenVPN's type-1 creation timestamp. Non-nil metadata is
// type-0 caller data (up to 733 bytes); the wrapper authenticates but does not
// interpret it. This issuance does not grant or replace TLS certificate access.
func IssueTLSCryptV2ClientKey(key *TLSCryptV2ServerKey, metadata []byte) ([]byte, error) {
	if key == nil {
		return nil, ErrKey
	}
	if len(metadata) > maxWKcLen-minWKcLen-1 {
		return nil, fmt.Errorf("%w: tls-crypt-v2 metadata too large", ErrKey)
	}
	var meta []byte
	if metadata == nil {
		meta = make([]byte, 9)
		meta[0] = 1
		binary.BigEndian.PutUint64(meta[1:], uint64(time.Now().Unix()))
	} else {
		meta = append([]byte{0}, metadata...)
	}
	plain := make([]byte, len(StaticKey{})+len(meta))
	defer clear(plain)
	if _, err := rand.Read(plain[:256]); err != nil {
		return nil, err
	}
	copy(plain[256:], meta)
	length := 32 + len(plain) + 2
	wkc := make([]byte, length)
	defer clear(wkc)
	binary.BigEndian.PutUint16(wkc[length-2:], uint16(length))
	mac := hmac.New(sha256.New, key[64:96])
	mac.Write(wkc[length-2:])
	mac.Write(plain)
	copy(wkc[:32], mac.Sum(nil))
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, err
	}
	cipher.NewCTR(block, wkc[:16]).XORKeyStream(wkc[32:length-2], plain)
	bundle := make([]byte, 256+len(wkc))
	defer clear(bundle)
	copy(bundle, plain[:256])
	copy(bundle[256:], wkc)
	return pem.EncodeToMemory(&pem.Block{Type: v2ClientKeyType, Bytes: bundle}), nil
}
