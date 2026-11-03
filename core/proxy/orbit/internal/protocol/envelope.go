package protocol

// VPN-Core 0.12 protocol/envelope.go: the provider API (launch) and router
// envelopes. Only the custom outbound's discovery uses them.

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

const (
	RouterHeaderSize = 10
	MaxRouterPayload = 65535
	MaxRouterDecoded = 32768
	DefaultAPILimit  = 4 << 20
)

// apiKeyIV returns the fixed reference API envelope key and IV. They are
// decoded per call rather than held in package variables, so nothing in this
// package is mutable shared state.
func apiKeyIV() (key, iv []byte) {
	key, _ = base64.StdEncoding.DecodeString("KrnxsOghq7vRIYK/cR//mgkCE/8nECQ6Qm+UReUNNlU=")
	iv, _ = base64.StdEncoding.DecodeString("RXPNTtNiqA+09K6McCB1iA==")
	return key, iv
}

func cryptCTR(key, iv, src []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	dst := make([]byte, len(src))
	cipher.NewCTR(block, iv).XORKeyStream(dst, src)
	return dst
}

// EncodeAPI preserves JSON bytes, then applies gzip and the fixed reference API
// CTR envelope. JSON validity and size are checked before compression.
func EncodeAPI(rawJSON []byte, maxBytes int) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultAPILimit
	}
	if len(rawJSON) > maxBytes {
		return nil, fmt.Errorf("%w: API JSON exceeds limit", ErrMalformed)
	}
	if !json.Valid(rawJSON) {
		return nil, fmt.Errorf("%w: API JSON", ErrMalformed)
	}
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write(rawJSON); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	if b.Len() > maxBytes {
		return nil, fmt.Errorf("%w: API envelope exceeds limit", ErrMalformed)
	}
	key, iv := apiKeyIV()
	return cryptCTR(key, iv, b.Bytes()), nil
}

// DecodeAPI also accepts the plain JSON error bodies seen on this API. It does
// not interpret HTTP success or decrypted JSON as successful authorization.
func DecodeAPI(body []byte, maxBytes int) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultAPILimit
	}
	if len(body) == 0 || len(body) > maxBytes {
		return nil, fmt.Errorf("%w: API envelope size", ErrMalformed)
	}
	if json.Valid(body) {
		return append([]byte(nil), body...), nil
	}
	key, iv := apiKeyIV()
	compressed := cryptCTR(key, iv, body)
	r, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("%w: API gzip", ErrMalformed)
	}
	decoded, err := readBounded(r, maxBytes)
	closeErr := r.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if !json.Valid(decoded) {
		return nil, fmt.Errorf("%w: decoded API JSON", ErrMalformed)
	}
	return decoded, nil
}

func readBounded(r io.Reader, n int) ([]byte, error) {
	// +1 is safe after this guard, even if a caller supplies max-int.
	if n < 0 || n == int(^uint(0)>>1) {
		return nil, fmt.Errorf("%w: invalid decode limit", ErrMalformed)
	}
	b, err := io.ReadAll(io.LimitReader(r, int64(n)+1))
	if err != nil {
		return nil, fmt.Errorf("%w: compressed payload: %v", ErrMalformed, err)
	}
	if len(b) > n {
		return nil, fmt.Errorf("%w: decompressed payload exceeds limit", ErrMalformed)
	}
	return b, nil
}

type RouterPacket struct {
	Random0              byte
	CorrelationID        uint32
	Random1, Type, Flags byte
	Payload              []byte
}

func (p RouterPacket) MarshalBinary() ([]byte, error) {
	if len(p.Payload) > MaxRouterPayload {
		return nil, fmt.Errorf("%w: router payload too large", ErrMalformed)
	}
	b := make([]byte, RouterHeaderSize+len(p.Payload))
	b[0] = p.Random0
	binary.LittleEndian.PutUint32(b[1:5], p.CorrelationID)
	b[5], b[6], b[7] = p.Random1, p.Type, p.Flags
	binary.LittleEndian.PutUint16(b[8:10], uint16(len(p.Payload)))
	copy(b[10:], p.Payload)
	return b, nil
}

func ParseRouterPacket(b []byte) (RouterPacket, error) {
	if len(b) < RouterHeaderSize {
		return RouterPacket{}, io.ErrUnexpectedEOF
	}
	n := int(binary.LittleEndian.Uint16(b[8:10]))
	if len(b) != RouterHeaderSize+n {
		return RouterPacket{}, fmt.Errorf("%w: router declared length", ErrMalformed)
	}
	return RouterPacket{b[0], binary.LittleEndian.Uint32(b[1:5]), b[5], b[6], b[7], append([]byte(nil), b[10:]...)}, nil
}

// ParseRouterResponse additionally validates expected correlation and type.
func ParseRouterResponse(b []byte, correlationID uint32) (RouterPacket, error) {
	p, err := ParseRouterPacket(b)
	if err != nil {
		return RouterPacket{}, err
	}
	if p.Type != 6 || p.CorrelationID != correlationID {
		return RouterPacket{}, fmt.Errorf("%w: router correlation or type", ErrMalformed)
	}
	return p, nil
}

type RouterRequest struct {
	UserInfo   [UserInfoSize]byte
	FlatBuffer []byte
}

// MarshalBinary encodes only the proven envelope. FlatBuffer schema validation
// belongs to the schema-specific layer; arbitrary bytes are not a valid route.
func (r RouterRequest) MarshalBinary() ([]byte, error) {
	if len(r.FlatBuffer) > MaxRouterPayload-133 {
		return nil, fmt.Errorf("%w: router request too large", ErrMalformed)
	}
	b := make([]byte, 133+len(r.FlatBuffer))
	binary.LittleEndian.PutUint16(b, 5)
	b[2] = 1
	copy(b[3:131], r.UserInfo[:])
	binary.LittleEndian.PutUint16(b[131:133], uint16(len(r.FlatBuffer)))
	copy(b[133:], r.FlatBuffer)
	return b, nil
}

func ParseRouterRequest(b []byte) (RouterRequest, error) {
	var r RouterRequest
	if len(b) < 133 || len(b) > MaxRouterPayload {
		return r, ErrMalformed
	}
	if binary.LittleEndian.Uint16(b) != 5 || b[2] != 1 {
		return r, ErrUnsupported
	}
	n := int(binary.LittleEndian.Uint16(b[131:133]))
	if len(b) != 133+n {
		return r, ErrMalformed
	}
	copy(r.UserInfo[:], b[3:131])
	r.FlatBuffer = append([]byte(nil), b[133:]...)
	return r, nil
}

func routerKey(nonce [8]byte) [16]byte {
	material := append(nonce[:], []byte("#v$p*")...)
	return md5.Sum(material)
}

// EncodeRouterBody and DecodeRouterBody handle compression and encryption only.
// The returned bytes still REQUIRE a complete RouteResp FlatBuffer verifier.
func EncodeRouterBody(flatBuffer []byte, nonce [8]byte) ([]byte, error) {
	if len(flatBuffer) > MaxRouterDecoded {
		return nil, fmt.Errorf("%w: router decoded size", ErrMalformed)
	}
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	if _, err := w.Write(flatBuffer); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	key := routerKey(nonce)
	encrypted := cryptCTR(key[:], key[:], b.Bytes())
	if len(encrypted) > MaxRouterPayload-10 {
		return nil, ErrMalformed
	}
	out := make([]byte, 10+len(encrypted))
	copy(out, nonce[:])
	binary.LittleEndian.PutUint16(out[8:10], uint16(len(encrypted)))
	copy(out[10:], encrypted)
	return out, nil
}

func DecodeRouterBody(body []byte) ([]byte, error) {
	if len(body) < 10 || len(body) > MaxRouterPayload {
		return nil, ErrMalformed
	}
	n := int(binary.LittleEndian.Uint16(body[8:10]))
	if len(body) != 10+n {
		return nil, fmt.Errorf("%w: router ciphertext length", ErrMalformed)
	}
	var nonce [8]byte
	copy(nonce[:], body[:8])
	key := routerKey(nonce)
	compressed := cryptCTR(key[:], key[:], body[10:])
	input := bytes.NewReader(compressed)
	r, err := zlib.NewReader(input)
	if err != nil {
		return nil, fmt.Errorf("%w: router zlib", ErrMalformed)
	}
	decoded, err := readBounded(r, MaxRouterDecoded)
	closeErr := r.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if input.Len() != 0 {
		return nil, fmt.Errorf("%w: trailing router zlib bytes", ErrMalformed)
	}
	return decoded, nil
}
