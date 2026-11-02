package encoding

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

// The client's core version, carried in the request header's Addons as
// ClientVer (field 1000, which stock servers skip as an unknown field).
//
// The value is 15 bytes, fresh for every connection:
//
//	nonce[8] || (x, y, z) XOR HMAC-SHA256(uuid, label 0x01 nonce)[:3] || tag[4]
//	tag = HMAC-SHA256(uuid, label 0x02 nonce x y z)[:4]
//
// uuid is the 16-byte user id. Only a server that knows that user's id can
// read it, and a value made under another id, or any other bytes, fail the tag.
const (
	clientVerLabel    = "xray-vless-clientver"
	clientVerNonceLen = 8
	clientVerTagLen   = 4
	ClientVerLen      = clientVerNonceLen + 3 + clientVerTagLen
)

func clientVerMac(id []byte, kind byte, nonce []byte, ver []byte) []byte {
	m := hmac.New(sha256.New, id)
	m.Write([]byte(clientVerLabel))
	m.Write([]byte{kind})
	m.Write(nonce)
	m.Write(ver)
	return m.Sum(nil)
}

// SealClientVer returns the ClientVer addon value for version ver under the
// user id id.
func SealClientVer(id []byte, ver [3]byte) []byte {
	out := make([]byte, ClientVerLen)
	nonce := out[:clientVerNonceLen]
	if _, err := rand.Read(nonce); err != nil {
		return nil
	}
	ks := clientVerMac(id, 1, nonce, nil)
	for i := 0; i < 3; i++ {
		out[clientVerNonceLen+i] = ver[i] ^ ks[i]
	}
	copy(out[clientVerNonceLen+3:], clientVerMac(id, 2, nonce, ver[:])[:clientVerTagLen])
	return out
}

// OpenClientVer reads a ClientVer addon value made under the user id id. ok is
// false for an empty value, a value made under another id, or any other bytes.
func OpenClientVer(id []byte, v []byte) (ver [3]byte, ok bool) {
	if len(v) != ClientVerLen {
		return ver, false
	}
	nonce := v[:clientVerNonceLen]
	ks := clientVerMac(id, 1, nonce, nil)
	for i := 0; i < 3; i++ {
		ver[i] = v[clientVerNonceLen+i] ^ ks[i]
	}
	if !hmac.Equal(v[clientVerNonceLen+3:], clientVerMac(id, 2, nonce, ver[:])[:clientVerTagLen]) {
		return [3]byte{}, false
	}
	return ver, true
}

// ClientVerAllowed reports whether a request carrying the ClientVer value v
// from user id id passes an inbound's minClientVer/maxClientVer (3 bytes each,
// empty = no limit). With neither set every request passes, including ones
// that carry no version. A request with no readable version fails a min limit
// and passes a max-only limit.
func ClientVerAllowed(id []byte, v []byte, min []byte, max []byte) (bool, string) {
	if len(min) == 0 && len(max) == 0 {
		return true, ""
	}
	ver, ok := OpenClientVer(id, v)
	if !ok {
		if len(min) != 0 {
			return false, "no readable client version"
		}
		return true, ""
	}
	if len(min) != 0 && bytes.Compare(ver[:], min) < 0 {
		return false, fmt.Sprintf("client version %d.%d.%d below minClientVer", ver[0], ver[1], ver[2])
	}
	if len(max) != 0 && bytes.Compare(ver[:], max) > 0 {
		return false, fmt.Sprintf("client version %d.%d.%d above maxClientVer", ver[0], ver[1], ver[2])
	}
	return true, ""
}
