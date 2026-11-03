package protocol

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
)

const UserInfoSize = 128

// ConnectFlags is the native client's ordinary connection-request header byte.
// The reference separately sets bit 2 from its application-owned "cracked"
// state; this implementation does not invent or advertise that state.
const ConnectFlags byte = 0x02

// This is an embedded wire-format constant, not an operator credential. The
// fixed-key record is not authentication: servers must validate decoded tokens.
var commonKey = [16]byte{0x40, 0x73, 0x64, 0x21, 0x6c, 0x33, 0x6a, 0x75, 0x77, 0x26, 0x2d, 0x23, 0x6d, 0x39, 0x24, 0x3c}

type UserInfo struct {
	UID, Token, DeviceID string
	MemberLevel          uint16
	Flag0, Flag1         bool
}

// NormalizeIdentity performs the native setter's byte truncation and decoder's
// first-NUL termination. Truncation deliberately does not repair UTF-8.
func NormalizeIdentity(u UserInfo) UserInfo {
	u.UID = boundedString([]byte(u.UID), 32)
	u.Token = boundedString([]byte(u.Token), 32)
	u.DeviceID = boundedString([]byte(u.DeviceID), 40)
	return u
}

func boundedString(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	if at := bytes.IndexByte(b, 0); at >= 0 {
		b = b[:at]
	}
	return string(b)
}

// EncodeUserInfo uses crypto/rand unless an explicit entropy reader is supplied
// for reproducible tests. Entropy supplies four little-endian 16-bit fields.
func EncodeUserInfo(u UserInfo, entropy io.Reader) ([UserInfoSize]byte, error) {
	var plain, out [UserInfoSize]byte
	if entropy == nil {
		entropy = rand.Reader
	}
	for _, off := range []int{0, 36, 72, 120} {
		if _, err := io.ReadFull(entropy, plain[off:off+2]); err != nil {
			return out, fmt.Errorf("protocol: userinfo randomness: %w", err)
		}
	}
	copy(plain[4:36], u.UID)
	copy(plain[40:72], u.Token)
	copy(plain[80:120], u.DeviceID)
	binary.LittleEndian.PutUint16(plain[76:78], 0xab9f)
	if u.Flag0 {
		plain[78] |= 1
	}
	if u.Flag1 {
		plain[78] |= 2
	}
	binary.LittleEndian.PutUint16(plain[124:126], u.MemberLevel)
	block, _ := aes.NewCipher(commonKey[:])
	cipher.NewCBCEncrypter(block, commonKey[:]).CryptBlocks(out[:], plain[:])
	return out, nil
}

func DecodeUserInfo(encoded []byte) (UserInfo, error) {
	if len(encoded) != UserInfoSize {
		return UserInfo{}, fmt.Errorf("%w: userinfo length", ErrMalformed)
	}
	var plain [UserInfoSize]byte
	block, _ := aes.NewCipher(commonKey[:])
	cipher.NewCBCDecrypter(block, commonKey[:]).CryptBlocks(plain[:], encoded)
	if binary.LittleEndian.Uint16(plain[76:78]) != 0xab9f {
		return UserInfo{}, fmt.Errorf("%w: userinfo marker", ErrMalformed)
	}
	return UserInfo{UID: boundedString(plain[4:36], 32), Token: boundedString(plain[40:72], 32), DeviceID: boundedString(plain[80:120], 40), MemberLevel: binary.LittleEndian.Uint16(plain[124:126]), Flag0: plain[78]&1 != 0, Flag1: plain[78]&2 != 0}, nil
}

type ConnectRequest struct {
	UserInfo     [UserInfoSize]byte
	ConnectionID uint32
	ChannelID    [16]byte
}

func ParseChannelID(s string) ([16]byte, error) {
	var id [16]byte
	if len(s) != 32 {
		return id, fmt.Errorf("%w: channel ID requires 32 hex characters", ErrMalformed)
	}
	_, err := hex.Decode(id[:], []byte(s))
	if err != nil {
		return [16]byte{}, fmt.Errorf("%w: invalid channel ID", ErrMalformed)
	}
	return id, nil
}

func (c ConnectRequest) Frame(flags byte) Frame {
	b := make([]byte, 151)
	binary.LittleEndian.PutUint16(b[:2], 1)
	b[2] = 1
	copy(b[3:131], c.UserInfo[:])
	binary.LittleEndian.PutUint32(b[131:135], c.ConnectionID)
	copy(b[135:], c.ChannelID[:])
	return Frame{Type: TypeConnect, Flags: flags, Payload: b}
}

func ParseConnectRequest(f Frame) (ConnectRequest, error) {
	var c ConnectRequest
	if err := require(f, TypeConnect, 151); err != nil {
		return c, err
	}
	if binary.LittleEndian.Uint16(f.Payload[:2]) != 1 || f.Payload[2] != 1 {
		return c, fmt.Errorf("%w: connection format", ErrUnsupported)
	}
	copy(c.UserInfo[:], f.Payload[3:131])
	c.ConnectionID = binary.LittleEndian.Uint32(f.Payload[131:135])
	copy(c.ChannelID[:], f.Payload[135:])
	return c, nil
}
