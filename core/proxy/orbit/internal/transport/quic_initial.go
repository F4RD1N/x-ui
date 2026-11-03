package transport

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

var ErrQUICInitial = errors.New("transport: unsupported or malformed reference QUIC Initial")

// QUICMetadata is the recovered custom Initial trailer. The userinfo envelope
// must be validated by the protocol authentication layer before trusting it.
type QUICMetadata struct {
	UserInfo     [128]byte
	ConnectionID uint32
	ChannelID    [16]byte
	ProxyBuffer  []byte
}

// QUICInitialOptions uses a callback so the native entropy ordering (header,
// random type byte, userinfo salts, then padding) can be reproduced exactly.
type QUICInitialOptions struct {
	Random         io.Reader
	EncodeUserInfo func(io.Reader) ([128]byte, error)
	ConnectionID   uint32
	ChannelID      [16]byte
	ProxyBuffer    []byte
	// PacketConnFactory lets platform adapters protect/bind the UDP socket before
	// it sends any packet (for example Android VpnService.protect).
	PacketConnFactory func(context.Context) (net.PacketConn, error)
	// ResolveUDP allows protected, context-aware bootstrap DNS. TLS ServerName
	// remains the configured identity even when this returns a numeric address.
	ResolveUDP func(context.Context, string) (*net.UDPAddr, error)
	// AllocateSocketID optionally shares the native channel ID namespace across
	// multiple TCP and QUIC connections. It must be safe for concurrent calls.
	AllocateSocketID func() (uint32, error)
}

// ParseReferenceVarint is deliberately limited to the 1/2-byte integers that
// the reference parser accepts. A generic QUIC varint parser would differ.
func ParseReferenceVarint(data []byte) (value, used int, err error) {
	if len(data) == 0 {
		return 0, 0, ErrQUICInitial
	}
	switch data[0] >> 6 {
	case 0:
		return int(data[0]), 1, nil
	case 1:
		if len(data) < 2 {
			return 0, 0, ErrQUICInitial
		}
		return int(binary.BigEndian.Uint16(data[:2]) & 0x3fff), 2, nil
	default:
		return 0, 0, ErrQUICInitial
	}
}

func appendReferenceVarint(dst []byte, value int) ([]byte, error) {
	if value < 0 || value >= 16384 {
		return nil, ErrQUICInitial
	}
	if value < 64 {
		return append(dst, byte(value)), nil
	}
	return append(dst, byte(value>>8)|0x40, byte(value)), nil
}

func initialOffsets(packet []byte) (lengthOffset, payloadOffset, payloadLength int, err error) {
	bad := func() (int, int, int, error) { return 0, 0, 0, ErrQUICInitial }
	if len(packet) < 7 || packet[0]&0xb0 != 0x80 {
		return bad()
	}
	i := 6 + int(packet[5])
	if i >= len(packet) {
		return bad()
	}
	i += 1 + int(packet[i])
	if i >= len(packet) {
		return bad()
	}
	token, n, e := ParseReferenceVarint(packet[i:])
	if e != nil {
		return bad()
	}
	i += n
	// The native path assumes an empty token and does not skip nonempty token
	// bytes. Reject retry/resumption rather than claim an unverified behavior.
	if token != 0 {
		return bad()
	}
	lengthOffset = i
	payloadLength, n, e = ParseReferenceVarint(packet[i:])
	if e != nil {
		return bad()
	}
	i += n
	if payloadLength > len(packet)-i {
		return bad()
	}
	// Native formatting drops any coalesced following packets. Require one
	// Initial explicitly to avoid silently losing a caller's datagrams.
	if i+payloadLength != len(packet) {
		return bad()
	}
	return lengthOffset, i, payloadLength, nil
}

func randomWord(r io.Reader) ([4]byte, error) {
	var b [4]byte
	_, err := io.ReadFull(r, b[:])
	return b, err
}

func referenceRandBuf(r io.Reader, dst []byte) error {
	// rand_buf groups eight bytes as second uint32 || first uint32.
	for len(dst) >= 8 {
		a, err := randomWord(r)
		if err != nil {
			return err
		}
		b, err := randomWord(r)
		if err != nil {
			return err
		}
		copy(dst, b[:])
		copy(dst[4:], a[:])
		dst = dst[8:]
	}
	for i := range dst {
		w, err := randomWord(r)
		if err != nil {
			return err
		}
		dst[i] = w[0]
	}
	return nil
}

// FormatQUICInitial appends the exact recovered terminal Initial envelope and
// changes the visible payload-length varint. QUIC packet protection is not
// recalculated: the receiver must strip this envelope before its QUIC stack.
// This codec alone is not a complete QUIC transport implementation.
func FormatQUICInitial(packet []byte, o QUICInitialOptions) ([]byte, error) {
	return formatQUICInitial(packet, o, true)
}

func formatQUICInitial(packet []byte, o QUICInitialOptions, pad bool) ([]byte, error) {
	lengthOffset, payloadOffset, payloadLength, err := initialOffsets(packet)
	if err != nil {
		return nil, err
	}
	if o.EncodeUserInfo == nil {
		return nil, errors.New("transport: userinfo encoder is required")
	}
	if len(o.ProxyBuffer) > 1024 {
		return nil, ErrProxyBuffer
	}
	r := o.Random
	if r == nil {
		r = rand.Reader
	}
	header, _, err := MakeHeader(r)
	if err != nil {
		return nil, err
	}
	w, err := randomWord(r)
	if err != nil {
		return nil, err
	}
	info, err := o.EncodeUserInfo(r)
	if err != nil {
		return nil, err
	}
	frame := make([]byte, 4, 1300)
	frame[0] = w[0]
	frame = append(frame, 1, 0, 1)
	frame = append(frame, info[:]...)
	frame = binary.LittleEndian.AppendUint32(frame, o.ConnectionID)
	frame = append(frame, o.ChannelID[:]...)
	if len(o.ProxyBuffer) > 0 {
		frame[1] |= 1
		frame = binary.LittleEndian.AppendUint16(frame, uint16(len(o.ProxyBuffer)))
		frame = append(frame, o.ProxyBuffer...)
	}
	if total := len(header) + len(frame) + len(packet); pad && total <= 1199 {
		padding := 1198 - total
		if padding < 0 {
			padding = 0
		}
		frame[1] |= 2
		frame = binary.LittleEndian.AppendUint16(frame, uint16(padding))
		start := len(frame)
		frame = append(frame, make([]byte, padding)...)
		if err = referenceRandBuf(r, frame[start:]); err != nil {
			return nil, err
		}
	}
	if len(header)+len(frame) > 1300 {
		return nil, ErrQUICInitial
	}
	binary.LittleEndian.PutUint16(frame[2:4], uint16(len(frame)-4))
	out := append([]byte(nil), packet[:lengthOffset]...)
	out, err = appendReferenceVarint(out, payloadLength+len(header)+len(frame))
	if err != nil {
		return nil, err
	}
	out = append(out, packet[payloadOffset:]...)
	out = append(out, header...)
	out = append(out, frame...)
	return out, nil
}

// RewriteQUICInitial performs the relay branch of init_packet_filter: retain
// the protected QUIC payload, encrypted userinfo, connection ID and channel ID;
// replace the route with the next node's nested route. A fresh obfuscation header
// is generated, but the relay does not add the client's optional padding.
func RewriteQUICInitial(packet, nextProxy []byte, random io.Reader) ([]byte, QUICMetadata, error) {
	plain, meta, err := StripQUICInitial(packet)
	if err != nil {
		return nil, meta, err
	}
	out, err := formatQUICInitial(plain, QUICInitialOptions{
		Random:         random,
		EncodeUserInfo: func(io.Reader) ([128]byte, error) { return meta.UserInfo, nil },
		ConnectionID:   meta.ConnectionID,
		ChannelID:      meta.ChannelID,
		ProxyBuffer:    nextProxy,
	}, false)
	return out, meta, err
}

// SplitQUICInitialDatagram returns the first Initial packet and any coalesced
// packets that follow it. Returned slices borrow the datagram. The native codec
// operates on one Initial; socket adapters preserve the remainder separately.
func SplitQUICInitialDatagram(datagram []byte) (initial, remainder []byte, err error) {
	end, err := quicInitialEnd(datagram)
	if err != nil {
		return nil, nil, err
	}
	return datagram[:end], datagram[end:], nil
}

// ParseUDPParameters recovers the native vector2string -> strlen SNI argument.
// No schema or transport script is encoded here. Empty parameters leave SNI
// unspecified; certificate-verification policy belongs to the caller's TLS config.
func ParseUDPParameters(parameters []byte) string {
	for i, b := range parameters {
		if b == 0 {
			return string(parameters[:i])
		}
	}
	return string(parameters)
}

// StripQUICInitial reverses the terminal (non-relay) envelope. It returns
// encrypted userinfo for separate validation; it does not authenticate peers.
func StripQUICInitial(packet []byte) ([]byte, QUICMetadata, error) {
	var meta QUICMetadata
	lengthOffset, payloadOffset, payloadLength, err := initialOffsets(packet)
	if err != nil {
		return nil, meta, err
	}
	payload := packet[payloadOffset : payloadOffset+payloadLength]
	consumed, _, found := FindHeader(payload)
	if !found {
		return nil, meta, ErrQUICInitial
	}
	// Recover header start: valid headers are 10..15 bytes. The scanner returns
	// the first header, exactly as the native relay parser does.
	headerStart := -1
	for n := 10; n <= 15 && n <= consumed; n++ {
		b := payload[consumed-n : consumed]
		c, _, ok := FindHeader(b)
		if ok && c == n {
			headerStart = consumed - n
			break
		}
	}
	if headerStart < 0 {
		return nil, meta, ErrQUICInitial
	}
	frame := payload[consumed:]
	if len(frame) < 155 || int(binary.LittleEndian.Uint16(frame[2:4])) != len(frame)-4 {
		return nil, meta, ErrQUICInitial
	}
	if frame[1]&^byte(3) != 0 || frame[4] != 1 || frame[5] != 0 || frame[6] != 1 {
		return nil, meta, ErrQUICInitial
	}
	copy(meta.UserInfo[:], frame[7:135])
	meta.ConnectionID = binary.LittleEndian.Uint32(frame[135:139])
	copy(meta.ChannelID[:], frame[139:155])
	i := 155
	if frame[1]&1 != 0 {
		if len(frame)-i < 2 {
			return nil, meta, ErrQUICInitial
		}
		n := int(binary.LittleEndian.Uint16(frame[i : i+2]))
		i += 2
		if n > len(frame)-i {
			return nil, meta, ErrQUICInitial
		}
		meta.ProxyBuffer = append([]byte(nil), frame[i:i+n]...)
		i += n
	}
	if frame[1]&2 != 0 {
		if len(frame)-i < 2 {
			return nil, meta, ErrQUICInitial
		}
		n := int(binary.LittleEndian.Uint16(frame[i : i+2]))
		i += 2
		if n != len(frame)-i {
			return nil, meta, ErrQUICInitial
		}
		i += n
	}
	if i != len(frame) {
		return nil, meta, fmt.Errorf("%w: trailing metadata", ErrQUICInitial)
	}
	out := append([]byte(nil), packet[:lengthOffset]...)
	out, err = appendReferenceVarint(out, headerStart)
	if err != nil {
		return nil, meta, err
	}
	out = append(out, payload[:headerStart]...)
	return out, meta, nil
}
