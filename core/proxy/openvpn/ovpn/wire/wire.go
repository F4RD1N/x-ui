// Package wire encodes and decodes OpenVPN packets as they appear on the link:
// the opcode/key-id byte, the fields of a control-channel packet, the
// data-channel header and the two-byte length framing used over TCP.
//
// Control packets here are in their unwrapped form. tls-auth and tls-crypt
// insert or encrypt fields between the session id and the ack array; that is
// the ctlwrap package's job, which uses AppendBody and ParseBody to do it.
//
// Unwrapped control packet layout:
//
//	op/key(1) session-id(8) ack-count(1) ack-ids(4*n) [remote-session-id(8) if n>0]
//	[message-packet-id(4), absent for P_ACK_V1] payload...
package wire

import (
	"encoding/binary"
	"errors"
	"io"
	"strconv"
)

// Opcode is the high five bits of the first byte of every packet.
type Opcode uint8

const (
	ControlHardResetClientV1 Opcode = 1
	ControlHardResetServerV1 Opcode = 2
	ControlSoftResetV1       Opcode = 3
	ControlV1                Opcode = 4
	AckV1                    Opcode = 5
	DataV1                   Opcode = 6
	ControlHardResetClientV2 Opcode = 7
	ControlHardResetServerV2 Opcode = 8
	DataV2                   Opcode = 9
	ControlHardResetClientV3 Opcode = 10
	ControlWKCV1             Opcode = 11
)

// KeyIDMask selects the key id from the first byte of a packet.
const KeyIDMask = 0x07

// MaxAcks is the largest ack array ParseBody accepts.
const MaxAcks = 8

// NoPeerID is the 24-bit peer id meaning "none assigned"; a channel without
// a pushed peer-id sends P_DATA_V1.
const NoPeerID uint32 = 0xFFFFFF

// MaxPacketSize is the largest packet the TCP framing can carry.
const MaxPacketSize = 65535

var (
	ErrShort     = errors.New("wire: packet too short")
	ErrBadOpcode = errors.New("wire: unexpected opcode")
	ErrTooMany   = errors.New("wire: ack array too long")
	ErrTooLarge  = errors.New("wire: packet too large for framing")
)

// Header builds the first byte of a packet.
func Header(op Opcode, keyID uint8) byte { return byte(op)<<3 | keyID&KeyIDMask }

// SplitHeader splits the first byte of a packet into opcode and key id.
func SplitHeader(b byte) (Opcode, uint8) { return Opcode(b >> 3), b & KeyIDMask }

// IsData reports whether op is P_DATA_V1 or P_DATA_V2.
func (op Opcode) IsData() bool { return op == DataV1 || op == DataV2 }

// IsControl reports whether op is one of the control-channel opcodes
// (1-5, 7, 8, 10, 11).
func (op Opcode) IsControl() bool {
	switch op {
	case ControlHardResetClientV1, ControlHardResetServerV1, ControlSoftResetV1, ControlV1, AckV1,
		ControlHardResetClientV2, ControlHardResetServerV2, ControlHardResetClientV3, ControlWKCV1:
		return true
	}
	return false
}

// IsReset reports whether op opens a key state: a hard reset (client or
// server, any version) or a soft reset.
func (op Opcode) IsReset() bool {
	switch op {
	case ControlHardResetClientV1, ControlHardResetServerV1, ControlSoftResetV1,
		ControlHardResetClientV2, ControlHardResetServerV2, ControlHardResetClientV3:
		return true
	}
	return false
}

// String names the opcode as OpenVPN logs it, e.g. "P_CONTROL_V1".
func (op Opcode) String() string {
	switch op {
	case ControlHardResetClientV1:
		return "P_CONTROL_HARD_RESET_CLIENT_V1"
	case ControlHardResetServerV1:
		return "P_CONTROL_HARD_RESET_SERVER_V1"
	case ControlSoftResetV1:
		return "P_CONTROL_SOFT_RESET_V1"
	case ControlV1:
		return "P_CONTROL_V1"
	case AckV1:
		return "P_ACK_V1"
	case DataV1:
		return "P_DATA_V1"
	case ControlHardResetClientV2:
		return "P_CONTROL_HARD_RESET_CLIENT_V2"
	case ControlHardResetServerV2:
		return "P_CONTROL_HARD_RESET_SERVER_V2"
	case DataV2:
		return "P_DATA_V2"
	case ControlHardResetClientV3:
		return "P_CONTROL_HARD_RESET_CLIENT_V3"
	case ControlWKCV1:
		return "P_CONTROL_WKC_V1"
	}
	return "P_OPCODE_" + strconv.Itoa(int(op))
}

// SessionID identifies one side of a control session.
type SessionID [8]byte

// PacketID numbers control-channel messages (per key state, from 0) and
// data-channel packets (per key, from 1).
type PacketID uint32

// ControlPacket is a control-channel packet without any tls-auth/tls-crypt
// wrapping.
type ControlPacket struct {
	Opcode    Opcode
	KeyID     uint8
	SessionID SessionID // the sender's session id
	// Acks are the peer's message ids this packet acknowledges.
	Acks []PacketID
	// RemoteSessionID is the receiver's session id; on the wire only when
	// len(Acks) > 0.
	RemoteSessionID SessionID
	// PacketID is the message id; not on the wire for P_ACK_V1.
	PacketID PacketID
	// Payload follows the message id; empty for P_ACK_V1. After ParseBody or
	// Unmarshal it aliases the input buffer.
	Payload []byte
}

// HasMessageID reports whether the packet carries a message packet id and a
// payload, i.e. it is not P_ACK_V1.
func (p *ControlPacket) HasMessageID() bool { return p.Opcode != AckV1 }

// AppendBody appends everything after the session id: the ack count, the
// acks, the remote session id (if any acks), the message id (unless
// P_ACK_V1) and the payload.
func AppendBody(dst []byte, p *ControlPacket) []byte {
	dst = append(dst, byte(len(p.Acks)))
	for _, id := range p.Acks {
		dst = binary.BigEndian.AppendUint32(dst, uint32(id))
	}
	if len(p.Acks) > 0 {
		dst = append(dst, p.RemoteSessionID[:]...)
	}
	if p.HasMessageID() {
		dst = binary.BigEndian.AppendUint32(dst, uint32(p.PacketID))
		dst = append(dst, p.Payload...)
	}
	return dst
}

// ParseBody parses what AppendBody writes into p, whose Opcode must already
// be set. p.Payload aliases body.
func ParseBody(p *ControlPacket, body []byte) error {
	if len(body) < 1 {
		return ErrShort
	}
	n := int(body[0])
	body = body[1:]
	if n > MaxAcks {
		return ErrTooMany
	}
	if len(body) < 4*n {
		return ErrShort
	}
	p.Acks = nil
	if n > 0 {
		p.Acks = make([]PacketID, n)
		for i := range p.Acks {
			p.Acks[i] = PacketID(binary.BigEndian.Uint32(body[4*i:]))
		}
		body = body[4*n:]
		if len(body) < 8 {
			return ErrShort
		}
		copy(p.RemoteSessionID[:], body[:8])
		body = body[8:]
	} else {
		p.RemoteSessionID = SessionID{}
	}
	if !p.HasMessageID() {
		p.PacketID = 0
		p.Payload = nil
		return nil
	}
	if len(body) < 4 {
		return ErrShort
	}
	p.PacketID = PacketID(binary.BigEndian.Uint32(body))
	p.Payload = body[4:]
	return nil
}

// Marshal encodes p unwrapped: header byte, session id, body.
func Marshal(p *ControlPacket) []byte {
	b := make([]byte, 0, 1+8+1+12*len(p.Acks)+4+len(p.Payload))
	b = append(b, Header(p.Opcode, p.KeyID))
	b = append(b, p.SessionID[:]...)
	return AppendBody(b, p)
}

// Unmarshal decodes an unwrapped control packet. It fails with ErrBadOpcode
// for data opcodes.
func Unmarshal(b []byte) (*ControlPacket, error) {
	if len(b) < 9 {
		return nil, ErrShort
	}
	op, key := SplitHeader(b[0])
	if !op.IsControl() {
		return nil, ErrBadOpcode
	}
	p := &ControlPacket{Opcode: op, KeyID: key}
	copy(p.SessionID[:], b[1:9])
	if err := ParseBody(p, b[9:]); err != nil {
		return nil, err
	}
	return p, nil
}

// AppendDataHeader appends the data-channel header: one byte for P_DATA_V1
// (peerID == NoPeerID), or the header byte followed by the 24-bit big-endian
// peer id for P_DATA_V2.
func AppendDataHeader(dst []byte, keyID uint8, peerID uint32) []byte {
	if peerID == NoPeerID {
		return append(dst, Header(DataV1, keyID))
	}
	return append(dst, Header(DataV2, keyID), byte(peerID>>16), byte(peerID>>8), byte(peerID))
}

// ParseDataHeader reads the header of a data packet and returns its length
// (1 or 4). peerID is NoPeerID for P_DATA_V1.
func ParseDataHeader(b []byte) (op Opcode, keyID uint8, peerID uint32, headerLen int, err error) {
	if len(b) < 1 {
		return 0, 0, 0, 0, ErrShort
	}
	op, keyID = SplitHeader(b[0])
	switch op {
	case DataV1:
		return op, keyID, NoPeerID, 1, nil
	case DataV2:
		if len(b) < 4 {
			return 0, 0, 0, 0, ErrShort
		}
		return op, keyID, uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]), 4, nil
	}
	return 0, 0, 0, 0, ErrBadOpcode
}

// AppendFrame appends pkt prefixed with its 16-bit big-endian length, the
// framing OpenVPN uses over TCP.
func AppendFrame(dst, pkt []byte) ([]byte, error) {
	if len(pkt) > MaxPacketSize {
		return dst, ErrTooLarge
	}
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(pkt)))
	return append(dst, pkt...), nil
}

// FrameReader reads length-prefixed packets from a TCP stream.
type FrameReader struct {
	r io.Reader
}

// NewFrameReader returns a FrameReader reading from r.
func NewFrameReader(r io.Reader) *FrameReader { return &FrameReader{r: r} }

// ReadPacket reads one framed packet into buf and returns its length. A
// packet longer than buf is an error (io.ErrShortBuffer) after the packet has
// been consumed from the stream, so the stream stays in sync.
func (f *FrameReader) ReadPacket(buf []byte) (int, error) {
	var l [2]byte
	if _, err := io.ReadFull(f.r, l[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(l[:]))
	if n > len(buf) {
		if _, err := io.CopyN(io.Discard, f.r, int64(n)); err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF // the stream ended inside a packet
			}
			return 0, err
		}
		return 0, io.ErrShortBuffer
	}
	if _, err := io.ReadFull(f.r, buf[:n]); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return 0, err
	}
	return n, nil
}
