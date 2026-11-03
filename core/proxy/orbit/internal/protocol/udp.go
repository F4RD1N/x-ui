package protocol

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

const (
	UDPHeaderSize          = 15
	MaxUDPDataSize         = 1470
	MaxUDPReceiveSize      = 1500
	UDPKindDNS        byte = 0x14
	UDPKindData       byte = 0x15
)

// UDPEnvelope is the recovered IPv4 datagram envelope. The native producer caps
// data at 1470 bytes; the receiver accepts total envelope sizes through 1500.
// IPv6 UDP envelopes have not been established and are rejected explicitly.
type UDPEnvelope struct {
	Kind                byte
	Source, Destination netip.AddrPort
	Data                []byte
}

func (u UDPEnvelope) MarshalBinary() ([]byte, error) {
	if u.Kind != UDPKindDNS && u.Kind != UDPKindData {
		return nil, ErrUnsupported
	}
	if !u.Source.IsValid() || !u.Destination.IsValid() || !u.Source.Addr().Is4() || !u.Destination.Addr().Is4() {
		return nil, fmt.Errorf("%w: UDP requires IPv4", ErrUnsupported)
	}
	if len(u.Data) > MaxUDPDataSize {
		return nil, fmt.Errorf("%w: UDP payload exceeds 1470 bytes", ErrMalformed)
	}
	b := make([]byte, UDPHeaderSize+len(u.Data))
	b[0] = u.Kind
	source, destination := u.Source.Addr().As4(), u.Destination.Addr().As4()
	copy(b[1:5], source[:])
	binary.LittleEndian.PutUint16(b[5:7], u.Source.Port())
	copy(b[7:11], destination[:])
	binary.LittleEndian.PutUint16(b[11:13], u.Destination.Port())
	binary.LittleEndian.PutUint16(b[13:15], uint16(len(u.Data)))
	copy(b[15:], u.Data)
	return b, nil
}

func (u UDPEnvelope) Frame() (Frame, error) {
	b, err := u.MarshalBinary()
	if err != nil {
		return Frame{}, err
	}
	return Frame{Type: TypeUDP, Payload: b}, nil
}

func ParseUDPEnvelope(b []byte) (UDPEnvelope, error) {
	if len(b) < UDPHeaderSize || len(b) > MaxUDPReceiveSize {
		return UDPEnvelope{}, ErrMalformed
	}
	if b[0] != UDPKindDNS && b[0] != UDPKindData {
		return UDPEnvelope{}, ErrUnsupported
	}
	if int(binary.LittleEndian.Uint16(b[13:15])) != len(b)-UDPHeaderSize {
		return UDPEnvelope{}, fmt.Errorf("%w: UDP payload length", ErrMalformed)
	}
	var source, destination [4]byte
	copy(source[:], b[1:5])
	copy(destination[:], b[7:11])
	return UDPEnvelope{b[0], netip.AddrPortFrom(netip.AddrFrom4(source), binary.LittleEndian.Uint16(b[5:7])), netip.AddrPortFrom(netip.AddrFrom4(destination), binary.LittleEndian.Uint16(b[11:13])), append([]byte(nil), b[15:]...)}, nil
}

func ParseUDPFrame(f Frame) (UDPEnvelope, error) {
	if f.Type != TypeUDP {
		return UDPEnvelope{}, ErrMalformed
	}
	return ParseUDPEnvelope(f.Payload)
}
