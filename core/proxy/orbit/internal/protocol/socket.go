package protocol

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const AddressSize = 131

// Address preserves the complete native fixed-width address, including opaque
// padding. Known kinds are 1 (IPv4), 2 (IPv6), and 3 (NUL-terminated domain).
type Address struct {
	Kind    byte
	Port    uint16
	Storage [128]byte
}

func NewAddress(host string, port uint16) (Address, error) {
	a := Address{Port: port}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" {
			return Address{}, fmt.Errorf("%w: scoped IPv6 address", ErrUnsupported)
		}
		if ip.Is4() {
			a.Kind = 1
			b := ip.As4()
			copy(a.Storage[:], b[:])
		} else {
			a.Kind = 2
			b := ip.As16()
			copy(a.Storage[:], b[:])
		}
		return a, nil
	}
	if len(host) == 0 || len(host) > 127 || strings.ContainsAny(host, "\x00:/[]\r\n\t ") {
		return Address{}, fmt.Errorf("%w: destination host", ErrMalformed)
	}
	a.Kind = 3
	copy(a.Storage[:], host)
	return a, nil
}

func (a Address) Host() (string, error) {
	switch a.Kind {
	case 1:
		var b [4]byte
		copy(b[:], a.Storage[:4])
		return netip.AddrFrom4(b).String(), nil
	case 2:
		var b [16]byte
		copy(b[:], a.Storage[:16])
		return netip.AddrFrom16(b).String(), nil
	default:
		if a.Kind < 3 {
			return "", ErrUnsupported
		}
		s := boundedString(a.Storage[:], 128)
		if s == "" {
			return "", ErrMalformed
		}
		return s, nil
	}
}

func (a Address) NetworkAddress() (string, error) {
	host, err := a.Host()
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(a.Port))), nil
}

func (a Address) MarshalBinary() ([]byte, error) {
	b := make([]byte, AddressSize)
	b[0] = a.Kind
	binary.LittleEndian.PutUint16(b[1:3], a.Port)
	copy(b[3:], a.Storage[:])
	return b, nil
}

func ParseAddress(b []byte) (Address, error) {
	var a Address
	if len(b) != AddressSize {
		return a, ErrMalformed
	}
	a.Kind = b[0]
	a.Port = binary.LittleEndian.Uint16(b[1:3])
	copy(a.Storage[:], b[3:])
	return a, nil
}

type SocketConnect struct {
	SocketID uint32
	Metadata uint16
	Address  *Address
}

func (s SocketConnect) Frame() Frame {
	n := 6
	if s.Address != nil {
		n += AddressSize
	}
	b := make([]byte, n)
	binary.LittleEndian.PutUint32(b, s.SocketID)
	binary.LittleEndian.PutUint16(b[4:6], s.Metadata)
	flags := byte(0)
	if s.Address != nil {
		flags = 1
		a, _ := s.Address.MarshalBinary()
		copy(b[6:], a)
	}
	return Frame{Type: TypeSocketConnect, Flags: flags, Payload: b}
}

func ParseSocketConnect(f Frame) (SocketConnect, error) {
	var s SocketConnect
	if err := require(f, TypeSocketConnect, 6, 6+AddressSize); err != nil {
		return s, err
	}
	s.SocketID = binary.LittleEndian.Uint32(f.Payload)
	s.Metadata = binary.LittleEndian.Uint16(f.Payload[4:6])
	if len(f.Payload) > 6 {
		a, _ := ParseAddress(f.Payload[6:])
		s.Address = &a
	}
	return s, nil
}

// SocketConnectResponse copies the six-byte native socket-connection structure.
// Metadata remains opaque: it must not silently become a SOCKS error/status.
type SocketConnectResponse struct {
	SocketID uint32
	Metadata uint16
}

func (s SocketConnectResponse) Frame() Frame {
	f := SocketConnect{SocketID: s.SocketID, Metadata: s.Metadata}.Frame()
	f.Type = TypeSocketConnectResponse
	return f
}
func ParseSocketConnectResponse(f Frame) (SocketConnectResponse, error) {
	if err := require(f, TypeSocketConnectResponse, 6); err != nil {
		return SocketConnectResponse{}, err
	}
	return SocketConnectResponse{binary.LittleEndian.Uint32(f.Payload), binary.LittleEndian.Uint16(f.Payload[4:])}, nil
}

type SocketClose struct {
	SocketID uint32
	Flag     bool
}

func (s SocketClose) Frame() Frame {
	b := make([]byte, 5)
	binary.LittleEndian.PutUint32(b, s.SocketID)
	if s.Flag {
		b[4] = 1
	}
	return Frame{Type: TypeSocketClose, Payload: b}
}
func ParseSocketClose(f Frame) (SocketClose, error) {
	if err := require(f, TypeSocketClose, 5); err != nil {
		return SocketClose{}, err
	}
	return SocketClose{binary.LittleEndian.Uint32(f.Payload), f.Payload[4] != 0}, nil
}

// The two value fields retain neutral names until receive-window semantics are
// proven. Their widths and byte order are verified by the native packet oracle.
type SocketBuffer struct {
	SocketID uint32
	Value64  uint64
	Value32  uint32
	Flag     bool
}

func (s SocketBuffer) Frame() Frame {
	b := make([]byte, 17)
	binary.LittleEndian.PutUint32(b, s.SocketID)
	binary.LittleEndian.PutUint64(b[4:12], s.Value64)
	binary.LittleEndian.PutUint32(b[12:16], s.Value32)
	if s.Flag {
		b[16] = 1
	}
	return Frame{Type: TypeSocketBuffer, Payload: b}
}
func ParseSocketBuffer(f Frame) (SocketBuffer, error) {
	if err := require(f, TypeSocketBuffer, 17); err != nil {
		return SocketBuffer{}, err
	}
	return SocketBuffer{binary.LittleEndian.Uint32(f.Payload), binary.LittleEndian.Uint64(f.Payload[4:12]), binary.LittleEndian.Uint32(f.Payload[12:16]), f.Payload[16] == 1}, nil
}

// SocketReadClose reserves six bytes in the native builder, which only writes
// the socket ID. Preserve the unclassified tail on decode; owned emitters use 0.
type SocketReadClose struct {
	SocketID uint32
	Tail     [2]byte
}

func (s SocketReadClose) Frame() Frame {
	b := make([]byte, 6)
	binary.LittleEndian.PutUint32(b, s.SocketID)
	copy(b[4:], s.Tail[:])
	return Frame{Type: TypeSocketReadClose, Payload: b}
}
func ParseSocketReadClose(f Frame) (SocketReadClose, error) {
	var s SocketReadClose
	if err := require(f, TypeSocketReadClose, 6); err != nil {
		return s, err
	}
	s.SocketID = binary.LittleEndian.Uint32(f.Payload)
	copy(s.Tail[:], f.Payload[4:])
	return s, nil
}

type DataChunk struct {
	SocketID         uint32
	Sequence, Offset uint64
	Data             []byte
}

func (d DataChunk) Frame() (Frame, error) {
	if len(d.Data) > MaxDataSize {
		return Frame{}, ErrFrameTooLarge
	}
	b := make([]byte, 20+len(d.Data))
	binary.LittleEndian.PutUint32(b, d.SocketID)
	binary.LittleEndian.PutUint64(b[4:12], d.Sequence)
	binary.LittleEndian.PutUint64(b[12:20], d.Offset)
	copy(b[20:], d.Data)
	return Frame{Type: TypeData, Payload: b}, nil
}
func ParseDataChunk(f Frame) (DataChunk, error) {
	if f.Type != TypeData || len(f.Payload) < 20 || len(f.Payload) > 20+MaxDataSize {
		return DataChunk{}, ErrMalformed
	}
	return DataChunk{binary.LittleEndian.Uint32(f.Payload), binary.LittleEndian.Uint64(f.Payload[4:12]), binary.LittleEndian.Uint64(f.Payload[12:20]), append([]byte(nil), f.Payload[20:]...)}, nil
}
