// Package protocol implements the recovered byte-level tunnel and control
// envelopes. Message names describe observable layouts, not backend policy.
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	HeaderSize                     = 4
	MaxFrameSize                   = 2080
	MaxPayloadSize                 = MaxFrameSize - HeaderSize
	MaxDataSize                    = 2048
	TypeConnect               byte = 1
	TypeConnectResponse       byte = 2
	TypeHeartbeat             byte = 3
	TypeLeave                 byte = 4
	TypeSocketConnect         byte = 8
	TypeSocketConnectResponse byte = 9
	TypeSocketClose           byte = 10
	TypeSocketBuffer          byte = 11
	TypeUDPControl            byte = 12
	TypeUDPControlReady       byte = 13
	TypeData                  byte = 16
	TypeUDP                   byte = 18
	TypeKickOut               byte = 20
	TypeApp                   byte = 25
	TypeSocketReadClose       byte = 30
)

var (
	ErrFrameTooLarge = errors.New("protocol: frame exceeds 2080 bytes")
	ErrMalformed     = errors.New("protocol: malformed message")
	ErrUnsupported   = errors.New("protocol: unsupported message format")
)

// Frame owns Payload after ParseFrame or ReadFrame. Flags are retained verbatim.
// Unknown types are retained so the session layer can apply its own policy.
type Frame struct {
	Type, Flags byte
	Payload     []byte
}

func (f Frame) MarshalBinary() ([]byte, error) {
	if len(f.Payload) > MaxPayloadSize {
		return nil, ErrFrameTooLarge
	}
	b := make([]byte, HeaderSize+len(f.Payload))
	b[0], b[1] = f.Type, f.Flags
	binary.LittleEndian.PutUint16(b[2:4], uint16(len(f.Payload)))
	copy(b[4:], f.Payload)
	return b, nil
}

// ParseFrame accepts exactly one complete frame, rejecting trailing data.
func ParseFrame(b []byte) (Frame, error) {
	if len(b) < HeaderSize {
		return Frame{}, io.ErrUnexpectedEOF
	}
	n := int(binary.LittleEndian.Uint16(b[2:4]))
	if n > MaxPayloadSize {
		return Frame{}, ErrFrameTooLarge
	}
	if len(b) < HeaderSize+n {
		return Frame{}, io.ErrUnexpectedEOF
	}
	if len(b) != HeaderSize+n {
		return Frame{}, fmt.Errorf("%w: trailing frame bytes", ErrMalformed)
	}
	return Frame{Type: b[0], Flags: b[1], Payload: append([]byte(nil), b[4:]...)}, nil
}

// ReadFrame handles arbitrary fragmentation without reading into the next frame.
// EOF before any header byte is io.EOF; a partial frame is io.ErrUnexpectedEOF.
func ReadFrame(r io.Reader) (Frame, error) {
	var h [HeaderSize]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return Frame{}, err
	}
	n := int(binary.LittleEndian.Uint16(h[2:]))
	if n > MaxPayloadSize {
		return Frame{}, ErrFrameTooLarge
	}
	f := Frame{Type: h[0], Flags: h[1], Payload: make([]byte, n)}
	if n != 0 {
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return Frame{}, err
		}
	}
	return f, nil
}

// WriteFrame must be serialized by callers sharing a stream. Short writes are
// retried; a writer making no progress is rejected instead of spinning forever.
func WriteFrame(w io.Writer, f Frame) error {
	b, err := f.MarshalBinary()
	if err != nil {
		return err
	}
	for len(b) > 0 {
		n, err := w.Write(b)
		if n < 0 || n > len(b) {
			return io.ErrShortWrite
		}
		b = b[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func require(f Frame, typ byte, sizes ...int) error {
	if f.Type != typ {
		return fmt.Errorf("%w: expected type %d, got %d", ErrMalformed, typ, f.Type)
	}
	for _, n := range sizes {
		if len(f.Payload) == n {
			return nil
		}
	}
	return fmt.Errorf("%w: type %d payload length %d", ErrMalformed, typ, len(f.Payload))
}

// Control constructs one of the recovered empty-body controls.
func Control(typ, flags byte) (Frame, error) {
	switch typ {
	case TypeConnectResponse, TypeHeartbeat, TypeLeave, TypeUDPControl, TypeUDPControlReady:
		return Frame{Type: typ, Flags: flags}, nil
	}
	return Frame{}, ErrUnsupported
}

func KickOut(reason uint16) Frame {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, reason)
	return Frame{Type: TypeKickOut, Payload: b}
}

func ParseKickOut(f Frame) (uint16, error) {
	if err := require(f, TypeKickOut, 2); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(f.Payload), nil
}

// UDPFrame copies the supplied envelope unchanged. It does not invent the
// unresolved destination envelope or claim arbitrary raw datagrams are usable.
func UDPFrame(parts ...[]byte) (Frame, error) {
	n := 0
	for _, part := range parts {
		if len(part) > MaxPayloadSize-n {
			return Frame{}, ErrFrameTooLarge
		}
		n += len(part)
	}
	f := Frame{Type: TypeUDP, Payload: make([]byte, 0, n)}
	for _, part := range parts {
		f.Payload = append(f.Payload, part...)
	}
	return f, nil
}
