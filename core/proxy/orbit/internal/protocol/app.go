package protocol

import "encoding/binary"

const MaxAppDataSize = MaxPayloadSize - 8

// AppMessage is the recovered type-25 envelope. Application types are retained
// verbatim; interpretation belongs to the authenticated session's handler.
type AppMessage struct {
	Type      uint16
	RequestID uint32
	Data      []byte
}

func (m AppMessage) Frame() (Frame, error) {
	if len(m.Data) > MaxAppDataSize {
		return Frame{}, ErrMalformed
	}
	size := 6
	if len(m.Data) > 0 {
		size += 2 + len(m.Data)
	}
	b := make([]byte, size)
	binary.LittleEndian.PutUint16(b, m.Type)
	binary.LittleEndian.PutUint32(b[2:], m.RequestID)
	if len(m.Data) > 0 {
		binary.LittleEndian.PutUint16(b[6:], uint16(len(m.Data)))
		copy(b[8:], m.Data)
	}
	return Frame{Type: TypeApp, Payload: b}, nil
}

func ParseAppMessage(f Frame) (AppMessage, error) {
	b := f.Payload
	if f.Type != TypeApp || len(b) < 6 || len(b) > MaxPayloadSize {
		return AppMessage{}, ErrMalformed
	}
	m := AppMessage{Type: binary.LittleEndian.Uint16(b), RequestID: binary.LittleEndian.Uint32(b[2:])}
	if len(b) == 6 {
		return m, nil
	}
	if len(b) < 8 || int(binary.LittleEndian.Uint16(b[6:])) != len(b)-8 {
		return AppMessage{}, ErrMalformed
	}
	m.Data = append([]byte(nil), b[8:]...)
	return m, nil
}
