package transport

// The client half of VPN-Core 0.12 transport/script.go: the route-supplied
// segment program a provider route with TCP selector 4 runs before the
// header exchange. Only the provider outbound sets Options.Script.

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"time"
)

var ErrScript = errors.New("transport: malformed or unsupported segment script")
var ErrUninitializedScriptCipher = errors.New("transport: zero-length terminal script leaves native AES contexts uninitialized")

// Segment follows the native descriptor: bit15 receives/discards Length bytes;
// otherwise its next Length bytes in the script are sent verbatim.
type Segment struct {
	Receive bool
	Length  int
	Data    []byte
}
type Script struct {
	Header   [7]byte
	Segments []Segment
}

// ParseScript preserves the seven-byte route-supplied prefix. Only its segment
// count (byte2) has established meaning here; other fields are not reinterpreted.
// A zero-length terminal enters native state6 without initializing its AES
// contexts, yet state6 reads/writes unconditionally invoke AES. Reject that
// broken branch instead of inventing a plaintext replacement.
func ParseScript(b []byte) (Script, error) {
	var s Script
	if len(b) < 7 || len(b) > 65535 {
		return s, ErrScript
	}
	copy(s.Header[:], b[:7])
	i := 7
	for j := 0; j < int(b[2]); j++ {
		if len(b)-i < 2 {
			return Script{}, ErrScript
		}
		v := binary.LittleEndian.Uint16(b[i : i+2])
		i += 2
		segment := Segment{Receive: v&0x8000 != 0, Length: int(v & 0x7fff)}
		if segment.Length == 0 {
			return Script{}, ErrUninitializedScriptCipher
		}
		if !segment.Receive {
			if segment.Length > len(b)-i {
				return Script{}, ErrScript
			}
			segment.Data = append([]byte(nil), b[i:i+segment.Length]...)
			i += segment.Length
		}
		s.Segments = append(s.Segments, segment)
	}
	if i != len(b) {
		return Script{}, ErrScript
	}
	return s, nil
}

func executeScript(ctx context.Context, rw io.ReadWriter, s Script) error {
	previousSend := false
	for _, v := range s.Segments {
		if err := ctx.Err(); err != nil {
			return err
		}
		if v.Receive {
			if _, err := io.CopyN(io.Discard, rw, int64(v.Length)); err != nil {
				return err
			}
			previousSend = false
			continue
		}
		if previousSend {
			timer := time.NewTimer(5 * time.Millisecond)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			}
		}
		if _, err := writeFull(rw, v.Data); err != nil {
			return err
		}
		previousSend = true
	}
	return nil
}
