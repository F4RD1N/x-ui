package protocol

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"testing"
)

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func wire(t testing.TB, f Frame) []byte {
	t.Helper()
	b, err := f.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestFrameFragmentationCoalescingAndOwnership(t *testing.T) {
	frames := []Frame{{Type: TypeHeartbeat}, {Type: TypeData, Flags: 255, Payload: bytes.Repeat([]byte{7}, MaxPayloadSize)}, {Type: 255, Payload: []byte("opaque")}}
	var stream []byte
	for _, f := range frames {
		stream = append(stream, wire(t, f)...)
	}
	for fragment := 1; fragment <= 67; fragment++ {
		r := &chunkReader{data: append([]byte(nil), stream...), max: fragment}
		for _, want := range frames {
			got, err := ReadFrame(r)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(wire(t, got), wire(t, want)) {
				t.Fatalf("fragment=%d", fragment)
			}
		}
		if _, err := ReadFrame(r); err != io.EOF {
			t.Fatalf("EOF=%v", err)
		}
	}
	input := wire(t, frames[1])
	f, err := ParseFrame(input)
	if err != nil {
		t.Fatal(err)
	}
	input[4] ^= 255
	if f.Payload[0] != 7 {
		t.Fatal("payload aliases input")
	}
}

type chunkReader struct {
	data []byte
	max  int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := min(len(r.data), len(p), r.max)
	copy(p, r.data[:n])
	r.data = r.data[n:]
	return n, nil
}

type limitedWriter struct {
	b   bytes.Buffer
	max int
}

func (w *limitedWriter) Write(p []byte) (int, error) { return w.b.Write(p[:min(len(p), w.max)]) }

type badWriter int

func (w badWriter) Write(p []byte) (int, error) {
	switch w {
	case 0:
		return 0, nil
	case 1:
		return -1, nil
	case 2:
		return len(p) + 1, nil
	default:
		return 0, io.ErrClosedPipe
	}
}

func TestFrameBoundsAndTruncation(t *testing.T) {
	full := wire(t, Frame{Type: 1, Payload: []byte{1, 2, 3}})
	for n := 0; n < len(full); n++ {
		if _, err := ParseFrame(full[:n]); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("n=%d err=%v", n, err)
		}
		_, err := ReadFrame(bytes.NewReader(full[:n]))
		expected := io.ErrUnexpectedEOF
		if n == 0 {
			expected = io.EOF
		}
		if !errors.Is(err, expected) {
			t.Fatalf("read n=%d err=%v", n, err)
		}
	}
	if _, err := ParseFrame(append(full, 0)); !errors.Is(err, ErrMalformed) {
		t.Fatal(err)
	}
	bad := []byte{1, 0, 0xff, 0xff}
	if _, err := ParseFrame(bad); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatal(err)
	}
	if _, err := ReadFrame(bytes.NewReader(bad)); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatal(err)
	}
	big := Frame{Payload: make([]byte, MaxPayloadSize+1)}
	if _, err := big.MarshalBinary(); err != ErrFrameTooLarge {
		t.Fatal(err)
	}
	if err := WriteFrame(io.Discard, big); err != ErrFrameTooLarge {
		t.Fatal(err)
	}
}

func TestWriteFrameShortWritesAndErrors(t *testing.T) {
	f := Frame{Type: 3, Flags: 9, Payload: []byte("sample")}
	w := &limitedWriter{max: 1}
	if err := WriteFrame(w, f); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(w.b.Bytes(), wire(t, f)) {
		t.Fatal("short write corrupted")
	}
	for _, w := range []badWriter{0, 1, 2, 3} {
		if err := WriteFrame(w, f); err == nil {
			t.Fatalf("bad writer %d accepted", w)
		}
	}
}

func TestSimpleControlsAndUDPConcatenation(t *testing.T) {
	for _, typ := range []byte{TypeConnectResponse, TypeHeartbeat, TypeLeave, TypeUDPControl, TypeUDPControlReady} {
		f, err := Control(typ, 3)
		if err != nil || len(f.Payload) != 0 || f.Flags != 3 {
			t.Fatalf("%v %v", f, err)
		}
	}
	if _, err := Control(TypeData, 0); err != ErrUnsupported {
		t.Fatal(err)
	}
	if n, err := ParseKickOut(KickOut(500)); n != 500 || err != nil {
		t.Fatalf("%d %v", n, err)
	}
	for _, f := range []Frame{{Type: TypeData, Payload: []byte{0, 0}}, {Type: TypeKickOut, Payload: []byte{1}}} {
		if _, err := ParseKickOut(f); err == nil {
			t.Fatal("bad kick accepted")
		}
	}
	f, err := UDPFrame([]byte("first"), nil, []byte("second"))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(wire(t, f)); got != "12000b0066697273747365636f6e64" {
		t.Fatal(got)
	}
	if _, err := UDPFrame(make([]byte, MaxPayloadSize), []byte{1}); err != ErrFrameTooLarge {
		t.Fatal(err)
	}
}

func FuzzFrame(f *testing.F) {
	for _, s := range []string{"", "03000000", "01029700010001", "1000190078563412070000000000000000000000000000000102030405", "0000ffff"} {
		b, _ := hex.DecodeString(s)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := ParseFrame(b)
		if err != nil {
			return
		}
		out, err := got.MarshalBinary()
		if err != nil || !bytes.Equal(out, b) {
			t.Fatal("frame did not round trip")
		}
		read, err := ReadFrame(bytes.NewReader(b))
		if err != nil || !bytes.Equal(wire(t, read), b) {
			t.Fatal("stream differed")
		}
	})
}
