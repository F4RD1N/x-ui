package protocol

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestNativeAppMessageVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/native-app.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Type              uint16
			RequestID         uint32
			DataHex, FrameHex string
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, tc := range fixture.Cases {
		data, _ := hex.DecodeString(tc.DataHex)
		want, _ := hex.DecodeString(tc.FrameHex)
		f, err := (AppMessage{Type: tc.Type, RequestID: tc.RequestID, Data: data}).Frame()
		if err != nil {
			t.Fatal(err)
		}
		got, err := f.MarshalBinary()
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("native vector mismatch type=%d err=%v", tc.Type, err)
		}
		decoded, err := ParseAppMessage(f)
		if err != nil || decoded.Type != tc.Type || decoded.RequestID != tc.RequestID || !bytes.Equal(decoded.Data, data) {
			t.Fatal("round trip mismatch", err)
		}
	}
}
func TestAppMessageBoundsAndOwnedData(t *testing.T) {
	for _, size := range []int{0, 1, MaxAppDataSize} {
		input := AppMessage{Type: 2, RequestID: 1, Data: bytes.Repeat([]byte{'x'}, size)}
		frame, err := input.Frame()
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := ParseAppMessage(frame)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decoded.Data, input.Data) {
			t.Fatal("data mismatch")
		}
		if size > 0 {
			frame.Payload[8] = 0
			if decoded.Data[0] != 'x' || input.Data[0] != 'x' {
				t.Fatal("data aliased")
			}
		}
	}
	if _, err := (AppMessage{Data: make([]byte, MaxAppDataSize+1)}).Frame(); err == nil {
		t.Fatal("oversize accepted")
	}
	for _, body := range [][]byte{nil, make([]byte, 5), make([]byte, 7), append(make([]byte, 6), 1, 0), append(make([]byte, 6), 0, 0, 99), make([]byte, MaxPayloadSize+1)} {
		if _, err := ParseAppMessage(Frame{Type: TypeApp, Payload: body}); err == nil {
			t.Fatalf("malformed length=%d", len(body))
		}
	}
	if _, err := ParseAppMessage(Frame{Type: TypeData, Payload: make([]byte, 6)}); err == nil {
		t.Fatal("wrong type")
	}
	if m, err := ParseAppMessage(Frame{Type: TypeApp, Payload: make([]byte, 8)}); err != nil || m.Type != 0 || len(m.Data) != 0 {
		t.Fatal("explicit empty", err)
	}
	a, _ := (AppMessage{}).Frame()
	b, _ := (AppMessage{Data: []byte{}}).Frame()
	if !reflect.DeepEqual(a, b) || len(a.Payload) != 6 {
		t.Fatal("empty must be canonical")
	}
}
func FuzzAppMessage(f *testing.F) {
	f.Add([]byte{1, 0, 1, 0, 0, 0})
	f.Add([]byte{2, 0, 1, 0, 0, 0, 1, 0, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := ParseAppMessage(Frame{Type: TypeApp, Payload: b})
		if err != nil {
			return
		}
		frame, err := m.Frame()
		if err != nil {
			t.Fatal(err)
		}
		again, err := ParseAppMessage(frame)
		if err != nil || !reflect.DeepEqual(m, again) {
			t.Fatal("round trip", err)
		}
	})
}
