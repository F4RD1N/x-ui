package mieru

import (
	"bytes"
	"testing"
)

// Authenticated metadata remains untrusted: authenticated peers can choose
// lengths, kinds and sequence numbers. Exercise that parser independently of
// ciphertext rejection so malformed lengths reach the actual allocation path.
func FuzzMieruMetadata(f *testing.F) {
	for _, kind := range []byte{openRequest, dataClient, closeRequest, ackClient} {
		f.Add(metadata(segment{kind: kind, session: 1, seq: 1, payload: []byte("seed")}))
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, p []byte) {
		s, prefix, suffix, err := parseMetadata(p)
		if err == nil && (len(s.payload) > 32768 || prefix < 0 || prefix > 255 || suffix < 0 || suffix > 255) {
			t.Fatal("metadata escaped protocol bounds")
		}
	})
}

func FuzzMieruInboundFrame(f *testing.F) {
	const username = "a3ac6533-7c27-45c4-93f2-9192745e218b"
	for _, custom := range []bool{false, true} {
		w, _ := newWire(nil, username, "synthetic-fuzz-secret", true, custom)
		nonce := make([]byte, 24)
		envelope := append(append([]byte(nil), nonce...), w.send.Seal(nil, nonce, metadata(segment{kind: openRequest, session: 1}), nil)...)
		frame := append([]byte(nil), envelope...)
		if custom {
			trailer, _ := UUIDTrailer(username, envelope)
			frame = append(frame, trailer[:]...)
		}
		f.Add(frame, custom)
	}
	f.Fuzz(func(t *testing.T, p []byte, custom bool) {
		if len(p) > 65535 {
			t.Skip()
		}
		w, err := newWire(nil, username, "synthetic-fuzz-secret", true, custom)
		if err != nil {
			t.Fatal(err)
		}
		w.server = true
		s, err := w.parse(bytes.NewReader(p))
		if err == nil && len(s.payload) > 32768 {
			t.Fatal("frame escaped payload bound")
		}
	})
}
