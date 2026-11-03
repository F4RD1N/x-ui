package ctlwrap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/wire"
)

// fuzzWrappers returns a fresh (sender, receiver) pair for selector sel:
// the receiver is what a client unwraps with.
func fuzzWrappers(t testing.TB, sel byte) (send, recv Wrapper) {
	k := testKey(20)
	switch sel % 5 {
	case 1:
		return mustTLSAuth(t, k, Normal, "SHA1"), mustTLSAuth(t, k, Inverse, "SHA1")
	case 2:
		return mustTLSAuth(t, k, Bidirectional, "SHA512"), mustTLSAuth(t, k, Bidirectional, "SHA512")
	case 3:
		return mustTLSCrypt(t, k, false), mustTLSCrypt(t, k, true)
	case 4:
		return mustTLSCrypt(t, k, false), mustV2(t, k, testWKc(299))
	}
	return NewPlain(), NewPlain()
}

func FuzzUnwrap(f *testing.F) {
	for sel := byte(0); sel < 5; sel++ {
		send, _ := fuzzWrappers(f, sel)
		for _, p := range testPackets() {
			b, err := send.Wrap(p)
			if err != nil {
				f.Fatal(err)
			}
			f.Add(sel, b)
		}
		f.Add(sel, []byte{})
		f.Add(sel, []byte{wire.Header(wire.ControlV1, 0)})
	}
	f.Fuzz(func(t *testing.T, sel byte, b []byte) {
		_, w := fuzzWrappers(t, sel)
		orig := bytes.Clone(b)
		p, err := w.Unwrap(b)
		if !bytes.Equal(b, orig) {
			t.Fatalf("Unwrap modified its input")
		}
		if err != nil {
			if p != nil {
				t.Fatalf("Unwrap returned a packet and %v", err)
			}
			return
		}
		if !p.Opcode.IsControl() || p.KeyID > wire.KeyIDMask || len(p.Acks) > wire.MaxAcks {
			t.Fatalf("Unwrap accepted %+v", p)
		}
		if len(p.Acks) == 0 && p.RemoteSessionID != (wire.SessionID{}) {
			t.Fatalf("remote session id without acks")
		}
		if !p.HasMessageID() && (p.PacketID != 0 || len(p.Payload) != 0) {
			t.Fatalf("P_ACK_V1 with message id or payload")
		}
		if sel%5 != 0 {
			if _, err := w.Unwrap(b); !errors.Is(err, ErrReplay) {
				t.Fatalf("second Unwrap of the same bytes: err = %v, want ErrReplay", err)
			}
		}
		q, err := wire.Unmarshal(wire.Marshal(p))
		if err != nil || !samePacket(p, q) {
			t.Fatalf("unwrapped packet does not survive Marshal/Unmarshal: %v", err)
		}
	})
}

func FuzzParseStaticKey(f *testing.F) {
	k := testKey(21)
	f.Add([]byte(keyText(k, "\n")))
	f.Add([]byte(keyText(k, "\r\n")))
	f.Add([]byte(staticKeyBegin + "\n# c\n" + staticKeyEnd))
	f.Add([]byte(staticKeyBegin + "\nzz\n" + staticKeyEnd))
	f.Add([]byte("garbage"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, text []byte) {
		got, err := ParseStaticKey(text)
		if err != nil {
			if got != nil || !errors.Is(err, ErrKey) {
				t.Fatalf("ParseStaticKey: %v, %v", got, err)
			}
			return
		}
		again, err := ParseStaticKey([]byte(keyText(got, "\n")))
		if err != nil || *again != *got {
			t.Fatalf("parsed key does not round-trip: %v", err)
		}
	})
}

func FuzzParseTLSCryptV2ClientKey(f *testing.F) {
	kc := testKey(22)
	f.Add([]byte(v2KeyText(kc, testWKc(299), "\n")))
	f.Add([]byte(v2KeyText(kc, testWKc(290), "\r\n")))
	f.Add([]byte(v2KeyText(kc, testWKc(1024), "\n")))
	f.Add([]byte(v2KeyText(kc, nil, "\n")))
	f.Add([]byte("-----BEGIN " + v2ClientKeyType + "-----\nAAAA\n-----END " + v2ClientKeyType + "-----\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, text []byte) {
		k, wkc, err := ParseTLSCryptV2ClientKey(text)
		if err != nil {
			if k != nil || wkc != nil || !errors.Is(err, ErrKey) {
				t.Fatalf("ParseTLSCryptV2ClientKey: %v", err)
			}
			return
		}
		if len(wkc) < minWKcLen || len(wkc) > maxWKcLen || int(binary.BigEndian.Uint16(wkc[len(wkc)-2:])) != len(wkc) {
			t.Fatalf("accepted a WKc of %d bytes", len(wkc))
		}
		if _, err := NewTLSCryptV2Client(k, wkc); err != nil {
			t.Fatalf("parsed key rejected by NewTLSCryptV2Client: %v", err)
		}
		k2, wkc2, err := ParseTLSCryptV2ClientKey([]byte(v2KeyText(k, wkc, "\n")))
		if err != nil || *k2 != *k || !bytes.Equal(wkc2, wkc) {
			t.Fatalf("parsed key does not round-trip: %v", err)
		}
	})
}
