package handshake

import (
	"errors"
	"testing"
)

func fuzzSeeds(f *testing.F, msgs ...[]byte) {
	for _, b := range msgs {
		f.Add(b)
		f.Add(b[:len(b)/2])
		f.Add(append(append([]byte(nil), b...), "PUSH_REPLY,ping 10\x00"...))
	}
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0, 2})
	f.Add([]byte{0, 0, 0, 0, 1, 0xff})
}

// checkParseError checks what every failed parse must look like.
func checkParseError(t *testing.T, b []byte, n int, err error, nilResult bool) {
	t.Helper()
	if !errors.Is(err, ErrShort) && !errors.Is(err, ErrBad) {
		t.Fatalf("error %v is neither ErrShort nor ErrBad", err)
	}
	if !nilResult || n != 0 {
		t.Fatalf("error %v with a result (n=%d)", err, n)
	}
	if errors.Is(err, ErrShort) && len(b) >= MaxMessageLen {
		t.Fatalf("ErrShort for %d bytes, at least MaxMessageLen", len(b))
	}
}

func FuzzParseServerMessage(f *testing.F) {
	fuzzSeeds(f,
		(&ServerMessage{Source: testServerSource(), Options: "V4,tls-server", PeerInfo: "IV_PROTO=2\n"}).Marshal(),
		(&ServerMessage{Options: "V4"}).Marshal()[:serverFixedLen+5],
	)
	f.Fuzz(func(t *testing.T, b []byte) {
		m, n, err := ParseServerMessage(b)
		if err != nil {
			checkParseError(t, b, n, err, m == nil)
			return
		}
		if n <= serverFixedLen || n > len(b) {
			t.Fatalf("consumed %d of %d bytes", n, len(b))
		}
		// The consumed prefix alone gives the same message.
		m2, n2, err := ParseServerMessage(b[:n])
		if err != nil || n2 != n || *m2 != *m {
			t.Fatalf("prefix parse differs: %+v %d %v vs %+v %d", m2, n2, err, m, n)
		}
		// What Marshal writes parses back to the same message.
		enc := m.Marshal()
		m3, n3, err := ParseServerMessage(enc)
		if err != nil || n3 != len(enc) || *m3 != *m {
			t.Fatalf("re-marshal round trip: %+v %d %v vs %+v", m3, n3, err, m)
		}
	})
}

func FuzzParseClientMessage(f *testing.F) {
	fuzzSeeds(f,
		(&ClientMessage{Source: testClientSource(), Options: "V4,tls-client", Username: "u", Password: "p", PeerInfo: "IV_PROTO=2\n"}).Marshal(),
		(&ClientMessage{Options: "V4"}).Marshal(),
	)
	f.Fuzz(func(t *testing.T, b []byte) {
		m, n, err := ParseClientMessage(b)
		if err != nil {
			checkParseError(t, b, n, err, m == nil)
			return
		}
		if n < clientFixedLen+8 || n > len(b) {
			t.Fatalf("consumed %d of %d bytes", n, len(b))
		}
		// Every client message is whole only at its end.
		if _, _, err := ParseClientMessage(b[:n-1]); err != ErrShort {
			t.Fatalf("one byte short: %v, want ErrShort", err)
		}
		m2, n2, err := ParseClientMessage(b[:n])
		if err != nil || n2 != n || *m2 != *m {
			t.Fatalf("prefix parse differs: %v %d %v", m2, n2, err)
		}
		enc := m.Marshal()
		m3, n3, err := ParseClientMessage(enc)
		if err != nil || n3 != len(enc) || *m3 != *m {
			t.Fatalf("re-marshal round trip: %v %d %v", m3, n3, err)
		}
	})
}
