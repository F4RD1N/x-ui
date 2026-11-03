package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// VPN-Core 0.12 transport/script_test.go, client half. The camouflage reply
// comes from the test-only server half (script_server_test.go).

func TestNativeCamouflageServerHellos(t *testing.T) {
	for _, v := range fixtures(t).TLSHellos {
		b, err := MakeCamouflageServerHello(unhex(t, v.SessionHex), v.Hybrid, &lcgReader{state: v.Seed})
		if err != nil {
			t.Fatal(err)
		}
		if want := unhex(t, v.Hex); !bytes.Equal(b, want) {
			t.Fatalf("native hello differs (%d/%d bytes)", len(b), len(want))
		}
	}
}

func scriptBytes(segments ...Segment) []byte {
	b := []byte{0, 0, byte(len(segments)), 0, 0, 0, 0}
	for _, s := range segments {
		v := uint16(s.Length)
		if s.Receive {
			v |= 0x8000
		}
		b = binary.LittleEndian.AppendUint16(b, v)
		if !s.Receive {
			b = append(b, s.Data...)
		}
	}
	return b
}

func TestScriptParserAndFragmentedExchange(t *testing.T) {
	b := scriptBytes(Segment{Length: 3, Data: []byte("one")}, Segment{Receive: true, Length: 4}, Segment{Length: 3, Data: []byte("two")})
	s, err := ParseScript(b)
	if err != nil {
		t.Fatal(err)
	}
	a, c := net.Pipe()
	defer a.Close()
	defer c.Close()
	done := make(chan error, 1)
	go func() { done <- executeScript(context.Background(), fragmentedConn{a, 1}, s) }()
	p := make([]byte, 3)
	if _, err = io.ReadFull(c, p); err != nil || string(p) != "one" {
		t.Fatal(err, string(p))
	}
	if _, err = c.Write([]byte("abcd")); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(c, p); err != nil || string(p) != "two" {
		t.Fatal(err, string(p))
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	for n := 0; n < len(b); n++ {
		if _, err = ParseScript(b[:n]); err == nil {
			t.Fatalf("accepted short script %d", n)
		}
	}
	if _, err = ParseScript(scriptBytes(Segment{})); !errors.Is(err, ErrUninitializedScriptCipher) {
		t.Fatal("zero-length terminal segment accepted", err)
	}
	if _, err = ParseScript(append(b, 1)); err == nil {
		t.Fatal("trailing script accepted")
	}
	if _, err = ParseScript(make([]byte, 65536)); err == nil {
		t.Fatal("oversized script accepted")
	}
}

func fakeClientHello() []byte {
	// Structurally complete TLS 1.2 ClientHello carrying only public test bytes.
	b := []byte{0x16, 3, 1, 0, 0, 1, 0, 0, 0, 3, 3}
	b = append(b, make([]byte, 32)...)
	b = append(b, 0, 0, 2, 0x13, 1, 1, 0, 0, 8, 0, 21, 0, 4, 0, 0, 0, 0)
	binary.BigEndian.PutUint16(b[3:5], uint16(len(b)-5))
	n := len(b) - 9
	b[6] = byte(n >> 16)
	b[7] = byte(n >> 8)
	b[8] = byte(n)
	return b
}

// TestScriptCamouflageOwnedTCPPeer runs a selector-4 script (a TLS-shaped
// hello, then a 100-byte receive) before the header exchange, against the
// camouflage reply VPN-Core's server sends, and checks the framed stream.
func TestScriptCamouflageOwnedTCPPeer(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan error, 1)
	go func() {
		r, e := l.Accept()
		if e != nil {
			done <- e
			return
		}
		defer r.Close()
		_ = r.SetDeadline(time.Now().Add(3 * time.Second))
		// The client sends nothing after its hello until it has the reply,
		// so reading the record straight off the socket loses no bytes.
		if e = serveCamouflage(r, r, nil); e != nil {
			done <- e
			return
		}
		c, _, e := Server(context.Background(), r, Options{Timeout: time.Second})
		if e != nil {
			done <- e
			return
		}
		p := make([]byte, 4)
		if _, e = io.ReadFull(c, p); e == nil {
			_, e = c.Write(p)
		}
		done <- e
	}()
	raw, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	h := fakeClientHello()
	script := scriptBytes(Segment{Length: len(h), Data: h}, Segment{Receive: true, Length: 100})
	c, err := Client(context.Background(), raw, Options{Script: script, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err = c.Write([]byte("echo")); err != nil {
		t.Fatal(err)
	}
	p := make([]byte, 4)
	if _, err = io.ReadFull(c, p); err != nil || string(p) != "echo" {
		t.Fatal(err, string(p))
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

// A malformed script fails the handshake before any byte is sent.
func TestScriptMalformedSendsNothing(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	got := make(chan int, 1)
	go func() {
		n, _ := io.Copy(io.Discard, b)
		got <- int(n)
	}()
	_, err := Client(context.Background(), a, Options{Script: []byte{0, 0, 1, 0, 0, 0, 0}, Timeout: time.Second})
	if !errors.Is(err, ErrScript) {
		t.Fatal("malformed script accepted", err)
	}
	_ = a.Close()
	if n := <-got; n != 0 {
		t.Fatalf("a malformed script sent %d bytes", n)
	}
}

func FuzzSegmentScript(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		s, e := ParseScript(b)
		if e == nil && len(s.Segments) > 255 {
			t.Fatal("count exceeded")
		}
	})
}
