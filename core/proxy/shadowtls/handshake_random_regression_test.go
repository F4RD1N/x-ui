package shadowtls

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"testing"
)

type handshakeRecordInput struct {
	net.Conn
	*bytes.Reader
}

func (c *handshakeRecordInput) Read(p []byte) (int, error) { return c.Reader.Read(p) }

func serverHelloFixture(random []byte, tls13 bool) []byte {
	body := append([]byte{3, 3}, random...)
	body = append(body, 0, 0xc0, 0x2f, 0) // no session ID, cipher, compression
	if tls13 {
		body = append(body, 0, 6, 0, 43, 0, 2, 3, 4)
	}
	return append([]byte{2, 0, 0, byte(len(body))}, body...)
}

func consumeHandshakeRecord(t *testing.T, reader *handshakeReader, typ byte, payload []byte) {
	t.Helper()
	frame := record(typ, [2]byte{3, 3}, payload)
	reader.Conn = &handshakeRecordInput{Reader: bytes.NewReader(frame)}
	got := make([]byte, len(frame))
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, frame) {
		t.Fatal("handshake observation changed the TLS wire bytes")
	}
}

func assertServerRandomState(t *testing.T, reader *handshakeReader, random []byte) {
	t.Helper()
	if !bytes.Equal(reader.serverRandom, random) {
		t.Fatal("TLS ciphertext replaced the authenticated ServerHello random")
	}
	if reader.mac == nil || !bytes.Equal(reader.mac.Sum(nil), newMAC(reader.password, random).Sum(nil)) {
		t.Fatal("handshake authentication state does not match ServerHello")
	}
	if reader.xor != sha256.Sum256(append([]byte(reader.password), random...)) {
		t.Fatal("handshake masking state does not match ServerHello")
	}
}

func TestShadowTLSTLS12EncryptedFinishedKeepsServerRandom(t *testing.T) {
	for _, plausibleHeader := range []bool{false, true} {
		name := "random-cbc-iv"
		if plausibleHeader {
			name = "ciphertext-resembles-complete-serverhello"
		}
		t.Run(name, func(t *testing.T) {
			reader := &handshakeReader{version: 3, password: "regression-password"}
			random := bytes.Repeat([]byte{0x31}, 32)
			consumeHandshakeRecord(t, reader, 22, serverHelloFixture(random, false))
			assertServerRandomState(t, reader, random)
			consumeHandshakeRecord(t, reader, 20, []byte{1})
			ciphertext := bytes.Repeat([]byte{0x52}, 80)
			ciphertext[0] = 2 // A CBC IV begins with this byte about 1/256 of the time.
			if plausibleHeader {
				copy(ciphertext, serverHelloFixture(bytes.Repeat([]byte{0x53}, 32), false))
			}
			consumeHandshakeRecord(t, reader, 22, ciphertext)
			assertServerRandomState(t, reader, random)
			consumeHandshakeRecord(t, reader, 22, serverHelloFixture(bytes.Repeat([]byte{0x54}, 32), true))
			assertServerRandomState(t, reader, random)
		})
	}
}

func TestShadowTLSFragmentedServerHelloRandom(t *testing.T) {
	for _, size := range []int{1, 2, 3, 7, 13, 37} {
		reader := &handshakeReader{version: 3, password: "regression-password"}
		random := bytes.Repeat([]byte{0x61}, 32)
		hello := serverHelloFixture(random, true)
		for off := 0; off < len(hello); off += size {
			end := off + size
			if end > len(hello) {
				end = len(hello)
			}
			consumeHandshakeRecord(t, reader, 22, hello[off:end])
		}
		assertServerRandomState(t, reader, random)
	}
}

func TestShadowTLSCoalescedServerHelloObservation(t *testing.T) {
	reader := &handshakeReader{version: 3, password: "regression-password"}
	random := bytes.Repeat([]byte{0x64}, 32)
	message := serverHelloFixture(random, false)
	message = append(message, 11, 0, 0, 128) // A coalesced Certificate message.
	message = append(message, bytes.Repeat([]byte{0x65}, 128)...)
	consumeHandshakeRecord(t, reader, 22, message)
	assertServerRandomState(t, reader, random)
	if len(reader.serverHello.pending) != 0 {
		t.Fatal("coalesced certificate retained as an incomplete ServerHello")
	}
}

func TestShadowTLSServerHelloObservationBounds(t *testing.T) {
	for _, size := range []int{4, 41, 65537, 0xffffff + 4} {
		observer := new(serverHelloObserver)
		bodyLength := size - 4
		header := []byte{2, byte(bodyLength >> 16), byte(bodyLength >> 8), byte(bodyLength)}
		if _, err := observer.observe(22, header); err == nil {
			t.Fatalf("invalid declared ServerHello size %d accepted", size)
		}
		if len(observer.pending) > 4 {
			t.Fatal("invalid size caused unbounded reassembly")
		}
	}
	observer := new(serverHelloObserver)
	message := append([]byte{2, 0, 255, 252}, bytes.Repeat([]byte{0x66}, 65532)...)
	for off := 0; off < len(message); off += 1000 {
		end := off + 1000
		if end > len(message) {
			end = len(message)
		}
		if _, err := observer.observe(22, message[off:end]); err != nil {
			t.Fatal(err)
		}
		if len(observer.pending) > 65536 {
			t.Fatal("reassembly exceeded its bound")
		}
	}
	if !observer.final || len(observer.pending) != 0 || len(observer.random) != 32 {
		t.Fatal("maximum-sized complete ServerHello was not released")
	}
}

func TestShadowTLSHelloRetryThenFinalServerRandom(t *testing.T) {
	reader := &handshakeReader{version: 3, password: "regression-password"}
	retry, err := hex.DecodeString("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")
	if err != nil {
		t.Fatal(err)
	}
	consumeHandshakeRecord(t, reader, 22, serverHelloFixture(retry, true))
	assertServerRandomState(t, reader, retry)
	// TLS 1.3 allows a compatibility CCS before the final plaintext ServerHello.
	consumeHandshakeRecord(t, reader, 20, []byte{1})
	finalRandom := bytes.Repeat([]byte{0x72}, 32)
	hello := serverHelloFixture(finalRandom, true)
	consumeHandshakeRecord(t, reader, 22, hello[:11])
	consumeHandshakeRecord(t, reader, 22, hello[11:])
	assertServerRandomState(t, reader, finalRandom)
	consumeHandshakeRecord(t, reader, 22, serverHelloFixture(bytes.Repeat([]byte{0x73}, 32), true))
	assertServerRandomState(t, reader, finalRandom)
}
