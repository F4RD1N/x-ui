package transport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

const overlapHTTP101 = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n\r\n"

// The prefix's final LF followed by 01 80 looks like a 12-byte candidate,
// but only 11 bytes remain. The real 10-byte CRC-valid header begins at 01.
// Waiting to complete that false candidate deadlocks the request handshake.
func overlapHeader(t *testing.T) []byte {
	t.Helper()
	return unhex(t, "0180f60000003cbb7568")
}

func TestHeaderOverlappingIncompleteCandidate(t *testing.T) {
	header := overlapHeader(t)
	wantKey := md5.Sum(header)
	for _, prefix := range []string{overlapHTTP101, "HTTP/1.1 200 OK\r\n\r\n", "\n"} {
		packet := append([]byte(prefix), header...)
		consumed, key, found := FindHeader(packet)
		if !found || consumed != len(packet) || key != wantKey {
			t.Fatal("incomplete prefix hid the complete valid header", consumed, len(packet), found)
		}
		for split := 0; split < len(packet); split++ {
			discard, _, found := FindHeader(packet[:split])
			if found {
				t.Fatal("accepted a truncated header", split)
			}
			rest := append(bytes.Clone(packet[discard:split]), packet[split:]...)
			n, key, found := FindHeader(rest)
			if !found || discard+n != len(packet) || key != wantKey {
				t.Fatal("lost candidate across a fragment boundary", split, discard, n)
			}
		}
		// readHeader feeds the scanner one byte at a time even when an entire
		// transport record is buffered. Leave following protocol data untouched.
		payload := []byte("next-native-frame")
		r := bufio.NewReader(bytes.NewReader(append(bytes.Clone(packet), payload...)))
		key, err := readHeader(r, len(packet))
		if err != nil || key != wantKey {
			t.Fatal("incremental scanner blocked on the overlap", err)
		}
		remaining, err := io.ReadAll(r)
		if err != nil || !bytes.Equal(remaining, payload) {
			t.Fatal("scanner consumed following protocol bytes", err)
		}
	}
}

func TestHeaderOverlapRetainsPartialsRejectsCRCAndBoundsScan(t *testing.T) {
	header := overlapHeader(t)
	partial := append([]byte(overlapHTTP101), header[:len(header)-1]...)
	consumed, _, found := FindHeader(partial)
	if found || consumed != len(overlapHTTP101)-1 {
		t.Fatal("earliest incomplete candidate was discarded", consumed, found)
	}
	for index := len(header) - 4; index < len(header); index++ {
		bad := bytes.Clone(header)
		bad[index] ^= 1
		packet := append([]byte(overlapHTTP101), bad...)
		packet = append(packet, make([]byte, 20)...)
		if _, _, found := FindHeader(packet); found {
			t.Fatal("overlap bypassed CRC validation", index)
		}
	}
	packet := append([]byte(overlapHTTP101), header...)
	if _, err := readHeader(bufio.NewReader(bytes.NewReader(packet)), len(packet)-1); !errors.Is(err, ErrHeader) {
		t.Fatal("scanner exceeded its byte limit", err)
	}
	for _, noise := range [][]byte{bytes.Repeat([]byte{0}, 64), append(bytes.Clone(partial), make([]byte, 64)...)} {
		if _, err := readHeader(bufio.NewReader(bytes.NewReader(noise)), 32); !errors.Is(err, ErrHeader) {
			t.Fatal("invalid input exceeded its scan budget", err)
		}
	}
}

func TestHeaderOverlapHandshakeWithNoFollowingServerBytes(t *testing.T) {
	for _, fragmented := range []bool{false, true} {
		name := "single-write"
		if fragmented {
			name = "byte-fragments"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			var serverConn net.Conn = b
			if fragmented {
				serverConn = fragmentedConn{Conn: b, chunk: 1}
			}
			done := make(chan error, 1)
			payload := []byte("authenticated-protocol-follows-this-carrier")
			go func() {
				// MakeHeader consumes one random word then twelve bytes for this
				// vector. No padding or subsequent server frame rescues the parser.
				random := bytes.NewReader(append([]byte{1, 128, 0, 0}, make([]byte, 12)...))
				server, _, err := serverWithPrefix(ctx, serverConn, Options{Random: random}, []byte(overlapHTTP101))
				if err == nil {
					defer server.Close()
					got := make([]byte, len(payload))
					_, err = io.ReadFull(server, got)
					if err == nil && !bytes.Equal(got, payload) {
						err = errors.New("client stream was corrupted")
					}
					if err == nil {
						_, err = server.Write(got)
					}
				}
				done <- err
			}()
			client, err := Client(ctx, a, Options{})
			if err != nil {
				t.Fatal("prefixed carrier handshake stalled before native request", err)
			}
			defer client.Close()
			if _, err = client.Write(payload); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(payload))
			if _, err = io.ReadFull(client, got); err != nil || !bytes.Equal(got, payload) {
				t.Fatal("reverse stream was corrupted", err)
			}
			if err = <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
