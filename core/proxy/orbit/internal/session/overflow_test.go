package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/orbit/internal/protocol"
)

// inject sends n bytes of data for a client flow straight from the server's
// session, as the server's queue, socket buffer and the path deliver data
// that was already in flight when the client's 'full' notice went out.
func inject(t *testing.T, s *Session, id uint32, offset uint64, sequence uint64, n int) (uint64, uint64) {
	t.Helper()
	chunk := bytes.Repeat([]byte("d"), protocol.MaxDataSize)
	for n > 0 {
		m := min(n, len(chunk))
		f, err := (protocol.DataChunk{SocketID: id, Sequence: sequence, Offset: offset, Data: chunk[:m]}).Frame()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = s.send(ctx, f)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		offset += uint64(m)
		sequence++
		n -= m
	}
	return offset, sequence
}

func echoThrough(t *testing.T, client, server *Stream, msg string) {
	t.Helper()
	if _, err := client.Write([]byte(msg)); err != nil {
		t.Fatal("client write:", err)
	}
	b := make([]byte, len(msg))
	if _, err := io.ReadFull(server, b); err != nil {
		t.Fatal("server read:", err)
	}
	if _, err := server.Write(b); err != nil {
		t.Fatal("server write:", err)
	}
	if _, err := io.ReadFull(client, b); err != nil || string(b) != msg {
		t.Fatalf("client read %q %v", b, err)
	}
}

// TestClientStalledReaderFailsOnlyItsFlow: a client flow whose reader
// stopped receives more than its cap (data the server had in flight). Only
// that flow fails; the session and the other flows go on.
func TestClientStalledReaderFailsOnlyItsFlow(t *testing.T) {
	c, s := pair(t, Options{CloseTimeout: 200 * time.Millisecond})
	stalled, serverStalled := openPair(t, c, s)
	other, serverOther := openPair(t, c, s)
	echoThrough(t, other, serverOther, "before")
	inject(t, s, stalled.ID(), 0, 0, maxClientFlowBufferBytes+protocol.MaxDataSize)
	echoThrough(t, other, serverOther, "after")
	select {
	case <-c.Done():
		t.Fatal("one stalled reader ended the client session:", c.Err())
	default:
	}
	if _, err := stalled.Read(make([]byte, 1)); !errors.Is(err, ErrBufferLimit) {
		t.Fatal("the overflowing flow did not fail with ErrBufferLimit:", err)
	}
	eventually(t, func() bool { return c.BufferedBytes() == 0 })
	// The server learns that the flow is closed.
	_ = serverStalled.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.Copy(io.Discard, serverStalled); err != nil {
		t.Fatal("the server side of the failed flow did not end:", err)
	}
	// The data the server still had in flight for it is dropped quietly.
	inject(t, s, stalled.ID(), uint64(maxClientFlowBufferBytes+protocol.MaxDataSize), 1<<20, protocol.MaxDataSize)
	echoThrough(t, other, serverOther, "still")
}

// TestClientDropsDataAfterItsOwnClose: the client closes a flow while the
// server is still sending. What was in flight arrives after the close and
// must not end the session.
func TestClientDropsDataAfterItsOwnClose(t *testing.T) {
	c, s := pair(t, Options{CloseTimeout: 200 * time.Millisecond})
	closed, _ := openPair(t, c, s)
	other, serverOther := openPair(t, c, s)
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	inject(t, s, closed.ID(), 0, 0, 3*protocol.MaxDataSize)
	echoThrough(t, other, serverOther, "alive")
	select {
	case <-c.Done():
		t.Fatal("data in flight after a close ended the client session:", c.Err())
	default:
	}
}

// TestClientSessionBudgetFailsOnlyTheFlowOverIt: the session-wide receive
// budget also fails only the flow that went over it on the client.
func TestClientSessionBudgetFailsOnlyTheFlowOverIt(t *testing.T) {
	c, s := pair(t, Options{MaxBufferedBytes: 64 << 10})
	full, _ := openPair(t, c, s)
	other, serverOther := openPair(t, c, s)
	inject(t, s, full.ID(), 0, 0, 64<<10+1)
	echoThrough(t, other, serverOther, "ok")
	select {
	case <-c.Done():
		t.Fatal("the session budget ended the client session:", c.Err())
	default:
	}
	if _, err := full.Read(make([]byte, 1)); !errors.Is(err, ErrBufferLimit) {
		t.Fatal(err)
	}
}
