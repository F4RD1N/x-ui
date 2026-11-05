package anytls

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net"
	"testing"
	"time"
)

func anyTLSBackpressureStream(t *testing.T) *serverStream {
	t.Helper()
	r, w := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	s := &serverStream{read: r, deliver: w, queue: make(chan []byte, 8), queueSpace: make(chan struct{}, 1), ctx: ctx, cancel: cancel, pumpDone: make(chan struct{})}
	t.Cleanup(func() { s.close(false) })
	return s
}

func TestAnyTLSBackpressureByteBudgetMatrix(t *testing.T) {
	s := anyTLSBackpressureStream(t)
	frame := bytes.Repeat([]byte{'a'}, 65535)
	for i := 0; i < 4; i++ {
		if !s.enqueue(frame) {
			t.Fatal("initial byte-budget fill failed")
		}
	}
	accepted := make(chan bool, 1)
	go func() { accepted <- s.enqueue([]byte("overflow")) }()
	select {
	case result := <-accepted:
		t.Fatalf("full byte budget must wait, returned %v", result)
	case <-time.After(30 * time.Millisecond):
	}
	s.mu.Lock()
	queued := s.queued
	s.mu.Unlock()
	if queued != 4*len(frame) || len(s.queue) != 4 {
		t.Fatal("pending frame exceeded byte budget")
	}
	anyTLSBackpressurePump(t, s)
	readDone := make(chan error, 1)
	go func() {
		want := append(bytes.Repeat([]byte{'a'}, 4*len(frame)), []byte("overflow")...)
		got := make([]byte, len(want))
		_, err := io.ReadFull(s.read, got)
		if err == nil && !bytes.Equal(got, want) {
			err = io.ErrUnexpectedEOF
		}
		readDone <- err
	}()
	select {
	case ok := <-accepted:
		if !ok {
			t.Fatal("byte-budget wait rejected after drain")
		}
	case <-time.After(time.Second):
		t.Fatal("byte-budget wait did not wake")
	}
	select {
	case err := <-readDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("byte-budget stream did not drain")
	}
}

func TestAnyTLSBackpressureCancellationMatrix(t *testing.T) {
	s := anyTLSBackpressureStream(t)
	for i := 0; i < cap(s.queue); i++ {
		if !s.enqueue([]byte{'a'}) {
			t.Fatal("initial queue fill failed")
		}
	}
	accepted := make(chan bool, 1)
	go func() { accepted <- s.enqueue([]byte{'z'}) }()
	select {
	case result := <-accepted:
		t.Fatalf("full queue did not wait before cancellation: %v", result)
	case <-time.After(30 * time.Millisecond):
	}
	s.cancel()
	select {
	case ok := <-accepted:
		if ok {
			t.Fatal("canceled wait accepted frame")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not unblock enqueue")
	}
}

func TestAnyTLSBackpressureTenSecondStallMatrix(t *testing.T) {
	s := anyTLSBackpressureStream(t)
	for i := 0; i < cap(s.queue); i++ {
		if !s.enqueue([]byte{'a'}) {
			t.Fatal("initial queue fill failed")
		}
	}
	start := time.Now()
	if s.enqueue([]byte{'z'}) {
		t.Fatal("stalled queue accepted a frame")
	}
	elapsed := time.Since(start)
	if elapsed < 9500*time.Millisecond || elapsed > 20*time.Second {
		t.Fatalf("stall bound should be ten seconds, got %s", elapsed)
	}
	t.Logf("stalled queue released after %s", elapsed)
}

func TestAnyTLSBackpressureSlowReaderOneMiBIntegrityMatrix(t *testing.T) {
	s := anyTLSBackpressureStream(t)
	anyTLSBackpressurePump(t, s)
	payload := bytes.Repeat([]byte("integrity-check!"), 1+(1<<20)/16)[:1<<20]
	readDone := make(chan error, 1)
	go func() {
		got := make([]byte, len(payload))
		for offset := 0; offset < len(got); {
			n, err := s.read.Read(got[offset:min(offset+1024, len(got))])
			offset += n
			if err != nil {
				readDone <- err
				return
			}
			time.Sleep(100 * time.Microsecond)
		}
		if sha256.Sum256(got) != sha256.Sum256(payload) {
			readDone <- io.ErrUnexpectedEOF
			return
		}
		readDone <- nil
	}()
	for offset := 0; offset < len(payload); offset += 2048 {
		if !s.enqueue(payload[offset:min(offset+2048, len(payload))]) {
			t.Fatalf("slow-reader upload rejected at byte %d", offset)
		}
		s.mu.Lock()
		queued := s.queued
		s.mu.Unlock()
		if queued < 0 || queued > streamQueueBytes {
			t.Fatalf("queue byte budget violated: %d", queued)
		}
	}
	select {
	case err := <-readDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("slow-reader upload did not finish")
	}
}

func anyTLSBackpressurePump(t *testing.T, s *serverStream) {
	t.Helper()
	go func() { defer close(s.pumpDone); s.pump() }()
	t.Cleanup(func() {
		s.close(false)
		select {
		case <-s.pumpDone:
		case <-time.After(time.Second):
			t.Error("pump did not stop")
		}
	})
}

func TestAnyTLSBackpressureFrameQueueMatrix(t *testing.T) {
	s := anyTLSBackpressureStream(t)
	for i := 0; i < cap(s.queue); i++ {
		if !s.enqueue([]byte{'a'}) {
			t.Fatal("initial queue fill failed")
		}
	}
	accepted := make(chan bool, 1)
	go func() { accepted <- s.enqueue([]byte{'z'}) }()
	select {
	case result := <-accepted:
		t.Fatalf("full frame queue must wait, returned %v", result)
	case <-time.After(30 * time.Millisecond):
	}
	anyTLSBackpressurePump(t, s)
	readDone := make(chan error, 1)
	go func() {
		p := make([]byte, 9)
		_, err := io.ReadFull(s.read, p)
		if err == nil && !bytes.Equal(p, []byte("aaaaaaaaz")) {
			err = io.ErrUnexpectedEOF
		}
		readDone <- err
	}()
	select {
	case ok := <-accepted:
		if !ok {
			t.Fatal("queue rejected after drain")
		}
	case <-time.After(time.Second):
		t.Fatal("space did not wake enqueue")
	}
	select {
	case err := <-readDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("queued stream did not drain")
	}
}
