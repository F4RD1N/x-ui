package singbridge

import (
	"errors"
	"fmt"
	"io"
	stdnet "net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	B "github.com/sagernet/sing/common/buf"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/pipe"
)

type packetReaderFunc func() (buf.MultiBuffer, error)

func (f packetReaderFunc) ReadMultiBuffer() (buf.MultiBuffer, error) { return f() }

func testPacket(payload string, destination *net.Destination) *buf.Buffer {
	b := buf.New()
	b.Write([]byte(payload))
	b.UDP = destination
	return b
}

func awaitPacketTest(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("packet operation did not complete")
	}
}

func TestPacketConnWrapperBatchDestinations(t *testing.T) {
	explicit := net.UDPDestination(net.ParseAddress("2001:db8::5"), 5353)
	fallback := net.UDPDestination(net.DomainAddress("example.invalid"), 53)
	first, second := testPacket("first", &explicit), testPacket("second", nil)
	reads := 0
	w := &PacketConnWrapper{Dest: fallback, Reader: packetReaderFunc(func() (buf.MultiBuffer, error) {
		reads++
		if reads > 1 {
			return nil, io.EOF
		}
		return buf.MultiBuffer{nil, first, nil, second}, nil
	})}
	defer w.Close()
	for _, want := range []struct {
		payload string
		dest    net.Destination
	}{{"first", explicit}, {"second", fallback}} {
		out := B.NewPacket()
		address, err := w.ReadPacket(out)
		got := string(out.Bytes())
		out.Release()
		if err != nil || got != want.payload || address != ToSocksaddr(want.dest) {
			t.Fatalf("got payload=%q address=%v err=%v; want %q %v", got, address, err, want.payload, want.dest)
		}
	}
	if reads != 1 || first.Len() != 0 || second.Len() != 0 {
		t.Fatalf("batch ownership: reads=%d first=%d second=%d", reads, first.Len(), second.Len())
	}
	out := B.NewPacket()
	defer out.Release()
	if _, err := w.ReadPacket(out); !errors.Is(err, io.EOF) {
		t.Fatalf("EOF was not preserved: %v", err)
	}
}

func TestPacketConnWrapperErrorReleasesBatch(t *testing.T) {
	packet := testPacket("discard on error", nil)
	w := &PacketConnWrapper{Reader: packetReaderFunc(func() (buf.MultiBuffer, error) {
		return buf.MultiBuffer{packet}, io.ErrUnexpectedEOF
	})}
	defer w.Close()
	out := B.NewPacket()
	defer out.Release()
	if _, err := w.ReadPacket(out); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("read error changed: %v", err)
	}
	if packet.Len() != 0 || out.Len() != 0 {
		t.Fatal("errored read retained or delivered its packet")
	}
}

func TestPacketConnWrapperConcurrentCloseAndCachedReads(t *testing.T) {
	for iteration := 0; iteration < 20; iteration++ {
		packets := make([]*buf.Buffer, 128)
		batch := make(buf.MultiBuffer, len(packets))
		for i := range packets {
			packets[i] = testPacket(fmt.Sprintf("packet-%d", i), nil)
			batch[i] = packets[i]
		}
		w := &PacketConnWrapper{Dest: net.UDPDestination(net.LocalHostIP, 53), Reader: packetReaderFunc(func() (buf.MultiBuffer, error) {
			if batch == nil {
				return nil, io.EOF
			}
			mb := batch
			batch = nil
			return mb, nil
		})}
		out := B.NewPacket()
		_, err := w.ReadPacket(out)
		out.Release()
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var workers sync.WaitGroup
		for i := 0; i < 64; i++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				<-start
				out := B.NewPacket()
				defer out.Release()
				if _, err := w.ReadPacket(out); err != nil && !errors.Is(err, stdnet.ErrClosed) {
					t.Errorf("concurrent read: %v", err)
				}
			}()
		}
		for i := 0; i < 8; i++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				<-start
				w.Close()
			}()
		}
		close(start)
		workers.Wait()
		for i, packet := range packets {
			if packet.Len() != 0 {
				t.Fatalf("iteration %d packet %d retained after Close", iteration, i)
			}
		}
		if w.cached != nil {
			t.Fatal("closed wrapper retained cached slice")
		}
	}
}

func TestPacketConnWrapperSerializesReaders(t *testing.T) {
	var active, peak atomic.Int32
	var serial atomic.Int32
	w := &PacketConnWrapper{Dest: net.UDPDestination(net.LocalHostIP, 53), Reader: packetReaderFunc(func() (buf.MultiBuffer, error) {
		n := active.Add(1)
		for prior := peak.Load(); n > prior; prior = peak.Load() {
			if peak.CompareAndSwap(prior, n) {
				break
			}
		}
		time.Sleep(time.Millisecond)
		packet := testPacket(fmt.Sprint(serial.Add(1)), nil)
		active.Add(-1)
		return buf.MultiBuffer{packet}, nil
	})}
	defer w.Close()
	var workers sync.WaitGroup
	results := make(chan string, 32)
	for i := 0; i < cap(results); i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			out := B.NewPacket()
			defer out.Release()
			if _, err := w.ReadPacket(out); err != nil {
				t.Errorf("read: %v", err)
				return
			}
			results <- string(out.Bytes())
		}()
	}
	workers.Wait()
	close(results)
	seen := make(map[string]bool)
	for payload := range results {
		if seen[payload] {
			t.Fatalf("duplicate delivery: %q", payload)
		}
		seen[payload] = true
	}
	if peak.Load() != 1 || len(seen) != cap(results) {
		t.Fatalf("underlying read peak=%d, unique packets=%d", peak.Load(), len(seen))
	}
}

func TestPacketConnWrapperCloseUnblocksUninterruptibleReader(t *testing.T) {
	started, release, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
	w := &PacketConnWrapper{Reader: packetReaderFunc(func() (buf.MultiBuffer, error) {
		close(started)
		<-release
		close(returned)
		return nil, io.EOF
	})}
	defer func() { close(release); awaitPacketTest(t, returned) }()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		out := B.NewPacket()
		defer out.Release()
		if _, err := w.ReadPacket(out); !errors.Is(err, stdnet.ErrClosed) {
			t.Errorf("close read: %v", err)
		}
	}()
	awaitPacketTest(t, started)
	closed := make(chan struct{})
	go func() { w.Close(); close(closed) }()
	awaitPacketTest(t, closed)
	awaitPacketTest(t, finished)
	// Reader is still blocked: Close must not acquire the serialization lock.
	select {
	case <-returned:
		t.Fatal("underlying reader unexpectedly returned")
	default:
	}
}

type interruptiblePacketReader struct {
	buf.Reader
	interrupt func()
}

func (r *interruptiblePacketReader) Interrupt() { r.interrupt() }

func TestPacketConnWrapperTimeoutIsTerminal(t *testing.T) {
	started, release, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var calls, interrupts atomic.Int32
	r := &interruptiblePacketReader{
		Reader: packetReaderFunc(func() (buf.MultiBuffer, error) {
			calls.Add(1)
			close(started)
			<-release
			close(returned)
			return nil, io.EOF
		}),
		interrupt: func() { interrupts.Add(1) }, // Deliberately cannot stop the read.
	}
	w := &PacketConnWrapper{Reader: r}
	defer func() { close(release); awaitPacketTest(t, returned) }()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		out := B.NewPacket()
		defer out.Release()
		if _, err := w.readPacket(out, 30*time.Millisecond); !errors.Is(err, buf.ErrReadTimeout) {
			t.Errorf("timeout: %v", err)
		}
	}()
	awaitPacketTest(t, started)
	awaitPacketTest(t, finished)
	out := B.NewPacket()
	defer out.Release()
	if _, err := w.ReadPacket(out); !errors.Is(err, stdnet.ErrClosed) {
		t.Fatalf("timed-out wrapper was reused: %v", err)
	}
	w.Close()
	if calls.Load() != 1 || interrupts.Load() != 1 {
		t.Fatalf("calls=%d interrupts=%d; want one each", calls.Load(), interrupts.Load())
	}
}

func TestPacketReadLateResultReleased(t *testing.T) {
	for _, readErr := range []error{nil, io.ErrUnexpectedEOF} {
		t.Run(fmt.Sprint(readErr), func(t *testing.T) {
			packet := testPacket("late packet", nil)
			started, release, finished, done := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
			reader := packetReaderFunc(func() (buf.MultiBuffer, error) {
				close(started)
				<-release
				return buf.MultiBuffer{packet}, readErr
			})
			// Run exactly the production read worker, joining its completion so
			// checking recycled-buffer state itself is synchronized under -race.
			go func() {
				defer close(finished)
				readPacketBuffers(reader, make(chan packetReadResult), done)
			}()
			awaitPacketTest(t, started)
			close(done)
			close(release)
			awaitPacketTest(t, finished)
			if packet.Len() != 0 {
				t.Fatal("late result was not released after cancellation")
			}
		})
	}
}

func TestPacketReadAlreadyCancelled(t *testing.T) {
	done := make(chan struct{})
	close(done)
	called := false
	readPacketBuffers(packetReaderFunc(func() (buf.MultiBuffer, error) {
		called = true
		return nil, nil
	}), make(chan packetReadResult), done)
	if called {
		t.Fatal("started a reader after cancellation")
	}
}

type packetWriterCloseProbe struct{ closed bool }

func (*packetWriterCloseProbe) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	return nil
}
func (p *packetWriterCloseProbe) Close() error { p.closed = true; return nil }

type packetConnCloseProbe struct {
	net.Conn
	closed bool
}

func (p *packetConnCloseProbe) Close() error { p.closed = true; return nil }

func TestPacketConnWrapperClosesReaderOnly(t *testing.T) {
	reader, writer := pipe.New(pipe.WithoutSizeLimit())
	started := make(chan struct{})
	r := &interruptiblePacketReader{
		Reader: packetReaderFunc(func() (buf.MultiBuffer, error) {
			close(started)
			return reader.ReadMultiBuffer()
		}),
		interrupt: reader.Interrupt,
	}
	writerProbe, connProbe := &packetWriterCloseProbe{}, &packetConnCloseProbe{}
	w := &PacketConnWrapper{Reader: r, Writer: writerProbe, Conn: connProbe}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		out := B.NewPacket()
		defer out.Release()
		if _, err := w.ReadPacket(out); err == nil {
			t.Error("interrupted pipe read succeeded")
		}
	}()
	awaitPacketTest(t, started)
	w.Close()
	awaitPacketTest(t, finished)
	if writerProbe.closed || connProbe.closed {
		t.Fatal("wrapper closed caller-owned writer or connection")
	}
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{testPacket("after close", nil)}); err == nil {
		t.Fatal("underlying pipe was not interrupted")
	}
}

func TestPacketConnWrapperCloseBeforeRead(t *testing.T) {
	w := &PacketConnWrapper{Reader: packetReaderFunc(func() (buf.MultiBuffer, error) {
		t.Error("closed wrapper called reader")
		return nil, io.EOF
	})}
	w.Close()
	w.Close()
	out := B.NewPacket()
	defer out.Release()
	if _, err := w.ReadPacket(out); !errors.Is(err, stdnet.ErrClosed) {
		t.Fatalf("closed wrapper returned %v", err)
	}
}
