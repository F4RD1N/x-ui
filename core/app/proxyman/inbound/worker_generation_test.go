package inbound

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/task"
)

func generationTestWorker(t *testing.T) (*udpWorker, connID) {
	t.Helper()
	w := &udpWorker{ctx: context.Background(), address: net.LocalHostIP, port: 12345, activeConn: make(map[connID]*udpConn)}
	w.checker = &task.Periodic{Interval: time.Hour, Execute: w.clean}
	t.Cleanup(func() {
		_ = w.checker.Close()
		w.Lock()
		defer w.Unlock()
		for _, conn := range w.activeConn {
			_ = conn.Close()
			_ = common.Interrupt(conn.reader)
		}
	})
	return w, connID{src: net.UDPDestination(net.LocalHostIP, 23456)}
}

func TestUDPWorkerStaleCleanupPreservesReplacement(t *testing.T) {
	w, id := generationTestWorker(t)
	old, existing := w.getConnection(id)
	if existing {
		t.Fatal("first connection unexpectedly reused")
	}
	_ = old.Close() // Process has returned, but its deferred map cleanup is delayed.
	replacement, existing := w.getConnection(id)
	if existing || replacement == old {
		t.Fatal("closed connection was not replaced")
	}
	w.removeConn(id, old)
	if w.activeConn[id] != replacement {
		t.Fatal("stale cleanup removed the live replacement")
	}
	if err := w.checker.Start(); err != nil {
		t.Fatal("checker lost the live replacement", err)
	}
	if reused, existing := w.getConnection(id); !existing || reused != replacement {
		t.Fatal("next packet did not reuse the live replacement")
	}
	if replacement.ctx.Err() != nil || replacement.done.Done() {
		t.Fatal("stale cleanup canceled the replacement")
	}
	_ = replacement.Close()
	w.removeConn(id, replacement)
	if len(w.activeConn) != 0 {
		t.Fatal("current generation was not removed")
	}
}

func TestUDPWorkerCheckerFailureDoesNotPanicOrLeak(t *testing.T) {
	for _, replace := range []bool{false, true} {
		name := "no-replacement"
		if replace {
			name = "concurrent-replacement"
		}
		t.Run(name, func(t *testing.T) {
			w, id := generationTestWorker(t)
			var rejected, replacement *udpConn
			w.checker.Execute = func() error {
				w.RLock()
				rejected = w.activeConn[id]
				w.RUnlock()
				if rejected == nil {
					t.Fatal("connection was not registered before checker startup")
				}
				if replace {
					_ = rejected.Close()
					replacement, _ = w.getConnection(id)
				}
				return errors.New("synthetic checker stop")
			}
			packet := buf.New()
			_, _ = packet.Write([]byte("queued-before-checker-start"))
			// A hub and proxy are deliberately absent: this error must return
			// before creating a processing goroutine or touching network state.
			w.callback(packet, id.src, net.Destination{})
			if rejected == nil || !rejected.done.Done() || rejected.ctx.Err() == nil {
				t.Fatal("unstarted connection was not closed and canceled")
			}
			if n := rejected.writer.(interface{ Len() int32 }).Len(); n != 0 {
				t.Fatalf("unstarted connection retained %d queued bytes", n)
			}
			if data, err := rejected.reader.ReadMultiBuffer(); err == nil || len(data) != 0 {
				buf.ReleaseMulti(data)
				t.Fatal("unstarted connection's reader remained open")
			}
			if replace {
				if w.activeConn[id] != replacement || replacement.ctx.Err() != nil || replacement.done.Done() {
					t.Fatal("failed startup removed or canceled a concurrent replacement")
				}
			} else if len(w.activeConn) != 0 {
				t.Fatal("failed startup left an active connection entry")
			}
		})
	}
}

func TestUDPWorkerReplacementCleanupRace(t *testing.T) {
	w, id := generationTestWorker(t)
	for i := 0; i < 128; i++ {
		old, _ := w.getConnection(id)
		_ = old.Close()
		replacement, _ := w.getConnection(id)
		var tasks sync.WaitGroup
		tasks.Add(3)
		go func() {
			defer tasks.Done()
			_ = old.Close()
			w.removeConn(id, old)
		}()
		go func() {
			defer tasks.Done()
			if err := w.clean(); err != nil {
				t.Error("cleanup lost the replacement", err)
			}
		}()
		go func() {
			defer tasks.Done()
			replacement.updateActivity()
		}()
		tasks.Wait()
		if w.activeConn[id] != replacement || replacement.ctx.Err() != nil {
			t.Fatal("concurrent cleanup affected the replacement")
		}
		_ = replacement.Close()
		w.removeConn(id, replacement)
	}
}

func TestUDPWorkerCheckerIdleHandoffAndClose(t *testing.T) {
	w, id := generationTestWorker(t)
	emptyChecked := make(chan struct{})
	finishFirst := make(chan struct{})
	nextTick := make(chan struct{})
	finishTick := make(chan struct{})
	thirdTick := make(chan struct{}, 1)
	var executions atomic.Int32
	w.checker.Interval = 10 * time.Millisecond
	w.checker.Execute = func() error {
		err := w.clean()
		switch executions.Add(1) {
		case 1:
			close(emptyChecked)
			<-finishFirst
		case 2:
			close(nextTick)
			<-finishTick
		default:
			select {
			case thirdTick <- struct{}{}:
			default:
			}
		}
		return err
	}
	firstResult := make(chan error, 1)
	go func() { firstResult <- w.checker.Start() }()
	<-emptyChecked // First Execute has checked an empty map but not returned.
	conn, _ := w.getConnection(id)
	if err := w.checker.Start(); err != nil {
		t.Fatal("connection could not join the running checker", err)
	}
	close(finishFirst)
	if err := <-firstResult; err != nil {
		t.Fatal("empty cleanup stopped the checker after a connection joined", err)
	}
	select {
	case <-nextTick:
	case <-time.After(time.Second):
		t.Fatal("connection was left without periodic cleanup")
	}
	if conn.ctx.Err() != nil || conn.done.Done() {
		t.Fatal("idle checker handoff closed the new connection")
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	close(finishTick)
	select {
	case <-thirdTick:
		t.Fatal("checker scheduled another execution after Close")
	case <-time.After(40 * time.Millisecond):
	}
}

func TestUDPWorkerClosedCallbackReleasesPacket(t *testing.T) {
	w, id := generationTestWorker(t)
	var executions atomic.Int32
	w.checker.Execute = func() error {
		executions.Add(1)
		return nil
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	packet := buf.New()
	_, _ = packet.Write([]byte("packet-after-close"))
	w.callback(packet, id.src, net.Destination{})
	if !packet.IsEmpty() || len(w.activeConn) != 0 || executions.Load() != 0 {
		t.Fatal("closed callback retained its packet, connection or checker")
	}
	if conn, _ := w.getConnection(id); conn != nil {
		t.Fatal("closed worker admitted a connection")
	}
}

func TestUDPWorkerCloseBeforeCheckerStartStopsRestart(t *testing.T) {
	w, id := generationTestWorker(t)
	conn, _ := w.getConnection(id)
	packet := buf.New()
	_, _ = packet.Write([]byte("queued-before-close"))
	_ = conn.writer.WriteMultiBuffer(buf.MultiBuffer{packet})
	var executions atomic.Int32
	w.checker.Interval = 5 * time.Millisecond
	w.checker.Execute = func() error {
		executions.Add(1)
		return w.clean()
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	// This is exactly the callback handoff: getConnection already returned,
	// Close stopped the checker, and Start can now restart it synchronously.
	if w.startConnection(id, conn) {
		t.Fatal("closed worker admitted an unstarted processing goroutine")
	}
	if executions.Load() != 1 {
		t.Fatal("test did not exercise the post-Start closure check")
	}
	if !conn.done.Done() || conn.ctx.Err() == nil || len(w.activeConn) != 0 || conn.writer.(interface{ Len() int32 }).Len() != 0 {
		t.Fatal("closed startup retained context, queue or active registration")
	}
	time.Sleep(25 * time.Millisecond)
	if executions.Load() != 1 {
		t.Fatal("checker kept executing after the listener closed")
	}
}

func TestUDPWorkerCloseDuringCheckerStartDoesNotProcess(t *testing.T) {
	w, id := generationTestWorker(t)
	var rejected *udpConn
	var executions atomic.Int32
	w.checker.Interval = 5 * time.Millisecond
	w.checker.Execute = func() error {
		executions.Add(1)
		w.RLock()
		rejected = w.activeConn[id]
		w.RUnlock()
		return w.Close()
	}
	packet := buf.New()
	_, _ = packet.Write([]byte("close-during-checker-start"))
	// No hub or proxy is installed. A processing goroutine must not launch.
	w.callback(packet, id.src, net.Destination{})
	if rejected == nil || !rejected.done.Done() || rejected.ctx.Err() == nil || len(w.activeConn) != 0 || rejected.writer.(interface{ Len() int32 }).Len() != 0 {
		t.Fatal("callback survived listener closure during checker Start")
	}
	time.Sleep(25 * time.Millisecond)
	if executions.Load() != 1 {
		t.Fatal("checker was rescheduled after listener closure")
	}
}
