package mieru

import (
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type callbackPanicConn struct {
	net.Conn
	writes atomic.Int32
	closed chan struct{}
	once   sync.Once
}

func (c *callbackPanicConn) Write(p []byte) (int, error) {
	if c.writes.Add(1) == 1 {
		panic("private callback fixture marker")
	}
	return len(p), nil
}
func (c *callbackPanicConn) Close() error { c.once.Do(func() { close(c.closed) }); return nil }

func TestReviewAcknowledgementCallbackPanicContained(t *testing.T) {
	for _, trigger := range []string{"delayed-timer", "reader-window"} {
		for _, multiplexed := range []bool{false, true} {
			mode := "standalone"
			if multiplexed {
				mode = "multiplexed"
			}
			t.Run(trigger+"/"+mode, func(t *testing.T) {
				raw := &callbackPanicConn{closed: make(chan struct{})}
				parent, err := newWire(raw, "callback-user", "callback-password", true, false)
				if err != nil {
					t.Fatal(err)
				}
				parent.server = true
				w := parent
				var entry *inboundSession
				budget := new(atomic.Int64)
				if multiplexed {
					entry = resourceSession(t, budget, 4)
					entry.parent = raw
					w = &wire{conn: entry, parent: parent, udp: true, server: true, sessionDone: entry.done, incoming: entry.incoming, dequeue: entry.dequeue}
					if !entry.enqueue(resourceSegment(32768)) {
						t.Fatal("could not reserve cleanup fixture")
					}
				}
				c := &Conn{wire: w, sid: 1, next: 1, expected: 1, ooo: make(map[uint32][]byte), done: make(chan struct{}), opened: make(chan struct{}), kick: make(chan struct{}, 1), peerWindow: 128, cwnd: 32, ssthresh: 128}
				c.cond = sync.NewCond(&c.mu)
				c.advertised = c.maxReceiveSegments()
				t.Cleanup(func() { c.abort(net.ErrClosed) })
				if trigger == "delayed-timer" {
					// A single ordinary data frame schedules the real AfterFunc callback.
					if c.receiveUDP(segment{kind: dataClient, session: 1, seq: 1, payload: []byte{1}}) {
						t.Fatal("session ended before delayed acknowledgement")
					}
				} else {
					c.queue = [][]byte{{1}}
					c.queued = 1
					c.advertised = 0
					b := make([]byte, 1)
					if n, e := c.Read(b); n != 1 || e != nil || b[0] != 1 {
						t.Fatal("reader window fixture failed", n, e)
					}
				}
				select {
				case <-c.done:
				case <-time.After(time.Second):
					t.Fatal("panicking acknowledgement callback did not abort its session")
				}
				if err := c.error(); err == nil || !strings.Contains(err.Error(), "worker internal failure") || strings.Contains(err.Error(), "private callback fixture marker") {
					t.Fatal("callback panic was not converted to a sanitized session error", err)
				}
				if multiplexed {
					select {
					case <-entry.done:
					case <-time.After(time.Second):
						t.Fatal("callback failure did not close the logical stream")
					}
					entry.queueMu.Lock()
					retained := entry.bytes.Load() + budget.Load()
					entry.queueMu.Unlock()
					if retained != 0 {
						t.Fatal("callback failure leaked queued reservations")
					}
					select {
					case <-raw.closed:
						t.Fatal("one callback failure closed a shared underlay")
					default:
					}
					// Panic unwinding must release the common framing lock so an
					// unrelated stream can still send a valid acknowledgement.
					sibling := &wire{parent: parent, sessionDone: make(chan struct{})}
					result := make(chan error, 1)
					go func() { result <- sibling.write(segment{kind: ackServer, session: 2, window: 32, windowSet: true}) }()
					select {
					case e := <-result:
						if e != nil {
							t.Fatal("healthy sibling could not write", e)
						}
					case <-time.After(time.Second):
						t.Fatal("panic retained shared writer lock")
					}
				} else {
					select {
					case <-raw.closed:
					case <-time.After(time.Second):
						t.Fatal("callback failure did not close standalone transport")
					}
				}
			})
		}
	}
}
